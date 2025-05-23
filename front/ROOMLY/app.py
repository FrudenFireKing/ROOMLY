from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_wtf.csrf import CSRFProtect
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
import json
import os
import re
import logging
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.text import MIMEText
from threading import Thread

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=60)
csrf = CSRFProtect(app)

# Настройка логирования
logging.basicConfig(
    filename='security.log',
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

# Конфигурация
SUPERUSER_USERNAME = "superadmin"
SUPERUSER_PASSWORD = os.environ.get('SUPERUSER_PASSWORD', "superpassword123")
METADATA_FILE = 'metadata.txt'
DB_FILE = 'users.db'
EMAIL_SMTP_SERVER = "smtp.yandex.ru"  # SMTP сервер
EMAIL_SMTP_PORT = 587
EMAIL_SMTP_USER = "roomlynoreply@yandex.ru"  # email
EMAIL_SMTP_PASSWORD = "sklzhhhmyuzxlanj"  # пароль для SMTP
EMAIL_FROM = "Roomly <roomlynoreply@yandex.ru>"  # email отправителя

# Глобальный словарь для хранения временных кодов подтверждения
email_verification_codes = {}

PASSWORD_RESET_CODES = {}

# Регулярные выражения для валидации
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$')

AVAILABLE_EQUIPMENT = [
    "Проектор",
    "Доска",
    "Телевизор",
    "Wi-Fi",
    "Кондиционер",
    "Кофе",
    "Конференц-зал",
    #"Кухня",
    #"Балкон",
    #"Библиотека",
]

def safe_string_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA secure_delete = ON')
    return conn


def check_db_integrity():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('PRAGMA integrity_check')
        result = cursor.fetchone()
        conn.close()
        return result[0] == 'ok'
    except sqlite3.DatabaseError as e:
        logger.error(f"Database integrity check failed: {str(e)}")
        return False


def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Проверяем существование таблиц
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            # Создаём таблицы только если они не существуют
            cursor.execute('PRAGMA foreign_keys = ON')
            cursor.execute('PRAGMA secure_delete = ON')

            # Таблица пользователей
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    is_admin BOOLEAN DEFAULT 0,
                    joined_date TEXT,
                    last_login TEXT,
                    failed_attempts INTEGER DEFAULT 0
                )
            ''')

            # Таблица комнат
            cursor.execute('''
                CREATE TABLE rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    capacity INTEGER NOT NULL,
                    equipment TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Таблица фотографий комнат
            cursor.execute('''
                CREATE TABLE room_photos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id INTEGER NOT NULL,
                    photo_url TEXT NOT NULL,
                    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
                )
            ''')

            # Таблица бронирований
            cursor.execute('''
                CREATE TABLE bookings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')

            # Создаём индексы
            cursor.execute('CREATE INDEX idx_users_username ON users(username)')
            cursor.execute('CREATE INDEX idx_bookings_room_id ON bookings(room_id)')
            cursor.execute('CREATE INDEX idx_bookings_user_id ON bookings(user_id)')

            # Добавляем тестового администратора (пароль: admin123)
            hashed_password = hashpw(b'admin123', gensalt())
            cursor.execute(
                'INSERT INTO users (username, email, password, is_admin, joined_date) VALUES (?, ?, ?, ?, ?)',
                ('admin', 'admin@example.com', hashed_password, 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )

            conn.commit()
            logger.info("Database initialized successfully")
        else:
            logger.info("Database already exists, skipping initialization")

    except sqlite3.Error as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()


def validate_input(data, regex, field_name):
    if not regex.match(data):
        logger.warning(f"Invalid input attempt for {field_name}: {data} from IP {request.remote_addr}")
        raise ValueError(f"Некорректный формат {field_name}")


def sanitize_input(input_str):
    return re.sub(r'[;\\\'"<>%$]', '', input_str)


def is_room_available(room_id, start_time, end_time, booking_id=None):
    conn = None
    try:
        conn = get_db_connection()

        query = '''
            SELECT id FROM bookings 
            WHERE room_id = ? 
            AND (
                (start_time < ? AND end_time > ?) OR
                (start_time BETWEEN ? AND ?) OR
                (end_time BETWEEN ? AND ?) OR
                (start_time <= ? AND end_time >= ?)
            )
        '''
        params = [
            room_id,
            end_time, start_time,
            start_time, end_time,
            start_time, end_time,
            start_time, end_time
        ]

        if booking_id:
            query += ' AND id != ?'
            params.append(booking_id)

        existing = conn.execute(query, params).fetchone()
        return existing is None

    except sqlite3.Error as e:
        logger.error(f"Error in is_room_available: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


@app.before_request
def security_checks():
    if request.content_length and request.content_length > 1024 * 1024:
        abort(413)
    if request.method == 'POST' and not request.content_type.startswith('application/x-www-form-urlencoded'):
        abort(400)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        conn = get_db_connection()
        try:
            # Проверка входа суперпользователя
            if safe_string_compare(username, SUPERUSER_USERNAME) and safe_string_compare(password, SUPERUSER_PASSWORD):
                session['user_id'] = 0
                session['username'] = SUPERUSER_USERNAME
                session['is_admin'] = True
                session['is_superuser'] = True  # Добавляем флаг суперпользователя
                flash('Вход выполнен успешно как суперпользователь!', 'success')
                return redirect(url_for('profile'))

            # Обычный вход пользователя
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

            if user and user['failed_attempts'] > 5:
                flash('Слишком много неудачных попыток. Попробуйте позже.', 'error')
                return redirect(url_for('profile'))

            if user and checkpw(password.encode('utf-8'), user['password']):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['is_admin'] = user['is_admin']
                session['is_superuser'] = False  # Обычный пользователь
                session['joined_date'] = user['joined_date']

                conn.execute(
                    'UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id'])
                )
                conn.commit()

                flash('Вход выполнен успешно!', 'success')
                return redirect(url_for('profile'))
            else:
                if user:
                    conn.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user['id'],))
                    conn.commit()
                flash('Неверное имя пользователя или пароль.', 'error')
        finally:
            conn.close()
        return redirect(url_for('profile'))

    if 'user_id' not in session:
        return render_template('profile.html', is_authenticated=False)

    conn = get_db_connection()
    try:
        # Проверяем, является ли пользователь суперпользователем
        is_superuser = session.get('is_superuser', False)

        # Получаем бронирования
        if is_superuser:
            # Для суперпользователя показываем только его бронирования (user_id=0)
            bookings = conn.execute('''
                SELECT b.id, b.start_time, b.end_time, b.purpose, r.name as room_name
                FROM bookings b JOIN rooms r ON b.room_id = r.id
                WHERE b.user_id = 0 AND b.end_time > ?
                ORDER BY b.start_time DESC
            ''', (datetime.now().strftime('%Y-%m-%dT%H:%M'),)).fetchall()
        else:
            # Для обычных пользователей показываем их бронирования
            bookings = conn.execute('''
                SELECT b.id, b.start_time, b.end_time, b.purpose, r.name as room_name
                FROM bookings b JOIN rooms r ON b.room_id = r.id
                WHERE b.user_id = ? AND b.end_time > ?
                ORDER BY b.start_time DESC
            ''', (session['user_id'], datetime.now().strftime('%Y-%m-%dT%H:%M'))).fetchall()

        formatted_bookings = []
        for booking in bookings:
            formatted_booking = dict(booking)
            start_time = booking['start_time']
            end_time = booking['end_time']

            if isinstance(start_time, str):
                start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
                formatted_booking['start_time'] = start_time.strftime('%Y-%m-%d %H:%M')

            if isinstance(end_time, str):
                end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
                formatted_booking['end_time'] = end_time.strftime('%Y-%m-%d %H:%M')

            formatted_bookings.append(formatted_booking)

        return render_template('profile.html',
                           is_authenticated=True,
                           username=session['username'],
                           email=session.get('email', ''),
                           joined_date=session.get('joined_date', 'Не указана'),
                           bookings=formatted_bookings,
                           is_superuser=is_superuser)
    finally:
        conn.close()



def generate_verification_code():
    return str(random.randint(100000, 999999))


def send_verification_email(email, code):
    try:
        msg = MIMEText(f"""
        Здравствуйте!
        Ваш код подтверждения для регистрации на ROOMLY: {code}
        Введите этот код на странице подтверждения, чтобы завершить регистрацию.
        Если вы не регистрировались на нашем сайте, проигнорируйте это письмо.

        С уважением,
        Команда ROOMLY
        """, 'plain', 'utf-8')
        msg['Subject'] = 'Код подтверждения для ROOMLY'
        msg['From'] = EMAIL_FROM
        msg['To'] = email
        msg['Content-Type'] = 'text/plain; charset=utf-8'

        with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SMTP_USER, EMAIL_SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Error sending verification email: {str(e)}")
        return False

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''))
            email = sanitize_input(request.form.get('email', ''))
            password = request.form.get('password', '')
            password_confirm = request.form.get('password_confirm', '')

            validate_input(username, USERNAME_REGEX, 'имя пользователя')
            validate_input(email, EMAIL_REGEX, 'email')

            if len(password) < 8:
                raise ValueError("Пароль должен содержать минимум 8 символов")

            if password != password_confirm:
                raise ValueError("Пароли не совпадают")

            # Генерируем код подтверждения
            verification_code = generate_verification_code()
            email_verification_codes[email] = {
                'code': verification_code,
                'username': username,
                'password': password,
                'timestamp': datetime.now()
            }

            print(f"Код подтверждения для {email}: {verification_code}")

            # Отправляем email в отдельном потоке, чтобы не блокировать ответ
            Thread(target=send_verification_email, args=(email, verification_code)).start()

            # Перенаправляем на страницу подтверждения
            session['pending_email'] = email
            flash('Код подтверждения отправлен на вашу почту. Пожалуйста, введите его ниже.', 'success')
            return redirect(url_for('verify_email'))

        except ValueError as e:
            flash(str(e), 'error')
            return render_template('register.html',
                                   username=request.form.get('username', ''),
                                   email=request.form.get('email', ''))
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('Ошибка сервера при регистрации', 'error')
            return render_template('register.html',
                                   username=request.form.get('username', ''),
                                   email=request.form.get('email', ''))
    return render_template('register.html', username='', email='')


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if 'pending_email' not in session:
        flash('Пожалуйста, сначала зарегистрируйтесь.', 'error')
        return redirect(url_for('register'))

    email = session['pending_email']

    if request.method == 'POST':
        code = request.form.get('code', '').strip()

        if not code or not code.isdigit() or len(code) != 6:
            flash('Пожалуйста, введите 6-значный код.', 'error')
            return render_template('verify_email.html')

        # Проверяем код
        if email in email_verification_codes:
            stored_data = email_verification_codes[email]

            # Проверяем срок действия кода (30 минут)
            if (datetime.now() - stored_data['timestamp']) > timedelta(minutes=30):
                flash('Срок действия кода истёк. Пожалуйста, зарегистрируйтесь снова.', 'error')
                del email_verification_codes[email]
                session.pop('pending_email', None)
                return redirect(url_for('register'))

            if code == stored_data['code']:
                # Код верный, регистрируем пользователя
                hashed_password = hashpw(stored_data['password'].encode('utf-8'), gensalt())
                joined_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                conn = get_db_connection()
                try:
                    conn.execute(
                        'INSERT INTO users (username, email, password, joined_date) VALUES (?, ?, ?, ?)',
                        (stored_data['username'], email, hashed_password, joined_date)
                    )
                    conn.commit()

                    # Автоматически входим пользователя
                    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['email'] = user['email']
                    session['is_admin'] = user['is_admin']
                    session['joined_date'] = user['joined_date']

                    # Очищаем временные данные
                    del email_verification_codes[email]
                    session.pop('pending_email', None)

                    flash('Регистрация прошла успешно! Добро пожаловать!', 'success')
                    return redirect(url_for('profile'))
                except sqlite3.IntegrityError:
                    flash('Пользователь с таким именем или email уже существует.', 'error')
                finally:
                    conn.close()
            else:
                flash('Неверный код подтверждения. Попробуйте еще раз.', 'error')
        else:
            flash('Код подтверждения не найден или истёк. Пожалуйста, зарегистрируйтесь снова.', 'error')
            return redirect(url_for('register'))

    return render_template('verify_email.html')


@app.route('/resend_code', methods=['GET', 'POST'])
def resend_code():
    if 'pending_email' not in session:
        flash('Пожалуйста, сначала зарегистрируйтесь.', 'error')
        return redirect(url_for('register'))

    email = session['pending_email']

    if request.method == 'POST':
        # Генерируем новый код
        new_code = generate_verification_code()
        email_verification_codes[email] = {
            'code': new_code,
            'username': email_verification_codes[email]['username'],
            'password': email_verification_codes[email]['password'],
            'timestamp': datetime.now()
        }

        # Отправляем email
        if send_verification_email(email, new_code):
            flash('Новый код подтверждения отправлен на вашу почту.', 'success')
        else:
            flash('Не удалось отправить код. Попробуйте позже.', 'error')

        return redirect(url_for('verify_email'))

    return render_template('resend_code.html')


# Добавляем в глобальные переменные
PASSWORD_RESET_CODES = {}


# Добавляем новые маршруты
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', ''))

        try:
            validate_input(email, EMAIL_REGEX, 'email')

            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            if not user:
                flash('Пользователь с таким email не найден', 'error')
                return redirect(url_for('forgot_password'))

            # Генерируем код сброса
            reset_code = generate_verification_code()
            PASSWORD_RESET_CODES[email] = {
                'code': reset_code,
                'timestamp': datetime.now()
            }

            # Отправляем email с кодом
            Thread(target=send_password_reset_email, args=(email, reset_code)).start()

            session['reset_email'] = email
            flash('Код для сброса пароля отправлен на вашу почту', 'success')
            return redirect(url_for('reset_password'))

        except ValueError as e:
            flash(str(e), 'error')

    return render_template('forgot_password.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash('Сначала запросите сброс пароля', 'error')
        return redirect(url_for('forgot_password'))

    email = session['reset_email']

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not code or not code.isdigit() or len(code) != 6:
            flash('Пожалуйста, введите 6-значный код', 'error')
        elif new_password != confirm_password:
            flash('Пароли не совпадают', 'error')
        elif len(new_password) < 8:
            flash('Пароль должен содержать минимум 8 символов', 'error')
        elif email not in PASSWORD_RESET_CODES:
            flash('Код сброса не найден или истёк', 'error')
            return redirect(url_for('forgot_password'))
        elif (datetime.now() - PASSWORD_RESET_CODES[email]['timestamp']) > timedelta(minutes=30):
            flash('Срок действия кода истёк', 'error')
            del PASSWORD_RESET_CODES[email]
            return redirect(url_for('forgot_password'))
        elif code != PASSWORD_RESET_CODES[email]['code']:
            flash('Неверный код подтверждения', 'error')
        else:
            # Обновляем пароль
            hashed_password = hashpw(new_password.encode('utf-8'), gensalt())

            conn = get_db_connection()
            conn.execute(
                'UPDATE users SET password = ? WHERE email = ?',
                (hashed_password, email)
            )
            conn.commit()
            conn.close()

            # Очищаем сессию
            del PASSWORD_RESET_CODES[email]
            session.pop('reset_email', None)

            flash('Пароль успешно изменён! Теперь вы можете войти', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html')


def send_password_reset_email(email, code):
    try:
        msg = MIMEText(f"""
        Здравствуйте!
        Для сброса пароля на ROOMLY используйте следующий код: {code}
        Если вы не запрашивали сброс пароля, проигнорируйте это письмо.
        С уважением,
        Команда ROOMLY
        """, 'plain', 'utf-8')
        msg['Subject'] = 'Сброс пароля для ROOMLY'
        msg['From'] = EMAIL_FROM
        msg['To'] = email

        with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SMTP_USER, EMAIL_SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Error sending password reset email: {str(e)}")
        return False


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('profile'))


@app.route('/rooms')
def rooms():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('profile'))

    capacity_filter = request.args.get('capacity')
    equipment_filter = request.args.getlist('equipment')

    conn = get_db_connection()
    try:
        # Базовый запрос
        query = 'SELECT * FROM rooms WHERE 1=1'
        params = []

        # Фильтр по вместимости
        if capacity_filter and capacity_filter.isdigit():
            query += ' AND capacity >= ?'
            params.append(int(capacity_filter))

        # Фильтр по оборудованию
        if equipment_filter:
            # Создаем условия для каждого элемента оборудования
            conditions = []
            for equipment in equipment_filter:
                # Ищем оборудование в разных вариантах:
                # - в начале списка: "Проектор, ..."
                # - в середине списка: "... , Проектор, ..."
                # - в конце списка: "... , Проектор"
                conditions.append(
                    "(equipment LIKE ? OR equipment LIKE ? OR equipment LIKE ? OR equipment = ?)"
                )
                params.extend([
                    f"{equipment},%",
                    f"%, {equipment},%",
                    f"%, {equipment}",
                    equipment
                ])

            query += " AND (" + " OR ".join(conditions) + ")"

        rooms = conn.execute(query, params).fetchall()
        return render_template('rooms.html',
                               rooms=rooms,
                               available_equipment=AVAILABLE_EQUIPMENT,
                               selected_equipment=equipment_filter,
                               selected_capacity=capacity_filter)
    finally:
        conn.close()

@app.route('/add_room', methods=['GET', 'POST'])
def add_room():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для выполнения этого действия.', 'error')
        return redirect(url_for('rooms'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        capacity = request.form.get('capacity', '')
        equipment = request.form.getlist('equipment')  # Получаем список выбранных элементов
        equipment_str = ', '.join(equipment)  # Преобразуем в строку
        photo_urls = request.form.getlist('photo_urls[]')

        if not name:
            flash('Название комнаты не может быть пустым', 'error')
            return redirect(url_for('add_room'))

        if not capacity.isdigit():
            flash('Вместимость должна быть числом', 'error')
            return redirect(url_for('add_room'))

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO rooms (name, capacity, equipment) VALUES (?, ?, ?)',
                (name, capacity, equipment_str)
            )
            room_id = cursor.lastrowid

            for url in photo_urls:
                if url.strip():
                    cursor.execute(
                        'INSERT INTO room_photos (room_id, photo_url) VALUES (?, ?)',
                        (room_id, url.strip())
                    )

            conn.commit()
            flash('Комната успешно добавлена!', 'success')
            return redirect(url_for('rooms'))
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error adding room: {str(e)}")
            flash('Ошибка при добавлении комнаты', 'error')
        finally:
            conn.close()

    return render_template('add_room.html', available_equipment=AVAILABLE_EQUIPMENT)


@app.route('/book_room/<int:room_id>', methods=['GET', 'POST'])
def book_room(room_id):
    if 'user_id' not in session:
        flash('Для бронирования необходимо войти в систему', 'error')
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
        if not room:
            flash('Указанная комната не существует', 'error')
            return redirect(url_for('rooms'))

        # Для суперпользователя пропускаем проверку пользователя в БД
        if not session.get('is_superuser'):
            user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            if not user:
                session.clear()
                flash('Ваш аккаунт не найден. Пожалуйста, войдите снова', 'error')
                return redirect(url_for('login'))

        if request.method == 'POST':
            start_time = request.form.get('start_time', '').strip()
            end_time = request.form.get('end_time', '').strip()
            purpose = sanitize_input(request.form.get('purpose', ''))

            try:
                current_time = datetime.now()
                buffer_time = timedelta(minutes=2)  # Добавляем буфер в 2 минуты
                min_start_time = current_time - buffer_time

                start_dt = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
                end_dt = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')

                if start_dt >= end_dt:
                    flash('Время окончания должно быть позже времени начала', 'error')
                elif start_dt < min_start_time:
                    flash(
                        'Нельзя забронировать комнату на время, которое уже прошло (или начинается менее чем через 2 минуты)',
                        'error')
                else:
                    if is_room_available(room_id, start_time, end_time):
                        # Для суперпользователя используем user_id=0, для обычных - их реальный ID
                        user_id = 0 if session.get('is_superuser') else session['user_id']

                        conn.execute(
                            '''INSERT INTO bookings 
                            (room_id, user_id, start_time, end_time, purpose) 
                            VALUES (?, ?, ?, ?, ?)''',
                            (room_id, user_id, start_time, end_time, purpose)
                        )
                        conn.commit()
                        flash('Комната успешно забронирована!', 'success')
                        return redirect(url_for('profile'))
                    else:
                        flash('Комната уже занята на выбранное время', 'error')
            except ValueError:
                flash('Некорректный формат времени', 'error')

        photos = conn.execute(
            'SELECT photo_url FROM room_photos WHERE room_id = ?',
            (room_id,)
        ).fetchall()

        # Устанавливаем минимальное время для бронирования (текущее время + 2 минуты)
        min_datetime = (datetime.now() + timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M')

        return render_template('book_room.html',
                               room=room,
                               photos=photos,
                               min_datetime=min_datetime,
                               max_date=(datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'))
    except sqlite3.Error as e:
        logger.error(f"Database error in book_room: {str(e)}")
        flash('Произошла ошибка при работе с базой данных', 'error')
        return redirect(url_for('rooms'))
    finally:
        if conn:
            conn.close()

# Добавляем новый маршрут в app.py с пагинацией
@app.route('/all_bookings')
def all_bookings():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для просмотра этой страницы.', 'error')
        return redirect(url_for('profile'))

    page = request.args.get('page', 1, type=int)
    per_page = 10  # Количество бронирований на странице

    conn = get_db_connection()
    try:
        # Получаем общее количество бронирований для пагинации
        total_bookings = conn.execute('SELECT COUNT(*) FROM bookings').fetchone()[0]

        # Получаем бронирования для текущей страницы
        bookings = conn.execute('''
            SELECT b.id, b.start_time, b.end_time, b.purpose, 
                   r.name as room_name, 
                   u.username as user_name,
                   u.email as user_email
            FROM bookings b 
            JOIN rooms r ON b.room_id = r.id
            JOIN users u ON b.user_id = u.id
            WHERE b.end_time > ?
            ORDER BY b.start_time DESC
            LIMIT ? OFFSET ?
        ''', (datetime.now().strftime('%Y-%m-%dT%H:%M'), per_page, (page - 1) * per_page)).fetchall()

        formatted_bookings = []
        for booking in bookings:
            formatted_booking = dict(booking)
            start_time = booking['start_time']
            end_time = booking['end_time']

            if isinstance(start_time, str):
                start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
                formatted_booking['start_time'] = start_time.strftime('%Y-%m-%d %H:%M')

            if isinstance(end_time, str):
                end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
                formatted_booking['end_time'] = end_time.strftime('%Y-%m-%d %H:%M')

            formatted_bookings.append(formatted_booking)

        return render_template('all_bookings.html',
                               bookings=formatted_bookings,
                               page=page,
                               per_page=per_page,
                               total_bookings=total_bookings)
    finally:
        conn.close()


# Обновляем маршрут cancel_booking для суперпользователя
@app.route('/cancel_booking/<int:booking_id>')
def cancel_booking(booking_id):
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    try:
        # Проверяем, является ли пользователь суперпользователем
        is_superuser = session.get('username') == SUPERUSER_USERNAME and session.get('is_admin')

        if is_superuser:
            # Суперпользователь может отменить любое бронирование
            booking = conn.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,)).fetchone()
            if not booking:
                flash('Бронирование не найдено', 'error')
                return redirect(url_for('all_bookings'))
        else:
            # Обычный пользователь может отменить только свои бронирования
            booking = conn.execute(
                'SELECT * FROM bookings WHERE id = ? AND user_id = ?',
                (booking_id, session['user_id'])
            ).fetchone()
            if not booking:
                flash('Бронирование не найдено или у вас нет прав для его отмены', 'error')
                return redirect(url_for('profile'))

        conn.execute('DELETE FROM bookings WHERE id = ?', (booking_id,))
        conn.commit()

        flash('Бронирование успешно отменено', 'success')
        return redirect(url_for('all_bookings')) if is_superuser else redirect(url_for('profile'))
    finally:
        conn.close()

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        if not user:
            flash('Пользователь не найден.', 'error')
            return redirect(url_for('profile'))

        if request.method == 'POST':
            new_username = sanitize_input(request.form.get('username', ''))
            new_email = sanitize_input(request.form.get('email', ''))
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')

            if not checkpw(current_password.encode('utf-8'), user['password']):
                flash('Неверный текущий пароль.', 'error')
                return redirect(url_for('edit_profile'))

            try:
                conn.execute(
                    'UPDATE users SET username = ?, email = ? WHERE id = ?',
                    (new_username, new_email, session['user_id'])
                )

                if new_password:
                    if len(new_password) < 8:
                        flash('Новый пароль должен содержать минимум 8 символов', 'error')
                        return redirect(url_for('edit_profile'))

                    hashed_password = hashpw(new_password.encode('utf-8'), gensalt())
                    conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, session['user_id']))

                conn.commit()
                session['username'] = new_username
                session['email'] = new_email
                flash('Профиль успешно обновлен!', 'success')
                return redirect(url_for('profile'))
            except sqlite3.IntegrityError:
                flash('Пользователь с таким именем или email уже существует.', 'error')

        return render_template('edit_profile.html',
                               username=user['username'],
                               email=user['email'])
    finally:
        conn.close()


@app.route('/edit_room/<int:room_id>', methods=['GET', 'POST'])
def edit_room(room_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для выполнения этого действия.', 'error')
        return redirect(url_for('rooms'))

    conn = get_db_connection()
    try:
        room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
        if not room:
            flash('Комната не найдена.', 'error')
            return redirect(url_for('rooms'))

        photos = conn.execute('SELECT * FROM room_photos WHERE room_id = ?', (room_id,)).fetchall()

        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            capacity = request.form.get('capacity', '')
            equipment = request.form.getlist('equipment')  # Получаем список выбранных элементов

            # Преобразуем список в строку для хранения в БД
            equipment_str = ', '.join(equipment)

            if not name:
                flash('Название комнаты не может быть пустым', 'error')
                return redirect(url_for('edit_room', room_id=room_id))

            if not capacity.isdigit():
                flash('Вместимость должна быть числом', 'error')
                return redirect(url_for('edit_room', room_id=room_id))

            conn.execute(
                'UPDATE rooms SET name = ?, capacity = ?, equipment = ? WHERE id = ?',
                (name, capacity, equipment_str, room_id)
            )
            conn.commit()
            flash('Изменения комнаты успешно сохранены!', 'success')
            return redirect(url_for('rooms'))

        # Преобразуем equipment в список для шаблона
        equipment_list = [e.strip() for e in room['equipment'].split(',')]
        return render_template('edit_room.html',
                               room=room,
                               photos=photos,
                               available_equipment=AVAILABLE_EQUIPMENT,
                               current_equipment=equipment_list)
    finally:
        conn.close()

@app.route('/add_photo/<int:room_id>', methods=['POST'])
def add_photo(room_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для выполнения этого действия.', 'error')
        return redirect(url_for('rooms'))

    photo_url = sanitize_input(request.form.get('photo_url', ''))

    if not photo_url:
        flash('URL фотографии не может быть пустым', 'error')
        return redirect(url_for('edit_room', room_id=room_id))

    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO room_photos (room_id, photo_url) VALUES (?, ?)',
            (room_id, photo_url)
        )
        conn.commit()
        flash('Фотография успешно добавлена!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Error adding photo: {str(e)}")
        flash('Ошибка при добавлении фотографии', 'error')
    finally:
        conn.close()

    return redirect(url_for('edit_room', room_id=room_id))


@app.route('/delete_photo/<int:photo_id>', methods=['POST'])
def delete_photo(photo_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для выполнения этого действия.', 'error')
        return redirect(url_for('rooms'))

    conn = get_db_connection()
    try:
        # Получаем room_id перед удалением, чтобы вернуться на страницу редактирования
        photo = conn.execute('SELECT room_id FROM room_photos WHERE id = ?', (photo_id,)).fetchone()
        if photo:
            conn.execute('DELETE FROM room_photos WHERE id = ?', (photo_id,))
            conn.commit()
            flash('Фотография успешно удалена!', 'success')
            return redirect(url_for('edit_room', room_id=photo['room_id']))
        else:
            flash('Фотография не найдена', 'error')
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Error deleting photo: {str(e)}")
        flash('Ошибка при удалении фотографии', 'error')
    finally:
        conn.close()

    return redirect(url_for('rooms'))

@app.route('/delete_room/<int:room_id>')
def delete_room(room_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для выполнения этого действия.', 'error')
        return redirect(url_for('rooms'))

    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
        flash('Комната успешно удалена!', 'success')
    finally:
        conn.close()
    return redirect(url_for('rooms'))


@app.after_request
def add_security_headers(response):
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' https://s.iimg.su https://i.ibb.co https://sun9-55.userapi.com https://i.imgur.com data:; "
        "connect-src 'self' https://api.example.com; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "block-all-mixed-content;"
    )

    if request.path.startswith('/book_room/'):
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
            "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' https://s.iimg.su https://i.ibb.co https://sun9-55.userapi.com https://i.imgur.com data:; "
            "connect-src 'self' https://api.example.com; "
            "frame-src 'none'; "
            "object-src 'none';"
        )

    response.headers['Content-Security-Policy'] = csp_policy
    return response


def check_db_integrity():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Проверяем существование всех таблиц
        required_tables = ['users', 'rooms', 'room_photos', 'bookings']
        for table in required_tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if not cursor.fetchone():
                return False

        # Проверяем внешние ключи
        cursor.execute('PRAGMA foreign_key_check')
        if cursor.fetchone():
            return False

        return True
    except sqlite3.Error as e:
        logger.error(f"Database integrity check failed: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


def print_startup_message():
    print("\n" + "=" * 50)
    print("Сервер успешно запущен!")
    print(f"  - Главная страница: http://127.0.0.1:5000/")
    print("=" * 50 + "\n")


if __name__ == '__main__':
    # Проверяем и инициализируем БД
    if not os.path.exists(DB_FILE) or not check_db_integrity():
        try:
            if os.path.exists(DB_FILE):
                os.remove(DB_FILE)
            init_db()
        except Exception as e:
            logger.critical(f"Failed to initialize database: {str(e)}")
            raise

    # Выводим сообщение перед запуском
    print_startup_message()
    # Запускаем сервер с выводом в консоль
    app.run(debug=True, host='0.0.0.0')
    print_startup_message()