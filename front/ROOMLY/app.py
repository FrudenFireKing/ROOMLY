from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_wtf.csrf import CSRFProtect
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
import json
import os
import re
import logging
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=30)
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
    "Кухня",
    "Балкон",
    "Библиотека",
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
    db_needs_init = False

    if not os.path.exists(DB_FILE):
        db_needs_init = True
    else:
        if not check_db_integrity():
            logger.warning("Database is corrupted, recreating...")
            try:
                os.remove(DB_FILE)
                db_needs_init = True
            except OSError as e:
                logger.error(f"Failed to remove corrupted database: {str(e)}")
                raise

    if db_needs_init:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=10)
            cursor = conn.cursor()

            cursor.execute('PRAGMA foreign_keys = ON')
            cursor.execute('PRAGMA secure_delete = ON')
            cursor.execute('PRAGMA journal_mode = WAL')

            # Создаем таблицы
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

            cursor.execute('CREATE INDEX idx_users_username ON users(username)')

            cursor.execute('''
                CREATE TABLE rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    capacity INTEGER NOT NULL,
                    equipment TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE room_photos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id INTEGER NOT NULL,
                    photo_url TEXT NOT NULL,
                    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
                )
            ''')

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

            cursor.execute('CREATE INDEX idx_bookings_room_id ON bookings(room_id)')
            cursor.execute('CREATE INDEX idx_bookings_user_id ON bookings(user_id)')

            # Добавляем тестовые данные
            rooms_data = [
                ('Комната 1', 4, 'Проектор, доска'),
                ('Комната 2', 6, 'Телевизор, Wi-Fi'),
                ('Комната 3', 8, 'Кондиционер, кофе'),
                ('Комната 4', 10, 'Конференц-зал, проектор'),
                ('Комната 5', 12, 'Кухня, телевизор'),
                ('Комната 6', 15, 'Балкон, кондиционер'),
                ('Комната 7', 20, 'Большой зал, сцена'),
                ('Комната 8', 25, 'Бильярд, бар'),
                ('Комната 9', 30, 'Тренажерный зал, душ'),
                ('Комната 10', 35, 'Кинотеатр, барная стойка'),
                ('Комната 11', 40, 'Библиотека, камин'),
                ('Комната 12', 50, 'Банкетный зал, сцена')
            ]

            cursor.executemany('INSERT INTO rooms (name, capacity, equipment) VALUES (?, ?, ?)', rooms_data)

            # Добавляем тестовые фото для комнат
            for room_id in range(1, 13):
                cursor.execute(
                    'INSERT INTO room_photos (room_id, photo_url) VALUES (?, ?)',
                    (room_id, f'https://i.ibb.co/BVR0ZjRY/peregovorochka.jpg')
                )

            conn.commit()
            logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise
        finally:
            if conn:
                conn.close()
    else:
        logger.info("Database already exists and is valid, skipping initialization")


def validate_input(data, regex, field_name):
    if not regex.match(data):
        logger.warning(f"Invalid input attempt for {field_name}: {data} from IP {request.remote_addr}")
        raise ValueError(f"Некорректный формат {field_name}")


def sanitize_input(input_str):
    return re.sub(r'[;\\\'"<>%$]', '', input_str)


def is_room_available(room_id, start_time, end_time, booking_id=None):
    conn = get_db_connection()
    try:
        query = '''
            SELECT id FROM bookings 
            WHERE room_id = ? 
            AND (
                (start_time < ? AND end_time > ?)
                OR (start_time < ? AND end_time > ?)
                OR (start_time BETWEEN ? AND ?)
                OR (end_time BETWEEN ? AND ?)
            )
        '''
        params = (
            room_id,
            end_time, start_time,
            end_time, start_time,
            start_time, end_time,
            start_time, end_time
        )

        if booking_id:
            query += ' AND id != ?'
            params += (booking_id,)

        existing_booking = conn.execute(query, params).fetchone()
        return existing_booking is None
    finally:
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
            if safe_string_compare(username, SUPERUSER_USERNAME) and safe_string_compare(password, SUPERUSER_PASSWORD):
                session['user_id'] = 0
                session['username'] = SUPERUSER_USERNAME
                session['is_admin'] = True
                flash('Вход выполнен успешно как суперпользователь!', 'success')
                return redirect(url_for('profile'))

            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

            if user and user['failed_attempts'] > 5:
                flash('Слишком много неудачных попыток. Попробуйте позже.', 'error')
                return redirect(url_for('profile'))

            if user and checkpw(password.encode('utf-8'), user['password']):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['is_admin'] = user['is_admin']
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
        bookings = conn.execute('''
                SELECT b.id, b.start_time, b.end_time, b.purpose, r.name as room_name
                FROM bookings b JOIN rooms r ON b.room_id = r.id
                WHERE b.user_id = ? ORDER BY b.start_time DESC
            ''', (session['user_id'],)).fetchall()

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
                               bookings=formatted_bookings)
    finally:
        conn.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''))
            email = sanitize_input(request.form.get('email', ''))
            password = request.form.get('password', '')

            validate_input(username, USERNAME_REGEX, 'имя пользователя')
            validate_input(email, EMAIL_REGEX, 'email')

            if len(password) < 8:
                raise ValueError("Пароль должен содержать минимум 8 символов")

            hashed_password = hashpw(password.encode('utf-8'), gensalt())
            joined_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            conn = get_db_connection()
            try:
                conn.execute(
                    'INSERT INTO users (username, email, password, joined_date) VALUES (?, ?, ?, ?)',
                    (username, email, hashed_password, joined_date)
                )
                conn.commit()

                user_data = {
                    'username': username,
                    'email': email,
                    'password': hashed_password.decode('utf-8'),
                    'joined_date': joined_date
                }

                with open(METADATA_FILE, 'a') as file:
                    file.write("=== Новый пользователь ===\n")
                    for key, value in user_data.items():
                        file.write(f"{key}: {value}\n")
                    file.write("\n")

                flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
                return redirect(url_for('profile'))
            except sqlite3.IntegrityError:
                flash('Пользователь с таким именем или email уже существует.', 'error')
            finally:
                conn.close()
        except ValueError as e:
            flash(str(e), 'error')
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('Ошибка сервера при регистрации', 'error')
    return render_template('register.html')


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
        query = 'SELECT * FROM rooms WHERE 1=1'
        params = []

        if capacity_filter and capacity_filter.isdigit():
            query += ' AND capacity >= ?'
            params.append(int(capacity_filter))

        if equipment_filter:
            for equipment in equipment_filter:
                query += ' AND equipment LIKE ?'
                params.append(f'%{equipment}%')

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
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    try:
        room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
        if not room:
            flash('Комната не найдена.', 'error')
            return redirect(url_for('rooms'))

        photos = conn.execute('SELECT photo_url FROM room_photos WHERE room_id = ?', (room_id,)).fetchall()

        if request.method == 'POST':
            start_time = request.form.get('start_time')
            end_time = request.form.get('end_time')
            purpose = sanitize_input(request.form.get('purpose', ''))

            try:
                start_datetime = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
                end_datetime = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')

                if start_datetime >= end_datetime:
                    flash('Время окончания должно быть позже времени начала', 'error')
                    return redirect(url_for('book_room', room_id=room_id))

                if start_datetime < datetime.now():
                    flash('Нельзя забронировать комнату в прошлом', 'error')
                    return redirect(url_for('book_room', room_id=room_id))

                if not is_room_available(room_id, start_time, end_time):
                    flash('Комната уже забронирована на это время', 'error')
                    return redirect(url_for('book_room', room_id=room_id))

                conn.execute(
                    'INSERT INTO bookings (room_id, user_id, start_time, end_time, purpose) VALUES (?, ?, ?, ?, ?)',
                    (room_id, session['user_id'], start_time, end_time, purpose)
                )
                conn.commit()

                flash('Комната успешно забронирована!', 'success')
                return redirect(url_for('profile'))
            except ValueError as e:
                flash(f'Некорректный формат времени: {str(e)}', 'error')
                return redirect(url_for('book_room', room_id=room_id))

        return render_template('book_room.html', room=room, photos=photos)
    finally:
        conn.close()


@app.route('/cancel_booking/<int:booking_id>')
def cancel_booking(booking_id):
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    try:
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
        return redirect(url_for('profile'))
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


if __name__ == '__main__':
    # Создаем контекст приложения и инициализируем БД
    with app.app_context():
        init_db()  # Теперь таблицы точно создадутся
    app.run(debug=True)