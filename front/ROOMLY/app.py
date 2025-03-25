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
app.secret_key = os.urandom(24)  # Генерация случайного секретного ключа
app.permanent_session_lifetime = timedelta(minutes=30)  # Ограничение времени сессии
csrf = CSRFProtect(app)  # Защита от CSRF

# Настройка логирования
logging.basicConfig(
    filename='security.log',
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

# Конфигурация
SUPERUSER_USERNAME = "superadmin"
SUPERUSER_PASSWORD = os.environ.get('SUPERUSER_PASSWORD', "superpassword123")  # Безопасное хранение пароля
METADATA_FILE = 'metadata.txt'

# Регулярные выражения для валидации
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$')


def safe_string_compare(a, b):
    """Безопасное сравнение строк для предотвращения timing-атак"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def get_db_connection():
    """Безопасное подключение к базе данных"""
    conn = sqlite3.connect('users.db', timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA secure_delete = ON')  # Полное удаление данных
    return conn


def init_db():
    """Инициализация базы данных с улучшенной структурой"""
    conn = get_db_connection()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
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
        conn.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                capacity INTEGER NOT NULL,
                equipment TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Добавляем начальные данные о комнатах
        if conn.execute('SELECT COUNT(*) FROM rooms').fetchone()[0] == 0:
            conn.execute('''
                INSERT INTO rooms (name, capacity, equipment) VALUES
                ('Комната 1', 4, 'Проектор, доска'),
                ('Комната 2', 6, 'Телевизор, Wi-Fi'),
                ('Комната 3', 8, 'Кондиционер, кофе-машина')
            ''')
        conn.commit()
    finally:
        conn.close()


def validate_input(data, regex, field_name):
    """Валидация входных данных"""
    if not regex.match(data):
        logger.warning(f"Invalid input attempt for {field_name}: {data} from IP {request.remote_addr}")
        raise ValueError(f"Некорректный формат {field_name}")


def sanitize_input(input_str):
    """Очистка входных данных от опасных символов"""
    return re.sub(r'[;\\\'"<>%$]', '', input_str)


@app.before_request
def security_checks():
    """Проверки безопасности перед каждым запросом"""
    # Ограничение размера запроса
    if request.content_length and request.content_length > 1024 * 1024:  # 1MB
        abort(413)

    # Защита от MIME-спуфинга
    if request.method == 'POST' and not request.content_type.startswith('application/x-www-form-urlencoded'):
        abort(400)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/personal', methods=['GET', 'POST'])
def personal():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        conn = get_db_connection()
        try:
            # Проверка на суперпользователя
            if safe_string_compare(username, SUPERUSER_USERNAME) and safe_string_compare(password, SUPERUSER_PASSWORD):
                session['user_id'] = 0
                session['username'] = SUPERUSER_USERNAME
                session['is_admin'] = True
                flash('Вход выполнен успешно как суперпользователь!', 'success')
                return redirect(url_for('profile'))

            user = conn.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()

            # Защита от brute force
            if user and user['failed_attempts'] > 5:
                flash('Слишком много неудачных попыток. Попробуйте позже.', 'error')
                logger.warning(f"Too many attempts for user {username}")
                return redirect(url_for('personal'))

            if user and checkpw(password.encode('utf-8'), user['password']):
                # Успешный вход
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['is_admin'] = user['is_admin']
                session['joined_date'] = user['joined_date']

                # Обновляем информацию о входе
                conn.execute(
                    'UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id'])
                )
                conn.commit()

                flash('Вход выполнен успешно!', 'success')
                return redirect(url_for('profile'))
            else:
                # Неудачная попытка входа
                if user:
                    conn.execute(
                        'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?',
                        (user['id'],)
                    )
                    conn.commit()
                flash('Неверное имя пользователя или пароль.', 'error')
        finally:
            conn.close()
    return render_template('personal.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''))
            email = sanitize_input(request.form.get('email', ''))
            password = request.form.get('password', '')

            # Валидация ввода
            validate_input(username, USERNAME_REGEX, 'имя пользователя')
            validate_input(email, EMAIL_REGEX, 'email')

            if len(password) < 8:
                raise ValueError("Пароль должен содержать минимум 8 символов")

            # Хеширование пароля
            hashed_password = hashpw(password.encode('utf-8'), gensalt())
            joined_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            conn = get_db_connection()
            try:
                conn.execute(
                    'INSERT INTO users (username, email, password, joined_date) VALUES (?, ?, ?, ?)',
                    (username, email, hashed_password, joined_date)
                )
                conn.commit()

                # Сохранение метаданных в столбик
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
                    file.write("\n")  # Пустая строка между записями

                flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
                return redirect(url_for('personal'))
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


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('personal'))
    return render_template('profile.html',
                           username=session['username'],
                           email=session.get('email', ''),
                           joined_date=session.get('joined_date', 'Не указана'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('personal'))


@app.route('/rooms')
def rooms():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('personal'))

    conn = get_db_connection()
    try:
        rooms = conn.execute('SELECT * FROM rooms').fetchall()
        return render_template('rooms.html', rooms=rooms)
    finally:
        conn.close()


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('personal'))

    conn = get_db_connection()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        if not user:
            flash('Пользователь не найден.', 'error')
            return redirect(url_for('personal'))

        if request.method == 'POST':
            new_username = sanitize_input(request.form.get('username', ''))
            new_email = sanitize_input(request.form.get('email', ''))
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')

            if not checkpw(current_password.encode('utf-8'), user['password']):
                flash('Неверный текущий пароль.', 'error')
                return redirect(url_for('edit_profile'))

            try:
                # Обновление данных пользователя
                conn.execute(
                    'UPDATE users SET username = ?, email = ? WHERE id = ?',
                    (new_username, new_email, session['user_id'])
                )

                if new_password:
                    if len(new_password) < 8:
                        flash('Новый пароль должен содержать минимум 8 символов', 'error')
                        return redirect(url_for('edit_profile'))

                    hashed_password = hashpw(new_password.encode('utf-8'), gensalt())
                    conn.execute(
                        'UPDATE users SET password = ? WHERE id = ?',
                        (hashed_password, session['user_id'])
                    )

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

        if request.method == 'POST':
            name = sanitize_input(request.form.get('name', ''))
            capacity = request.form.get('capacity', '')
            equipment = sanitize_input(request.form.get('equipment', ''))

            if not capacity.isdigit():
                flash('Вместимость должна быть числом', 'error')
                return redirect(url_for('edit_room', room_id=room_id))

            conn.execute(
                'UPDATE rooms SET name = ?, capacity = ?, equipment = ? WHERE id = ?',
                (name, capacity, equipment, room_id)
            )
            conn.commit()
            flash('Комната успешно обновлена!', 'success')
            return redirect(url_for('rooms'))

        return render_template('edit_room.html', room=room)
    finally:
        conn.close()


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
    """Добавление HTTP-заголовков безопасности"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


if __name__ == '__main__':
    init_db()
    app.run(debug=True)