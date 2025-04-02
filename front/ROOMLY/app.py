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

# Регулярные выражения для валидации
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$')

def safe_string_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

def get_db_connection():
    conn = sqlite3.connect('users.db', timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA secure_delete = ON')
    return conn

def init_db():
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

        conn.execute('''
            CREATE TABLE IF NOT EXISTS bookings (
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
        conn.execute('CREATE INDEX IF NOT EXISTS idx_bookings_room_id ON bookings(room_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_bookings_user_id ON bookings(user_id)')

        # Добавляем комнаты
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

        conn.executemany('INSERT INTO rooms (name, capacity, equipment) VALUES (?, ?, ?)', rooms_data)
        conn.commit()
    finally:
        conn.close()

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
            end_time, start_time,  # Второе условие (дублируется для SQLite)
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

        # Преобразуем даты к нужному формату
        formatted_bookings = []
        for booking in bookings:
            formatted_booking = dict(booking)
            # Преобразуем строки в datetime, если они еще не преобразованы
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

    conn = get_db_connection()
    try:
        rooms = conn.execute('SELECT * FROM rooms').fetchall()
        return render_template('rooms.html', rooms=rooms)
    finally:
        conn.close()

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

        if request.method == 'POST':
            start_time = request.form.get('start_time')
            end_time = request.form.get('end_time')
            purpose = sanitize_input(request.form.get('purpose', ''))

            try:
                # Преобразуем строки в datetime объекты
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

                # Сохраняем бронирование
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

        return render_template('book_room.html', room=room)
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
    # Основные настройки CSP
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

    # Для страницы бронирования разрешаем unsafe-inline
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
    init_db()
    app.run(debug=True)