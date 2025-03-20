from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
import json
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Секретный ключ для сессий

# Логин и пароль суперпользователя
SUPERUSER_USERNAME = "superadmin"
SUPERUSER_PASSWORD = "superpassword123"

# Путь к файлу metadata.txt
METADATA_FILE = 'metadata.txt'

# Подключение к SQLite базе данных
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Создание таблиц пользователей и комнат, если их нет
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            equipment TEXT NOT NULL
        )
    ''')

    # Добавляем начальные данные о комнатах, если таблица пуста
    rooms = conn.execute('SELECT COUNT(*) FROM rooms').fetchone()[0]
    if rooms == 0:
        conn.execute('''
            INSERT INTO rooms (name, capacity, equipment) VALUES
            ('Комната 1', 4, 'Проектор, доска'),
            ('Комната 2', 6, 'Телевизор, Wi-Fi'),
            ('Комната 3', 8, 'Кондиционер, кофе-машина')
        ''')

    conn.commit()
    conn.close()

# Загрузка данных пользователей из файла metadata.txt
def load_users_metadata():
    if os.path.exists(METADATA_FILE):
        try:
            with open(METADATA_FILE, 'r') as file:
                content = file.read()
                if content.strip():  # Проверяем, не пустой ли файл
                    return json.loads(content)
                else:
                    return []  # Возвращаем пустой массив, если файл пуст
        except json.JSONDecodeError:
            return []  # Возвращаем пустой массив, если файл содержит некорректный JSON
    else:
        return []  # Возвращаем пустой массив, если файл не существует

# Сохранение данных пользователей в файл metadata.txt
def save_users_metadata(users):
    with open(METADATA_FILE, 'w') as file:
        json.dump(users, file)

# Главная страница
@app.route('/')
def home():
    return render_template('index.html')

# Страница "О нас"
@app.route('/about')
def about():
    return render_template('about.html')

# Личный кабинет (страница входа)
@app.route('/personal', methods=['GET', 'POST'])
def personal():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Проверка на суперпользователя
        if username == SUPERUSER_USERNAME and password == SUPERUSER_PASSWORD:
            session['user_id'] = 0  # Идентификатор суперпользователя
            session['username'] = SUPERUSER_USERNAME
            session['is_admin'] = True
            flash('Вход выполнен успешно как суперпользователь!', 'success')
            return redirect(url_for('profile'))

        # Обычная проверка для других пользователей
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['is_admin'] = user['is_admin']
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверное имя пользователя или пароль.', 'error')

    return render_template('personal.html')

# Регистрация нового пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Хеширование пароля
        hashed_password = hashpw(password.encode('utf-8'), gensalt())

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_password))
            conn.commit()

            # Сохранение данных в metadata.txt
            users_metadata = load_users_metadata()
            users_metadata.append({
                'username': username,
                'email': email,
                'password': hashed_password.decode('utf-8')  # Сохраняем хешированный пароль
            })
            save_users_metadata(users_metadata)

            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('personal'))
        except sqlite3.IntegrityError:
            flash('Пользователь с таким именем или email уже существует.', 'error')
        finally:
            conn.close()

    return render_template('register.html')

# Страница профиля (после успешного входа)
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('personal'))
    return render_template('profile.html', username=session['username'])

# Выход из системы
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('personal'))

# Страница "Комнаты"
@app.route('/rooms')
def rooms():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('personal'))

    # Логика для отображения комнат
    conn = get_db_connection()
    rooms = conn.execute('SELECT * FROM rooms').fetchall()
    conn.close()
    return render_template('rooms.html', rooms=rooms)

# Редактирование профиля
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('personal'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        if user and checkpw(current_password.encode('utf-8'), user['password']):
            try:
                # Обновление имени пользователя и почты
                conn.execute('UPDATE users SET username = ?, email = ? WHERE id = ?',
                             (new_username, new_email, session['user_id']))

                # Обновление пароля, если новый пароль был введен
                if new_password:
                    hashed_password = hashpw(new_password.encode('utf-8'), gensalt())
                    conn.execute('UPDATE users SET password = ? WHERE id = ?',
                                 (hashed_password, session['user_id']))

                conn.commit()
                session['username'] = new_username
                session['email'] = new_email
                flash('Профиль успешно обновлен!', 'success')
                return redirect(url_for('profile'))
            except sqlite3.IntegrityError:
                flash('Пользователь с таким именем или email уже существует.', 'error')
            finally:
                conn.close()
        else:
            flash('Неверный текущий пароль.', 'error')
            conn.close()

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user:
        return render_template('edit_profile.html', username=user['username'], email=user['email'])
    else:
        flash('Пользователь не найден.', 'error')
        return redirect(url_for('personal'))

# Редактирование комнаты
@app.route('/edit_room/<int:room_id>', methods=['GET', 'POST'])
def edit_room(room_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для выполнения этого действия.', 'error')
        return redirect(url_for('rooms'))

    conn = get_db_connection()
    room = conn.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        capacity = request.form['capacity']
        equipment = request.form['equipment']

        conn.execute('UPDATE rooms SET name = ?, capacity = ?, equipment = ? WHERE id = ?',
                     (name, capacity, equipment, room_id))
        conn.commit()
        conn.close()
        flash('Комната успешно обновлена!', 'success')
        return redirect(url_for('rooms'))

    conn.close()
    return render_template('edit_room.html', room=room)

# Удаление комнаты
@app.route('/delete_room/<int:room_id>')
def delete_room(room_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('У вас нет прав для выполнения этого действия.', 'error')
        return redirect(url_for('rooms'))

    conn = get_db_connection()
    conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
    conn.commit()
    conn.close()
    flash('Комната успешно удалена!', 'success')
    return redirect(url_for('rooms'))

if __name__ == '__main__':
    init_db()  # Инициализация базы данных
    app.run(debug=True)
