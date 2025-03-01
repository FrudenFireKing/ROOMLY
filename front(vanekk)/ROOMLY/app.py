from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
import json
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Секретный ключ для сессий

# Путь к файлу metadata.txt
METADATA_FILE = 'metadata.txt'

# Подключение к SQLite базе данных
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Создание таблицы пользователей, если её нет
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
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
        # Логика для входа
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
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
    return render_template('rooms.html')

if __name__ == '__main__':
    init_db()  # Инициализация базы данных
    app.run(debug=True)