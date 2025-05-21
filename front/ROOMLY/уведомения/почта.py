import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Конфигурация почтового сервера для Яндекс
SMTP_SERVER = "smtp.yandex.ru"
SMTP_PORT = 465  # Яндекс использует только SSL
EMAIL_ADDRESS = "artemy.dobroff@yandex.ru"  # Полный email Яндекс
EMAIL_PASSWORD = "zpE-M99-cv6-gHy"  # Пароль от почты или пароль приложения


# Загрузка данных из JSON-файла
def load_json_data(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"Ошибка загрузки JSON: {e}")
        return None


# Отправка email
def send_email(to_email, subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        # Для Яндекс используем SMTP_SSL вместо SMTP
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"Письмо отправлено на {to_email}")
    except Exception as e:
        print(f"Ошибка отправки письма: {e}")


# Формирование сообщения о бронировании/отмене
def generate_booking_message(booking_data, is_cancelled=False):
    user_name = booking_data.get("user_name", "Клиент")
    room_number = booking_data.get("room_number", "N/A")
    check_in = booking_data.get("check_in", "N/A")
    check_out = booking_data.get("check_out", "N/A")

    if is_cancelled:
        subject = f"Отмена бронирования комнаты {room_number}"
        message = (
            f"Уважаемый(ая) {user_name},\n\n"
            f"Ваше бронирование комнаты №{room_number} ({check_in} - {check_out}) отменено.\n\n"
            "С уважением,\nОтель"
        )
    else:
        subject = f"Подтверждение бронирования комнаты {room_number}"
        message = (
            f"Уважаемый(ая) {user_name},\n\n"
            f"Ваше бронирование комнаты №{room_number} успешно оформлено.\n"
            f"Дата заезда: {check_in}\n"
            f"Дата выезда: {check_out}\n\n"
            "С уважением,\nОтель"
        )

    return subject, message


# Основная логика обработки бронирований
def process_bookings(json_file):
    data = load_json_data(json_file)
    if not data:
        return

    for booking in data.get("bookings", []):
        user_email = booking.get("user_email")
        if not user_email:
            print("Ошибка: отсутствует email пользователя")
            continue

        is_cancelled = booking.get("is_cancelled", False)
        subject, message = generate_booking_message(booking, is_cancelled)
        send_email(user_email, subject, message)


# Запуск скрипта
if __name__ == "__main__":
    process_bookings("bookings.json")  # Укажите путь к вашему JSON-файлу