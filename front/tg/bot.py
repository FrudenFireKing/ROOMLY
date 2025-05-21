import requests
import json
import os
import hashlib
from datetime import datetime
import time
from threading import Thread

# Конфигурация
TELEGRAM_BOT_TOKEN = "7807297026:AAFIeVKj1oS31tZyI420KDVNycdKkR3l-E4"
ADMIN_CHAT_ID = "700275431"
DATABASE_FILE = "booking.json"  # Основной файл с бронированиями
STATE_FILE = "bot_state.json"  # Файл состояния бота
CHECK_INTERVAL = 30  # Интервал проверки новых событий в секундах


class BookingManager:
    def __init__(self):
        self._init_files()
        self._load_state()
        self.last_update_time = datetime.now().isoformat()

    def _init_files(self):
        try:
            if not os.path.exists(DATABASE_FILE):
                with open(DATABASE_FILE, 'w', encoding='utf-8') as f:
                    json.dump({"bookings": [], "cancellations": []}, f, ensure_ascii=False)

            if not os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'w', encoding='utf-8') as f:
                    json.dump({"processed": []}, f, ensure_ascii=False)

        except Exception as e:
            print(f"Ошибка инициализации файлов: {e}")
            raise

    def _load_data(self):
        try:
            with open(DATABASE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if not all(key in data for key in ["bookings", "cancellations"]):
                raise ValueError("Неверная структура файла бронирований")

            cancelled_ids = {c['id'] for c in data['cancellations'] if 'id' in c}
            active_bookings = [
                b for b in data['bookings']
                if isinstance(b, dict) and 'id' in b and b['id'] not in cancelled_ids
            ]

            return {
                "active": active_bookings,
                "cancelled": data['cancellations'],
                "all_bookings": data['bookings']
            }

        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            print(f"Ошибка загрузки данных: {e}")
            return {
                "active": [],
                "cancelled": [],
                "all_bookings": []
            }

    def _load_state(self):
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r', encoding='utf-8') as f:
                    state_data = json.load(f)

                if not isinstance(state_data, dict) or 'processed' not in state_data:
                    state_data = {"processed": []}
                    self._save_state(state_data)

                self.processed_hashes = set(state_data['processed'])
            else:
                self.processed_hashes = set()

        except (json.JSONDecodeError, TypeError) as e:
            print(f"Ошибка загрузки состояния: {e}")
            self.processed_hashes = set()
            self._save_state({"processed": []})

    def _save_state(self, state_data=None):
        try:
            data = state_data if state_data else {"processed": list(self.processed_hashes)}
            with open(STATE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения состояния: {e}")

    def _generate_hash(self, item, item_type):
        try:
            unique_str = f"{item_type}_{item.get('id', '')}_{item.get('room', '')}_{item.get('start_time', '')}"
            return hashlib.md5(unique_str.encode('utf-8')).hexdigest()
        except Exception as e:
            print(f"Ошибка генерации хэша: {e}")
            return ""

    def send_telegram_message(self, message, reply_markup=None):
        if not message or not TELEGRAM_BOT_TOKEN or not ADMIN_CHAT_ID:
            print("Недостаточно данных для отправки уведомления")
            return False

        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            params = {
                "chat_id": ADMIN_CHAT_ID,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }

            if reply_markup:
                params["reply_markup"] = json.dumps(reply_markup)

            response = requests.post(url, params=params, timeout=10)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Ошибка отправки в Telegram: {e}")
            return False
        except Exception as e:
            print(f"Неожиданная ошибка при отправке: {e}")
            return False

    def check_new_entries(self):
        """Проверяет новые бронирования и отмены"""
        try:
            data = self._load_data()
            new_entries = []

            for booking in data['active']:
                if not isinstance(booking, dict):
                    continue

                item_hash = self._generate_hash(booking, "booking")
                if item_hash and item_hash not in self.processed_hashes:
                    new_entries.append(("booking", booking))
                    self.processed_hashes.add(item_hash)

            for cancellation in data['cancelled']:
                if not isinstance(cancellation, dict):
                    continue

                item_hash = self._generate_hash(cancellation, "cancel")
                if item_hash and item_hash not in self.processed_hashes:
                    original = next(
                        (b for b in data['all_bookings']
                         if isinstance(b, dict) and b.get('id') == cancellation.get('id')),
                        None
                    )
                    if original:
                        new_entries.append((
                            "cancellation",
                            original,
                            cancellation.get('cancelled_at', 'неизвестно')
                        ))
                        self.processed_hashes.add(item_hash)

            # Отправляем уведомления
            for entry in new_entries:
                if entry[0] == "booking":
                    booking = entry[1]
                    msg = (
                        "📅 <b>Новое бронирование</b>\n\n"
                        f"🏠 Комната: <b>{booking.get('room', 'N/A')}</b>\n"
                        f"🕒 Время: {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                        f"👤 Пользователь: {booking.get('user', 'N/A')}\n"
                        f"🔔 ID: {booking.get('id', 'N/A')}"
                    )

                    # Кнопка для просмотра всех бронирований
                    keyboard = {
                        "inline_keyboard": [[
                            {"text": "📋 Все бронирования", "callback_data": "show_all_bookings"}
                        ]]
                    }
                    self.send_telegram_message(msg, keyboard)
                else:
                    booking, cancel_time = entry[1], entry[2]
                    msg = (
                        "❌ <b>Отмена бронирования</b>\n\n"
                        f"🏠 Комната: <b>{booking.get('room', 'N/A')}</b>\n"
                        f"🕒 Время: {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                        f"👤 Пользователь: {booking.get('user', 'N/A')}\n"
                        f"🔔 ID: {booking.get('id', 'N/A')}\n"
                        f"⏱ Время отмены: {cancel_time}"
                    )
                    self.send_telegram_message(msg)

            if new_entries:
                self._save_state()
                self.last_update_time = datetime.now().isoformat()

            return len(new_entries)

        except Exception as e:
            print(f"Ошибка при проверке новых записей: {e}")
            return 0

    def generate_report(self, report_type="full"):
        """Генерирует отчет о бронированиях"""
        try:
            data = self._load_data()

            if report_type == "active":
                return self._generate_active_report(data['active'])
            elif report_type == "cancelled":
                return self._generate_cancelled_report(data['cancelled'])
            else:
                return self._generate_full_report(data)

        except Exception as e:
            print(f"Ошибка генерации отчета: {e}")
            return "⚠️ Произошла ошибка при формировании отчета"

    def _generate_active_report(self, active_bookings):
        report_lines = ["<b>📋 Активные бронирования:</b>\n"]

        if not active_bookings:
            report_lines.append("\nНет активных бронирований")
        else:
            for booking in active_bookings:
                report_lines.append(
                    f"\n🏠 <b>{booking.get('room', 'N/A')}</b>\n"
                    f"   🕒 {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                    f"   👤 {booking.get('user', 'N/A')} (ID: {booking.get('id', 'N/A')})\n"
                    f"   📅 Дата создания: {booking.get('created_at', 'N/A')}"
                )

        report_lines.append(
            f"\n\n<i>Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

        return "\n".join(report_lines)

    def _generate_cancelled_report(self, cancellations):
        report_lines = ["<b>❌ Отмененные бронирования:</b>\n"]

        if not cancellations:
            report_lines.append("\nНет отмененных бронирований")
        else:
            for cancel in cancellations:
                report_lines.append(
                    f"\n🔔 ID: {cancel.get('id', 'N/A')}\n"
                    f"   ⏱ Время отмены: {cancel.get('cancelled_at', 'N/A')}\n"
                    f"   📅 Дата создания: {cancel.get('created_at', 'N/A')}"
                )

        report_lines.append(
            f"\n\n<i>Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

        return "\n".join(report_lines)

    def _generate_full_report(self, data):
        report_lines = [
            "<b>📊 Полный отчет о бронированиях</b>",
            "\n\n<b>Активные бронирования:</b>"
        ]

        if not data['active']:
            report_lines.append("\nНет активных бронирований")
        else:
            for booking in data['active']:
                report_lines.append(
                    f"\n🏠 <b>{booking.get('room', 'N/A')}</b>\n"
                    f"   🕒 {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                    f"   👤 {booking.get('user', 'N/A')} (ID: {booking.get('id', 'N/A')})\n"
                    f"   📅 Дата создания: {booking.get('created_at', 'N/A')}"
                )

        report_lines.append("\n\n<b>Отмененные бронирования:</b>")
        if not data['cancelled']:
            report_lines.append("\nНет отмененных бронирований")
        else:
            for cancel in data['cancelled']:
                report_lines.append(
                    f"\n🔔 ID: {cancel.get('id', 'N/A')}\n"
                    f"   ⏱ Время отмены: {cancel.get('cancelled_at', 'N/A')}\n"
                    f"   📅 Дата создания: {cancel.get('created_at', 'N/A')}"
                )

        report_lines.append(
            f"\n\n<i>Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

        return "\n".join(report_lines)

    def get_main_menu(self):
        """Возвращает клавиатуру главного меню"""
        return {
            "inline_keyboard": [
                [{"text": "📋 Активные бронирования", "callback_data": "show_active"}],
                [{"text": "❌ Отмененные бронирования", "callback_data": "show_cancelled"}],
                [{"text": "📊 Полный отчет", "callback_data": "show_full_report"}],
                [{"text": "🔄 Проверить сейчас", "callback_data": "check_now"}]
            ]
        }


def process_updates(bot):
    """Функция для обработки обновлений от Telegram"""
    last_update_id = 0

    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
            params = {"offset": last_update_id + 1, "timeout": 30}
            response = requests.get(url, params=params, timeout=35)
            response.raise_for_status()

            data = response.json()

            if not data.get("ok") or not data.get("result"):
                time.sleep(5)
                continue

            for update in data["result"]:
                last_update_id = update["update_id"]

                if "callback_query" in update:
                    callback = update["callback_query"]
                    chat_id = callback["message"]["chat"]["id"]
                    message_id = callback["message"]["message_id"]
                    data = callback["data"]

                    if data == "show_active":
                        report = bot.generate_report("active")
                        keyboard = bot.get_main_menu()
                        bot.send_telegram_message(report, keyboard)

                    elif data == "show_cancelled":
                        report = bot.generate_report("cancelled")
                        keyboard = bot.get_main_menu()
                        bot.send_telegram_message(report, keyboard)

                    elif data == "show_full_report":
                        report = bot.generate_report("full")
                        keyboard = bot.get_main_menu()
                        bot.send_telegram_message(report, keyboard)

                    elif data == "check_now":
                        new_events = bot.check_new_entries()
                        if new_events > 0:
                            message = f"🔍 Проверено. Найдено {new_events} новых событий."
                        else:
                            message = "🔍 Проверено. Новых событий нет."
                        keyboard = bot.get_main_menu()
                        bot.send_telegram_message(message, keyboard)

                    elif data == "show_all_bookings":
                        report = bot.generate_report("active")
                        keyboard = bot.get_main_menu()
                        bot.send_telegram_message(report, keyboard)

        except requests.exceptions.RequestException as e:
            print(f"Ошибка при получении обновлений: {e}")
            time.sleep(10)
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")
            time.sleep(10)


def monitor_bookings(bot):
    """Функция для мониторинга новых бронирований"""
    while True:
        try:
            new_events = bot.check_new_entries()
            if new_events > 0:
                print(f"Обнаружено {new_events} новых событий")

            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            print(f"Ошибка в мониторинге: {e}")
            time.sleep(30)


def main():
    print("=== Бот управления бронированиями ===")
    print("Инициализация...")

    try:
        bot = BookingManager()

        # Запускаем поток для мониторинга бронирований
        monitor_thread = Thread(target=monitor_bookings, args=(bot,), daemon=True)
        monitor_thread.start()

        # Запускаем поток для обработки команд от пользователя
        updates_thread = Thread(target=process_updates, args=(bot,), daemon=True)
        updates_thread.start()

        # Отправляем приветственное сообщение с меню
        welcome_msg = (
            "🤖 <b>Бот управления бронированиями активирован</b>\n\n"
            "Вы можете просматривать текущие бронирования и отмены с помощью меню ниже.\n"
            f"Последнее обновление: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        keyboard = bot.get_main_menu()
        bot.send_telegram_message(welcome_msg, keyboard)

        print("Бот запущен и работает...")

        # Бесконечный цикл для поддержания работы потоков
        while True:
            time.sleep(1)

    except Exception as e:
        print(f"Критическая ошибка: {e}")
    finally:
        print("Работа завершена")


if __name__ == "__main__":
    main()