import requests
import json
import os
import hashlib
from datetime import datetime
import time
from threading import Thread

# Конфигурация
TELEGRAM_BOT_TOKEN = "7807297026:AAFIeVKj1oS31tZyI420KDVNycdKkR3l-E4"
ADMIN_CHAT_ID = "12344342"
DATABASE_FILE = "booking.json"
STATE_FILE = "bot_state.json"
USERS_FILE = "users.json"
CHECK_INTERVAL = 30


class BookingManager:
    def __init__(self):
        self._init_files()
        self._load_state()
        self._load_users()
        self.last_update_time = datetime.now().isoformat()
        self.waiting_for_name = set()

    def _init_files(self):
        try:
            if not os.path.exists(DATABASE_FILE):
                with open(DATABASE_FILE, 'w', encoding='utf-8') as f:
                    json.dump({"bookings": [], "cancellations": []}, f, ensure_ascii=False)

            if not os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'w', encoding='utf-8') as f:
                    json.dump({"processed": []}, f, ensure_ascii=False)

            if not os.path.exists(USERS_FILE):
                with open(USERS_FILE, 'w', encoding='utf-8') as f:
                    json.dump({
                        "users": {
                            ADMIN_CHAT_ID: {
                                "username": "admin",
                                "is_admin": True,
                                "name": "Главный администратор",
                                "registered": True
                            }
                        }
                    }, f, ensure_ascii=False)
        except Exception as e:
            print(f"Ошибка инициализации файлов: {e}")
            raise

    def _load_data(self):
        try:
            with open(DATABASE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Гарантируем наличие всех необходимых ключей
            if 'bookings' not in data:
                data['bookings'] = []
            if 'cancellations' not in data:
                data['cancellations'] = []

            cancelled_ids = {c['id'] for c in data['cancellations'] if isinstance(c, dict) and 'id' in c}
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

    def _load_users(self):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                users_data = json.load(f)

            if not isinstance(users_data, dict) or 'users' not in users_data:
                raise ValueError("Неверная структура файла пользователей")

            self.users = users_data['users']
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            print(f"Ошибка загрузки пользователей: {e}")
            self.users = {
                ADMIN_CHAT_ID: {
                    "username": "admin",
                    "is_admin": True,
                    "name": "Главный администратор",
                    "registered": True
                }
            }
            self._save_users()

    def _save_state(self, state_data=None):
        try:
            data = state_data if state_data else {"processed": list(self.processed_hashes)}
            with open(STATE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения состояния: {e}")

    def _save_users(self):
        try:
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                json.dump({"users": self.users}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения пользователей: {e}")

    def _generate_hash(self, item, item_type):
        try:
            unique_str = f"{item_type}_{item.get('id', '')}_{item.get('room', '')}_{item.get('start_time', '')}"
            return hashlib.md5(unique_str.encode('utf-8')).hexdigest()
        except Exception as e:
            print(f"Ошибка генерации хэша: {e}")
            return ""

    def is_admin(self, chat_id):
        user = self.users.get(str(chat_id), {})
        return user.get('is_admin', False)

    def is_registered(self, chat_id):
        user = self.users.get(str(chat_id), {})
        return user.get('registered', False)

    def get_user_bookings(self, chat_id):
        if not self.is_registered(chat_id):
            return {"active": [], "cancelled": []}

        data = self._load_data()
        user = self.users.get(str(chat_id), {})
        username = user.get('username', '')

        if not username:
            return {"active": [], "cancelled": []}

        active = [
            b for b in data['active']
            if isinstance(b, dict) and b.get('user', '').lower() == username.lower()
        ]

        cancelled_ids = {c['id'] for c in data['cancellations'] if 'id' in c}
        user_cancellations = [
            c for c in data['cancellations']
            if isinstance(c, dict) and c.get('id') in {b['id'] for b in active if 'id' in b}
        ]

        return {
            "active": active,
            "cancelled": user_cancellations
        }

    def send_telegram_message(self, chat_id, message, reply_markup=None):
        if not message or not TELEGRAM_BOT_TOKEN or not chat_id:
            print("Недостаточно данных для отправки уведомления")
            return False

        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            params = {
                "chat_id": chat_id,
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
        try:
            data = self._load_data()
            new_entries = []

            # Проверяем, что ключи существуют в данных
            if 'bookings' not in data:
                data['bookings'] = []
            if 'cancellations' not in data:
                data['cancellations'] = []

            for booking in data['bookings']:
                if not isinstance(booking, dict):
                    continue

                item_hash = self._generate_hash(booking, "booking")
                if item_hash and item_hash not in self.processed_hashes:
                    new_entries.append(("booking", booking))
                    self.processed_hashes.add(item_hash)

            for cancellation in data['cancellations']:
                if not isinstance(cancellation, dict):
                    continue

                item_hash = self._generate_hash(cancellation, "cancel")
                if item_hash and item_hash not in self.processed_hashes:
                    original = next(
                        (b for b in data['bookings']
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

            # Отправляем уведомления админам
            for entry in new_entries:
                for chat_id, user_data in self.users.items():
                    if user_data.get('is_admin', False) and user_data.get('registered', False):
                        if entry[0] == "booking":
                            booking = entry[1]
                            msg = (
                                "📅 <b>Новое бронирование</b>\n\n"
                                f"🏠 Комната: <b>{booking.get('room', 'N/A')}</b>\n"
                                f"🕒 Время: {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                                f"👤 Пользователь: {booking.get('user', 'N/A')}\n"
                                f"🔔 ID: {booking.get('id', 'N/A')}"
                            )

                            keyboard = {
                                "inline_keyboard": [
                                    [
                                        {"text": "❌ Отменить", "callback_data": f"cancel_{booking.get('id', '')}"},
                                        {"text": "📋 Все бронирования", "callback_data": "show_all_bookings"}
                                    ]
                                ]
                            }
                            self.send_telegram_message(chat_id, msg, keyboard)
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
                            self.send_telegram_message(chat_id, msg)

            if new_entries:
                self._save_state()
                self.last_update_time = datetime.now().isoformat()

            return len(new_entries)
        except Exception as e:
            print(f"Ошибка при проверке новых записей: {e}")
            return 0

    def generate_report(self, chat_id, report_type="full"):
        try:
            is_admin = self.is_admin(chat_id)
            is_registered = self.is_registered(chat_id)

            if not is_registered:
                return "⚠️ Пожалуйста, завершите регистрацию, введя свое имя"

            if is_admin:
                data = self._load_data()

                if report_type == "active":
                    if not data['active']:
                        return "📋 Активных бронирований нет"
                    return self._generate_active_report(data['active'], is_admin=True)
                elif report_type == "cancelled":
                    if not data['cancelled']:
                        return "❌ Отмененных бронирований нет"
                    return self._generate_cancelled_report(data['cancelled'], is_admin=True)
                elif report_type == "show_all_bookings":
                    if not data['active'] and not data['cancelled']:
                        return "📊 Бронирований нет"
                    return self._generate_full_report(data, is_admin=True)
                else:
                    if not data['active'] and not data['cancelled']:
                        return "📊 Бронирований нет"
                    return self._generate_full_report(data, is_admin=True)
            else:
                user_bookings = self.get_user_bookings(chat_id)
                if not user_bookings['active'] and not user_bookings['cancelled']:
                    return "📋 У вас нет бронирований"
                return self._generate_user_report(user_bookings)
        except Exception as e:
            print(f"Ошибка генерации отчета: {e}")
            # Возвращаем сообщение об отсутствии бронирований вместо сообщения об ошибке
            if is_admin:
                return "📊 Бронирований нет"
            else:
                return "📋 У вас нет бронирований"
    def _generate_active_report(self, active_bookings, is_admin=False):
        report_lines = ["<b>📋 Активные бронирования:</b>\n"]

        if not active_bookings:
            report_lines.append("\nНет активных бронирований")
        else:
            for booking in active_bookings:
                line = (
                    f"\n🏠 <b>{booking.get('room', 'N/A')}</b>\n"
                    f"   🕒 {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                    f"   👤 {booking.get('user', 'N/A')} (ID: {booking.get('id', 'N/A')})\n"
                    f"   📅 Дата создания: {booking.get('created_at', 'N/A')}"
                )
                if is_admin:
                    line += f"\n   🔗 /cancel_{booking.get('id', '')} - отменить"
                report_lines.append(line)

        report_lines.append(
            f"\n\n<i>Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

        return "\n".join(report_lines)

    def _generate_cancelled_report(self, cancellations, is_admin=False):
        report_lines = ["<b>❌ Отмененные бронирования:</b>\n"]

        if not cancellations:
            report_lines.append("\nНет отмененных бронирований")
        else:
            for cancel in cancellations:
                line = (
                    f"\n🔔 ID: {cancel.get('id', 'N/A')}\n"
                    f"   ⏱ Время отмены: {cancel.get('cancelled_at', 'N/A')}\n"
                    f"   📅 Дата создания: {cancel.get('created_at', 'N/A')}"
                )
                if is_admin and 'reason' in cancel:
                    line += f"\n   📝 Причина: {cancel.get('reason', 'не указана')}"
                report_lines.append(line)

        report_lines.append(
            f"\n\n<i>Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

        return "\n".join(report_lines)

    def _generate_full_report(self, data, is_admin=False):
        report_lines = [
            "<b>📊 Полный отчет о бронированиях</b>",
            "\n\n<b>Активные бронирования:</b>"
        ]

        if not data['active']:
            report_lines.append("\nНет активных бронирований")
        else:
            for booking in data['active']:
                line = (
                    f"\n🏠 <b>{booking.get('room', 'N/A')}</b>\n"
                    f"   🕒 {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                    f"   👤 {booking.get('user', 'N/A')} (ID: {booking.get('id', 'N/A')})\n"
                    f"   📅 Дата создания: {booking.get('created_at', 'N/A')}"
                )
                if is_admin:
                    line += f"\n   🔗 /cancel_{booking.get('id', '')} - отменить"
                report_lines.append(line)

        report_lines.append("\n\n<b>Отмененные бронирования:</b>")
        if not data['cancelled']:
            report_lines.append("\nНет отмененных бронирований")
        else:
            for cancel in data['cancelled']:
                line = (
                    f"\n🔔 ID: {cancel.get('id', 'N/A')}\n"
                    f"   ⏱ Время отмены: {cancel.get('cancelled_at', 'N/A')}\n"
                    f"   📅 Дата создания: {cancel.get('created_at', 'N/A')}"
                )
                if is_admin and 'reason' in cancel:
                    line += f"\n   📝 Причина: {cancel.get('reason', 'не указана')}"
                report_lines.append(line)

        report_lines.append(
            f"\n\n<i>Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

        return "\n".join(report_lines)

    def _generate_user_report(self, user_bookings):
        report_lines = ["<b>📋 Ваши бронирования:</b>\n"]

        if not user_bookings['active'] and not user_bookings['cancelled']:
            report_lines.append("\nУ вас нет бронирований")
        else:
            if user_bookings['active']:
                report_lines.append("\n<b>Активные:</b>")
                for booking in user_bookings['active']:
                    report_lines.append(
                        f"\n🏠 <b>{booking.get('room', 'N/A')}</b>\n"
                        f"   🕒 {booking.get('start_time', 'N/A')} - {booking.get('end_time', 'N/A')}\n"
                        f"   🔔 ID: {booking.get('id', 'N/A')}\n"
                        f"   📅 Дата создания: {booking.get('created_at', 'N/A')}"
                    )

            if user_bookings['cancelled']:
                report_lines.append("\n\n<b>Отмененные:</b>")
                for cancel in user_bookings['cancelled']:
                    report_lines.append(
                        f"\n🔔 ID: {cancel.get('id', 'N/A')}\n"
                        f"   ⏱ Время отмены: {cancel.get('cancelled_at', 'N/A')}\n"
                        f"   📅 Дата создания: {cancel.get('created_at', 'N/A')}"
                    )

        report_lines.append(
            f"\n\n<i>Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

        return "\n".join(report_lines)

    def get_main_menu(self, chat_id):
        if not self.is_registered(chat_id):
            return None

        is_admin = self.is_admin(chat_id)

        if is_admin:
            return {
                "inline_keyboard": [
                    [{"text": "📋 Активные бронирования", "callback_data": "show_active"}],
                    [{"text": "❌ Отмененные бронирования", "callback_data": "show_cancelled"}],
                    [{"text": "📊 Полный отчет", "callback_data": "show_all_bookings"}],
                    [{"text": "🔄 Проверить сейчас", "callback_data": "check_now"}],
                    [{"text": "👥 Управление пользователями", "callback_data": "manage_users"}]
                ]
            }
        else:
            return {
                "inline_keyboard": [
                    [{"text": "📋 Мои бронирования", "callback_data": "show_my_bookings"}],
                    [{"text": "🔄 Проверить сейчас", "callback_data": "check_now"}]
                ]
            }

    def get_users_menu(self):
        users_list = []
        for chat_id, user_data in self.users.items():
            status = "👑 Админ" if user_data.get('is_admin') else "👤 Пользователь"
            users_list.append(
                f"{status}: {user_data.get('name', 'N/A')} (@{user_data.get('username', 'N/A')})"
            )

        text = "<b>👥 Список пользователей:</b>\n\n" + "\n".join(users_list)

        keyboard = {
            "inline_keyboard": [
                [{"text": "➕ Добавить админа", "callback_data": "add_admin"}],
                [{"text": "➖ Удалить админа", "callback_data": "remove_admin"}],
                [{"text": "🔙 Назад", "callback_data": "back_to_main"}]
            ]
        }

        return text, keyboard

    def cancel_booking(self, booking_id, cancelled_by, reason=None):
        try:
            with open(DATABASE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)

            booking = next(
                (b for b in data['bookings']
                 if isinstance(b, dict) and b.get('id') == booking_id),
                None
            )

            if not booking:
                return False, "Бронирование не найдено"

            if any(c['id'] == booking_id for c in data['cancellations']):
                return False, "Бронирование уже отменено"

            cancellation = {
                "id": booking_id,
                "cancelled_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "cancelled_by": cancelled_by,
                "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            if reason:
                cancellation["reason"] = reason

            data['cancellations'].append(cancellation)

            with open(DATABASE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            return True, "Бронирование успешно отменено"
        except Exception as e:
            print(f"Ошибка при отмене бронирования: {e}")
            return False, f"Ошибка при отмене бронирования: {e}"

    def register_user(self, chat_id, username, name, is_admin=False):
        try:
            if str(chat_id) in self.users:
                return False, "Пользователь уже зарегистрирован"

            self.users[str(chat_id)] = {
                "username": username,
                "is_admin": is_admin,
                "name": name,
                "registered": False
            }

            self._save_users()
            return True, "Пользователь добавлен, требуется ввод имени"
        except Exception as e:
            print(f"Ошибка регистрации пользователя: {e}")
            return False, f"Ошибка регистрации: {e}"

    def complete_registration(self, chat_id, name):
        try:
            user = self.users.get(str(chat_id))
            if not user:
                return False, "Пользователь не найден"

            user['name'] = name
            user['registered'] = True
            self._save_users()
            return True, "Регистрация завершена"
        except Exception as e:
            print(f"Ошибка завершения регистрации: {e}")
            return False, f"Ошибка завершения регистрации: {e}"

    def set_admin(self, chat_id, make_admin=True):
        try:
            user = self.users.get(str(chat_id))
            if not user:
                return False, "Пользователь не найден"

            user['is_admin'] = make_admin
            self._save_users()

            action = "назначен" if make_admin else "снят"
            return True, f"Пользователь {action} админом"
        except Exception as e:
            print(f"Ошибка изменения прав: {e}")
            return False, f"Ошибка изменения прав: {e}"


def process_updates(bot):
    last_update_id = 0
    waiting_for_reason = {}
    waiting_for_admin = {}
    waiting_for_name = {}

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
                chat_id = None
                message_text = ""

                if "message" in update:
                    chat_id = update["message"]["chat"]["id"]
                    message_text = update["message"].get("text", "")
                    username = update["message"]["from"].get("username", "")
                    first_name = update["message"]["from"].get("first_name", "")
                    last_name = update["message"]["from"].get("last_name", "")
                    name = f"{first_name} {last_name}".strip()

                    if str(chat_id) not in bot.users and str(chat_id) != ADMIN_CHAT_ID:
                        success, msg = bot.register_user(
                            chat_id,
                            username,
                            name or username or str(chat_id),
                            is_admin=False
                        )
                        if success:
                            waiting_for_name[chat_id] = username
                            bot.send_telegram_message(
                                chat_id,
                                "👋 Добро пожаловать!\n"
                                "Пожалуйста, введите ваше имя для завершения регистрации:"
                            )
                            continue

                elif "callback_query" in update:
                    callback = update["callback_query"]
                    chat_id = callback["message"]["chat"]["id"]
                    message_text = callback["data"]

                    try:
                        requests.post(
                            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageReplyMarkup",
                            json={
                                "chat_id": chat_id,
                                "message_id": callback["message"]["message_id"],
                                "reply_markup": {"inline_keyboard": []}
                            }
                        )
                    except:
                        pass

                if not chat_id:
                    continue

                if chat_id in waiting_for_name and message_text:
                    username = waiting_for_name[chat_id]
                    name = message_text.strip()

                    success, msg = bot.complete_registration(chat_id, name)
                    if success:
                        bot.send_telegram_message(
                            chat_id,
                            f"✅ Регистрация завершена, {name}!\n"
                            "Теперь вы можете просматривать свои бронирования.",
                            bot.get_main_menu(chat_id)
                        )
                    else:
                        bot.send_telegram_message(chat_id, f"❌ {msg}")

                    del waiting_for_name[chat_id]
                    continue

                if chat_id in waiting_for_reason and message_text:
                    booking_id = waiting_for_reason[chat_id]
                    success, msg = bot.cancel_booking(
                        booking_id,
                        f"admin:{chat_id}",
                        reason=message_text
                    )

                    if success:
                        bot.send_telegram_message(
                            chat_id,
                            f"✅ Бронирование {booking_id} отменено.\n"
                            f"📝 Причина: {message_text}",
                            bot.get_main_menu(chat_id)
                        )

                        booking_data = bot._load_data()
                        booking = next(
                            (b for b in booking_data['all_bookings']
                             if isinstance(b, dict) and b.get('id') == booking_id),
                            None
                        )

                        if booking:
                            user_username = booking.get('user', '')
                            for user_chat_id, user_info in bot.users.items():
                                if user_info.get('username', '').lower() == user_username.lower():
                                    bot.send_telegram_message(
                                        user_chat_id,
                                        f"❌ Ваше бронирование {booking_id} было отменено администратором.\n"
                                        f"🏠 Комната: {booking.get('room', 'N/A')}\n"
                                        f"🕒 Время: {booking.get('start_time', 'N/A')}\n"
                                        f"📝 Причина: {message_text}"
                                    )
                                    break
                    else:
                        bot.send_telegram_message(chat_id, f"❌ {msg}")

                    del waiting_for_reason[chat_id]
                    continue

                if chat_id in waiting_for_admin and message_text:
                    username = message_text.strip().replace('@', '')
                    found = False

                    for user_chat_id, user_info in bot.users.items():
                        if user_info.get('username', '').lower() == username.lower():
                            success, msg = bot.set_admin(user_chat_id, make_admin=True)
                            bot.send_telegram_message(chat_id, msg, bot.get_main_menu(chat_id))
                            found = True
                            break

                    if not found:
                        bot.send_telegram_message(
                            chat_id,
                            f"Пользователь @{username} не найден. "
                            "Попросите пользователя сначала написать боту любое сообщение.",
                            bot.get_main_menu(chat_id)
                        )

                    del waiting_for_admin[chat_id]
                    continue

                if not bot.is_registered(chat_id) and str(chat_id) != ADMIN_CHAT_ID:
                    if chat_id not in waiting_for_name:
                        waiting_for_name[chat_id] = bot.users.get(str(chat_id), {}).get('username', '')
                        bot.send_telegram_message(
                            chat_id,
                            "Пожалуйста, введите ваше имя для завершения регистрации:"
                        )
                    continue

                if message_text.startswith('/start'):
                    welcome_msg = (
                        "🤖 <b>Бот управления бронированиями</b>\n\n"
                        f"Привет, {bot.users.get(str(chat_id), {}).get('name', 'пользователь')}!\n"
                        "Используйте меню ниже для работы с бронированиями."
                    )
                    keyboard = bot.get_main_menu(chat_id)
                    bot.send_telegram_message(chat_id, welcome_msg, keyboard)

                elif message_text.startswith('/cancel_') and bot.is_admin(chat_id):
                    booking_id = message_text.split('_')[1]
                    waiting_for_reason[chat_id] = booking_id
                    bot.send_telegram_message(
                        chat_id,
                        "Введите причину отмены бронирования:"
                    )

                elif message_text == "show_active":
                    report = bot.generate_report(chat_id, "active")
                    keyboard = bot.get_main_menu(chat_id)
                    bot.send_telegram_message(chat_id, report, keyboard)

                elif message_text == "show_cancelled":
                    report = bot.generate_report(chat_id, "cancelled")
                    keyboard = bot.get_main_menu(chat_id)
                    bot.send_telegram_message(chat_id, report, keyboard)

                elif message_text == "show_all_bookings":
                    report = bot.generate_report(chat_id, "show_all_bookings")
                    keyboard = bot.get_main_menu(chat_id)
                    bot.send_telegram_message(chat_id, report, keyboard)

                elif message_text == "show_my_bookings":
                    report = bot.generate_report(chat_id, "user")
                    keyboard = bot.get_main_menu(chat_id)
                    bot.send_telegram_message(chat_id, report, keyboard)

                elif message_text == "check_now":
                    new_events = bot.check_new_entries()
                    if new_events > 0 and bot.is_admin(chat_id):
                        message = f"🔍 Проверено. Найдено {new_events} новых событий."
                    else:
                        message = "🔍 Проверено. Новых событий нет."
                    keyboard = bot.get_main_menu(chat_id)
                    bot.send_telegram_message(chat_id, message, keyboard)

                elif message_text == "manage_users" and bot.is_admin(chat_id):
                    text, keyboard = bot.get_users_menu()
                    bot.send_telegram_message(chat_id, text, keyboard)

                elif message_text == "add_admin" and bot.is_admin(chat_id):
                    waiting_for_admin[chat_id] = True
                    bot.send_telegram_message(
                        chat_id,
                        "Введите username пользователя (без @), которого хотите сделать админом:"
                    )

                elif message_text == "remove_admin" and bot.is_admin(chat_id):
                    bot.send_telegram_message(
                        chat_id,
                        "Функция удаления админа в разработке. "
                        "Пока вы можете редактировать файл users.json вручную.",
                        bot.get_main_menu(chat_id)
                    )

                elif message_text == "back_to_main":
                    keyboard = bot.get_main_menu(chat_id)
                    bot.send_telegram_message(
                        chat_id,
                        "Главное меню:",
                        keyboard
                    )

                elif message_text.startswith("cancel_") and bot.is_admin(chat_id):
                    booking_id = message_text.split('_')[1]
                    waiting_for_reason[chat_id] = booking_id
                    bot.send_telegram_message(
                        chat_id,
                        "Введите причину отмены бронирования:"
                    )

        except requests.exceptions.RequestException as e:
            print(f"Ошибка при получении обновлений: {e}")
            time.sleep(10)
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")
            time.sleep(10)


def monitor_bookings(bot):
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

        monitor_thread = Thread(target=monitor_bookings, args=(bot,), daemon=True)
        monitor_thread.start()

        updates_thread = Thread(target=process_updates, args=(bot,), daemon=True)
        updates_thread.start()

        print("Бот запущен и работает...")

        while True:
            time.sleep(1)

    except Exception as e:
        print(f"Критическая ошибка: {e}")
    finally:
        print("Работа завершена")


if __name__ == "__main__":
    main()
