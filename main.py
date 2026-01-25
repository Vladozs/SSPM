import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import random
import string
import threading

try:
    import pystray
    from PIL import Image, ImageDraw, ImageFont

    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False


class PasswordManager:
    def __init__(self):
        self.db_name = "passwords.db"
        self.key = None
        self.fernet = None
        self.init_db()

    def init_db(self):
        """Инициализация базы данных"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Таблица для хэша мастер-пароля
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Таблица для паролей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                category TEXT DEFAULT 'General',
                is_favorite INTEGER DEFAULT 0
            )
        ''')

        # Таблица для журнала входов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL
            )
        ''')

        # Таблица для настроек
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY,
                theme TEXT DEFAULT 'classic_light',
                font_size INTEGER DEFAULT 10,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def get_setting(self, key, default=None):
        """Получение настройки"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(f"SELECT {key} FROM settings LIMIT 1")
            result = cursor.fetchone()
            conn.close()
            if result and result[0] is not None:
                return result[0]
        except:
            pass
        return default

    def save_setting(self, key, value):
        """Сохранение настройки"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            # Проверяем, есть ли уже запись
            cursor.execute("SELECT COUNT(*) FROM settings")
            count = cursor.fetchone()[0]

            if count == 0:
                cursor.execute("INSERT INTO settings (id) VALUES (1)")

            cursor.execute(f"UPDATE settings SET {key} = ?, updated_at = datetime('now', 'localtime') WHERE id = 1",
                           (value,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Ошибка сохранения настроек: {e}")
            return False

    def log_login_attempt(self, status):
        """Логирование попытки входа"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_history (login_time, status)
                VALUES (datetime('now', 'localtime'), ?)
            ''', (status,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Ошибка при логировании входа: {e}")
            return False

    def get_login_history(self, limit=50):
        """Получение истории входов"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, login_time, status 
                FROM login_history 
                ORDER BY login_time DESC 
                LIMIT ?
            ''', (limit,))
            results = cursor.fetchall()
            conn.close()
            return results
        except:
            return []

    def clear_login_history(self):
        """Очистка истории входов"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM login_history")
            conn.commit()
            conn.close()
            return True
        except:
            return False

    def set_master_password(self, password):
        """Установка мастер-пароля"""
        try:
            salt = secrets.token_bytes(32)
            password_hash = self._hash_password(password, salt)

            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute("DELETE FROM master_password")
            cursor.execute(
                "INSERT INTO master_password (password_hash, salt) VALUES (?, ?)",
                (password_hash.hex(), salt.hex())
            )

            # Генерируем ключ шифрования
            self._generate_key(password, salt)

            # Логируем установку пароля
            self.log_login_attempt("MASTER_PASSWORD_SET")

            conn.commit()
            conn.close()

            return True
        except Exception as e:
            print(f"Ошибка при установке мастер-пароля: {e}")
            return False

    def verify_master_password(self, password):
        """Проверка мастер-пароля"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute("SELECT password_hash, salt FROM master_password LIMIT 1")
            result = cursor.fetchone()
            conn.close()

            if not result:
                self.log_login_attempt("FAILED_NO_MASTER_PASSWORD")
                return False

            stored_hash_hex, salt_hex = result
            salt = bytes.fromhex(salt_hex)

            # Хэшируем введенный пароль
            input_hash = self._hash_password(password, salt)

            # Сравниваем хэши
            if input_hash.hex() == stored_hash_hex:
                # Генерируем ключ для сессии
                self._generate_key(password, salt)
                self.log_login_attempt("SUCCESS")
                return True

            self.log_login_attempt("FAILED_WRONG_PASSWORD")
            return False
        except Exception as e:
            print(f"Ошибка при проверке пароля: {e}")
            self.log_login_attempt("FAILED_ERROR")
            return False

    def _hash_password(self, password, salt):
        """Хэширование пароля с солью"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )

    def _generate_key(self, password, salt):
        """Генерация ключа шифрования на основе пароля"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(key)
        self.key = key

    def add_password(self, title, username, password, category="General"):
        """Добавление нового пароля"""
        try:
            if not self.fernet:
                print("Ошибка: не инициализирован ключ шифрования")
                return False

            encrypted_password = self.fernet.encrypt(password.encode())

            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            # ОШИБКА БЫЛА ЗДЕСЬ: в запросе было указано 5 колонок, но передавалось 6 значений
            cursor.execute('''
                INSERT INTO passwords (title, username, password, category, updated_at)
                VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
            ''', (title, username, encrypted_password, category))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Ошибка при добавлении пароля: {e}")
            return False

    def get_passwords(self, search_term=None, category=None, favorites_only=False):
        """Получение всех паролей с возможностью поиска"""
        try:
            if not self.fernet:
                print("Ошибка: не инициализирован ключ шифрования")
                return []

            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            query = '''
                SELECT id, title, username, password,
                       created_at, category, updated_at, is_favorite
                FROM passwords 
                WHERE 1=1
            '''
            params = []

            if search_term:
                query += " AND (title LIKE ? OR username LIKE ? OR category LIKE ?)"
                search_pattern = f'%{search_term}%'
                # Исправлено: было 4 параметра, теперь 3
                params.extend([search_pattern, search_pattern, search_pattern])

            if category and category != "All":
                query += " AND category = ?"
                params.append(category)

            if favorites_only:
                query += " AND is_favorite = 1"

            query += " ORDER BY title"

            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()

            # Дешифруем пароли
            decrypted_results = []
            for row in results:
                try:
                    decrypted_password = self.fernet.decrypt(row[3]).decode()
                    # Исправлено индексацию
                    decrypted_results.append((row[0], row[1], row[2] or "", decrypted_password,
                                              row[4] or "", row[5], row[6] or "", row[7]))
                except Exception as e:
                    print(f"Ошибка дешифрования пароля ID {row[0]}: {e}")
                    decrypted_results.append((row[0], row[1], row[2] or "", "[Ошибка дешифрования]",
                                              row[4] or "", row[5], row[6] or "", row[7]))

            return decrypted_results
        except Exception as e:
            print(f"Ошибка при получении паролей: {e}")
            return []

    def get_categories(self):
        """Получение списка категорий"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute("SELECT DISTINCT category FROM passwords WHERE category IS NOT NULL ORDER BY category")
            results = [row[0] for row in cursor.fetchall() if row[0]]
            conn.close()

            return results if results else ["General"]
        except Exception as e:
            print(f"Ошибка при получении категорий: {e}")
            return ["General"]

    def delete_password(self, password_id):
        """Удаление пароля по ID"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            conn.commit()
            conn.close()
            return True
        except:
            return False

    def toggle_favorite(self, password_id):
        """Переключение статуса избранного для пароля"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            # Получаем текущий статус
            cursor.execute("SELECT is_favorite FROM passwords WHERE id = ?", (password_id,))
            current = cursor.fetchone()

            if current:
                # Проверяем, сколько уже избранных паролей
                cursor.execute("SELECT COUNT(*) FROM passwords WHERE is_favorite = 1")
                favorite_count = cursor.fetchone()[0]

                new_status = 0 if current[0] == 1 else 1

                # Если пытаемся добавить в избранное и уже есть 5
                if new_status == 1 and favorite_count >= 5:
                    return False, "Максимум 5 избранных паролей"

                cursor.execute("UPDATE passwords SET is_favorite = ? WHERE id = ?", (new_status, password_id))
                conn.commit()
                conn.close()
                return True, "Успешно"

            conn.close()
            return False, "Пароль не найден"
        except Exception as e:
            print(f"Ошибка при переключении избранного: {e}")
            return False, f"Ошибка: {e}"

    def get_favorite_passwords(self, limit=5):
        """Получение избранных паролей"""
        try:
            if not self.fernet:
                return []

            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, title, username, password 
                FROM passwords 
                WHERE is_favorite = 1 
                ORDER BY title 
                LIMIT ?
            ''', (limit,))
            results = cursor.fetchall()
            conn.close()

            # Дешифруем пароли
            decrypted_results = []
            for row in results:
                try:
                    decrypted_password = self.fernet.decrypt(row[3]).decode()
                    decrypted_results.append((row[0], row[1], row[2] or "", decrypted_password))
                except:
                    decrypted_results.append((row[0], row[1], row[2] or "", "[Ошибка дешифрования]"))

            return decrypted_results
        except Exception as e:
            print(f"Ошибка при получении избранных паролей: {e}")
            return []

    def master_password_exists(self):
        """Проверка, установлен ли мастер-пароль"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM master_password")
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except:
            return False


class ThemeManager:
    """Менеджер тем для приложения"""

    @staticmethod
    def apply_theme(root, theme_name):
        """Применение выбранной темы"""
        style = ttk.Style()

        if theme_name == "classic_light":
            style.theme_use('clam')
            ThemeManager._apply_classic_light(style, root)

        elif theme_name == "classic_dark":
            style.theme_use('clam')
            ThemeManager._apply_classic_dark(style, root)

        else:
            # По умолчанию классическая светлая
            style.theme_use('clam')
            ThemeManager._apply_classic_light(style, root)

    @staticmethod
    def _apply_classic_light(style, root):
        """Классическая светлая тема"""
        # Основные цвета
        bg_color = '#f0f0f0'
        fg_color = '#000000'
        entry_bg = '#ffffff'
        button_bg = '#e0e0e0'

        # Настройка виджетов
        style.configure('.',
                        background=bg_color,
                        foreground=fg_color,
                        font=('Segoe UI', 10))

        style.configure('TButton',
                        background=button_bg,
                        foreground=fg_color,
                        borderwidth=1,
                        relief='raised',
                        padding=6)

        style.map('TButton',
                  background=[('active', '#d0d0d0')])

        style.configure('TEntry',
                        fieldbackground=entry_bg,
                        foreground=fg_color,
                        borderwidth=1,
                        relief='sunken')

        style.configure('TCombobox',
                        fieldbackground=entry_bg,
                        foreground=fg_color,
                        background=entry_bg)

        style.map('TCombobox',
                  fieldbackground=[('readonly', entry_bg)],
                  background=[('readonly', entry_bg)])

        style.configure('Treeview',
                        background=entry_bg,
                        foreground=fg_color,
                        fieldbackground=entry_bg)

        style.configure('Treeview.Heading',
                        background=button_bg,
                        foreground=fg_color,
                        font=('Segoe UI', 10, 'bold'))

        style.configure('TNotebook',
                        background=bg_color,
                        borderwidth=0)

        style.configure('TNotebook.Tab',
                        background=button_bg,
                        foreground=fg_color,
                        padding=[10, 5])

        style.map('TNotebook.Tab',
                  background=[('selected', bg_color)])

        style.configure('Title.TLabel',
                        font=('Segoe UI', 18, 'bold'))

        style.configure('Header.TLabel',
                        font=('Segoe UI', 12, 'bold'))

        style.configure('Success.TLabel',
                        foreground='#2ecc71')

        style.configure('Error.TLabel',
                        foreground='#e74c3c')

        style.configure('Warning.TLabel',
                        foreground='#f39c12')

        style.configure('TLabelframe',
                        background=bg_color,
                        foreground=fg_color)

        style.configure('TLabelframe.Label',
                        background=bg_color,
                        foreground=fg_color)

        # Настройка для Radiobutton
        style.configure('TRadiobutton',
                        background=bg_color,
                        foreground=fg_color)

        root.configure(bg=bg_color)

    @staticmethod
    def _apply_classic_dark(style, root):
        """Классическая темная тема"""
        # Основные цвета
        bg_color = '#2b2b2b'
        fg_color = '#ffffff'
        entry_bg = '#3c3c3c'
        button_bg = '#404040'
        tab_bg = '#303030'

        # Настройка виджетов
        style.configure('.',
                        background=bg_color,
                        foreground=fg_color,
                        font=('Segoe UI', 10))

        style.configure('TButton',
                        background=button_bg,
                        foreground=fg_color,
                        borderwidth=1,
                        relief='raised',
                        padding=6)

        style.map('TButton',
                  background=[('active', '#505050')])

        style.configure('TEntry',
                        fieldbackground=entry_bg,
                        foreground=fg_color,
                        borderwidth=1,
                        relief='sunken')

        style.configure('TCombobox',
                        fieldbackground=entry_bg,
                        foreground=fg_color,
                        background=entry_bg)

        style.map('TCombobox',
                  fieldbackground=[('readonly', entry_bg)],
                  background=[('readonly', entry_bg)])

        style.configure('Treeview',
                        background=entry_bg,
                        foreground=fg_color,
                        fieldbackground=entry_bg)

        style.configure('Treeview.Heading',
                        background=button_bg,
                        foreground=fg_color,
                        font=('Segoe UI', 10, 'bold'))

        style.configure('TNotebook',
                        background=bg_color,
                        borderwidth=0)

        style.configure('TNotebook.Tab',
                        background=tab_bg,
                        foreground=fg_color,
                        padding=[10, 5])

        style.map('TNotebook.Tab',
                  background=[('selected', bg_color)])

        style.configure('Title.TLabel',
                        font=('Segoe UI', 18, 'bold'),
                        foreground=fg_color,
                        background=bg_color)

        style.configure('Header.TLabel',
                        font=('Segoe UI', 12, 'bold'),
                        foreground=fg_color,
                        background=bg_color)

        style.configure('Success.TLabel',
                        foreground='#2ecc71',
                        background=bg_color)

        style.configure('Error.TLabel',
                        foreground='#e74c3c',
                        background=bg_color)

        style.configure('Warning.TLabel',
                        foreground='#f39c12',
                        background=bg_color)

        style.configure('TLabelframe',
                        background=bg_color,
                        foreground=fg_color)

        style.configure('TLabelframe.Label',
                        background=bg_color,
                        foreground=fg_color)

        # Настройка для Radiobutton
        style.configure('TRadiobutton',
                        background=bg_color,
                        foreground=fg_color)

        # Настройка для Frame и других виджетов
        style.configure('TFrame',
                        background=bg_color)

        root.configure(bg=bg_color)


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSPM - Simple Secure Password Manager")
        self.root.geometry("1000x700")

        # Инициализация менеджера паролей
        self.manager = PasswordManager()

        # Загрузка темы из настроек
        self.current_theme = self.manager.get_setting('theme', 'classic_light')

        # Применение темы
        ThemeManager.apply_theme(root, self.current_theme)

        # Центрирование окна
        self.center_window(1000, 700)

        # Иконка для трея
        self.tray_icon = None
        self.in_tray = False
        self.tray_thread = None

        # Проверяем наличие иконки
        self.icon_path = self.find_icon_file()

        # Обработка закрытия окна
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)

        # Показываем соответствующее окно
        if not self.manager.master_password_exists():
            self.show_setup_window()
        else:
            self.show_login_window()

    def find_icon_file(self):
        """Поиск файла иконки в разных местах"""
        possible_paths = [
            'icon.ico',
            'icon.png',
            os.path.join(os.path.dirname(__file__), 'icon.ico'),
            os.path.join(os.path.dirname(__file__), 'icon.png'),
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None

    def create_default_tray_icon(self):
        """Создание иконки по умолчанию"""
        try:
            # Создаем изображение 64x64
            image = Image.new('RGBA', (64, 64), (74, 144, 226, 255))
            draw = ImageDraw.Draw(image)

            # Рисуем круг
            draw.ellipse([10, 10, 54, 54], fill='#ffffff', outline='#357ae8', width=3)

            # Рисуем букву S
            try:
                font = ImageFont.truetype("arial.ttf", 24)
            except:
                font = ImageFont.load_default()

            draw.text((32, 32), "S", fill='#4a90e2', anchor="mm", font=font)

            return image
        except Exception as e:
            print(f"Ошибка создания иконки по умолчанию: {e}")
            # Самый простой вариант на случай ошибки
            return Image.new('RGB', (64, 64), color='#4a90e2')

    def create_tray_icon(self):
        """Создание иконки для системного трея"""
        try:
            # Пробуем загрузить иконку из файла
            if self.icon_path and os.path.exists(self.icon_path):
                try:
                    image = Image.open(self.icon_path)
                    # Убедимся, что иконка имеет правильный размер
                    if image.size != (64, 64):
                        image = image.resize((64, 64), Image.Resampling.LANCZOS)
                    # Конвертируем в RGBA если нужно
                    if image.mode != 'RGBA':
                        image = image.convert('RGBA')
                except Exception as e:
                    print(f"Ошибка загрузки иконки: {e}")
                    image = self.create_default_tray_icon()
            else:
                image = self.create_default_tray_icon()

            # Создаем временное меню
            menu = pystray.Menu(
                pystray.MenuItem("Загрузка...", lambda: None)
            )

            self.tray_icon = pystray.Icon(
                "SSPM",
                image,
                "SSPM - Менеджер паролей",
                menu
            )

            print("Иконка трея создана успешно")
        except Exception as e:
            print(f"Ошибка при создании иконки трея: {e}")
            self.tray_icon = None

    def update_tray_menu(self):
        """Обновление меню трея"""
        if not self.tray_icon:
            return

        try:
            # Получаем избранные пароли
            favorites = self.manager.get_favorite_passwords()

            # Создаем элементы меню для избранных паролей
            favorite_items = []
            if favorites:
                for fav in favorites:
                    title = fav[1] if len(fav[1]) < 20 else fav[1][:17] + "..."
                    # Используем лямбду с замыканием
                    password = fav[3]  # Сохраняем пароль в переменной
                    favorite_items.append(
                        pystray.MenuItem(
                            title,
                            lambda _, p=password: self.copy_favorite_password(p)
                        )
                    )
            else:
                favorite_items.append(pystray.MenuItem("Нет избранных паролей", lambda _: None))

            # Создаем подменю для избранных
            favorites_submenu = pystray.Menu(*favorite_items)

            # Создаем главное меню
            menu = pystray.Menu(
                pystray.MenuItem("Открыть SSPM", self.restore_from_tray),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Избранные пароли", favorites_submenu),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Выход из системы", self.logout),
                pystray.MenuItem("Закрыть программу", self.quit_application)
            )

            self.tray_icon.menu = menu
            print(f"Меню трея обновлено. Избранных паролей: {len(favorites)}")

        except Exception as e:
            print(f"Ошибка при обновлении меню трея: {e}")

    def copy_favorite_password(self, password):
        """Копирование пароля из избранного"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(password))

            # Показываем уведомление
            if self.tray_icon:
                try:
                    self.tray_icon.notify("Пароль скопирован в буфер обмена", "SSPM")
                except:
                    pass

            print(f"Пароль скопирован: {password[:5]}...")
        except Exception as e:
            print(f"Ошибка копирования пароля: {e}")

    def minimize_to_tray(self):
        """Сворачивание в трей"""
        if not TRAY_AVAILABLE:
            if messagebox.askokcancel("Выход", "Закрыть программу?"):
                self.root.destroy()
            return

        try:
            self.root.withdraw()
            self.in_tray = True

            # Создаем иконку если еще не создана
            if not self.tray_icon:
                self.create_tray_icon()

            if self.tray_icon:
                # Обновляем меню с текущими избранными паролями
                self.update_tray_menu()

                # Запускаем иконку в отдельном потоке
                self.tray_thread = threading.Thread(
                    target=self.tray_icon.run,
                    daemon=True
                )
                self.tray_thread.start()
                print("Приложение свернуто в трей")
            else:
                print("Не удалось создать иконку трея")
                self.restore_from_tray()

        except Exception as e:
            print(f"Ошибка при сворачивании в трей: {e}")
            self.restore_from_tray()

    def restore_from_tray(self, icon=None, item=None):
        """Восстановление из трея"""
        if self.in_tray and self.tray_icon:
            try:
                # Останавливаем иконку трея
                self.tray_icon.stop()
                print("Иконка трея остановлена")

                # Ждем завершения потока
                if self.tray_thread and self.tray_thread.is_alive():
                    self.tray_thread.join(timeout=2)

            except Exception as e:
                print(f"Ошибка при остановке иконки трея: {e}")
            finally:
                self.tray_icon = None
                self.tray_thread = None

        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.in_tray = False
        print("Приложение восстановлено из трея")

    def quit_application(self, icon=None, item=None):
        """Полный выход из приложения"""
        if self.tray_icon:
            try:
                self.tray_icon.stop()
                if self.tray_thread and self.tray_thread.is_alive():
                    self.tray_thread.join(timeout=1)
            except:
                pass

        self.root.destroy()
        print("Приложение завершено")
        os._exit(0)

    def center_window(self, width, height):
        """Центрирование окна на экране"""
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def clear_window(self):
        """Очистка окна"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_setup_window(self):
        """Окно установки мастер-пароля"""
        self.clear_window()

        frame = ttk.Frame(self.root, padding="40")
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Установите мастер-пароль",
                  style='Title.TLabel').pack(pady=(0, 30))

        ttk.Label(frame, text="Мастер-пароль (минимум 8 символов):").pack(anchor=tk.W)
        self.setup_password = ttk.Entry(frame, show="*", width=40, font=('Arial', 11))
        self.setup_password.pack(pady=(0, 10))

        ttk.Label(frame, text="Подтверждение:").pack(anchor=tk.W)
        self.setup_confirm = ttk.Entry(frame, show="*", width=40, font=('Arial', 11))
        self.setup_confirm.pack(pady=(0, 20))

        # Индикатор сложности пароля
        self.password_strength = ttk.Label(frame, text="", style='Warning.TLabel')
        self.password_strength.pack()

        # Подсказки
        tips_frame = ttk.LabelFrame(frame, text="Рекомендации по безопасности", padding=10)
        tips_frame.pack(fill=tk.X, pady=20)

        tips = [
            "- Используйте не менее 8 символов",
            "- Комбинируйте буквы (заглавные и строчные), цифры и спецсимволы",
            "- Не используйте личную информацию",
            "- Не используйте один пароль для нескольких сервисов",
            "- Регулярно меняйте мастер-пароль"
        ]

        for tip in tips:
            ttk.Label(tips_frame, text=tip).pack(anchor=tk.W)

        self.setup_error = ttk.Label(frame, text="", style='Error.TLabel')
        self.setup_error.pack()

        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Установить",
                   command=self.process_setup, width=15).pack(side=tk.LEFT, padx=5)

        # Привязка событий
        self.setup_password.bind('<KeyRelease>', self.check_password_strength)

    def check_password_strength(self, event=None):
        """Проверка сложности пароля"""
        password = self.setup_password.get()

        if len(password) < 6:
            self.password_strength.config(text="Слишком короткий", style='Error.TLabel')
        elif len(password) < 8:
            self.password_strength.config(text="Средняя сложность", style='Warning.TLabel')
        else:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(not c.isalnum() for c in password)

            score = sum([has_upper, has_lower, has_digit, has_special])

            if score >= 3 and len(password) >= 8:
                self.password_strength.config(text="Отличный пароль", style='Success.TLabel')
            elif score >= 2:
                self.password_strength.config(text="Хороший пароль", style='Warning.TLabel')
            else:
                self.password_strength.config(text="Слабый пароль", style='Error.TLabel')

    def process_setup(self):
        """Обработка установки мастер-пароля"""
        password = self.setup_password.get()
        confirm = self.setup_confirm.get()

        if not password or not confirm:
            self.setup_error.config(text="Заполните все поля")
            return

        if password != confirm:
            self.setup_error.config(text="Пароли не совпадают")
            return

        if len(password) < 8:
            self.setup_error.config(text="Пароль должен быть не менее 8 символов")
            return

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)

        if not (has_upper and has_lower and has_digit):
            self.setup_error.config(text="Используйте заглавные, строчные буквы и цифры")
            return

        try:
            success = self.manager.set_master_password(password)
            if success:
                messagebox.showinfo("Успех", "Мастер-пароль установлен!")
                self.show_login_window()
            else:
                self.setup_error.config(text="Ошибка при установке пароля")
        except Exception as e:
            self.setup_error.config(text=f"Ошибка: {str(e)}")

    def show_login_window(self):
        """Окно входа"""
        self.clear_window()

        frame = ttk.Frame(self.root, padding="40")
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Вход в SSPM",
                  style='Title.TLabel').pack(pady=(0, 30))

        # Информация о последнем входе
        try:
            history = self.manager.get_login_history(limit=1)
            if history:
                last_login = history[0]
                status_icon = "Успешно" if last_login[2] == "SUCCESS" else "Ошибка"
                login_time = last_login[1]
                info_text = f"Последний вход: {login_time} ({status_icon})"
                ttk.Label(frame, text=info_text, style='Warning.TLabel').pack(pady=(0, 20))
        except:
            pass

        ttk.Label(frame, text="Мастер-пароль:").pack(anchor=tk.W)
        self.login_password = ttk.Entry(frame, show="*", width=40, font=('Arial', 11))
        self.login_password.pack(pady=(0, 20))

        show_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(frame, text="Показать пароль",
                                     variable=show_var,
                                     command=lambda: self.toggle_password_visibility(
                                         self.login_password, show_var))
        show_check.pack(pady=(0, 20))

        self.login_error = ttk.Label(frame, text="", style='Error.TLabel')
        self.login_error.pack()

        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Войти",
                   command=self.process_login, width=15).pack(side=tk.LEFT, padx=5)

        # Привязка событий
        self.login_password.bind('<Return>', lambda e: self.process_login())

        self.login_password.focus()

    def toggle_password_visibility(self, entry, var):
        """Показать/скрыть пароль"""
        if hasattr(entry, 'config'):
            entry.config(show='' if var.get() else '*')

    def process_login(self):
        """Обработка входа"""
        password = self.login_password.get()

        if not password:
            self.login_error.config(text="Введите пароль")
            return

        try:
            if self.manager.verify_master_password(password):
                self.show_main_window()
            else:
                self.login_error.config(text="Неверный пароль")
                self.login_password.delete(0, tk.END)
        except Exception as e:
            self.login_error.config(text=f"Ошибка: {str(e)}")

    def show_main_window(self):
        """Основное окно приложения"""
        self.clear_window()

        # Главный контейнер
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Панель статуса
        status_frame = ttk.Frame(main_container)
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = ttk.Label(status_frame, text="Защищено", style='Success.TLabel')
        self.status_label.pack(side=tk.LEFT)

        # Notebook (вкладки)
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=(0, 10))

        # Создаем вкладки
        self.view_frame = ttk.Frame(self.notebook)
        self.add_frame = ttk.Frame(self.notebook)
        self.history_frame = ttk.Frame(self.notebook)
        self.settings_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.view_frame, text="Пароли")
        self.notebook.add(self.add_frame, text="Добавить")
        self.notebook.add(self.history_frame, text="Журнал")
        self.notebook.add(self.settings_frame, text="Настройки")

        self.setup_view_tab()
        self.setup_add_tab()
        self.setup_history_tab()
        self.setup_settings_tab()

        # Кнопка выхода
        logout_frame = ttk.Frame(main_container)
        logout_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(logout_frame, text="Выход из системы",
                   command=self.logout, width=15).pack()

    def setup_view_tab(self):
        """Настройка вкладки просмотра паролей"""
        # Панель управления
        control_frame = ttk.Frame(self.view_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        # Поиск
        search_frame = ttk.Frame(control_frame)
        search_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Label(search_frame, text="Поиск:").pack(side=tk.LEFT, padx=(0, 10))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))

        # Checkbox для избранных
        self.favorites_only_var = tk.BooleanVar()
        favorites_check = ttk.Checkbutton(search_frame, text="Только избранные",
                                          variable=self.favorites_only_var,
                                          command=self.load_passwords)
        favorites_check.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(search_frame, text="Сброс",
                   command=self.reset_search).pack(side=tk.LEFT)

        # Фильтр по категориям
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(side=tk.RIGHT)

        ttk.Label(filter_frame, text="Категория:").pack(side=tk.LEFT, padx=(0, 10))
        self.category_var = tk.StringVar(value="All")
        self.category_combo = ttk.Combobox(filter_frame, textvariable=self.category_var,
                                           state="readonly", width=15)
        self.category_combo.pack(side=tk.LEFT)
        self.update_category_filter()

        # Таблица паролей
        table_frame = ttk.Frame(self.view_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        columns = ("ID", "Название", "Логин", "Пароль", "Категория", "Обновлено", "Избранное")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)

        col_widths = [50, 200, 150, 150, 100, 150, 80]
        for i, col in enumerate(columns):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths[i])

        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Кнопки управления
        button_frame = ttk.Frame(self.view_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        buttons = [
            ("Обновить", self.load_passwords),
            ("Копировать пароль", self.copy_password),
            ("Показать/Скрыть", self.toggle_password_display),
            ("★ Избранное", self.toggle_favorite),
            ("Удалить", self.delete_selected_password)
        ]

        for text, command in buttons:
            ttk.Button(button_frame, text=text,
                       command=command).pack(side=tk.LEFT, padx=5)

        # Загрузка паролей
        self.load_passwords()

        # Привязка событий
        self.search_var.trace('w', lambda *args: self.on_search_change())
        self.category_var.trace('w', lambda *args: self.on_category_change())
        self.tree.bind('<Double-1>', self.on_item_double_click)

    def update_category_filter(self):
        """Обновление фильтра категорий"""
        try:
            categories = ["All"] + self.manager.get_categories()
            self.category_combo['values'] = categories
        except:
            self.category_combo['values'] = ["All", "General"]

    def on_search_change(self):
        """Обработка изменения поискового запроса"""
        self.search_passwords()

    def on_category_change(self):
        """Обработка изменения категории"""
        self.load_passwords()

    def search_passwords(self):
        """Поиск паролей"""
        search_term = self.search_var.get()
        self.load_passwords(search_term)

    def reset_search(self):
        """Сброс поиска"""
        self.search_var.set("")
        self.category_var.set("All")
        self.favorites_only_var.set(False)
        self.load_passwords()

    def load_passwords(self, search_term=None):
        """Загрузка паролей в таблицу"""
        if not hasattr(self, 'tree'):
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            category = None
            if self.category_var.get() != "All":
                category = self.category_var.get()

            favorites_only = self.favorites_only_var.get()
            passwords = self.manager.get_passwords(search_term, category, favorites_only)

            for pwd in passwords:
                if len(pwd) >= 8:  # Исправлено: теперь 8 элементов
                    password = str(pwd[3]) if pwd[3] else ""
                    hidden_password = "*" * 8 if len(password) > 8 else "*" * len(password)
                    category_name = str(pwd[5]) if pwd[5] else "General"  # Исправлен индекс
                    updated_at = str(pwd[6]) if pwd[6] else ""  # Исправлен индекс
                    favorite = "★" if pwd[7] == 1 else "☆"  # Исправлен индекс

                    display_values = (
                        str(pwd[0]),
                        str(pwd[1]) if pwd[1] else "",
                        str(pwd[2]) if pwd[2] else "",
                        hidden_password,
                        category_name,
                        updated_at,
                        favorite
                    )
                    self.tree.insert("", tk.END, values=display_values, tags=(password, str(pwd[7])))
        except Exception as e:
            print(f"Ошибка при загрузке паролей: {e}")

    def on_item_double_click(self, event):
        """Двойной клик по элементу"""
        self.copy_password()

    def copy_password(self):
        """Копирование пароля в буфер обмена"""
        if not hasattr(self, 'tree'):
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите пароль для копирования")
            return

        try:
            item = self.tree.item(selection[0])
            password = item['tags'][0] if item['tags'] else ""

            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.status_label.config(text="Пароль скопирован", style='Success.TLabel')

            self.root.after(3000, lambda: self.status_label.config(
                text="Защищено", style='Success.TLabel'))
        except:
            pass

    def toggle_password_display(self):
        """Показать/скрыть пароли в таблице"""
        if not hasattr(self, 'tree'):
            return

        selection = self.tree.selection()

        if not selection:
            for item in self.tree.get_children():
                try:
                    values = list(self.tree.item(item)['values'])
                    tags = self.tree.item(item)['tags']

                    if values and len(values) > 3:
                        password = tags[0] if tags else ""
                        # Проверяем, состоит ли строка только из звездочек (любое количество)
                        if values[3] and all(c == '*' for c in values[3]):
                            values[3] = password
                        else:
                            values[3] = "*" * 8 if len(password) > 8 else "*" * len(password)

                        self.tree.item(item, values=values)
                except:
                    pass
        else:
            for item in selection:
                try:
                    values = list(self.tree.item(item)['values'])
                    tags = self.tree.item(item)['tags']

                    if values and len(values) > 3:
                        password = tags[0] if tags else ""
                        # Проверяем, состоит ли строка только из звездочек (любое количество)
                        if values[3] and all(c == '*' for c in values[3]):
                            values[3] = password
                        else:
                            values[3] = "*" * 8 if len(password) > 8 else "*" * len(password)

                        self.tree.item(item, values=values)
                except:
                    pass

    def toggle_favorite(self):
        """Добавление/удаление из избранного"""
        if not hasattr(self, 'tree'):
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите пароль")
            return

        try:
            item = self.tree.item(selection[0])
            password_id = int(item['values'][0])

            success, message = self.manager.toggle_favorite(password_id)

            if success:
                self.load_passwords()
                # Обновляем меню в трее
                if self.in_tray:
                    self.update_tray_menu()
                messagebox.showinfo("Успех", message)
            else:
                messagebox.showwarning("Внимание", message)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось изменить статус избранного: {e}")

    def delete_selected_password(self):
        """Удаление выбранного пароля"""
        if not hasattr(self, 'tree'):
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите пароль для удаления")
            return

        if messagebox.askyesno("Подтверждение",
                               "Вы уверены, что хотите удалить выбранный пароль?"):
            try:
                item = self.tree.item(selection[0])
                password_id = int(item['values'][0])

                if self.manager.delete_password(password_id):
                    messagebox.showinfo("Успех", "Пароль удален")
                    self.load_passwords()
                    self.update_category_filter()
                    # Обновляем меню в трее
                    if self.in_tray:
                        self.update_tray_menu()
            except:
                messagebox.showerror("Ошибка", "Не удалось удалить пароль")

    def setup_add_tab(self):
        """Настройка вкладки добавления пароля"""
        frame = ttk.Frame(self.add_frame, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Добавить новый пароль",
                  style='Header.TLabel').pack(anchor=tk.W, pady=(0, 20))

        fields_frame = ttk.Frame(frame)
        fields_frame.pack(fill=tk.BOTH, expand=True)

        fields = [
            ("Название*:", "title", 0),
            ("Логин/Email:", "username", 1),
            ("Пароль*:", "password", 2),
            ("Категория:", "category", 3),
        ]

        self.add_entries = {}

        for i, (label, field, row) in enumerate(fields):
            ttk.Label(fields_frame, text=label).grid(row=row, column=0,
                                                     sticky=tk.W, pady=5, padx=(0, 10))

            if field == "password":
                entry_frame = ttk.Frame(fields_frame)
                entry_frame.grid(row=row, column=1, sticky=tk.W + tk.E, pady=5)

                entry = ttk.Entry(entry_frame, width=40, show="*")
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

                btn_frame = ttk.Frame(entry_frame)
                btn_frame.pack(side=tk.RIGHT, padx=(5, 0))

                # Кнопки с эмодзи
                ttk.Button(btn_frame, text="👁",
                           command=lambda e=entry: self.toggle_password_visibility_field(e), width=3).pack(side=tk.LEFT)
                ttk.Button(btn_frame, text="🎲",
                           command=lambda e=entry: self.generate_password(e), width=3).pack(side=tk.LEFT, padx=2)
                ttk.Button(btn_frame, text="📋",
                           command=lambda e=entry: self.copy_from_field(e), width=3).pack(side=tk.LEFT)

                self.add_entries[field] = entry

            elif field == "category":
                entry = ttk.Combobox(fields_frame, width=38)
                entry['values'] = ["General", "Social Media", "Email", "Banking",
                                   "Work", "Shopping", "Entertainment", "Other"]
                entry.set("General")
                entry.grid(row=row, column=1, sticky=tk.W, pady=5)
                self.add_entries[field] = entry

            else:
                entry = ttk.Entry(fields_frame, width=40)
                entry.grid(row=row, column=1, sticky=tk.W, pady=5)
                self.add_entries[field] = entry

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=20)

        ttk.Button(button_frame, text="Добавить",
                   command=self.add_new_password, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Очистить форму",
                   command=self.clear_add_form, width=15).pack(side=tk.LEFT, padx=5)

    def toggle_password_visibility_field(self, entry):
        """Показать/скрыть пароль в поле"""
        if entry.cget('show') == '':
            entry.config(show='*')
        else:
            entry.config(show='')

    def generate_password(self, entry):
        """Генерация случайного пароля"""
        try:
            length = 16
            characters = string.ascii_letters + string.digits + "!@#$%^&*"
            password = ''.join(random.choice(characters) for _ in range(length))

            entry.delete(0, tk.END)
            entry.insert(0, password)
        except:
            pass

    def copy_from_field(self, entry):
        """Копирование из поля"""
        try:
            text = entry.get()
            if text:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.status_label.config(text="Скопировано", style='Success.TLabel')
                self.root.after(3000, lambda: self.status_label.config(
                    text="Защищено", style='Success.TLabel'))
        except:
            pass

    def add_new_password(self):
        """Добавление нового пароля"""
        title = self.add_entries['title'].get() if 'title' in self.add_entries else ""
        username = self.add_entries['username'].get() if 'username' in self.add_entries else ""
        password = self.add_entries['password'].get() if 'password' in self.add_entries else ""

        category = "General"
        if 'category' in self.add_entries and isinstance(self.add_entries['category'], ttk.Combobox):
            category = self.add_entries['category'].get()

        if not title or not password:
            messagebox.showwarning("Внимание", "Заполните обязательные поля")
            return

        try:
            success = self.manager.add_password(title, username, password, category)
            if success:
                messagebox.showinfo("Успех", "Пароль добавлен!")
                self.clear_add_form()
                self.load_passwords()
                self.update_category_filter()
                self.notebook.select(0)
        except:
            messagebox.showerror("Ошибка", "Не удалось добавить пароль")

    def clear_add_form(self):
        """Очистка формы добавления"""
        for field, entry in self.add_entries.items():
            if isinstance(entry, ttk.Entry):
                entry.delete(0, tk.END)
                if field == "password":
                    entry.config(show='*')
            elif isinstance(entry, ttk.Combobox):
                entry.set("General")
            elif isinstance(entry, tk.Text):
                entry.delete("1.0", tk.END)

    def setup_history_tab(self):
        """Настройка вкладки истории входов"""
        frame = ttk.Frame(self.history_frame, padding=10)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Журнал входов",
                  style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(control_frame, text="Обновить",
                   command=self.load_login_history).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="Очистить журнал",
                   command=self.clear_login_history).pack(side=tk.LEFT)

        columns = ("ID", "Время", "Статус")
        self.history_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)

        col_widths = [50, 200, 200]
        for i, col in enumerate(columns):
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=col_widths[i])

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.history_tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self.load_login_history()

    def load_login_history(self):
        """Загрузка истории входов"""
        if not hasattr(self, 'history_tree'):
            return

        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        try:
            history = self.manager.get_login_history()

            for record in history:
                if len(record) >= 3:
                    status = record[2]
                    status_text = {
                        "SUCCESS": "Успешно",
                        "FAILED_WRONG_PASSWORD": "Неверный пароль",
                        "FAILED_NO_MASTER_PASSWORD": "Нет пароля",
                        "MASTER_PASSWORD_SET": "Пароль установлен",
                        "FAILED_ERROR": "Ошибка системы"
                    }.get(status, status)

                    self.history_tree.insert("", tk.END, values=(
                        str(record[0]),
                        str(record[1]),
                        status_text
                    ))
        except:
            pass

    def clear_login_history(self):
        """Очистка истории входов"""
        if messagebox.askyesno("Подтверждение",
                               "Вы уверены, что хотите очистить историю входов?"):
            success = self.manager.clear_login_history()
            if success:
                messagebox.showinfo("Успех", "История входов очищена")
                self.load_login_history()

    def setup_settings_tab(self):
        """Настройка вкладки настроек"""
        frame = ttk.Frame(self.settings_frame, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        # Выбор темы
        theme_frame = ttk.LabelFrame(frame, text="Выбор дизайна", padding=15)
        theme_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(theme_frame, text="Выберите дизайн интерфейса:",
                  style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        # Создаем 2 кнопки с предпросмотром тем
        themes_container = ttk.Frame(theme_frame)
        themes_container.pack(fill=tk.X, pady=10)

        # Описания тем
        themes = [
            ("classic_light", "Классическая светлая", "Светлая версия классического дизайна"),
            ("classic_dark", "Классическая темная", "Темная версия классического дизайна")
        ]

        self.theme_buttons = []
        self.theme_vars = []

        for i, (theme_id, theme_name, theme_desc) in enumerate(themes):
            theme_row = ttk.Frame(themes_container)
            theme_row.pack(fill=tk.X, pady=5)

            # Радиокнопка выбора
            var = tk.StringVar(value=theme_id if self.current_theme == theme_id else "")
            self.theme_vars.append(var)

            rb = ttk.Radiobutton(theme_row, text="", variable=var, value=theme_id,
                                 command=lambda t=theme_id: self.on_theme_selected(t))
            rb.pack(side=tk.LEFT, padx=(0, 10))

            # Информация о теме
            info_frame = ttk.Frame(theme_row)
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

            ttk.Label(info_frame, text=theme_name, font=('Segoe UI', 11, 'bold')).pack(anchor=tk.W)
            ttk.Label(info_frame, text=theme_desc, font=('Segoe UI', 9)).pack(anchor=tk.W)

            # Показываем текущую тему
            if theme_id == self.current_theme:
                ttk.Label(theme_row, text="Текущая", style='Success.TLabel').pack(side=tk.RIGHT, padx=10)

            self.theme_buttons.append(rb)

        # Кнопка применения темы
        button_frame = ttk.Frame(theme_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(button_frame, text="Применить выбранную тему",
                   command=self.apply_selected_theme, width=25).pack(side=tk.LEFT, padx=(0, 10))

        # Информация о программе
        info_frame = ttk.LabelFrame(frame, text="О программе", padding=15)
        info_frame.pack(fill=tk.X)

        info_text = """SSPM - Simple Secure Password Manager
Версия 1.0.0

Функции:
- Безопасное хранение паролей
- Шифрование данных
- Генерация паролей
- Избранные пароли (до 5)
- Несколько тем оформления
- Работа из системного трея

Используемые технологии:
- SQLite для хранения данных
- Fernet-шифрование
- PBKDF2 для хэширования паролей"""

        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(anchor=tk.W)

    def on_theme_selected(self, theme_id):
        """Обработка выбора темы"""
        # Обновляем отображение радиокнопок
        for i, var in enumerate(self.theme_vars):
            if var.get() != theme_id:
                var.set("")
            else:
                var.set(theme_id)

    def apply_selected_theme(self):
        """Применение выбранной темы"""
        # Находим выбранную тему
        selected_theme = None
        for var in self.theme_vars:
            if var.get():
                selected_theme = var.get()
                break

        if not selected_theme:
            messagebox.showwarning("Внимание", "Выберите тему для применения")
            return

        if selected_theme == self.current_theme:
            messagebox.showinfo("Информация", "Эта тема уже активна")
            return

        # Сохраняем тему в настройках
        if self.manager.save_setting('theme', selected_theme):
            # Обновляем текущую тему
            self.current_theme = selected_theme

            # Применяем тему немедленно
            ThemeManager.apply_theme(self.root, selected_theme)

            # Перезагружаем все виджеты
            self._reload_all_widgets()

            messagebox.showinfo("Успех", "Тема применена!")
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить настройки темы")

    def _reload_all_widgets(self):
        """Перезагрузка всех виджетов с новой темой"""
        # Перезагружаем текущее окно
        if hasattr(self, 'notebook'):
            # Если мы в главном окне
            self.show_main_window()
        else:
            # Если в окне входа или установки
            if self.manager.master_password_exists():
                self.show_login_window()
            else:
                self.show_setup_window()

    def logout(self):
        """Выход из системы"""
        if messagebox.askyesno("Выход", "Вы уверены, что хотите выйти из системы?"):
            # Сбрасываем менеджер
            self.manager.fernet = None
            self.manager.key = None

            # Останавливаем иконку трея
            if self.tray_icon:
                try:
                    self.tray_icon.stop()
                    self.tray_icon = None
                    self.tray_thread = None
                except:
                    pass

            # Показываем окно входа
            self.show_login_window()


def main():
    root = tk.Tk()

    try:
        # Устанавливаем иконку для главного окна
        root.iconbitmap('icon.ico')
    except:
        # Создаем простую иконку, если файла нет
        try:
            # Создаем простую иконку
            from PIL import Image, ImageTk
            import io
            img = Image.new('RGB', (32, 32), color='#4a90e2')
            photo = ImageTk.PhotoImage(img)
            root.iconphoto(False, photo)
        except:
            pass

    app = PasswordManagerGUI(root)

    def on_closing():
        app.minimize_to_tray()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    try:
        root.mainloop()
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        root.destroy()


if __name__ == "__main__":
    main()