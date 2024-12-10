# Блог на фласке

## Описание

Этот проект представляет собой простой блог, созданный с использованием фреймворка Flask. Он включает в себя функциональность регистрации и входа пользователей, создания и удаления постов, а также добавления комментариев к постам. Администратор имеет доступ к специальной панели управления, где может удалять посты.

## Основные функции

- **Регистрация и аутентификация пользователей**: Пользователи могут зарегистрироваться, войти в систему и выйти из неё.
- **Создание постов**: Авторизованные пользователи могут создавать новые посты.
- **Комментарии**: Пользователи могут оставлять комментарии к постам.
- **Админ-панель**: Администратор может просматривать все посты и удалять их.
- **Каскадное удаление**: При удалении поста автоматически удаляются все связанные с ним комментарии.

## Установка и запуск

### Используемые технологии:

- **Flask**: Основной фреймворк для создания веб-приложений на Python.
- **Flask-SQLAlchemy**: ORM для работы с базой данных.
- **Flask-Login**: Расширение для управления аутентификацией пользователей.
- **Flask-WTF**: Расширение для работы с формами и валидацией данных.
- **WTForms**: Библиотека для создания и валидации форм.
- **Werkzeug**: Библиотека для работы с безопасностью и хэшированием паролей.
- **HTML/CSS**: Для создания пользовательского интерфейса.
- **SQLite**: Встроенная база данных для хранения данных.

### Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/whoami3342/blog-na-flaske.git
   cd blog-na-flaske

2. Создайте виртуальное окружение (рекомендуется):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Для Windows используйте `venv\Scripts\activate`

3. Установите зависимости:
   ```bash
   pip install -r requirements.txt

4. Инициализируйте базу данных:
   ```bash
   python init_db.py

5. Запустите приложение:
   ```bash
   python app.py

7. Откройте в браузере:
Перейдите по адресу http://127.0.0.1:5000 для просмотра блога.

## Структура проекта

- **app.py**: Основной файл приложения Flask.
- **init_db.py**: Скрипт для инициализации базы данных.
- **templates/**: Папка с HTML-шаблонами.
- **static/style.css**: Файл со стилями.

## Использование

- **Регистрация**: Нажмите на ссылку "Регистрация" в шапке сайта, чтобы создать новый аккаунт.
- **Вход**: Используйте свои учетные данные для входа.
- **Создание постов**: После входа в систему вы сможете создавать новые посты, нажав на ссылку "Новый пост".
- **Комментарии**: На странице каждого поста вы можете оставить комментарий.
- **Админ-панель**: Если вы зарегистрированы как администратор (имя пользователя admin), вы можете удалять посты через админ-панель.

### Скриншоты

![image](https://github.com/user-attachments/assets/8ac841b1-2efa-4b71-a3d7-81b05e65cd71)
![image](https://github.com/user-attachments/assets/cd05b9ae-6149-4db8-a054-dd7059c3cf27)
![image](https://github.com/user-attachments/assets/52dcce83-8940-488d-b44d-a312d4da37cf)
![image](https://github.com/user-attachments/assets/14c3e0cc-f001-4b8d-9ecd-a0a4b323c181)
![image](https://github.com/user-attachments/assets/0aba18d0-68d1-4fd5-b223-2bfefb843fc2)
![image](https://github.com/user-attachments/assets/b0ce2cb9-1d79-4173-924b-bf99c8c40ba5)
