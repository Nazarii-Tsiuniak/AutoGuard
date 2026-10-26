# AutoGuard

**AutoGuard** — навчальний вебзастосунок для лабораторної роботи №6 «Розробка безпечної системи управління обліковими записами». Дозволяє керувати автомобілями, історією технічного обслуговування та витратами, забезпечуючи захист облікових записів.

## Технології

- **Backend:** Python 3.11+, Flask, Waitress.
- **База даних:** SQLite, SQLAlchemy, Flask-Migrate.
- **Frontend:** HTML, CSS, JavaScript, Bootstrap 5.
- **Безпека:** Argon2id, Flask-Login, Flask-Limiter, TOTP, Google OIDC, Cloudflare Turnstile.

## Реалізовані завдання

1. **Реєстрація та авторизація** — перевірка складності паролів, безпечне хешування Argon2id, вхід і вихід.
2. **CAPTCHA** — Cloudflare Turnstile із серверною перевіркою.
3. **Email-активація** — підтвердження облікового запису через одноразове посилання.
4. **Захист від Brute Force** — обмеження спроб входу, блокування користувачів, журнал авторизацій, ролі USER/ADMIN.
5. **Двофакторна автентифікація** — TOTP через Google Authenticator.
6. **Google OIDC** — авторизація через обліковий запис Google.
7. **Відновлення пароля** — скидання через електронну пошту.

## Додаткові можливості

- Додавання, редагування та видалення автомобілів.
- Облік технічного обслуговування.
- Перегляд витрат і статистики.
- Особистий кабінет користувача.
- Адміністративна панель керування користувачами.

## Запуск проєкту

```powershell
git clone https://github.com/Nazarii-Tsiuniak/AutoGuard.git
cd AutoGuard
py -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python -m flask --app run db upgrade
.\.venv\Scripts\python run.py
```

Відкрити в браузері: **http://127.0.0.1:5050**

Для роботи з Gmail і Google OIDC необхідно додатково налаштувати відповідні параметри у `.env`.

## Перевірка

```powershell
.\.venv\Scripts\python -m pytest -q
```

Проведено 98 автоматизованих тестів і 23 HTTP-перевірки.

## Безпека

У застосунку реалізовано хешування паролів, CSRF-захист, обмеження спроб авторизації, контроль доступу та захищені сесії.

Конфіденційні файли (`.env`, база даних, ключі та токени) не повинні публікуватися в GitHub.

## GitHub

https://github.com/Nazarii-Tsiuniak/AutoGuard
