# Перевірка Google OIDC після налаштування credentials

Причину повідомлення «не налаштовано» підтверджено порівнянням двох процесів: нова фабрика Flask читала конфігурацію та повертала Google-кнопку, а старий сервер на 5050 — ні. Waitress був запущений до редагування `.env` і не перечитував файл. Сервер перезапущено; `.env`, його credentials і користувацька база не змінювалися.

## Безпечна діагностика

| Перевірка | Результат |
|---|---|
| Кореневий `.env` | configured |
| GOOGLE_CLIENT_ID у `.env` і Flask | configured |
| GOOGLE_CLIENT_SECRET у `.env` і Flask | configured |
| Перекривні значення Google у process/User/Machine environment | missing |
| Authlib Google client | configured |
| Очікувана локальна база callback | configured |
| Google-кнопка в запущеному `/auth/login` | configured |

Значення credentials не виводились і в цей файл не записувались. `load_dotenv` використовує абсолютний шлях до кореневого `.env` та зберігає пріоритет системних змінних (`override=False`). Наявні назви змінних правильні. Повідомлення в UI з’являється, коли в конфігурації запущеного процесу немає хоча б одного Google-параметра.

## Що змінено

- `autoguard/__init__.py`: обрізання крайових пробілів лише в двох Google-параметрах, CLI `oidc-status` без значень credentials.
- `run.py`: при запуску показує тільки Google OIDC configured/missing.
- `autoguard/auth.py`: мережеві/OAuth-помилки під час початкового discovery/redirect обробляються повідомленням без 500 і без показу provider response. Перевірки callback не вимикалися.
- `tests/test_google_configuration.py`: видимість кнопки при повній/неповній конфігурації, whitespace, нерозголошення секретів і обробка збоїв discovery.
- `tests/conftest.py`: ізоляція кешу Authlib між тестами з різними штучними credentials.
- `README.md`: пояснення перезапуску `.env` і безпечної діагностики.

## Фактичні перевірки

- Повний pytest: **98 passed**. Перевірені звичайний вхід/вихід, SMTP mocks і токени активації/reset, 2FA, CAPTCHA, гараж, ТО та ADMIN/RBAC. Всі pytest-мережеві залежності ізольовані; справжніх листів ці тести не надсилали.
- `pip check`: **No broken requirements found**.
- Запущений сайт: `/auth/login` повертає **HTTP 200** і Google-кнопку.
- Справжній `/auth/google` повертає **HTTP 302 на accounts.google.com**. Discovery звертався до реального Google, без mock.
- Перевірені `response_type=code`, `openid`, непорожні state/nonce, PKCE S256, відповідність client ID конфігурації та відсутність Client Secret у redirect URL. Повний redirect URL не виводився.
- Callback точно **http://127.0.0.1:5050/auth/google/callback**; localhost не використовувався.
- Існуючі тести перевіряють справжню валідацію RSA JWT через Authlib з mock discovery/JWKS/token exchange: signature, issuer, audience, expiry, nonce, state, verified email; також 2FA/blocked, заборону автозв’язування за email та прив’язування link intent до точного state.

Авторизаційне перенаправлення саме по собі не доводить, що Google прийме Client Secret, consent screen і Redirect URI при обміні code на token. **Реальний вхід до кінця ще NOT TESTED**: інвентар доступних браузерів порожній. Нових OAuthIdentity або користувачів під час перевірки реального redirect не створювали.

## Що зробити вручну

1. Відкрити http://127.0.0.1:5050/auth/login й оновити Ctrl+F5.
2. Для нового Google-only акаунта натиснути «Увійти через Google» та завершити вибір Google-акаунта/consent.
3. Для вже наявного локального акаунта з тим самим email спочатку увійти звичайним паролем, відкрити «Безпека», натиснути «Пов’язати Google-акаунт». Автоматичне зв’язування лише за email навмисно заборонене.
4. Якщо ввімкнено 2FA, ввести свіжий TOTP після Google-входу.
5. Якщо Google показує `redirect_uri_mismatch`, перевірити точний URI вище в налаштуваннях Web application client. Для `access_denied` перевірити дозволеного test user/consent; для `invalid_client` перевірити пару Client ID/Secret у `.env` і перезапустити сервер. Значення credentials не надсилати у чат.

Команда локальної перевірки з папки проєкту:

```powershell
.\.venv\Scripts\python -m flask --app run oidc-status
```

Вона створює новий процес. Якщо її результат configured, а старий сайт показує missing, перезапустіть саме процес, що слухає 5050.
