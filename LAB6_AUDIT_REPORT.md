# Аудит AutoGuard: лабораторна робота №6

Дата: **23 жовтня 2026 року**. Перевірено наявний проєкт, без створення нового застосунку. Середовище: Windows, Python 3.13.7, Flask 3.1.3, SQLite. Дизайн, наявні маршрути й користувацькі дані збережено.

Пізніше користувач додав Google credentials. Поточні конфігурація, кнопка та справжній redirect перевірені; повний набір тепер має 98 тестів. Окремий актуальний результат: [GOOGLE_OIDC_CHECK.md](GOOGLE_OIDC_CHECK.md). Нижче збережено факти першого аудиту; повний вхід у Google, як і раніше, не зараховано без ручного проходження.

## Підсумок і методика

**Функції всіх 7 завдань реалізовано. За суворим критерієм завершеної перевірки: 2 завдання PASS, 5 PARTIAL, немає завдань зі статусом FAIL.** PARTIAL означає неповну перевірку зовнішнього сервісу або реального пристрою, а не відсутність локальної реалізації.

- Початковий набір: **52 passed**.
- Перші додаткові регресійні тести: **9 failed, 5 passed**; помилки відтворено до виправлень. Окремо відтворено 2 помилки сесій.
- Підсумковий набір: **90 passed**, командою `python -m pytest -q --tb=short -p no:cacheprovider`.
- Наскрізний прогін `python local_http_audit.py`: **23/23 перевірки PASS** через справжній loopback HTTP, з CSRF, окремою тимчасовою SQLite і тимчасовою файловою поштою. Артефакт: [local-http-audit.json](local-http-audit.json).
- CAPTCHA: у цьому HTTP-прогоні справді викликано Cloudflare Siteverify з **публічними dummy-ключами**, без mock. Це не перевірка розпізнавання людини production-віджетом.
- Gmail: повторно перевірено реальні STARTTLS і SMTP-авторизацію, **без надсилання нових листів**. Раніше користувач повідомив, що листи працюють; це позначено як історичне підтвердження користувача, а не нове незалежне спостереження доставки.
- OIDC: справжня валідація RSA JWT бібліотекою Authlib перевірена з підміненою мережею; зовнішній вхід у Google не виконувався.
- `pip check`: **No broken requirements found**. `node --check autoguard/static/app.js`: успішно.
- `flask --app run db check`: **No new upgrade operations detected**.
- Аудит залежностей: до оновлення — 19 записів про відомі вразливості у 2 пакетах, з дублюванням advisory/alias у відповіді сервісу; після — **No known vulnerabilities found**. Це не твердження про відсутність усіх можливих вразливостей.

Використані лише вигадані тестові акаунти, окрема БД і тимчасова пошта. Pytest за замовчуванням блокує непідмінені зовнішні HTTP/SMTP-запити; тестова фабрика не завантажує `.env`. Робочі паролі, ключі, OAuth-налаштування та поштові credentials не змінювалися. У наскрізному прогоні додатково перевірено незмінність `.env`.

Статуси: **PASS** — виконано й перевірено в указаному обсязі; **PARTIAL** — реалізація є, але приймальна перевірка неповна; **FAIL** — відтворена несправність; **NOT TESTED** — фактичної перевірки не було. Нижче результати наведені **після виправлень**.

## 1. Реєстрація та авторизація — PASS, 3/3

| Вимога | Статус | Доказ у коді | Результат тестування | Що потрібно виправити |
|---|---|---|---|---|
| Реєстрація з валідними даними | PASS | `auth.register`, `/auth/register` | `test_registration_hash_salt_and_no_admin`; HTTP `live_dummy_captcha_registration=true` | Нічого в локальній логіці |
| Мінімум 8 символів, велика й мала літери, цифра, спецсимвол; відмова слабким паролям | PASS | `forms.password_policy`, `RegisterForm`, `ResetForm` | 7 негативних варіантів `test_password_policy`; позитивна реєстрація | Нічого |
| Захищений хеш і різна сіль | PASS | `security.hasher`, `verify_password`; `User.password_hash` | `test_registration_hash_salt_and_no_admin`: `$argon2id$`, різні хеші однакового пароля, успішна перевірка | Нічого |
| Коректний пароль відкриває профіль; неправильний відхиляється | PASS | `auth.login`, `begin_login`, `main.profile` | `test_login_logout_generic_failure`; HTTP `dashboard_authenticated`, `new_password_accepted` | Нічого |
| Вихід та відмова повтору скопійованого cookie | PASS | `auth.logout`: підвищення `session_version`, `session.clear()` | `test_logout_revokes_copied_cookie`; HTTP `logout`, `copied_cookie_revoked` | Виправлено під час аудиту |
| Захищені сторінки недоступні анонімно | PASS | `login_required`, `active_required`, `admin_required` | `test_anonymous_cannot_read_protected_pages` — 10 маршрутів | Нічого |
| Фіксація сесії та абсолютний timeout | PASS | `complete_login`, `create_app.load_user`, `authenticated_at` | `test_login_clears_fixed_anonymous_session`, `test_absolute_session_timeout_is_not_renewed_by_cookie_changes` | Виправлено timeout |

Вихід тепер відкликає всі попередні сесії цього акаунта, включно зі скопійованими cookie. Це свідомий компроміс у межах наявної моделі `session_version`, без додавання нової серверної таблиці сесій. Після оновлення старі сесії без `authenticated_at` вимагають повторного входу.

## 2. CAPTCHA — PARTIAL, орієнтовно 1.5/2

| Вимога | Статус | Доказ у коді | Результат тестування | Що потрібно виправити |
|---|---|---|---|---|
| Віджет на реєстрації | PASS | `templates/form.html`: `.cf-turnstile`; `base.html`: зовнішній скрипт | Сторінка реєстрації повертає HTML із віджетом; наскрізна реєстрація працює | Візуальне відображення потребує браузера |
| Серверна перевірка, успіх і відмова | PASS | `security.captcha_valid`, `auth.register` | `test_captcha_fails_closed`; HTTP-прогін із реальним Siteverify | Нічого в локальній логіці |
| Прямий POST без токена, timeout і некоректний JSON | PASS | `captcha_valid`: token length, timeout, `isinstance(result, dict)` | `test_captcha_fails_closed`, `test_malformed_captcha_response_fails_closed` | Некоректний JSON виправлено |
| Тестові ключі не обходять Siteverify | PASS | Dummy-ключі лише змінюють конфігурацію; локального `return True` немає | Реальний Cloudflare-виклик у `local_http_audit.py` | Нічого |
| Production не приймає dummy-ключі; hostname/action перевіряються | PASS | Production-guard фабрики; `captcha_valid` | `test_production_rejects_development_config`, `test_production_captcha_hostname_action` | Для deployment потрібні справжні ключі |
| Захист від ботів справжнім production-віджетом | NOT TESTED | Поточна локальна конфігурація має офіційні dummy-ключі | Browser challenge і реальні site/secret keys не перевірено | Налаштувати widget для домену й пройти вручну |

Dummy-віджет навмисно дає передбачуваний результат. Він придатний для лабораторної демонстрації інтеграції, але не доводить реальний захист від ботів.

## 3. Активація акаунта — PARTIAL, орієнтовно 1.5/2

| Вимога | Статус | Доказ у коді | Результат тестування | Що потрібно виправити |
|---|---|---|---|---|
| Випадковий токен; у БД лише SHA-256 | PASS | `issue_token`: `secrets.token_urlsafe(32)`; `SecurityToken.token_hash` | `test_activation_single_use_expiry_and_access`, `test_reissuing_token_revokes_previous` | Нічого |
| 30-хвилинний строк і одноразовість | PASS | `find_token`, атомарний `consume_token` | `test_expired_token_rejected_by_get_and_post`; HTTP `activation_replay_rejected` | Нічого |
| Активація посиланням із CSRF-підтвердженням | PASS | `/auth/activate/<token>` | HTTP `activation_get_and_post=true`; GET сам не активує | Нічого |
| Профіль показує статус, неактивний акаунт не відкриває гараж | PASS | `profile.html`, `active_required` | `test_activation_single_use_expiry_and_access`; HTTP `unactivated_garage_restricted` | Нічого |
| Локальний поштовий режим | PASS | `send_token`, `MAIL_MODE=file` | Реальні тимчасові `.eml` у HTTP-прогоні; токен із них активує тестовий акаунт | Не вважати файлову пошту SMTP-доставкою |
| Повторне надсилання та SMTP-помилки | PASS | `/auth/resend`, результати `sent/file/cooldown/failed` | `test_mail_generic_resend_cooldown`, `test_smtp_failure_is_not_reported_as_sent`, `test_failed_smtp_preserves_previous_working_token` | Виправлено неправдиве повідомлення й втрату попереднього токена при відмові SMTP |
| Реальна доставка листа активації у Gmail | PARTIAL | `send_token`: STARTTLS, SMTP login, `send_message` | SMTP-авторизація PASS; користувач раніше підтвердив роботу листів. Нове отримання в Inbox у цьому аудиті не перевірялося | Перед відео зареєструвати окремий демонстраційний акаунт і показати лист |

SMTP-прийняття повідомлення, навіть коли воно є, не гарантує Inbox: доставку та «Спам» перевіряють окремо. Під час поточного аудиту справжні листи не надсилалися.

## 4. Brute Force, адміністрування та RBAC — PASS, 2/2

| Вимога | Статус | Доказ у коді | Результат тестування | Що потрібно виправити |
|---|---|---|---|---|
| Логування email, IP, UTC-часу й результату | PASS | `LoginAttempt`, `security.audit`, `logins.html` | `test_login_logout_generic_failure`; HTTP `admin_users_and_journal` | Нічого |
| 5 невдалих спроб/15 хвилин; правильний пароль теж блокується | PASS | `security.locked`, `auth.login` | `test_lockout_across_ips_and_expiry`; HTTP `lockout_rejects_correct_password` | Нічого |
| Після спливу вікна вхід відновлюється | PASS | Порівняння `LoginAttempt.created_at` із cutoff | `test_lockout_across_ips_and_expiry` переносить тільки тестові дати | Нічого |
| IP-ліміт та неможливість обійти account lock зміною IP | PASS | Flask-Limiter; DB-лічильник за email | `test_actual_ip_and_totp_rate_limits`, `test_lockout_across_ips_and_expiry` | Для production потрібне спільне сховище; локально memory |
| Список, пошук, статуси, журнал і лічильник адміністратора | PASS | `/admin`, `/admin/logins`, ORM-запити `main.admin` | `test_rbac_block_revokes_and_unblock`; HTTP-журнал; `test_sql_injection_login_and_admin_search` | Нічого |
| Блокування/розблокування та відкликання попередніх сесій | PASS | `main.toggle`, `User.blocked`, `session_version` | `test_rbac_block_revokes_and_unblock` | Нічого |
| Розблокування не переписує старі спроби | PASS | Новий audit-event `account_unblocked`, cutoff у `locked` | `test_admin_unlock_keeps_original_failed_events` | Виправлено зміну історичних event-полів |
| USER не викликає ADMIN-маршрути; ADMIN не задається реєстрацією | PASS | `admin_required`, `RegisterForm`; CLI `create-admin` | `test_rbac_block_revokes_and_unblock`, `test_registration_hash_salt_and_no_admin`, `test_admin_cli_validation` | Нічого |
| Профіль, авто й записи ізольовані; IDOR відхиляється | PASS | `current_user`; `owned_vehicle`; owner predicate запису ТО | `test_vehicle_crud_idor_statistics`, `test_edit_maintenance_owner_only_preserves_single_total` | Нічого |

Блокування має ковзне вікно: додаткові невдалі спроби можуть продовжувати обмеження. Для перевірки спливу вікна необхідно припинити спроби, а не безперервно натискати «Увійти».

## 5. Двофакторна автентифікація — PARTIAL, орієнтовно 1.5/2

| Вимога | Статус | Доказ у коді | Результат тестування | Що потрібно виправити |
|---|---|---|---|---|
| Створення секрету й QR у профілі | PASS | `/auth/totp/setup`, `/auth/totp/qr`, PyOTP provisioning URI | `test_totp_encrypted_setup_login_replay_disable`: PNG 200 | Нічого в генерації |
| Секрет зашифровано | PASS | `cipher`, Fernet, `User.totp_secret` | Тест порівнює ciphertext із розшифрованим секретом; значення не публікуються | Нічого |
| Увімкнення підтверджується кодом, наступний вхід має окремий крок | PASS | `auth.security`, `begin_login`, `/auth/two-factor` | `test_totp_encrypted_setup_login_replay_disable` | Нічого |
| До другого фактора повної сесії немає | PASS | `pending`, `pending_version`, `pending_until`; `complete_login` лише після успіху | `test_bad_or_expired_totp_never_authenticates`, `test_pending_totp_invalidated_on_password_reset` | Нічого |
| Неправильний, повторний, прострочений і Unicode-код відхиляються | PASS | ASCII-формат, крок TOTP, atomic update, ліміти | `test_non_ascii_totp_cannot_crash`, `test_bad_or_expired_totp_never_authenticates`, replay-тест, реальні rate-limit тести | Unicode-збій виправлено |
| Безпечне вимкнення, помилковий пароль не витрачає код | PASS | `auth.security`: password check перед `verify_totp` | `test_wrong_disable_password_does_not_consume_totp` та повний TOTP-тест | Виправлено порядок перевірок |
| Сканування QR реальним Google/Microsoft Authenticator на телефоні | NOT TESTED | Стандартний `otpauth://` QR з PyOTP | Фізичний телефон під час аудиту не використовувався | Перед відео перевірити на демонстраційному акаунті |

Функціональні TOTP-перевірки використовують справжній алгоритм PyOTP та згенеровані тестові секрети; це не заглушка «прийняти будь-який код». Дозволене вікно ±1 крок по 30 секунд; вже прийнятий крок повторно не приймається.

## 6. OpenID Connect — PARTIAL, орієнтовно 1/2

| Вимога | Статус | Доказ у коді | Результат тестування | Що потрібно виправити |
|---|---|---|---|---|
| Справжній Authorization Code OIDC, discovery й PKCE | PASS | Authlib registration; `/auth/google`, callback | `test_real_authlib_oidc_validation_with_mock_network`: redirect, code, PKCE verifier | Потрібні реальні credentials для повного входу |
| State, nonce, підпис, issuer, audience, expiry, verified email | PASS | Authlib `authorize_access_token`; перевірка userinfo | 8 варіантів JWT-тесту: valid/state/nonce/signature/audience/issuer/expired/unverified | Нічого в перевіреній локальній логіці |
| Стабільний `sub`, без автоприв’язування лише за email | PASS | `OAuthIdentity(provider, subject)`, callback | `test_google_no_email_autolinking_and_blocked` | Нічого |
| Явне зв’язування з локальним акаунтом, прив’язане до конкретного state | PASS | `/auth/google/link`, `google_link.state` | `test_explicit_google_link_success`, `test_google_link_intent_bound_to_authorization_state` | Виправлено змішування паралельних OAuth-потоків |
| Блокування та 2FA діють і для Google | PASS | callback → `locked`, `blocked`, `begin_login` | `test_google_respects_second_factor`, `test_google_no_email_autolinking_and_blocked` | Нічого |
| Помилка конфлікту INSERT обробляється транзакційно | PASS | `flush` і `commit` у спільному `try/except IntegrityError` | `test_google_insert_conflict_rolls_back_cleanly` симулює unique-key conflict, перевіряє 400 і rollback | Реальне паралельне навантаження окремо не тестувалося |
| Реальний вхід у Google | NOT TESTED | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` відсутні | UI повідомляє про відсутність конфігурації; `test_google_unconfigured` PASS | Consent screen, тестові користувачі, client credentials, точний Redirect URI |

Локальний callback: **`http://127.0.0.1:5050/auth/google/callback`**. У production — той самий шлях на HTTPS-домені. Credentials не додавалися й не змінювалися. У JWT-тестах підмінено discovery/JWKS/token exchange, а криптографічна та claim-валідація Authlib справжня. Це не доказ реальної згоди Google або робочого Redirect URI.

## 7. Відновлення пароля — PARTIAL, орієнтовно 1.5/2

| Вимога | Статус | Доказ у коді | Результат тестування | Що потрібно виправити |
|---|---|---|---|---|
| Форма й лист з посиланням | PASS | `/auth/forgot`, `send_token`, `/auth/reset/<token>` | HTTP `reset_requested`, справжній тимчасовий `.eml`, mock SMTP STARTTLS | Реальну Inbox-доставку перевірити окремо |
| Випадковий токен, хеш у БД, 30 хвилин | PASS | `issue_token`, `SecurityToken`, `find_token` | Токенові тести та `test_expired_token_rejected_by_get_and_post` | Нічого |
| Прострочений, вигаданий і повторний токен не працюють | PASS | `find_token`, `consume_token` | HTTP `reset_replay_rejected`; токенові негативні тести | Нічого |
| Складність нового пароля; новий працює, старий ні | PASS | `ResetForm`, `hasher.hash`, `auth.reset` | HTTP `password_reset`, `old_password_rejected`, `new_password_accepted` | Нічого |
| Інші сесії та незавершена 2FA відкликаються, подія логується | PASS | `session_version`, `audit(...password_reset)` | `test_password_reset_revokes_all_sessions_and_replay`, `test_pending_totp_invalidated_on_password_reset` | Нічого |
| Однаковий текст і HTTP-результат для невідомого email; ліміти | PASS | Нейтральне повідомлення `forgot`, IP/account limiter | `test_mail_generic_resend_cooldown`, код обмежувачів | Залишається різниця часу через синхронний SMTP, див. ризики |
| Реальний Gmail-лист відновлення та перехід із Inbox | NOT TESTED | Той самий перевірений SMTP transport | Під час поточного аудиту не надсилали листи й не змінювали реальний пароль | Продемонструвати на окремому тестовому акаунті |

## Додаткові функції AutoGuard

| Функція | Статус | Доказ |
|---|---|---|
| Додавання/редагування/видалення власного авто | PASS | `test_vehicle_crud_idor_statistics`, HTTP `vehicle_created`, `vehicle_deleted` |
| Пошукові марки/моделі, залежність моделей від марки | PARTIAL | Каталог і JS перевірено, HTML поля присутні; реальну поведінку native datalist у браузері не перевірено |
| Ручний рік, дата, пробіг, вартість без спінерів | PASS | `test_manual_inputs_have_no_number_or_date_controls`; HTTP введення дати `ДД.ММ.РРРР` |
| Декілька робіт у одному записі, ручні назви, ліміти | PASS | `test_multiple_works_one_record_one_total`, `test_invalid_multiple_works_keep_user_input`; HTTP `multiple_works_created` |
| Редагування/видалення ТО | PASS | Новий `garage.edit_record`; owner-only тести; HTTP `maintenance_edited`, `record_deleted` |
| Decimal-суми, статистика без подвійного обліку | PASS | HTTP `statistics_single_total`, тести точних сум і оновленого запису |
| Старі записи, FK та CHECK-обмеження | PASS | `test_migration_preserves_old_records_and_constraints`, `db check` |
| Навігація, форми, кнопки на рівні HTML/HTTP | PASS | Тести сторінок, CSRF та наскрізний HTTP-прогін |
| Десктопний/мобільний вигляд, клавіатура, відкриття меню та datalist | NOT TESTED | Браузерний інвентар порожній; раніше IAB повернув `Browser is not available: iab` |

## Виявлені проблеми та виправлення

| Пріоритет | Проблема до аудиту | Виправлення | Доказ після виправлення |
|---|---|---|---|
| P1 | Повтор скопійованого auth-cookie після виходу | Серверне відкликання через `session_version` | Pytest replay + справжній HTTP replay |
| P1 | Cookie-зміни могли подовжувати заявлені 30 хвилин | Окремий `authenticated_at`, server-side age check | `test_absolute_session_timeout_is_not_renewed_by_cookie_changes` |
| P1 | Відомі advisory у `cryptography` та `pip` | Оновлено до **cryptography 50.0.2**, **pip 26.2.2** у `.venv`; `requirements.txt` вимагає cryptography>=50,<51 | [dependency-audit-before.json](dependency-audit-before.json), [dependency-audit-after.json](dependency-audit-after.json) |
| P1 | Умовне змішування наміру link із callback іншого OAuth-потоку | Link intent прив’язано до точного state | `test_google_link_intent_bound_to_authorization_state` |
| P2 | Unicode-цифри TOTP спричиняли TypeError/500 | ASCII-перевірка на формі й у verify helper | `test_non_ascii_totp_cannot_crash` |
| P2 | Невірний пароль при вимкненні 2FA витрачав код | Пароль перевіряється до атомарного споживання TOTP | `test_wrong_disable_password_does_not_consume_totp` |
| P2 | Неочікуваний JSON Siteverify спричиняв 500 | Перевірка типу й відмова за замовчуванням | 4 варіанти malformed CAPTCHA response |
| P2 | `sNaN` спричиняв збій, дробові копійки мовчки округлювалися | Звичайний числовий формат, до 2 десяткових знаків | 6 варіантів `test_invalid_money_is_validation_error` |
| P2 | UI повідомляв про надсилання після відмови SMTP | Явні результати й чесне повідомлення в авторизованому профілі | `test_smtp_failure_is_not_reported_as_sent` |
| P2 | Невдале надсилання відкликало попереднє робоче посилання | Токенова транзакція відкочується при SMTP/file помилці | `test_failed_smtp_preserves_previous_working_token` |
| P2 | Адмін-розблокування переписувало вид старих невдалих подій | Окремий append-only event, cutoff без переписування рядків | `test_admin_unlock_keeps_original_failed_events` |
| P2 | Відсутнє редагування ТО | Owner-scoped GET/POST, багаторобоча форма, кнопка | Pytest + HTTP edit |
| P2 | Частина OIDC INSERT могла виконатися поза обробкою IntegrityError | `add/flush/commit` у одному try | `test_google_insert_conflict_rolls_back_cleanly`; concurrency load окремо не тестовано |
| P2 | Випадково увімкнений debug у production міг підвищувати ризик витоку | Startup guard та fail-closed 503 без debugger | `test_secure_cookie_and_debug_fail_closed_in_production` |
| P3 | `.eml` незручно читати в редакторі через Base64 body | Нові листи мають явний UTF-8/8bit body | HTTP mail parsing; старі листи не переписано |
| P3 | Pytest сканував runtime/cache-папки та міг звернутися до реальних сервісів | `pytest.ini`, блокування зовнішніх викликів, skip dotenv в TESTING | Повний прогін 90 тестів |

## Перевірка атак і залишкові обмеження

- **SQL Injection:** login payload і admin search з лапками/`%`/`_` не обходять права та не розширюють результати. Використовується ORM, user input не інтерполюється в SQL.
- **XSS:** примітки, назви робіт і пошук екрануються; CSP без inline scripts. Тести перевіряють збережений і відображений payload.
- **CSRF:** негативні POST-перевірки для 13 маршрутів зміни стану; справжні токени в наскрізному HTTP-прогоні. Logout лише POST.
- **IDOR/RBAC:** перевірки власника застосовано до читання, зміни й видалення авто/ТО; роль контролюється на сервері.
- **Session fixation/replay:** pre-login marker очищується; logout, password reset, block і зміна 2FA відкликають попередню версію; абсолютний строк контролюється окремо від cookie timestamp.
- **2FA/CAPTCHA/rate limit bypass:** негативні й позитивні тести, DB-account lock незалежний від IP; production-guard забороняє dummy CAPTCHA й memory limits.
- **Токени:** SHA-256 у БД, random256-bit token, purpose/expiry, атомарне споживання; Waitress без access log, Flask logger приховує URL-токени.
- **Секрети:** Argon2id; Fernet-секрети; локальні ключі й `.env` виключені з Git. Значення не виводилися у звіти.
- **Cookies:** HttpOnly, SameSite=Lax, Secure у production; HSTS і CSP перевірені.
- **Git:** репозиторій відсутній. [source-audit.json](source-audit.json) не виявив очевидних ключів у source; це обмежений pattern scan. Історію й staged-файли перевірити неможливо до `git init`/створення комітів. Push не виконувався.

**Залишкові P2/P3 ризики перед публічним deployment:**

1. Синхронне надсилання SMTP може створювати часову різницю між існуючим і неіснуючим email у відновленні/реєстрації, хоча текст і статус однакові. Для усунення потрібна надійна черга листів/worker і вирівнювання часу обробки. Транзакція токена також утримується під час SMTP; навантажувальні/мережеві відмови довше timeout окремо не тестувалися.
2. У локальному режимі rate limits зберігаються в memory і скидаються при перезапуску; account lock залишається в SQLite. Для production guard вимагає спільне storage, але Redis/проксі/HTTPS тут не розгорталися.
3. Зберігання `.env` та encryption key захищене правами Windows і виключенням із репозиторію, а не окремим vault. Ротацію ключів, ACL, резервні копії й політику зберігання аудиту треба налаштувати для deployment.
4. Browser/accessibility/mobile QA, production CAPTCHA, фізичний Authenticator, реальний OIDC і незалежне отримання нових Gmail-листів залишаються ручними приймальними перевірками.

Архітектуру не переписували заради черги або deployment: ці обмеження прозоро зафіксовані. Незалежний pentest і навантажувальний аудит не проводилися.

## Оцінка та готовність

| Завдання | Підсумковий статус | Консервативна оцінка |
|---|---|---|
| 1. Реєстрація/вхід | PASS | 3/3 |
| 2. CAPTCHA | PARTIAL | 1.5/2 |
| 3. Активація | PARTIAL | 1.5/2 |
| 4. Brute Force/RBAC/admin | PASS | 2/2 |
| 5. 2FA | PARTIAL | 1.5/2 |
| 6. OIDC | PARTIAL | 1/2 |
| 7. Відновлення | PARTIAL | 1.5/2 |
| **Разом** | **2 PASS, 5 PARTIAL** | **≈12/15** |

Це інженерна оцінка готовності доказів, а не оцінка викладача: офіційного правила для часткових балів у наданій умові немає. Реалізація охоплює 15/15 за функціональним обсягом; неперевірені зовнішні й ручні сценарії не зараховано повністю.

**Відеозахист:** backend і локальний сценарій готові, але повний ролик ще потребує реального OIDC, отримання демонстраційних листів, фізичного TOTP та ручної браузерної перевірки. Покроковий список: [VIDEO_DEMO_CHECKLIST.md](VIDEO_DEMO_CHECKLIST.md).

**GitHub:** source можна готувати до публікації після перевірки staged-файлів; публікація не виконувалась. Створювати репозиторій слід у `lab6/autoguard`, щоб не захопити інші лабораторні. Перед push виключити `.env`, `instance/`, `.venv`, резервні БД і пошту та перевірити історію, якщо вона з’явиться.

## Відтворення

```powershell
# З папки lab6\autoguard
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest -q --tb=short -p no:cacheprovider
.\.venv\Scripts\python local_http_audit.py
.\.venv\Scripts\python -m pip check
.\.venv\Scripts\python -m pip_audit --progress-spinner off
.\.venv\Scripts\python -m flask --app run db check
node --check autoguard\static\app.js
```

`local_http_audit.py` робить один зовнішній запит до тестового Cloudflare Siteverify; справжніх SMTP-листів не надсилає, користувацьку БД не використовує. Не вимикайте CSRF/2FA/CAPTCHA на робочому сервері для демонстрації тестів.

Офіційні довідки, використані для інтерпретації: [OWASP — Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [Cloudflare — testing keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/), [Authlib — Flask OIDC](https://docs.authlib.org/en/latest/oauth2/client/web/flask.html).
