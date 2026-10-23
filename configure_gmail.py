"""Local Gmail SMTP setup. Run in your own terminal; never paste credentials into chat."""
from getpass import getpass
from pathlib import Path
from dotenv import set_key
from email_validator import validate_email, EmailNotValidError


def configure_gmail(env_path, address, app_password):
    """Validate before writing; preserve unrelated .env settings."""
    address = validate_email(address.strip(), check_deliverability=False).normalized
    password = app_password.replace(' ', '').strip()
    if len(password) != 16 or not password.isascii() or not password.isalnum():
        raise ValueError('Потрібний 16-символьний пароль застосунку Google, а не звичайний пароль Gmail.')
    values = {
        'SMTP_HOST': 'smtp.gmail.com', 'SMTP_PORT': '587',
        'SMTP_USER': address, 'SMTP_PASSWORD': password, 'MAIL_FROM': address,
    }
    for key, value in values.items():
        set_key(str(env_path), key, value)
    # Enable real delivery only after credentials have been entered and saved.
    set_key(str(env_path), 'MAIL_MODE', 'smtp')


def main():
    print('Налаштування Gmail для AutoGuard. Дані зберігаються тільки в локальному .env.')
    print('Потрібні двоетапна перевірка Google та окремий пароль застосунку AutoGuard.')
    print('Створити пароль: https://myaccount.google.com/apppasswords')
    try:
        address = input('Адреса Gmail (відправник): ')
        password = getpass('Пароль застосунку Google (введення приховане): ')
        configure_gmail(Path(__file__).resolve().parent / '.env', address, password)
    except (ValueError, EmailNotValidError) as error:
        print(f'Налаштування не збережено: {error}')
        return 1
    except (EOFError, KeyboardInterrupt):
        print('\nСкасовано. Налаштування не змінено.')
        return 1
    except OSError:
        print('Не вдалося записати .env. Перевірте права доступу. Дані не виводяться.')
        return 1
    print('SMTP Gmail налаштовано: smtp.gmail.com:587, STARTTLS.')
    print('Перезапустіть AutoGuard, відкрийте профіль і натисніть «Надіслати лист повторно».')
    print('З’єднання та доставку ще не перевірено. Якщо лист не видно, перевірте папку «Спам».')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
