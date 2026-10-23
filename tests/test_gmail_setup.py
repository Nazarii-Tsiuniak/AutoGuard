from dotenv import dotenv_values
import pytest
from configure_gmail import configure_gmail


def test_gmail_setup_preserves_settings_and_normalizes_password(tmp_path):
    env = tmp_path / '.env'
    env.write_text('PORT=5050\nPUBLIC_BASE_URL=http://127.0.0.1:5050\nMAIL_MODE=file\n', encoding='utf-8')
    configure_gmail(env, ' sender@gmail.com ', 'abcd efgh ijkl mnop')
    result = dotenv_values(env)
    assert result['SMTP_HOST'] == 'smtp.gmail.com'
    assert result['SMTP_PORT'] == '587'
    assert result['SMTP_USER'] == result['MAIL_FROM'] == 'sender@gmail.com'
    assert result['SMTP_PASSWORD'] == 'abcdefghijklmnop'
    assert result['MAIL_MODE'] == 'smtp'
    assert result['PORT'] == '5050'
    assert result['PUBLIC_BASE_URL'] == 'http://127.0.0.1:5050'
    configure_gmail(env, 'second@gmail.com', 'ponmlkjihgfedcba')
    assert env.read_text(encoding='utf-8').count('SMTP_USER=') == 1


@pytest.mark.parametrize('address,password', [('bad-email','abcdefghijklmnop'),('sender@gmail.com','short'),('sender@gmail.com','a'*17)])
def test_invalid_gmail_setup_does_not_change_env(tmp_path,address,password):
    env = tmp_path / '.env'
    env.write_text('MAIL_MODE=file\n',encoding='utf-8')
    with pytest.raises(ValueError):
        configure_gmail(env,address,password)
    assert env.read_text(encoding='utf-8') == 'MAIL_MODE=file\n'
