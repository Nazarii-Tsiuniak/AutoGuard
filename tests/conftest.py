import pytest
from cryptography.fernet import Fernet
from autoguard import create_app
from autoguard.extensions import db
from autoguard.models import User
from autoguard.security import hasher

PASSWORD = 'SecureDrive42!'


@pytest.fixture(autouse=True)
def isolated_oauth_clients(monkeypatch):
    """Each test gets its own Authlib registry and cached test credentials."""
    from autoguard.extensions import oauth
    monkeypatch.setattr(oauth, '_clients', {})
    monkeypatch.setattr(oauth, '_registry', {})


@pytest.fixture(autouse=True)
def deny_unmocked_external_services(monkeypatch):
    """Tests must never accidentally send mail or use real external credentials."""
    def denied(*args, **kwargs):
        raise AssertionError('External network disabled in pytest; use explicit mocks or local_http_audit.py.')
    monkeypatch.setattr('smtplib.SMTP', denied)
    monkeypatch.setattr('requests.sessions.Session.request', denied)


@pytest.fixture
def app(tmp_path):
    app = create_app({'TESTING': True, 'PRODUCTION': False, 'SECRET_KEY': 'test-session-key-only',
        'TOTP_ENCRYPTION_KEY': Fernet.generate_key().decode(), 'SQLALCHEMY_DATABASE_URI': 'sqlite://',
        'WTF_CSRF_ENABLED': False, 'RATELIMIT_ENABLED': False, 'MAIL_MODE': 'file',
        'GOOGLE_CLIENT_ID': None, 'GOOGLE_CLIENT_SECRET': None})
    app.instance_path = str(tmp_path)
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(app):
    def make(email='driver@example.com', **kwargs):
        with app.app_context():
            user = User(email=email, name='Водій', activated=True, password_hash=hasher.hash(PASSWORD))
            for key, value in kwargs.items():
                setattr(user, key, value)
            db.session.add(user)
            db.session.commit()
            return user.id
    return make


@pytest.fixture
def login(client):
    return lambda email='driver@example.com', password=PASSWORD: client.post('/auth/login', data={'email': email, 'password': password})
