from datetime import datetime, timezone
from flask_login import UserMixin
from .extensions import db


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.Text)
    role = db.Column(db.String(10), nullable=False, default='USER')
    activated = db.Column(db.Boolean, nullable=False, default=False)
    blocked = db.Column(db.Boolean, nullable=False, default=False)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    totp_secret = db.Column(db.Text)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_last_step = db.Column(db.BigInteger, nullable=False, default=-1)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    vehicles = db.relationship('Vehicle', back_populates='owner', cascade='all, delete-orphan')
    tokens = db.relationship('SecurityToken', backref='user', cascade='all, delete-orphan')
    identities = db.relationship('OAuthIdentity', backref='user', cascade='all, delete-orphan')
    __table_args__ = (db.CheckConstraint("role IN ('USER', 'ADMIN')"),)


class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    engine = db.Column(db.String(30), nullable=False)
    mileage = db.Column(db.Integer, nullable=False)
    vin = db.Column(db.String(17))
    owner = db.relationship('User', back_populates='vehicles')
    records = db.relationship('MaintenanceRecord', back_populates='vehicle', cascade='all, delete-orphan')
    __table_args__ = (db.CheckConstraint('mileage >= 0'), db.CheckConstraint('year >= 1886'))


class MaintenanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False, index=True)
    date = db.Column(db.Date, nullable=False)
    work = db.Column(db.Text, nullable=False)
    mileage = db.Column(db.Integer, nullable=False)
    cost = db.Column(db.Numeric(12, 2), nullable=False)
    notes = db.Column(db.Text, nullable=False, default='')
    vehicle = db.relationship('Vehicle', back_populates='records')
    __table_args__ = (db.CheckConstraint('cost >= 0'), db.CheckConstraint('mileage >= 0'))

    @property
    def work_items(self):
        return self.work.splitlines()


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    email = db.Column(db.String(254), nullable=False, index=True)
    ip = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    event = db.Column(db.String(40), nullable=False, default='login')
    created_at = db.Column(db.DateTime, nullable=False, default=now, index=True)

    @property
    def event_label(self):
        return {'login': 'Вхід', 'totp': 'Перевірка 2FA', 'password_reset': 'Зміна пароля',
                '2fa_changed': 'Налаштування 2FA', 'reviewed_failure': 'Невдала спроба (переглянуто)',
                'account_blocked': 'Адміністративне блокування',
                'account_unblocked': 'Адміністративне розблокування'}.get(self.event, 'Подія безпеки')


class SecurityToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    purpose = db.Column(db.String(15), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)


class OAuthIdentity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider = db.Column(db.String(30), nullable=False, default='google')
    subject = db.Column(db.String(255), nullable=False)
    __table_args__ = (db.UniqueConstraint('provider', 'subject'), db.UniqueConstraint('user_id', 'provider'))
