import hashlib
import secrets
import smtplib
import ssl
import time
from datetime import timedelta
from email.message import EmailMessage
from pathlib import Path
from functools import wraps
import pyotp
import requests
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError
from cryptography.fernet import Fernet
from flask import current_app, request, session, abort, redirect, url_for
from flask_login import current_user, login_required, login_user
from .extensions import db
from .models import User, SecurityToken, LoginAttempt, now

hasher = PasswordHasher(type=Type.ID)
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(32))


def verify_password(user, password):
    try:
        result = hasher.verify(user.password_hash if user and user.password_hash else DUMMY_HASH, password)
        return bool(result and user and user.password_hash)
    except (VerificationError, InvalidHashError):
        return False


def active_required(function):
    @wraps(function)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.activated:
            return redirect(url_for('main.profile'))
        return function(*args, **kwargs)
    return wrapped


def admin_required(function):
    @wraps(function)
    @active_required
    def wrapped(*args, **kwargs):
        if current_user.role != 'ADMIN':
            abort(403)
        return function(*args, **kwargs)
    return wrapped


def audit(email, success, user=None, event='login'):
    db.session.add(LoginAttempt(email=email, user_id=user.id if user else None, ip=request.remote_addr or 'unknown', success=success, event=event))
    db.session.commit()


def locked(email):
    window_start = now() - timedelta(minutes=15)
    unblocked_at = db.session.scalar(db.select(db.func.max(LoginAttempt.created_at)).where(
        LoginAttempt.email == email, LoginAttempt.event == 'account_unblocked', LoginAttempt.created_at >= window_start))
    cutoff = max(window_start, unblocked_at) if unblocked_at else window_start
    return db.session.scalar(db.select(db.func.count(LoginAttempt.id)).where(
        LoginAttempt.email == email, LoginAttempt.success.is_(False),
        LoginAttempt.event.in_(['login', 'totp']), LoginAttempt.created_at > cutoff)) >= 5


def complete_login(user):
    session.clear()
    session['version'] = user.session_version
    session['authenticated_at'] = time.time()
    session.permanent = True
    login_user(user, remember=False, fresh=True)
    audit(user.email, True, user)


def begin_login(user):
    session.clear()
    if user.totp_enabled:
        session['pending'] = user.id
        session['pending_version'] = user.session_version
        session['pending_until'] = time.time() + 300
        return redirect(url_for('auth.two_factor'))
    complete_login(user)
    return redirect(url_for('main.dashboard'))


def cipher():
    return Fernet(current_app.config['TOTP_ENCRYPTION_KEY'].encode())


def verify_totp(user, code):
    if not user.totp_secret or not code or len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    secret = cipher().decrypt(user.totp_secret.encode()).decode()
    totp = pyotp.TOTP(secret)
    step = int(time.time()) // 30
    for candidate in (step, step-1, step+1):
        if candidate > user.totp_last_step and secrets.compare_digest(totp.at(candidate*30), code):
            result = db.session.execute(db.update(User).where(User.id == user.id, User.totp_last_step < candidate).values(totp_last_step=candidate))
            db.session.commit()
            return result.rowcount == 1
    return False


def issue_token(user, purpose, commit=True):
    db.session.execute(db.update(SecurityToken).where(SecurityToken.user_id == user.id,
        SecurityToken.purpose == purpose, SecurityToken.used_at.is_(None)).values(used_at=now()))
    raw = secrets.token_urlsafe(32)
    db.session.add(SecurityToken(user_id=user.id, purpose=purpose, token_hash=hashlib.sha256(raw.encode()).hexdigest(), expires_at=now()+timedelta(minutes=30)))
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return raw


def find_token(raw, purpose):
    return db.session.scalar(db.select(SecurityToken).where(SecurityToken.token_hash == hashlib.sha256(raw.encode()).hexdigest(),
        SecurityToken.purpose == purpose, SecurityToken.used_at.is_(None), SecurityToken.expires_at > now()))


def consume_token(token):
    result = db.session.execute(db.update(SecurityToken).where(SecurityToken.id == token.id, SecurityToken.used_at.is_(None),
        SecurityToken.expires_at > now()).values(used_at=now()))
    return result.rowcount == 1


def send_token(user, purpose):
    recent = db.session.scalar(db.select(SecurityToken).where(SecurityToken.user_id == user.id, SecurityToken.purpose == purpose,
        SecurityToken.created_at > now()-timedelta(minutes=1)))
    if recent:
        return 'cooldown'
    raw = issue_token(user, purpose, commit=False)
    endpoint = 'auth.activate' if purpose == 'activate' else 'auth.reset'
    link = current_app.config['PUBLIC_BASE_URL'].rstrip('/') + url_for(endpoint, token=raw)
    message = EmailMessage()
    message['From'] = current_app.config['MAIL_FROM']
    message['To'] = user.email
    message['Subject'] = 'AutoGuard — ' + ('Активація облікового запису' if purpose == 'activate' else 'Відновлення пароля')
    message.set_content(f'Перейдіть за посиланням (діє 30 хвилин):\n{link}\nЯкщо ви не робили запит, проігноруйте лист.', cte='8bit')
    try:
        if current_app.config['MAIL_MODE'] == 'file' and not current_app.config['PRODUCTION']:
            directory = Path(current_app.instance_path) / 'mail'
            directory.mkdir(exist_ok=True)
            (directory / f'{secrets.token_hex(12)}.eml').write_text(message.as_string(), encoding='utf-8')
            db.session.commit()
            return 'file'
        with smtplib.SMTP(current_app.config['SMTP_HOST'], current_app.config['SMTP_PORT'], timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if current_app.config['SMTP_USER']:
                smtp.login(current_app.config['SMTP_USER'], current_app.config['SMTP_PASSWORD'])
            smtp.send_message(message)
        db.session.commit()
        return 'sent'
    except (OSError, smtplib.SMTPException):
        db.session.rollback()
        current_app.logger.error('SMTP delivery failed; no credentials or message content logged.')
        return 'failed'


def captcha_valid(token):
    if not token or len(token) > 2048:
        return False
    try:
        response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
            'secret': current_app.config['TURNSTILE_SECRET_KEY'], 'response': token,
            'remoteip': request.remote_addr}, timeout=8)
        response.raise_for_status()
        result = response.json()
        return isinstance(result, dict) and result.get('success') is True and (not current_app.config['PRODUCTION'] or
            (result.get('hostname') == current_app.config['TURNSTILE_HOSTNAME'] and result.get('action') == 'register'))
    except (requests.RequestException, ValueError):
        return False
