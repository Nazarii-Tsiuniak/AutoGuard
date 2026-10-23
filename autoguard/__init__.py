import os
import secrets
import logging
import re
import time
from datetime import timedelta
from pathlib import Path
import click
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, render_template, session, request, abort
from flask_login import current_user, logout_user
from sqlalchemy import event
from sqlalchemy.engine import Engine
from .extensions import db, login_manager, csrf, limiter, migrate, oauth


class TokenURLFilter(logging.Filter):
    def filter(self, record):
        record.msg = re.sub(r'(/auth/(?:activate|reset)/)[A-Za-z0-9_-]+', r'\1[REDACTED]', record.getMessage())
        record.args = ()
        return True


@event.listens_for(Engine, 'connect')
def sqlite_foreign_keys(connection, _):
    if connection.__class__.__module__.startswith('sqlite3'):
        connection.execute('PRAGMA foreign_keys=ON')


def create_app(test_config=None):
    root = Path(__file__).resolve().parent.parent
    if not (test_config and test_config.get('TESTING')):
        load_dotenv(root / '.env', override=False)
    app = Flask(__name__, instance_path=str(root / 'instance'))
    app.logger.addFilter(TokenURLFilter())
    production = os.getenv('APP_ENV', 'development') == 'production'
    app.config.from_mapping(
        PRODUCTION=production, SECRET_KEY=os.getenv('SECRET_KEY'),
        TOTP_ENCRYPTION_KEY=os.getenv('TOTP_ENCRYPTION_KEY'),
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///autoguard.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=production, PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=False, MAX_CONTENT_LENGTH=64*1024,
        WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_STORAGE_URI=os.getenv('RATELIMIT_STORAGE_URI', 'memory://'),
        TURNSTILE_SITE_KEY=os.getenv('TURNSTILE_SITE_KEY', '1x00000000000000000000AA'),
        TURNSTILE_SECRET_KEY=os.getenv('TURNSTILE_SECRET_KEY', '1x0000000000000000000000000000000AA'),
        TURNSTILE_HOSTNAME=os.getenv('TURNSTILE_HOSTNAME', ''),
        MAIL_MODE=os.getenv('MAIL_MODE', 'file'), SMTP_HOST=os.getenv('SMTP_HOST'),
        SMTP_PORT=int(os.getenv('SMTP_PORT', '587')), SMTP_USER=os.getenv('SMTP_USER'),
        SMTP_PASSWORD=os.getenv('SMTP_PASSWORD'), MAIL_FROM=os.getenv('MAIL_FROM', 'autoguard@localhost'),
        PUBLIC_BASE_URL=os.getenv('PUBLIC_BASE_URL', 'http://127.0.0.1:5050'),
        GOOGLE_CLIENT_ID=os.getenv('GOOGLE_CLIENT_ID'), GOOGLE_CLIENT_SECRET=os.getenv('GOOGLE_CLIENT_SECRET'),
    )
    if test_config:
        app.config.update(test_config)
    for key in ('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'):
        app.config[key] = (app.config.get(key) or '').strip()
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    for key, factory in [('SECRET_KEY', lambda: secrets.token_hex(32)), ('TOTP_ENCRYPTION_KEY', lambda: Fernet.generate_key().decode())]:
        if not app.config[key]:
            if app.config['PRODUCTION']:
                raise RuntimeError(f'Production requires {key}')
            path = Path(app.instance_path) / key.lower()
            try:
                with path.open('x', encoding='ascii') as stream:
                    stream.write(factory())
            except FileExistsError:
                pass
            app.config[key] = path.read_text(encoding='ascii').strip()
    Fernet(app.config['TOTP_ENCRYPTION_KEY'].encode())
    if app.config['PRODUCTION']:
        if app.config.get('DEBUG') or os.getenv('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes'):
            raise RuntimeError('Debug is forbidden in production')
        if (len(app.config['SECRET_KEY']) < 32 or app.config['MAIL_MODE'] != 'smtp'
                or not app.config['SMTP_HOST'] or not app.config['PUBLIC_BASE_URL'].startswith('https://')
                or not app.config['TURNSTILE_SITE_KEY'] or not app.config['TURNSTILE_SECRET_KEY']
                or app.config['TURNSTILE_SITE_KEY'].startswith(('1x', '2x', '3x'))
                or app.config['TURNSTILE_SECRET_KEY'].startswith(('1x', '2x', '3x'))
                or not app.config['TURNSTILE_HOSTNAME']
                or app.config['RATELIMIT_STORAGE_URI'] == 'memory://'):
            raise RuntimeError('Production requires real CAPTCHA keys/hostname, SMTP, HTTPS, strong keys and shared rate-limit storage.')
    for extension in (db, login_manager, csrf, limiter, migrate, oauth):
        if extension is migrate:
            extension.init_app(app, db, render_as_batch=True)
        else:
            extension.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Увійдіть, щоб продовжити.'
    login_manager.session_protection = 'strong'
    if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
        oauth.register('google', client_id=app.config['GOOGLE_CLIENT_ID'], client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                       server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                       client_kwargs={'scope': 'openid email profile', 'code_challenge_method': 'S256'})
    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        user = db.session.get(User, int(user_id)) if user_id.isdigit() else None
        authenticated_at = session.get('authenticated_at', 0)
        valid_age = (isinstance(authenticated_at, (int, float)) and
                     0 <= time.time() - authenticated_at <= app.permanent_session_lifetime.total_seconds())
        if user and not user.blocked and session.get('version') == user.session_version and valid_age:
            return user
        return None

    @app.before_request
    def production_debug_guard():
        if app.config['PRODUCTION'] and app.debug:
            app.debug = False
            abort(503)

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = ("default-src 'self'; script-src 'self' https://challenges.cloudflare.com; "
            "style-src 'self'; img-src 'self' data:; frame-src https://challenges.cloudflare.com; "
            "connect-src 'self' https://challenges.cloudflare.com; base-uri 'self'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'")
        if app.config['PRODUCTION']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    from .auth import bp as auth_bp
    from .garage import bp as garage_bp
    from .main import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(garage_bp)
    app.register_blueprint(main_bp)

    @app.context_processor
    def common():
        from .forms import BaseForm
        return {'action_form': BaseForm(), 'google_enabled': bool(app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET'])}

    for code in (400, 403, 404, 413, 429, 500, 503):
        def error_page(error, status=code):
            if status == 500:
                db.session.rollback()
            return render_template('error.html', code=status), status
        app.register_error_handler(code, error_page)

    @app.cli.command('create-admin')
    @click.option('--email', prompt=True)
    @click.option('--name', prompt=True)
    @click.password_option(confirmation_prompt=True)
    def create_admin(email, name, password):
        from .forms import RegisterForm
        from .security import hasher
        form = RegisterForm(data={'email': email, 'name': name, 'password': password, 'confirm': password}, meta={'csrf': False})
        if not form.validate():
            raise click.ClickException(str(form.errors))
        if db.session.scalar(db.select(User).where(User.email == email.strip().lower())):
            raise click.ClickException('Користувач уже існує; роль не змінено.')
        db.session.add(User(email=email.strip().lower(), name=name, password_hash=hasher.hash(password), role='ADMIN', activated=True))
        db.session.commit()
        click.echo('Адміністратора створено.')

    @app.cli.command('list-mail')
    def list_mail():
        if app.config['PRODUCTION'] or app.config['MAIL_MODE'] != 'file':
            raise click.ClickException('Файлова пошта доступна лише локально.')
        for path in sorted((Path(app.instance_path) / 'mail').glob('*.eml')):
            click.echo(path.read_text(encoding='utf-8'))

    @app.cli.command('oidc-status')
    def oidc_status():
        """Show only credential presence, never values or authorization URLs."""
        for key in ('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'):
            click.echo(f"{key}: {'configured' if app.config[key] else 'missing'}")
        enabled = bool(app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET'])
        registered = enabled and oauth.create_client('google') is not None
        click.echo(f"Authlib Google: {'configured' if registered else 'missing'}")
        local_callback = app.config['PUBLIC_BASE_URL'].rstrip('/') == 'http://127.0.0.1:5050'
        click.echo(f"Local callback base: {'configured' if local_callback else 'missing'}")

    return app
