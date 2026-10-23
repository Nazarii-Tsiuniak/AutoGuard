import time
from urllib.parse import urlparse, parse_qs
from io import BytesIO
import pyotp
import qrcode
from authlib.integrations.base_client.errors import OAuthError
from joserfc.errors import JoseError
from requests.exceptions import RequestException
from sqlalchemy.exc import IntegrityError
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, abort, send_file
from flask_login import login_required, current_user, logout_user
from .extensions import db, limiter, oauth
from .models import User, OAuthIdentity, SecurityToken, now
from .forms import RegisterForm, LoginForm, EmailForm, ResetForm, BaseForm, CodeForm, DisableForm
from .security import (hasher, verify_password, captcha_valid, send_token, find_token, consume_token,
                       locked, audit, begin_login, complete_login, cipher, verify_totp, active_required)

bp = Blueprint('auth', __name__, url_prefix='/auth')
FAILURE = 'Не вдалося увійти. Перевірте дані або спробуйте через 15 хвилин.'


@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per hour', methods=['POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if not captcha_valid(request.form.get('cf-turnstile-response')):
            flash('Перевірка CAPTCHA не пройдена. Спробуйте ще раз.', 'danger')
        else:
            email = form.email.data.strip().lower()
            user = db.session.scalar(db.select(User).where(User.email == email))
            if not user:
                user = User(email=email, name=form.name.data.strip(), password_hash=hasher.hash(form.password.data))
                db.session.add(user)
                try:
                    db.session.commit()
                    send_token(user, 'activate')
                except IntegrityError:
                    db.session.rollback()
            flash('Запит опрацьовано. Якщо адресу можна зареєструвати, перевірте пошту. За відсутності листа увійдіть і повторіть запит у профілі.', 'info')
            return redirect(url_for('auth.login'))
    return render_template('form.html', form=form, title='Створіть обліковий запис', subtitle='Ваш гараж починається тут.', kind='register')


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('20 per 15 minutes', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = db.session.scalar(db.select(User).where(User.email == email))
        valid = verify_password(user, form.password.data)
        if locked(email) or not valid or user.blocked:
            audit(email, False, user)
            flash(FAILURE, 'danger')
        else:
            if hasher.check_needs_rehash(user.password_hash):
                user.password_hash = hasher.hash(form.password.data)
                db.session.commit()
            return begin_login(user)
    return render_template('form.html', form=form, title='З поверненням', subtitle='Увійдіть до свого автомобільного простору.', kind='login')


@bp.post('/logout')
@login_required
def logout():
    # Revoke previously copied signed cookies as well as clearing this browser.
    current_user.session_version += 1
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for('main.home'))


@bp.route('/activate/<token>', methods=['GET', 'POST'])
def activate(token):
    item = find_token(token, 'activate')
    if not item:
        abort(400)
    form = BaseForm()
    if form.validate_on_submit():
        if not consume_token(item):
            abort(400)
        item.user.activated = True
        db.session.commit()
        flash('Обліковий запис активовано. Можете увійти.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('form.html', form=form, title='Підтвердьте вашу пошту', subtitle='Натисніть «Зберегти», щоб активувати обліковий запис.')


@bp.post('/resend')
@login_required
@limiter.limit('3 per hour')
def resend():
    result = None
    if not current_user.activated:
        result = send_token(current_user, 'activate')
    if result == 'failed':
        flash('Не вдалося надіслати лист. Перевірте налаштування пошти або спробуйте пізніше.', 'danger')
    elif result == 'cooldown':
        flash('Лист уже запитано. Зачекайте щонайменше хвилину перед повторною спробою.', 'info')
    elif result == 'file':
        flash('Тестовий лист збережено в локальній папці instance/mail; справжнього надсилання немає.', 'info')
    elif result == 'sent':
        flash('Поштовий сервер прийняв лист активації. Перевірте вхідні та «Спам».', 'success')
    else:
        flash('Ваш обліковий запис уже активовано.', 'info')
    return redirect(url_for('main.profile'))


@bp.route('/forgot', methods=['GET', 'POST'])
@limiter.limit('5 per hour', methods=['POST'])
@limiter.limit('3 per hour', key_func=lambda: request.form.get('email', '').strip().lower(), methods=['POST'])
def forgot():
    form = EmailForm()
    if form.validate_on_submit():
        user = db.session.scalar(db.select(User).where(User.email == form.email.data.strip().lower()))
        if user and not user.blocked:
            send_token(user, 'reset')
        flash('Якщо обліковий запис існує, ви отримаєте інструкцію на пошту. Якщо лист не з’явився, перевірте «Спам» або повторіть запит пізніше.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('form.html', form=form, title='Відновлення пароля', subtitle='Надішлемо посилання для встановлення нового пароля.')


@bp.route('/reset/<token>', methods=['GET', 'POST'])
@limiter.limit('10 per hour', methods=['POST'])
def reset(token):
    item = find_token(token, 'reset')
    if not item or item.user.blocked:
        abort(400)
    form = ResetForm()
    if form.validate_on_submit():
        if not consume_token(item):
            abort(400)
        user = item.user
        user.password_hash = hasher.hash(form.password.data)
        user.session_version += 1
        db.session.execute(db.update(SecurityToken).where(SecurityToken.user_id == user.id, SecurityToken.purpose == 'reset',
            SecurityToken.used_at.is_(None)).values(used_at=now()))
        db.session.commit()
        audit(user.email, True, user, 'password_reset')
        logout_user()
        session.clear()
        flash('Пароль оновлено. Попередні сесії завершено.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('form.html', form=form, title='Новий пароль', subtitle='Оберіть надійний пароль для AutoGuard.')


@bp.route('/two-factor', methods=['GET', 'POST'])
@limiter.limit('5 per 5 minutes', methods=['POST'])
def two_factor():
    user = db.session.get(User, session.get('pending')) if session.get('pending') else None
    if (not user or user.blocked or not user.totp_enabled or session.get('pending_until', 0) < time.time()
            or session.get('pending_version') != user.session_version):
        session.clear()
        return redirect(url_for('auth.login'))
    form = CodeForm()
    if form.validate_on_submit():
        if not locked(user.email) and verify_totp(user, form.code.data):
            complete_login(user)
            return redirect(url_for('main.dashboard'))
        audit(user.email, False, user, 'totp')
        flash(FAILURE, 'danger')
    return render_template('form.html', form=form, title='Другий рівень захисту', subtitle='Введіть код із застосунку автентифікатора.')


@bp.route('/security', methods=['GET', 'POST'])
@active_required
@limiter.limit('10 per 5 minutes', methods=['POST'])
def security():
    form = DisableForm()
    if form.validate_on_submit():
        user = current_user._get_current_object()
        if (not locked(user.email)
                and (not user.totp_enabled or not user.password_hash or verify_password(user, form.password.data or ''))
                and verify_totp(user, form.code.data)):
            user.totp_enabled = not user.totp_enabled
            if not user.totp_enabled:
                user.totp_secret = None
                user.totp_last_step = -1
            user.session_version += 1
            db.session.commit()
            session['version'] = user.session_version
            audit(user.email, True, user, '2fa_changed')
            flash('Налаштування двофакторної автентифікації збережено.', 'success')
            return redirect(url_for('auth.security'))
        audit(user.email, False, user, 'totp')
        flash('Перевірте код і поточний пароль.', 'danger')
    return render_template('security.html', form=form)


@bp.post('/totp/setup')
@active_required
@limiter.limit('5 per hour')
def totp_setup():
    if not current_user.totp_enabled:
        current_user.totp_secret = cipher().encrypt(pyotp.random_base32().encode()).decode()
        current_user.totp_last_step = -1
        db.session.commit()
    return redirect(url_for('auth.security'))


@bp.get('/totp/qr')
@active_required
def totp_qr():
    if current_user.totp_enabled or not current_user.totp_secret:
        abort(404)
    secret = cipher().decrypt(current_user.totp_secret.encode()).decode()
    image = qrcode.make(pyotp.TOTP(secret).provisioning_uri(current_user.email, issuer_name='AutoGuard'))
    stream = BytesIO()
    image.save(stream, format='PNG')
    stream.seek(0)
    return send_file(stream, mimetype='image/png')


@bp.get('/google')
@limiter.limit('20 per hour')
def google():
    if not current_app.config['GOOGLE_CLIENT_ID'] or not current_app.config['GOOGLE_CLIENT_SECRET']:
        flash('Вхід через Google ще не налаштовано.', 'info')
        return redirect(url_for('auth.login'))
    session.pop('google_link', None)
    callback = current_app.config['PUBLIC_BASE_URL'].rstrip('/') + url_for('auth.google_callback')
    try:
        return oauth.google.authorize_redirect(callback)
    except (OAuthError, RequestException):
        flash('Не вдалося з’єднатися з Google. Спробуйте пізніше.', 'danger')
        return redirect(url_for('auth.login'))


@bp.post('/google/link')
@active_required
def google_link():
    if not current_app.config['GOOGLE_CLIENT_ID'] or not current_app.config['GOOGLE_CLIENT_SECRET']:
        abort(400)
    callback = current_app.config['PUBLIC_BASE_URL'].rstrip('/') + url_for('auth.google_callback')
    try:
        response = oauth.google.authorize_redirect(callback, prompt='select_account')
    except (OAuthError, RequestException):
        session.pop('google_link', None)
        flash('Не вдалося з’єднатися з Google. Спробуйте пізніше.', 'danger')
        return redirect(url_for('auth.security'))
    state = parse_qs(urlparse(response.location).query).get('state', [None])[0]
    if not state:
        abort(400)
    session['google_link'] = {'id': current_user.id, 'version': current_user.session_version,
                              'expires': time.time()+300, 'state': state}
    return response


@bp.get('/google/callback')
@limiter.limit('20 per hour')
def google_callback():
    if not current_app.config['GOOGLE_CLIENT_ID'] or not current_app.config['GOOGLE_CLIENT_SECRET']:
        abort(400)
    linking = session.pop('google_link', None)
    if linking and request.args.get('state') != linking.get('state'):
        abort(400)
    try:
        token = oauth.google.authorize_access_token()
        # Authlib validates state, nonce, signature, issuer, audience and expiry.
        info = token.get('userinfo')
        if not token.get('id_token') or not info or not info.get('sub') or info.get('email_verified') is not True:
            raise ValueError('Invalid verified identity')
    except (OAuthError, JoseError, RequestException, ValueError, KeyError):
        flash('Google не підтвердив вхід. Спробуйте ще раз.', 'danger')
        return redirect(url_for('auth.login'))
    identity = db.session.scalar(db.select(OAuthIdentity).where(OAuthIdentity.provider == 'google', OAuthIdentity.subject == info['sub']))
    if linking:
        if (not current_user.is_authenticated or current_user.id != linking['id'] or not current_user.activated
                or current_user.session_version != linking['version'] or linking['expires'] < time.time()):
            abort(403)
        if identity or current_user.identities:
            flash('Google-акаунт уже пов’язано. Зміни не внесено.', 'warning')
        else:
            db.session.add(OAuthIdentity(user_id=current_user.id, subject=info['sub']))
            try:
                db.session.commit()
                flash('Google-акаунт пов’язано.', 'success')
            except IntegrityError:
                db.session.rollback()
                flash('Не вдалося пов’язати Google-акаунт.', 'danger')
        return redirect(url_for('auth.security'))
    if identity:
        user = identity.user
    else:
        email = info.get('email', '').strip().lower()
        if not email or len(email) > 254 or db.session.scalar(db.select(User).where(User.email == email)):
            flash('Увійдіть до локального профілю та пов’яжіть Google у налаштуваннях безпеки.', 'info')
            return redirect(url_for('auth.login'))
        user = User(email=email, name=str(info.get('name') or 'Водій')[:80], activated=True)
        try:
            db.session.add(user)
            db.session.flush()
            db.session.add(OAuthIdentity(user_id=user.id, subject=info['sub']))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            abort(400)
    if user.blocked or locked(user.email):
        audit(user.email, False, user)
        flash(FAILURE, 'danger')
        return redirect(url_for('auth.login'))
    return begin_login(user)
