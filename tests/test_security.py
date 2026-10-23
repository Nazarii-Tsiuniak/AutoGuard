import hashlib
import time
from datetime import timedelta, date
from pathlib import Path
from unittest.mock import Mock
import pyotp
import pytest
import requests
from autoguard.extensions import db, oauth
from autoguard.models import User, Vehicle, MaintenanceRecord, SecurityToken, LoginAttempt, OAuthIdentity, now
from autoguard.forms import RegisterForm
from autoguard.security import hasher, cipher, issue_token, find_token, verify_totp
from conftest import PASSWORD


def registration(**kwargs):
    data = {'email':'new@example.com','name':'Новий водій','password':PASSWORD,'confirm':PASSWORD,'cf-turnstile-response':'test-response'}
    data.update(kwargs)
    return data


@pytest.mark.parametrize('password', ['short', 'lowercase42!', 'UPPERCASE42!', 'NoNumbers!', 'NoSpecial42', 'Ab1!', 'A'*129+'a1!'])
def test_password_policy(app, password):
    with app.test_request_context():
        form = RegisterForm(data=registration(password=password, confirm=password))
        assert not form.validate()
        assert 'password' in form.errors


def test_registration_hash_salt_and_no_admin(app, client, monkeypatch):
    response = Mock()
    response.json.return_value = {'success':True}
    monkeypatch.setattr('autoguard.security.requests.post', Mock(return_value=response))
    assert client.post('/auth/register', data=registration(role='ADMIN')).status_code == 302
    assert client.post('/auth/register', data=registration(email='second@example.com')).status_code == 302
    with app.app_context():
        users = db.session.scalars(db.select(User).order_by(User.id)).all()
        assert users[0].role == 'USER' and not users[0].activated
        assert users[0].password_hash.startswith('$argon2id$')
        assert users[0].password_hash != users[1].password_hash
        assert hasher.verify(users[0].password_hash, PASSWORD)
        assert db.session.scalar(db.select(db.func.count(SecurityToken.id))) == 2
    assert len(list((Path(app.instance_path)/'mail').glob('*.eml'))) == 2


@pytest.mark.parametrize('result', [False, 'network', 'missing'])
def test_captcha_fails_closed(app, client, monkeypatch, result):
    post = Mock(side_effect=requests.Timeout()) if result == 'network' else Mock(return_value=Mock(json=lambda:{'success':False}))
    monkeypatch.setattr('autoguard.security.requests.post', post)
    data = registration()
    if result == 'missing':
        data.pop('cf-turnstile-response')
    assert client.post('/auth/register', data=data).status_code == 200
    with app.app_context():
        assert not db.session.scalar(db.select(User))


def test_activation_single_use_expiry_and_access(app, client, make_user, login):
    uid = make_user(activated=False)
    with app.app_context():
        raw = issue_token(db.session.get(User, uid), 'activate')
        token = find_token(raw, 'activate')
        assert token.token_hash == hashlib.sha256(raw.encode()).hexdigest()
        assert not find_token(raw, 'reset')
    login()
    assert client.get('/garage/').location.endswith('/profile')
    assert client.get('/auth/activate/'+raw).status_code == 200
    with app.app_context():
        assert not db.session.get(User, uid).activated
    assert client.post('/auth/activate/'+raw).status_code == 302
    assert client.post('/auth/activate/'+raw).status_code == 400
    assert client.get('/garage/').status_code == 200
    with app.app_context():
        raw2 = issue_token(db.session.get(User, uid), 'reset')
        find_token(raw2, 'reset').expires_at = now()-timedelta(seconds=1)
        db.session.commit()
        assert find_token(raw2, 'reset') is None


def test_login_logout_generic_failure(app, client, make_user, login):
    uid = make_user()
    known = login(password='wrong').data
    unknown = login(email='unknown@example.com',password='wrong').data
    assert 'Не вдалося увійти'.encode() in known and 'Не вдалося увійти'.encode() in unknown
    assert login().status_code == 302
    assert client.get('/dashboard').status_code == 200
    assert client.post('/auth/logout').status_code == 302
    assert client.get('/dashboard').status_code == 302
    with app.app_context():
        assert db.session.scalar(db.select(LoginAttempt).where(LoginAttempt.user_id==uid,LoginAttempt.success.is_(True)))


def test_lockout_across_ips_and_expiry(app, client, make_user, login):
    make_user()
    for n in range(5):
        client.post('/auth/login', data={'email':'driver@example.com','password':'wrong'}, environ_overrides={'REMOTE_ADDR':f'127.0.0.{n+1}'})
    assert login().status_code == 200
    assert client.get('/dashboard').status_code == 302
    with app.app_context():
        db.session.execute(db.update(LoginAttempt).values(created_at=now()-timedelta(minutes=16)))
        db.session.commit()
    assert login().status_code == 302
    assert client.get('/dashboard').status_code == 200


def test_rbac_block_revokes_and_unblock(app, client, make_user, login):
    uid = make_user()
    admin_id = make_user('admin@example.com',role='ADMIN')
    login()
    assert client.get('/admin').status_code == 403
    assert client.get('/admin/logins').status_code == 403
    assert client.post(f'/admin/users/{uid}/toggle').status_code == 403
    admin = app.test_client()
    admin.post('/auth/login', data={'email':'admin@example.com','password':PASSWORD})
    assert admin.get('/admin?q=driver').status_code == 200
    assert admin.get('/admin/logins').status_code == 200
    assert admin.post(f'/admin/users/{admin_id}/toggle').status_code == 403
    assert admin.post(f'/admin/users/{uid}/toggle').status_code == 302
    assert client.get('/dashboard').status_code == 302
    assert login().status_code == 200
    admin.post(f'/admin/users/{uid}/toggle')
    assert login().status_code == 302


def test_vehicle_crud_idor_statistics(app, client, make_user, login):
    uid = make_user()
    other = make_user('other@example.com')
    with app.app_context():
        vehicle = Vehicle(user_id=other,make='Other',model='Private',year=2020,engine='Бензин',mileage=0)
        db.session.add(vehicle)
        db.session.flush()
        record = MaintenanceRecord(vehicle_id=vehicle.id,date=date.today(),work='Private',cost=100,mileage=0,notes='Secret')
        db.session.add(record)
        db.session.commit()
        vid, rid = vehicle.id, record.id
    login()
    for path in [f'/garage/{vid}',f'/garage/{vid}/edit']:
        assert client.get(path).status_code == 404
        assert client.post(path,data={}).status_code == 404
    assert client.post(f'/garage/{vid}/delete').status_code == 404
    assert client.post(f'/garage/records/{rid}/delete').status_code == 404
    car = {'make':'Toyota','model':'Corolla','year':2021,'engine':'Гібрид','mileage':0,'vin':''}
    assert client.post('/garage/new',data=car).status_code == 302
    with app.app_context():
        owned = db.session.scalar(db.select(Vehicle).where(Vehicle.user_id==uid)).id
    car['model']='Yaris'
    assert client.post(f'/garage/{owned}/edit',data=car).status_code == 302
    assert client.post(f'/garage/{owned}',data={'date':date.today().isoformat(),'work':'Заміна мастила','mileage':2000,'cost':'1200.35','notes':'<script>alert(1)</script>'}).status_code == 302
    page = client.get(f'/garage/{owned}').data
    assert b'&lt;script&gt;' in page and b'<script>alert' not in page
    assert b'1200.35' in client.get('/statistics').data
    assert b'Private' not in client.get('/history').data
    with app.app_context():
        own_rid = db.session.scalar(db.select(MaintenanceRecord).where(MaintenanceRecord.vehicle_id==owned)).id
        assert db.session.get(Vehicle,owned).mileage == 2000
    assert client.post(f'/garage/records/{own_rid}/delete').status_code == 302
    assert client.post(f'/garage/{owned}/delete').status_code == 302
    assert client.get(f'/garage/{owned}').status_code == 404


def test_password_reset_revokes_all_sessions_and_replay(app, client, make_user, login):
    uid = make_user()
    login()
    other_client = app.test_client()
    other_client.post('/auth/login',data={'email':'driver@example.com','password':PASSWORD})
    with app.app_context():
        raw = issue_token(db.session.get(User,uid),'reset')
    assert client.post('/auth/reset/'+raw,data={'password':'bad','confirm':'bad'}).status_code == 200
    assert client.post('/auth/reset/'+raw,data={'password':'ChangedDrive42!','confirm':'ChangedDrive42!'}).status_code == 302
    assert client.post('/auth/reset/'+raw,data={'password':PASSWORD,'confirm':PASSWORD}).status_code == 400
    assert other_client.get('/dashboard').status_code == 302
    assert login().status_code == 200
    assert login(password='ChangedDrive42!').status_code == 302
    with app.app_context():
        assert db.session.scalar(db.select(LoginAttempt).where(LoginAttempt.event=='password_reset'))


def test_totp_encrypted_setup_login_replay_disable(app, client, make_user, login, monkeypatch):
    uid = make_user()
    login()
    assert client.post('/auth/totp/setup').status_code == 302
    assert client.get('/auth/totp/qr').mimetype == 'image/png'
    moment = time.time()
    monkeypatch.setattr('autoguard.security.time.time',lambda:moment)
    with app.app_context():
        user = db.session.get(User,uid)
        secret = cipher().decrypt(user.totp_secret.encode()).decode()
        assert secret != user.totp_secret
    totp = pyotp.TOTP(secret)
    assert client.post('/auth/security',data={'code':totp.at(moment)}).status_code == 302
    client.post('/auth/logout')
    assert login().location.endswith('/two-factor')
    with client.session_transaction() as sess:
        assert '_user_id' not in sess and sess['pending']==uid
    assert client.get('/dashboard').status_code == 302
    assert client.post('/auth/two-factor',data={'code':totp.at(moment)}).status_code == 200
    moment += 30
    assert client.post('/auth/two-factor',data={'code':totp.at(moment)}).status_code == 302
    assert client.get('/dashboard').status_code == 200
    assert client.get('/auth/totp/qr').status_code == 404
    moment += 30
    assert client.post('/auth/security',data={'code':totp.at(moment),'password':PASSWORD}).status_code == 302
    with app.app_context():
        assert not db.session.get(User,uid).totp_enabled
        assert db.session.get(User,uid).totp_secret is None


def test_pending_totp_invalidated_on_password_reset(app,client,make_user,login):
    secret = pyotp.random_base32()
    with app.app_context():
        encrypted = cipher().encrypt(secret.encode()).decode()
    uid = make_user(totp_enabled=True,totp_secret=encrypted)
    login()
    with app.app_context():
        user = db.session.get(User,uid)
        user.session_version += 1
        db.session.commit()
    assert client.post('/auth/two-factor',data={'code':pyotp.TOTP(secret).now()}).location.endswith('/login')


def test_csrf_enforced_and_headers(app, client, make_user):
    app.config['WTF_CSRF_ENABLED']=True
    assert client.post('/auth/register',data=registration()).status_code == 400
    response = client.get('/')
    assert response.headers['X-Frame-Options']=='DENY'
    assert "form-action 'self'" in response.headers['Content-Security-Policy']
    assert response.headers['Cache-Control']=='no-store'


def test_mail_generic_resend_cooldown(app,client,make_user,login):
    make_user(activated=False)
    login()
    client.post('/auth/resend')
    client.post('/auth/resend')
    assert len(list((Path(app.instance_path)/'mail').glob('*.eml')))==1
    known = client.post('/auth/forgot',data={'email':'driver@example.com'},follow_redirects=True)
    unknown = client.post('/auth/forgot',data={'email':'unknown@example.com'},follow_redirects=True)
    message='Якщо обліковий запис існує'.encode()
    assert message in known.data and message in unknown.data


def test_all_authenticated_pages(app,client,make_user,login):
    make_user()
    login()
    for path in ['/dashboard','/profile','/garage/','/garage/new','/history','/statistics','/auth/security','/logins']:
        assert client.get(path).status_code == 200, path


def test_google_unconfigured(client):
    assert client.get('/auth/google').location.endswith('/login')
    assert client.get('/auth/google/callback').status_code == 400


def test_google_no_email_autolinking_and_blocked(app,client,make_user,monkeypatch):
    uid = make_user()
    app.config.update(GOOGLE_CLIENT_ID='mock-id',GOOGLE_CLIENT_SECRET='mock-secret')
    provider = Mock()
    provider.authorize_access_token.return_value={'id_token':'mock-validated-id-token','userinfo':{'sub':'google-sub','email':'driver@example.com','email_verified':True}}
    monkeypatch.setattr(oauth,'google',provider,raising=False)
    assert client.get('/auth/google/callback').status_code == 302
    with app.app_context():
        assert db.session.scalar(db.select(OAuthIdentity)) is None
        db.session.add(OAuthIdentity(user_id=uid,subject='google-sub'))
        user = db.session.get(User,uid)
        user.blocked=True
        db.session.commit()
    client.get('/auth/google/callback')
    assert client.get('/dashboard').status_code == 302


def test_google_respects_second_factor(app,client,make_user,monkeypatch):
    uid=make_user(totp_enabled=True)
    with app.app_context():
        db.session.add(OAuthIdentity(user_id=uid,subject='google-sub'))
        db.session.commit()
    app.config.update(GOOGLE_CLIENT_ID='mock-id',GOOGLE_CLIENT_SECRET='mock-secret')
    provider=Mock()
    provider.authorize_access_token.return_value={'id_token':'mock-validated','userinfo':{'sub':'google-sub','email':'driver@example.com','email_verified':True}}
    monkeypatch.setattr(oauth,'google',provider,raising=False)
    assert client.get('/auth/google/callback').location.endswith('/two-factor')
    assert client.get('/dashboard').status_code==302


def test_admin_cli_validation(app):
    runner=app.test_cli_runner()
    assert runner.invoke(args=['create-admin','--email','bad','--name','Admin','--password',PASSWORD]).exit_code != 0
    result=runner.invoke(args=['create-admin','--email','admin@example.com','--name','Admin','--password',PASSWORD])
    assert result.exit_code==0, result.output
    with app.app_context():
        assert db.session.scalar(db.select(User)).role=='ADMIN'


def test_production_rejects_development_config():
    from autoguard import create_app
    with pytest.raises(RuntimeError):
        create_app({'PRODUCTION':True,'SECRET_KEY':'x'*32,'TOTP_ENCRYPTION_KEY':__import__('cryptography.fernet',fromlist=['Fernet']).Fernet.generate_key().decode()})
