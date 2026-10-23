from datetime import timedelta
from unittest.mock import Mock
import smtplib
import pyotp
import pytest
from flask import redirect
from autoguard.extensions import db, oauth
from autoguard.models import User, Vehicle, MaintenanceRecord, OAuthIdentity, now
from autoguard.security import cipher, issue_token, find_token, send_token


@pytest.mark.parametrize('path',['/profile','/dashboard','/garage/','/garage/new','/history','/statistics','/auth/security','/logins','/admin','/admin/logins'])
def test_anonymous_cannot_read_protected_pages(client,path):
    response=client.get(path)
    assert response.status_code==302 and '/auth/login' in response.location


@pytest.mark.parametrize('purpose,path',[('activate','activate'),('reset','reset')])
def test_expired_token_rejected_by_get_and_post(app,client,make_user,purpose,path):
    uid=make_user(activated=False)
    with app.app_context():
        token=issue_token(db.session.get(User,uid),purpose)
        find_token(token,purpose).expires_at=now()-timedelta(seconds=1)
        db.session.commit()
    assert client.get(f'/auth/{path}/{token}').status_code==400
    assert client.post(f'/auth/{path}/{token}').status_code==400
    assert client.post(f'/auth/{path}/invented-token').status_code==400


def test_login_clears_fixed_anonymous_session(client,make_user,login):
    make_user()
    with client.session_transaction() as state:
        state['attacker_marker']='fixed-anonymous-session'
        state['csrf_token']='fixed-csrf-token'
    assert login().status_code==302
    with client.session_transaction() as state:
        assert 'attacker_marker' not in state and 'csrf_token' not in state
        assert state['authenticated_at']>0


def test_csrf_covers_all_mutation_routes(app,client,make_user,login):
    uid=make_user(role='ADMIN')
    login()
    with app.app_context():
        vehicle=Vehicle(user_id=uid,make='Ford',model='Focus',year=2020,engine='Бензин',mileage=0)
        db.session.add(vehicle)
        db.session.flush()
        record=MaintenanceRecord(vehicle_id=vehicle.id,date=now().date(),work='ТО',mileage=0,cost=1,notes='')
        db.session.add(record)
        db.session.commit()
        vid,rid=vehicle.id,record.id
    app.config['WTF_CSRF_ENABLED']=True
    paths=['/auth/logout','/profile','/auth/resend','/auth/totp/setup','/auth/security','/auth/google/link',
           '/garage/new',f'/garage/{vid}',f'/garage/{vid}/edit',f'/garage/{vid}/delete',
           f'/garage/records/{rid}/edit',f'/garage/records/{rid}/delete',f'/admin/users/{uid}/toggle']
    for path in paths:
        assert client.post(path,data={}).status_code==400,path


def test_sql_injection_login_and_admin_search(app,client,make_user,login):
    make_user(role='ADMIN')
    assert login(email="' OR 1=1 --",password='anything').status_code==200
    assert client.get('/admin').status_code==302
    login()
    for query in ["' OR 1=1 --",'%','_','<script>alert(1)</script>']:
        response=client.get('/admin',query_string={'q':query})
        assert response.status_code==200
        assert b'driver@example.com' not in response.data
        assert b'<script>alert(1)</script>' not in response.data


def test_failed_smtp_preserves_previous_working_token(app,make_user,monkeypatch):
    uid=make_user(activated=False)
    app.config.update(MAIL_MODE='smtp',SMTP_HOST='smtp.example.com')
    with app.test_request_context():
        user=db.session.get(User,uid)
        old=issue_token(user,'activate')
        find_token(old,'activate').created_at=now()-timedelta(minutes=2)
        db.session.commit()
        monkeypatch.setattr('autoguard.security.smtplib.SMTP',Mock(side_effect=smtplib.SMTPAuthenticationError(535,b'mock rejection')))
        assert send_token(user,'activate')=='failed'
        assert find_token(old,'activate') is not None


def test_bad_or_expired_totp_never_authenticates(app,client,make_user,login):
    secret=pyotp.random_base32()
    with app.app_context():
        encrypted=cipher().encrypt(secret.encode()).decode()
    make_user(totp_enabled=True,totp_secret=encrypted)
    assert login().location.endswith('/two-factor')
    valid=pyotp.TOTP(secret).now()
    invalid=str((int(valid)+123456)%1000000).zfill(6)
    assert client.post('/auth/two-factor',data={'code':invalid}).status_code==200
    assert client.post('/auth/two-factor',data={'code':'٠١٢٣٤٥'}).status_code==200
    assert client.get('/dashboard').status_code==302
    with client.session_transaction() as state:
        state['pending_until']=0
    assert client.post('/auth/two-factor',data={'code':valid}).location.endswith('/login')
    with client.session_transaction() as state:
        assert '_user_id' not in state and 'pending' not in state


def test_explicit_google_link_success(app,client,make_user,login,monkeypatch):
    uid=make_user()
    login()
    app.config.update(GOOGLE_CLIENT_ID='mock-id',GOOGLE_CLIENT_SECRET='mock-secret')
    provider=Mock()
    provider.authorize_redirect.return_value=redirect('https://accounts.google.com/auth?state=bound-state')
    provider.authorize_access_token.return_value={'id_token':'mock-validated','userinfo':{'sub':'linked-sub','email':'another-google@example.com','email_verified':True}}
    monkeypatch.setattr(oauth,'google',provider,raising=False)
    client.post('/auth/google/link')
    assert client.get('/auth/google/callback?state=bound-state&code=mock').location.endswith('/security')
    with app.app_context():
        assert db.session.scalar(db.select(OAuthIdentity)).user_id==uid


def test_secure_cookie_and_debug_fail_closed_in_production(app,client,make_user,login):
    make_user()
    app.config.update(PRODUCTION=True,SESSION_COOKIE_SECURE=True)
    response=login()
    assert 'Secure' in response.headers['Set-Cookie']
    assert response.headers['Strict-Transport-Security'].startswith('max-age=')
    app.debug=True
    response=client.get('/')
    assert response.status_code==503 and app.debug is False
    assert b'Traceback' not in response.data and b'Werkzeug Debugger' not in response.data


def test_admin_unlock_keeps_original_failed_events(app,client,make_user,login):
    from autoguard.models import LoginAttempt
    from autoguard.security import locked
    uid=make_user()
    make_user('admin@example.com',role='ADMIN')
    with app.app_context():
        db.session.add_all([LoginAttempt(user_id=uid,email='driver@example.com',ip='127.0.0.1',success=False,event='login') for _ in range(5)])
        db.session.commit()
        assert locked('driver@example.com')
    login(email='admin@example.com')
    client.post(f'/admin/users/{uid}/toggle')
    client.post(f'/admin/users/{uid}/toggle')
    with app.app_context():
        assert not locked('driver@example.com')
        failures=db.session.scalars(db.select(LoginAttempt).where(LoginAttempt.user_id==uid,LoginAttempt.success.is_(False))).all()
        assert len(failures)==5 and all(event.event=='login' for event in failures)
        assert db.session.scalar(db.select(LoginAttempt).where(LoginAttempt.event=='account_unblocked'))


def test_google_insert_conflict_rolls_back_cleanly(app,client,monkeypatch):
    from sqlalchemy.exc import IntegrityError
    app.config.update(GOOGLE_CLIENT_ID='mock-id',GOOGLE_CLIENT_SECRET='mock-secret')
    provider=Mock()
    provider.authorize_access_token.return_value={'id_token':'mock-validated','userinfo':{'sub':'new-sub','email':'new-google@example.com','email_verified':True}}
    monkeypatch.setattr(oauth,'google',provider,raising=False)
    def conflict(*args,**kwargs):
        raise IntegrityError('mock INSERT',{},Exception('simulated unique-key conflict'))
    monkeypatch.setattr(db.session,'flush',conflict)
    assert client.get('/auth/google/callback').status_code==400
    with app.app_context():
        assert db.session.scalar(db.select(User)) is None
