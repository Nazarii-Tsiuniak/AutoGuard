from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import Mock
import smtplib
import pytest
import pyotp
from werkzeug.datastructures import MultiDict
from autoguard.extensions import db, oauth
from autoguard.models import User, Vehicle, MaintenanceRecord, LoginAttempt, now
from autoguard.security import cipher, verify_totp, send_token, find_token, issue_token
from conftest import PASSWORD


@pytest.mark.parametrize('value',['NaN','sNaN','Infinity','-Infinity','1.999','1e999999'])
def test_invalid_money_is_validation_error(app,client,make_user,login,value):
    uid=make_user()
    login()
    with app.app_context():
        car=Vehicle(user_id=uid,make='Toyota',model='Corolla',year=2021,engine='Гібрид',mileage=0)
        db.session.add(car)
        db.session.commit()
        vid=car.id
    response=client.post(f'/garage/{vid}',data={'date':date.today().isoformat(),'work':'ТО','mileage':'0','cost':value})
    assert response.status_code==200
    with app.app_context():
        assert db.session.scalar(db.select(MaintenanceRecord)) is None


@pytest.mark.parametrize('payload',[[],None,'unexpected string',{'success':'true'}])
def test_malformed_captcha_response_fails_closed(app,client,monkeypatch,payload):
    response=Mock()
    response.json.return_value=payload
    monkeypatch.setattr('autoguard.security.requests.post',Mock(return_value=response))
    response=client.post('/auth/register',data={'email':'new@example.com','name':'Driver','password':PASSWORD,'confirm':PASSWORD,'cf-turnstile-response':'test-token'})
    assert response.status_code==200
    with app.app_context():
        assert db.session.scalar(db.select(User)) is None


def test_non_ascii_totp_cannot_crash(app,make_user):
    secret=pyotp.random_base32()
    with app.app_context():
        encrypted=cipher().encrypt(secret.encode()).decode()
    uid=make_user(totp_enabled=True,totp_secret=encrypted)
    with app.app_context():
        assert verify_totp(db.session.get(User,uid),'٠١٢٣٤٥') is False


def test_wrong_disable_password_does_not_consume_totp(app,client,make_user,login):
    uid=make_user()
    login()
    secret=pyotp.random_base32()
    with app.app_context():
        user=db.session.get(User,uid)
        user.totp_secret=cipher().encrypt(secret.encode()).decode()
        user.totp_enabled=True
        db.session.commit()
    code=pyotp.TOTP(secret).now()
    assert client.post('/auth/security',data={'code':code,'password':'wrong'}).status_code==200
    with app.app_context():
        assert db.session.get(User,uid).totp_last_step==-1
    assert client.post('/auth/security',data={'code':code,'password':PASSWORD}).status_code==302


def test_smtp_failure_is_not_reported_as_sent(app,client,make_user,login,monkeypatch):
    uid=make_user(activated=False)
    login()
    app.config.update(MAIL_MODE='smtp',SMTP_HOST='smtp.example.com')
    monkeypatch.setattr('autoguard.security.smtplib.SMTP',Mock(side_effect=smtplib.SMTPServerDisconnected()))
    response=client.post('/auth/resend',follow_redirects=True)
    assert 'Не вдалося надіслати'.encode() in response.data
    with app.test_request_context():
        assert send_token(db.session.get(User,uid),'reset')=='failed'


def test_edit_maintenance_owner_only_preserves_single_total(app,client,make_user,login):
    uid=make_user()
    other=make_user('other@example.com')
    with app.app_context():
        car=Vehicle(user_id=uid,make='Toyota',model='Corolla',year=2021,engine='Гібрид',mileage=100)
        foreign=Vehicle(user_id=other,make='Other',model='Private',year=2020,engine='Бензин',mileage=0)
        db.session.add_all([car,foreign])
        db.session.flush()
        record=MaintenanceRecord(vehicle_id=car.id,date=date.today(),work='Old work',mileage=100,cost=10,notes='Old note')
        hidden=MaintenanceRecord(vehicle_id=foreign.id,date=date.today(),work='Private',mileage=0,cost=999,notes='')
        db.session.add_all([record,hidden])
        db.session.commit()
        rid,hidden_id=record.id,hidden.id
    login()
    assert client.get(f'/garage/records/{rid}/edit').status_code==200
    data=MultiDict([('work','First updated work'),('work','My second work'),('date',date.today().strftime('%d.%m.%Y')),('mileage','150'),('cost','250,50'),('notes','Updated')])
    assert client.post(f'/garage/records/{rid}/edit',data=data).status_code==302
    assert client.get(f'/garage/records/{hidden_id}/edit').status_code==404
    assert client.post(f'/garage/records/{hidden_id}/edit',data=data).status_code==404
    with app.app_context():
        record=db.session.get(MaintenanceRecord,rid)
        assert record.work_items==['First updated work','My second work']
        assert record.cost==Decimal('250.50') and record.notes=='Updated'
        assert record.vehicle.mileage==150
        assert db.session.scalar(db.select(db.func.count(MaintenanceRecord.id)))==2
    assert b'250.50' in client.get('/statistics').data


def test_logout_revokes_copied_cookie(app,client,make_user,login):
    make_user()
    login()
    cookie=client.get_cookie(app.config['SESSION_COOKIE_NAME']).value
    copy=app.test_client()
    copy.set_cookie(app.config['SESSION_COOKIE_NAME'],cookie)
    assert copy.get('/dashboard').status_code==200
    client.post('/auth/logout')
    assert copy.get('/dashboard').status_code==302


def test_absolute_session_timeout_is_not_renewed_by_cookie_changes(app,client,make_user,login):
    import time
    make_user()
    login()
    with client.session_transaction() as state:
        state['authenticated_at']=time.time()-1801
        state['_flashes']=[('info','A session change must not extend authentication')]
    assert client.get('/dashboard').status_code==302


def test_google_link_intent_bound_to_authorization_state(app,client,make_user,login,monkeypatch):
    make_user()
    login()
    app.config.update(GOOGLE_CLIENT_ID='mock-client',GOOGLE_CLIENT_SECRET='mock-secret')
    from flask import redirect
    provider=Mock()
    provider.authorize_redirect.return_value=redirect('https://accounts.google.com/o/oauth2/auth?state=expected-link-state')
    provider.authorize_access_token.return_value={'id_token':'mock','userinfo':{'sub':'subject','email':'google@example.com','email_verified':True}}
    monkeypatch.setattr(oauth,'google',provider,raising=False)
    assert client.post('/auth/google/link').status_code==302
    with client.session_transaction() as state:
        assert state['google_link']['state']=='expected-link-state'
    assert client.get('/auth/google/callback?code=mock&state=other-flow').status_code==400
    provider.authorize_access_token.assert_not_called()
