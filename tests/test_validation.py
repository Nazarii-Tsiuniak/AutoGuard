from datetime import date, timedelta
from autoguard.extensions import db
from autoguard.models import Vehicle, SecurityToken, User
from autoguard.security import issue_token, find_token


def test_vehicle_validation_and_service_cost(app,client,make_user,login):
    make_user()
    login()
    valid={'make':'Skoda','model':'Octavia','year':2020,'engine':'Бензин','mileage':100,'vin':''}
    for change in [{'year':1800},{'mileage':-1},{'vin':'INVALID'},{'engine':'unknown'},{'make':''}]:
        assert client.post('/garage/new',data=valid|change).status_code==200
    with app.app_context():
        assert db.session.scalar(db.select(Vehicle)) is None
    client.post('/garage/new',data=valid)
    with app.app_context():
        vid=db.session.scalar(db.select(Vehicle)).id
    service={'date':date.today().isoformat(),'work':'Перевірка','mileage':100,'cost':'20.10','notes':''}
    for change in [{'cost':'-0.01'},{'mileage':-1},{'date':(date.today()+timedelta(days=1)).isoformat()}]:
        assert client.post(f'/garage/{vid}',data=service|change).status_code==200
    assert b'0.00' in client.get('/statistics').data


def test_reissuing_token_revokes_previous(app,make_user):
    uid=make_user()
    with app.app_context():
        user=db.session.get(User,uid)
        old=issue_token(user,'activate')
        new=issue_token(user,'activate')
        assert find_token(old,'activate') is None
        assert find_token(new,'activate')
        assert db.session.scalar(db.select(db.func.count(SecurityToken.id)))==2


def test_session_cookie_flags_and_admin_secrets_absent(app,client,make_user,login):
    make_user(role='ADMIN')
    response=login()
    cookie=response.headers.get('Set-Cookie','')
    assert 'HttpOnly' in cookie and 'SameSite=Lax' in cookie
    page=client.get('/admin').data
    assert b'$argon2id$' not in page and b'totp_secret' not in page and b'token_hash' not in page


def test_error_logs_redact_token_urls(app,caplog):
    app.logger.error('Exception on %s', '/auth/reset/do-not-log-this-token')
    assert 'do-not-log-this-token' not in caplog.text
    assert '/auth/reset/[REDACTED]' in caplog.text
