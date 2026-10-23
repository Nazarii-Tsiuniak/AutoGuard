import re
import time
from urllib.parse import urlparse, parse_qs
from unittest.mock import Mock
import pytest
from cryptography.fernet import Fernet
from joserfc import jwt
from joserfc.jwk import RSAKey
from autoguard import create_app
from autoguard.extensions import db, oauth
from autoguard.models import User
from autoguard.security import captcha_valid, send_token
from conftest import PASSWORD


def test_csrf_valid_login_and_post_only_logout(app,client,make_user):
    make_user()
    app.config['WTF_CSRF_ENABLED'] = True
    response = client.get('/auth/login')
    csrf = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', response.data).group(1).decode()
    assert client.post('/auth/login',data={'email':'driver@example.com','password':PASSWORD,'csrf_token':csrf}).status_code == 302
    assert client.get('/auth/logout').status_code == 405
    assert client.post('/auth/logout').status_code == 400
    response = client.get('/profile')
    csrf = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', response.data).group(1).decode()
    assert client.post('/auth/logout',data={'csrf_token':csrf}).status_code == 302
    assert client.get('/dashboard').status_code == 302


def test_actual_ip_and_totp_rate_limits():
    app = create_app({'TESTING':True,'PRODUCTION':False,'SECRET_KEY':'rate-limit-test',
        'TOTP_ENCRYPTION_KEY':Fernet.generate_key().decode(), 'SQLALCHEMY_DATABASE_URI':'sqlite://',
        'WTF_CSRF_ENABLED':False,'RATELIMIT_ENABLED':True,'RATELIMIT_STORAGE_URI':'memory://'})
    client=app.test_client()
    # Invalid form: no credentials or DB writes; requests still consume IP limits.
    for _ in range(20):
        assert client.post('/auth/login',data={}).status_code==200
    assert client.post('/auth/login',data={}).status_code==429
    for _ in range(5):
        assert client.post('/auth/two-factor',data={}).status_code==302
    assert client.post('/auth/two-factor',data={}).status_code==429


def test_production_captcha_hostname_action(app,monkeypatch):
    app.config['PRODUCTION']=True
    app.config['TURNSTILE_HOSTNAME']='garage.example.com'
    response=Mock()
    post=Mock(return_value=response)
    monkeypatch.setattr('autoguard.security.requests.post',post)
    with app.test_request_context():
        response.json.return_value={'success':True,'hostname':'evil.example.com','action':'register'}
        assert not captcha_valid('a-token')
        response.json.return_value={'success':True,'hostname':'garage.example.com','action':'login'}
        assert not captcha_valid('a-token')
        response.json.return_value={'success':True,'hostname':'garage.example.com','action':'register'}
        assert captcha_valid('a-token')
    assert post.call_args.kwargs['timeout']==8


def test_smtp_starttls_delivery_mock(app,make_user,monkeypatch):
    uid=make_user()
    smtp=Mock()
    smtp.__enter__=Mock(return_value=smtp)
    smtp.__exit__=Mock(return_value=False)
    constructor=Mock(return_value=smtp)
    monkeypatch.setattr('autoguard.security.smtplib.SMTP',constructor)
    app.config.update(MAIL_MODE='smtp',SMTP_HOST='smtp.example.com',SMTP_USER='mock-user',SMTP_PASSWORD='mock-only')
    with app.test_request_context():
        send_token(db.session.get(User,uid),'activate')
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with('mock-user','mock-only')
    message=smtp.send_message.call_args.args[0]
    assert '/auth/activate/' in message.get_content()
    assert message['To']=='driver@example.com'


@pytest.mark.parametrize('flaw',['valid','state','nonce','signature','audience','issuer','expired','unverified'])
def test_real_authlib_oidc_validation_with_mock_network(app,client,monkeypatch,flaw):
    app.config.update(GOOGLE_CLIENT_ID='oidc-test-client',GOOGLE_CLIENT_SECRET='oidc-test-secret')
    oauth.register('google',overwrite=True,client_id='oidc-test-client',client_secret='oidc-test-secret',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope':'openid email profile','code_challenge_method':'S256'})
    # Real Authlib client and JWT verification. Only discovery, JWKS and token exchange are mocked.
    with app.app_context():
        provider=oauth.create_client('google')
    key=RSAKey.generate_key(2048,parameters={'kid':'test-key'})
    metadata={'issuer':'https://accounts.google.com','authorization_endpoint':'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint':'https://oauth2.googleapis.com/token','jwks_uri':'https://www.googleapis.com/oauth2/v3/certs',
        'id_token_signing_alg_values_supported':['RS256']}
    monkeypatch.setattr(provider,'load_server_metadata',lambda:metadata)
    monkeypatch.setattr(provider,'fetch_jwk_set',lambda **kwargs:{'keys':[key.as_dict(private=False)]})
    response=client.get('/auth/google')
    params=parse_qs(urlparse(response.location).query)
    assert params['response_type']==['code']
    assert params['nonce'] and params['state'] and params['code_challenge_method']==['S256']
    claims={'iss':'https://accounts.google.com','aud':'oidc-test-client','sub':'oidc-unique-sub',
        'email':'googleuser@example.com','email_verified':True,'name':'Google Driver',
        'iat':int(time.time()),'exp':int(time.time())+300,'nonce':params['nonce'][0]}
    if flaw=='nonce': claims['nonce']='wrong-nonce'
    if flaw=='audience': claims['aud']='another-client'
    if flaw=='issuer': claims['iss']='https://attacker.example.com'
    if flaw=='expired': claims['exp']=int(time.time())-600
    if flaw=='unverified': claims['email_verified']=False
    signing_key=RSAKey.generate_key(2048,parameters={'kid':'test-key'}) if flaw=='signature' else key
    id_token=jwt.encode({'alg':'RS256','kid':'test-key'},claims,signing_key)
    exchange=Mock(return_value={'access_token':'mock-access','token_type':'Bearer','id_token':id_token})
    monkeypatch.setattr(provider,'fetch_access_token',exchange)
    state='forged-state' if flaw=='state' else params['state'][0]
    response=client.get('/auth/google/callback',query_string={'code':'mock-authorization-code','state':state})
    assert response.status_code==302
    if flaw=='valid':
        assert client.get('/dashboard').status_code==200
        assert exchange.call_args.kwargs.get('code_verifier')
        # Authlib state is one-time; replay must not establish another session.
        client.post('/auth/logout')
        client.get('/auth/google/callback',query_string={'code':'mock-authorization-code','state':state})
        assert client.get('/dashboard').status_code==302
    else:
        assert client.get('/dashboard').status_code==302
        with app.app_context():
            assert db.session.scalar(db.select(User)) is None
