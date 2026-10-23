from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse
import pytest
import requests
from cryptography.fernet import Fernet
from autoguard import create_app
from autoguard.extensions import oauth


@pytest.mark.parametrize('client_id,secret,enabled', [
    ('','',False),('test-client','',False),('','test-secret',False),
    ('   ','   ',False),(' test-client ',' test-secret ',True)])
def test_google_button_follows_effective_configuration(client_id,secret,enabled):
    app=create_app({'TESTING':True,'PRODUCTION':False,'SECRET_KEY':'configuration-tests-only',
        'TOTP_ENCRYPTION_KEY':Fernet.generate_key().decode(),'SQLALCHEMY_DATABASE_URI':'sqlite://',
        'GOOGLE_CLIENT_ID':client_id,'GOOGLE_CLIENT_SECRET':secret,'RATELIMIT_ENABLED':False})
    html=app.test_client().get('/auth/login').get_data(as_text=True)
    assert ('href="/auth/google"' in html)==enabled
    assert ('Вхід через Google ще не налаштовано' in html)==(not enabled)
    assert 'test-secret' not in html


def test_status_command_never_prints_credentials(app):
    app.config.update(GOOGLE_CLIENT_ID='test-client-hidden',GOOGLE_CLIENT_SECRET='test-secret-hidden',
                      PUBLIC_BASE_URL='http://127.0.0.1:5050')
    # Register through the real factory separately for the client-present status.
    result=app.test_cli_runner().invoke(args=['oidc-status'])
    assert result.exit_code==0
    assert 'GOOGLE_CLIENT_ID: configured' in result.output
    assert 'GOOGLE_CLIENT_SECRET: configured' in result.output
    assert 'Local callback base: configured' in result.output
    assert 'test-client-hidden' not in result.output and 'test-secret-hidden' not in result.output


@pytest.mark.parametrize('linking',[False,True])
def test_google_discovery_network_failure_is_handled(app,client,make_user,login,monkeypatch,linking):
    if linking:
        make_user()
        login()
    app.config.update(GOOGLE_CLIENT_ID='mock-client',GOOGLE_CLIENT_SECRET='mock-secret')
    provider=Mock()
    provider.authorize_redirect.side_effect=requests.Timeout()
    monkeypatch.setattr(oauth,'google',provider,raising=False)
    response=client.post('/auth/google/link') if linking else client.get('/auth/google')
    assert response.status_code==302
    assert response.location.endswith('/security' if linking else '/login')
    with client.session_transaction() as state:
        assert '_user_id' not in state or linking
        assert 'google_link' not in state
