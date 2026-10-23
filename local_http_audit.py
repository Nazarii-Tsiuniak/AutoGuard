"""Reproducible audit over real loopback HTTP with a disposable database.

No real users, SMTP messages, OAuth credentials or production DB are used.
Only Cloudflare's public dummy Siteverify is an external integration here.
"""
import hashlib
import json
import re
import secrets
import tempfile
from datetime import date
from email import policy
from email.parser import BytesParser
from pathlib import Path
from threading import Thread
import requests
from cryptography.fernet import Fernet
from werkzeug.serving import make_server, WSGIRequestHandler
from autoguard import create_app
from autoguard.extensions import db
from autoguard.models import User, Vehicle, MaintenanceRecord
from autoguard.security import hasher


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass  # Do not log URLs carrying activation/reset tokens.


def run_audit():
    root=Path(__file__).resolve().parent
    env=root/'.env'
    initial_env=hashlib.sha256(env.read_bytes()).digest() if env.exists() else None
    report={'transport':'real loopback HTTP','database':'temporary SQLite',
            'email':'temporary local files; no SMTP delivery',
            'captcha':'real Cloudflare Siteverify, public dummy keys', 'checks':{}}
    checks=report['checks']
    password=secrets.token_urlsafe(20)+'Aa1!'
    changed=secrets.token_urlsafe(20)+'Bb2!'
    with tempfile.TemporaryDirectory(prefix='autoguard-http-audit-') as directory:
        temporary=Path(directory)
        app=create_app({'TESTING':True,'PRODUCTION':False,'SECRET_KEY':secrets.token_hex(32),
            'TOTP_ENCRYPTION_KEY':Fernet.generate_key().decode(),
            'SQLALCHEMY_DATABASE_URI':'sqlite:///'+(temporary/'audit.db').as_posix(),
            'MAIL_MODE':'file','GOOGLE_CLIENT_ID':None,'GOOGLE_CLIENT_SECRET':None,
            'WTF_CSRF_ENABLED':True,'RATELIMIT_ENABLED':True,'RATELIMIT_STORAGE_URI':'memory://',
            'TURNSTILE_SITE_KEY':'1x00000000000000000000AA',
            'TURNSTILE_SECRET_KEY':'1x0000000000000000000000000000000AA'})
        app.instance_path=str(temporary)
        with app.app_context():
            db.create_all()
            db.session.add(User(email='audit-admin@example.com',name='Audit Admin',activated=True,role='ADMIN',password_hash=hasher.hash(password)))
            db.session.commit()
        server=make_server('127.0.0.1',0,app,threaded=True,request_handler=QuietHandler)
        base=f'http://127.0.0.1:{server.server_port}'
        app.config['PUBLIC_BASE_URL']=base
        thread=Thread(target=server.serve_forever,daemon=True)
        thread.start()
        session=requests.Session()
        session.trust_env=False

        def submit(path, data, csrf_page=None):
            html=session.get(base+(csrf_page or path),timeout=20).text
            token=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',html).group(1)
            values=list(data.items()) if isinstance(data,dict) else list(data)
            return session.post(base+path,data=values+[('csrf_token',token)],allow_redirects=False,timeout=25)

        def mailed_path(kind):
            for path in (temporary/'mail').glob('*.eml'):
                message=BytesParser(policy=policy.default).parsebytes(path.read_bytes())
                match=re.search(re.escape(base)+r'(/auth/'+kind+r'/[A-Za-z0-9_-]+)',message.get_content())
                if match:
                    return match.group(1)
            raise AssertionError('Expected local email missing')

        try:
            checks['home_http_200']=session.get(base,timeout=5).status_code==200
            checks['csrf_missing_rejected']=session.post(base+'/auth/register',data={}).status_code==400
            registration={'email':'audit-driver@example.com','name':'Audit Driver','password':password,'confirm':password,'cf-turnstile-response':'XXXX.DUMMY.TOKEN.XXXX'}
            response=submit('/auth/register',registration)
            with app.app_context():
                user=db.session.scalar(db.select(User).where(User.email=='audit-driver@example.com'))
                checks['live_dummy_captcha_registration']=bool(user) and response.status_code==302
                if not user:
                    # Continue independent checks; do not call this a successful live CAPTCHA test.
                    user=User(email='audit-driver@example.com',name='Audit Driver',password_hash=hasher.hash(password))
                    db.session.add(user)
                    db.session.commit()
                    from autoguard.security import send_token
                    with app.test_request_context():
                        send_token(user,'activate')
            submit('/auth/login',{'email':'audit-driver@example.com','password':password})
            response=session.get(base+'/garage/',allow_redirects=False)
            checks['unactivated_garage_restricted']=response.status_code==302 and response.headers['Location'].endswith('/profile')
            activation=mailed_path('activate')
            checks['activation_get_and_post']=submit(activation,{}).status_code==302
            checks['activation_replay_rejected']=session.get(base+activation).status_code==400
            checks['dashboard_authenticated']=session.get(base+'/dashboard').status_code==200
            checks['vehicle_created']=submit('/garage/new',{'make':'Toyota','model':'Corolla','year':'2021','engine':'Гібрид','mileage':'45000','vin':''}).status_code==302
            with app.app_context():
                vid=db.session.scalar(db.select(Vehicle)).id
            values=[('date',date.today().strftime('%d.%m.%Y')),('work','Заміна оливи'),('work','Власна робота'),('mileage','46000'),('cost','1800,50'),('notes','Audit-only data')]
            checks['multiple_works_created']=submit(f'/garage/{vid}',values).status_code==302
            with app.app_context():
                rid=db.session.scalar(db.select(MaintenanceRecord)).id
            values=[(key,'1900,50' if key=='cost' else value) for key,value in values]
            checks['maintenance_edited']=submit(f'/garage/records/{rid}/edit',values).status_code==302
            checks['statistics_single_total']='1900.50' in session.get(base+'/statistics').text
            checks['user_admin_forbidden']=session.get(base+'/admin').status_code==403
            # Recovery uses the real HTTP route and real temporary mail, without touching Gmail.
            checks['reset_requested']=submit('/auth/forgot',{'email':'audit-driver@example.com'}).status_code==302
            reset=mailed_path('reset')
            checks['password_reset']=submit(reset,{'password':changed,'confirm':changed}).status_code==302
            checks['reset_replay_rejected']=session.get(base+reset).status_code==400
            checks['old_password_rejected']=submit('/auth/login',{'email':'audit-driver@example.com','password':password}).status_code==200
            checks['new_password_accepted']=submit('/auth/login',{'email':'audit-driver@example.com','password':changed}).status_code==302
            checks['record_deleted']=submit(f'/garage/records/{rid}/delete',{},csrf_page=f'/garage/{vid}').status_code==302
            checks['vehicle_deleted']=submit(f'/garage/{vid}/delete',{},csrf_page=f'/garage/{vid}').status_code==302
            cookie=session.cookies.get('session')
            checks['logout']=submit('/auth/logout',{},csrf_page='/profile').status_code==302
            replay=requests.Session()
            replay.trust_env=False
            replay.cookies.set('session',cookie,domain='127.0.0.1',path='/')
            checks['copied_cookie_revoked']=replay.get(base+'/dashboard',allow_redirects=False).status_code==302
            for _ in range(5):
                submit('/auth/login',{'email':'audit-driver@example.com','password':'wrong'})
            checks['lockout_rejects_correct_password']=submit('/auth/login',{'email':'audit-driver@example.com','password':changed}).status_code==200
            submit('/auth/login',{'email':'audit-admin@example.com','password':password})
            checks['admin_users_and_journal']=session.get(base+'/admin').status_code==200 and session.get(base+'/admin/logins').status_code==200
        except Exception as error:
            report['error_class']=type(error).__name__  # No URLs, tokens or credentials.
        finally:
            session.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            with app.app_context():
                db.session.remove()
                db.engine.dispose()
    report['env_unchanged']=(hashlib.sha256(env.read_bytes()).digest() if env.exists() else None)==initial_env
    report['all_checks_passed']=bool(checks) and all(checks.values()) and 'error_class' not in report
    (root/'local-http-audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=True,indent=2))
    return 0 if report['all_checks_passed'] else 1


if __name__=='__main__':
    raise SystemExit(run_audit())
