from autoguard import create_app
import os

app = create_app()

if __name__ == '__main__':
    from waitress import serve
    port = int(os.getenv('PORT', '5050'))
    print(f'AutoGuard: http://127.0.0.1:{port}', flush=True)
    google_ready = bool(app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET'])
    print(f"Google OIDC: {'configured' if google_ready else 'missing'}", flush=True)
    # Waitress has no default access log: activation/reset URLs stay out of logs.
    serve(app, host='127.0.0.1', port=port)
