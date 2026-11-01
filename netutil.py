"""
netutil.py: настройки HTTPS для узла, кошелька и майнера. Проверка сертификатов всегда включена.

На Mac Python, скачанный с python.org, часто не знает корневые сертификаты, и любой запрос к https:// падает
с «CERTIFICATE_VERIFY_FAILED». Здесь, если у Python нет своих сертификатов, подключается системный набор
(на Mac это /etc/ssl/cert.pem) или пакет certifi.
"""
import os
import ssl

_BUNDLES = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/openssl/cert.pem",
)


def make_context():
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0) > 0:
        return ctx
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
        return ctx
    except Exception:
        pass
    for path in _BUNDLES:
        if os.path.exists(path):
            try:
                ctx.load_verify_locations(path)
                return ctx
            except (ssl.SSLError, OSError):
                continue
    return ctx


CONTEXT = make_context()
