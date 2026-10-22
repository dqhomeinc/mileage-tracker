"""Check the attributes on the session cookie the app actually sends.

The session cookie is a bearer credential: whoever holds it is signed in. These
attributes decide where the browser will carry it, and all three were previously
left to defaults -- which for Secure meant off, so the cookie could be read off
the wire by anyone on the network path.

That last one is the reason this script is run twice. Secure has to be set when
deployed and unset locally, or nobody can sign in over http://localhost, so one
assertion cannot cover both. The script reads main.IS_DEPLOYED and asserts the
arm that applies; the integration workflow runs it locally and again in the
postgres job, where DATABASE_URL names a real server and the deployed arm is
what gets exercised.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import sys
import tempfile

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
# Only used when DATABASE_URL is not already set: the postgres job sets it, and
# that is what makes this run assert the deployed arm.
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'cookie-flags-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


main.app.config['TESTING'] = True
with main.app.app_context():
    main.db.create_all()
    if not main.User.query.filter_by(email='cookie@example.com').first():
        user = main.User(username='cookie', email='cookie@example.com')
        user.set_password(PASSWORD)
        main.db.session.add(user)
        main.db.session.commit()

# https so that a Secure cookie is actually emitted and stored -- over http a
# test client is entitled to drop it, which would look like a broken login
# rather than the flag being set.
client = main.app.test_client()
resp = client.post('/login', base_url='https://localhost',
                   data={'email': 'cookie@example.com', 'password': PASSWORD})

session_cookies = [c for c in resp.headers.getlist('Set-Cookie')
                   if c.startswith('session=')]
if not session_cookies:
    failures.append('signing in set no session cookie at all, so there is '
                    f'nothing to check; Set-Cookie was {resp.headers.getlist("Set-Cookie")!r}')
    header = ''
else:
    header = session_cookies[0]

# Read off the emitted header rather than the config, so this describes what a
# browser is actually told.
attrs = {part.strip().split('=', 1)[0].lower() for part in header.split(';')[1:]}
value_of = {}
for part in header.split(';')[1:]:
    if '=' in part:
        k, v = part.strip().split('=', 1)
        value_of[k.lower()] = v

if header:
    expect('the session cookie is HttpOnly, so scripts cannot read it',
           'httponly' in attrs, True)
    expect('and is SameSite=Lax, so it is not sent on cross-site POSTs',
           value_of.get('samesite'), 'Lax')

    # The arm that depends on the environment.
    if main.IS_DEPLOYED:
        expect('deployed, the cookie is Secure so it never travels in plaintext',
               'secure' in attrs, True)
    else:
        expect('locally, the cookie is not Secure so http://localhost can sign in',
               'secure' in attrs, False)

# And the config must track the environment rather than being a fixed value
# that happens to match this one.
expect('Secure is set exactly when deployed',
       main.app.config['SESSION_COOKIE_SECURE'], main.IS_DEPLOYED)

# Signing in has to still work, or these flags have broken the thing they
# protect. Checked by reaching a page that requires a session.
page = client.get('/', base_url='https://localhost')
expect('a signed-in request reaches the app rather than the login form',
       page.status_code, 200)

os.unlink(_db.name)

if failures:
    print('Cookie flags check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('Cookie flags check OK — HttpOnly and SameSite=Lax are set, and Secure '
      f'is {"on" if main.IS_DEPLOYED else "off"}, matching IS_DEPLOYED='
      f'{main.IS_DEPLOYED}.')
