"""Check the attributes on the cookies the app actually sends.

The session cookie is a bearer credential: whoever holds it is signed in. These
attributes decide where the browser will carry it, and all three were previously
left to defaults -- which for Secure meant off, so the cookie could be read off
the wire by anyone on the network path.

There are two such cookies. The session, and the longer-lived "remember me"
cookie that Flask-Login sets when the login form's checkbox is ticked -- a
second bearer credential that was running on Flask-Login's own defaults: 365
days, not Secure, no SameSite.

Secure is the reason this script is run twice. Secure has to be set when
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
# remember=1 so both cookies are set by the one request.
resp = client.post('/login', base_url='https://localhost',
                   data={'email': 'cookie@example.com', 'password': PASSWORD,
                         'remember': '1'})

ALL_SET_COOKIE = resp.headers.getlist('Set-Cookie')


def parse(prefix):
    """The attributes of the first Set-Cookie starting with `prefix`.

    Read off the emitted header rather than the config, so this describes what
    a browser is actually told rather than what the app meant to say.
    """
    matching = [c for c in ALL_SET_COOKIE if c.startswith(prefix)]
    if not matching:
        return None, {}, {}
    header = matching[0]
    flags = {p.strip().split('=', 1)[0].lower() for p in header.split(';')[1:]}
    values = {}
    for part in header.split(';')[1:]:
        if '=' in part:
            k, v = part.strip().split('=', 1)
            values[k.lower()] = v
    return header, flags, values


header, attrs, value_of = parse('session=')
if not header:
    failures.append('signing in set no session cookie at all, so there is '
                    f'nothing to check; Set-Cookie was {ALL_SET_COOKIE!r}')

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

# ── The "remember me" cookie ─────────────────────────────────────────────
remember_name = main.app.config.get('REMEMBER_COOKIE_NAME', 'remember_token')
r_header, r_attrs, r_values = parse(f'{remember_name}=')
if not r_header:
    failures.append('ticking "remember me" set no remember cookie, so its '
                    f'attributes cannot be checked; Set-Cookie was {ALL_SET_COOKIE!r}')
else:
    expect('the remember cookie is HttpOnly', 'httponly' in r_attrs, True)
    expect('and is SameSite=Lax', r_values.get('samesite'), 'Lax')
    if main.IS_DEPLOYED:
        expect('deployed, the remember cookie is Secure', 'secure' in r_attrs, True)
    else:
        expect('locally, the remember cookie is not Secure', 'secure' in r_attrs, False)

# The expiry is the whole lifetime control: there is no server-side revocation,
# so logging out clears this cookie in that browser and does nothing to a copy
# someone else holds. A year was Flask-Login's default, not a decision.
#
# Read off the cookie's own Expires, not app.config: Flask-Login keeps its
# defaults in its own module, so a version of this app that sets nothing has no
# REMEMBER_COOKIE_DURATION key at all and reading it raises instead of
# reporting. The header carries the value that was actually sent either way.
duration = None
if r_header:
    expires = r_values.get('expires')
    if not expires:
        failures.append('the remember cookie has no Expires, so it is a session '
                        'cookie and "remember me" does not outlive the browser')
    else:
        from datetime import timezone  # noqa: E402
        from email.utils import parsedate_to_datetime  # noqa: E402
        try:
            # Both sides tz-aware: Expires is a GMT string, and utcnow() is
            # deprecated from 3.12.
            duration = (parsedate_to_datetime(expires)
                        - main.datetime.now(timezone.utc))
        except (TypeError, ValueError) as exc:
            failures.append(f'could not read the remember cookie Expires ({expires!r}): {exc}')

if duration is not None:
    days = duration.days
    # A day of slack: the cookie was minted a moment before this was measured.
    if not 29 <= days <= 30:
        failures.append(f'the remember cookie lasts about {days} days, not the 30 '
                        'intended' + (" -- 365 is Flask-Login's default, meaning "
                                      'nothing here set it' if days > 300 else ''))
    if days > 90:
        failures.append(f'{days} days is long enough that a stolen copy stays useful '
                        'well past any plausible need, and nothing can revoke it early')

# And both configs must track the environment rather than being fixed values
# that happen to match this one.
#
# The remember value is read with Flask-Login's own default as the fallback, not
# with a plain subscript. Flask-Login keeps its defaults in its own module, so
# an app that sets nothing has no such key and a subscript raises -- which fails
# CI, but reports a KeyError instead of saying the cookie is not Secure.
import flask_login.config as fl_defaults  # noqa: E402

expect('the session cookie is Secure exactly when deployed',
       main.app.config['SESSION_COOKIE_SECURE'], main.IS_DEPLOYED)
expect('the remember cookie is Secure exactly when deployed',
       main.app.config.get('REMEMBER_COOKIE_SECURE', fl_defaults.COOKIE_SECURE),
       main.IS_DEPLOYED)
expect('and the remember cookie is HttpOnly in config as well as on the wire',
       main.app.config.get('REMEMBER_COOKIE_HTTPONLY', fl_defaults.COOKIE_HTTPONLY),
       True)

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

print('Cookie flags check OK — both cookies are HttpOnly and SameSite=Lax, '
      f'remember-me lasts {duration.days if duration else "?"} days, and Secure is '
      f'{"on" if main.IS_DEPLOYED else "off"} to match IS_DEPLOYED={main.IS_DEPLOYED}.')
