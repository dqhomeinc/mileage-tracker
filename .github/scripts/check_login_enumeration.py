"""Check that the login form does not reveal which emails are registered.

The form used to answer two different questions. "No account is associated with
that email" told an attacker which addresses exist here, which turns guessing an
email *and* a password into guessing only a password, and lets a leaked address
list be tested against this app. The reset form already refuses to answer that,
so login undoing it was an inconsistency rather than a decision.

The wording is the easy half. The hard half is timing: verifying a password runs
scrypt, which is deliberately slow, so returning early for an address with no
account made that response measurably faster and answered the same question
without words. Both halves are checked here, the second by measurement.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import statistics
import sys
import tempfile
import time

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'login-enumeration-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'
REAL_EMAIL = 'real@example.com'
ABSENT_EMAIL = 'absent@example.com'


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


main.app.config['TESTING'] = True
with main.app.app_context():
    main.db.create_all()
    user = main.User(username='real', email=REAL_EMAIL)
    user.set_password(PASSWORD)
    main.db.session.add(user)
    main.db.session.commit()


def attempt(email, password):
    """A login POST from a fresh client. Returns the flashed page text."""
    client = main.app.test_client()
    resp = client.post('/login', data={'email': email, 'password': password},
                       follow_redirects=True)
    return resp.get_data(as_text=True)


# ── The wording ───────────────────────────────────────────────────────────
absent_page = attempt(ABSENT_EMAIL, PASSWORD)
wrong_pw_page = attempt(REAL_EMAIL, 'Wrongpass123!')

# Neither page may contain anything that separates the two cases.
for phrase in ('No account', 'no account', 'not registered', 'Incorrect password',
               'incorrect password', 'does not exist'):
    if phrase in absent_page or phrase in wrong_pw_page:
        failures.append(f'a login failure page still says {phrase!r}, '
                        'which distinguishes the two cases')

expect('an unknown email gets the shared message',
       'Email or password is incorrect.' in absent_page, True)
expect('and so does a wrong password',
       'Email or password is incorrect.' in wrong_pw_page, True)

# The strongest form of the check: whatever the messages are, the two responses
# must be indistinguishable. Compared after stripping the CSRF-less form's own
# noise -- there is none here, so a straight comparison is the real test.
expect('the two failures are byte-for-byte identical',
       absent_page == wrong_pw_page, True)

# A correct login must still work, or this "fix" just breaks signing in.
ok_page = attempt(REAL_EMAIL, PASSWORD)
expect('a correct password still signs in',
       'Email or password is incorrect.' not in ok_page, True)

# ── The timing ────────────────────────────────────────────────────────────
# scrypt at the configured cost takes tens of milliseconds, so a path that
# skips it is obvious in a handful of samples. Medians rather than means, and a
# generous tolerance, because CI runners are noisy -- the failure this catches
# is one path doing no hashing at all, which is a whole order of magnitude, not
# a few percent.
def median_ms(email, password, n=7):
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        attempt(email, password)
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


absent_ms = median_ms(ABSENT_EMAIL, PASSWORD)
wrong_pw_ms = median_ms(REAL_EMAIL, 'Wrongpass123!')
ratio = max(absent_ms, wrong_pw_ms) / max(0.001, min(absent_ms, wrong_pw_ms))

# 2.5x leaves room for runner noise while still catching a skipped hash, and
# also catches the inverted version of the bug -- hashing twice on one path.
if ratio > 2.5:
    failures.append(
        f'the two login failures take measurably different times '
        f'(no such user {absent_ms:.1f}ms vs wrong password {wrong_pw_ms:.1f}ms, '
        f'{ratio:.1f}x), so the response time still reveals which emails exist'
    )

# Sanity check on the measurement itself. If *neither* path hashes, the ratio
# above is ~1.0 and passes for entirely the wrong reason, so the slower of the
# two is what has to look like real work. Testing the faster one instead would
# fire redundantly on a difference the ratio has already caught, and report it
# as "both" when only one was fast.
if max(absent_ms, wrong_pw_ms) < 1.0:
    failures.append(
        f'neither login path took a millisecond '
        f'({absent_ms:.2f}ms, {wrong_pw_ms:.2f}ms) — no password hashing appears '
        'to be happening at all, so comparing the two proves nothing'
    )

os.unlink(_db.name)

if failures:
    print('Login enumeration check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'Login enumeration check OK — both failures are identical and take the '
      f'same time ({absent_ms:.0f}ms vs {wrong_pw_ms:.0f}ms).')
