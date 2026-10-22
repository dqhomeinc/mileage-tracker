"""Check that login attempts are actually bounded.

Without a limit the password is not a boundary, only slow: scrypt costs tens of
milliseconds a guess, which hinders an attacker and does not stop one. With a
limit, the properties that matter are easy to get subtly wrong and invisible in
review:

  - the limit has to engage, and hold against the *correct* password too, or it
    merely slows wrong guesses down
  - it must not reveal which addresses exist, or it undoes the shared failure
    message it sits next to
  - one address being limited must not limit everyone else
  - a success has to clear the count, or ordinary mistyping accumulates
  - attempts against addresses with no account must still count, or the limit
    is sidestepped by guessing addresses

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import sys
import tempfile

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'rate-limit-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'
WRONG = 'Wrongpass123!'
LIMITED = 'Too many sign-in attempts'
REJECTED = 'Email or password is incorrect'


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


main.app.config['TESTING'] = True
with main.app.app_context():
    main.db.create_all()
    for name in ('alice', 'bob'):
        user = main.User(username=name, email=f'{name}@example.com')
        user.set_password(PASSWORD)
        main.db.session.add(user)
    main.db.session.commit()


def attempt(email, password, ip='203.0.113.1'):
    """One login POST from `ip`. Returns the resulting page text."""
    client = main.app.test_client()
    resp = client.post('/login', data={'email': email, 'password': password},
                       environ_overrides={'REMOTE_ADDR': ip},
                       follow_redirects=True)
    return resp.get_data(as_text=True)


def reset():
    with main.app.app_context():
        main.db.session.query(main.LoginAttempt).delete()
        main.db.session.commit()


# ── The email limit engages ───────────────────────────────────────────────
reset()
pages = [attempt('alice@example.com', WRONG, ip=f'198.51.100.{i}')
         for i in range(main.LOGIN_MAX_PER_EMAIL)]
expect('every attempt up to the email limit is an ordinary rejection',
       all(REJECTED in p and LIMITED not in p for p in pages), True)

nxt = attempt('alice@example.com', WRONG, ip='198.51.100.200')
expect('the next one is limited instead', LIMITED in nxt, True)

# The property that makes it a limit rather than a speed bump.
right = attempt('alice@example.com', PASSWORD, ip='198.51.100.201')
expect('and the limit holds against the correct password', LIMITED in right, True)
expect('so a limited attempt cannot sign in', 'Trip History' in right, False)

# ── It must not become an enumeration oracle ─────────────────────────────
# An address with no account must reach the same limit and say the same thing,
# or "too many attempts" would mean "this address is real".
reset()
for i in range(main.LOGIN_MAX_PER_EMAIL):
    attempt('nobody@example.com', WRONG, ip=f'192.0.2.{i}')
absent_limited = attempt('nobody@example.com', WRONG, ip='192.0.2.200')
expect('an address with no account is limited the same way',
       LIMITED in absent_limited, True)

reset()
for i in range(main.LOGIN_MAX_PER_EMAIL):
    attempt('alice@example.com', WRONG, ip=f'192.0.2.{i}')
real_limited = attempt('alice@example.com', WRONG, ip='192.0.2.200')
expect('and the two limited pages are byte-for-byte identical',
       absent_limited == real_limited, True)

# ── One account's limit is not everyone's ───────────────────────────────
reset()
for i in range(main.LOGIN_MAX_PER_EMAIL + 2):
    attempt('alice@example.com', WRONG, ip=f'198.51.100.{i}')
other = attempt('bob@example.com', PASSWORD, ip='198.51.100.250')
expect('another account can still sign in while one is limited',
       LIMITED in other, False)

# ── The address limit engages independently ────────────────────────────
# Spread across many addresses so no single email limit is reached first.
reset()
for i in range(main.LOGIN_MAX_PER_IP):
    attempt(f'user{i}@example.com', WRONG, ip='203.0.113.99')
ip_limited = attempt('fresh@example.com', WRONG, ip='203.0.113.99')
expect('one address making many attempts is limited', LIMITED in ip_limited, True)
elsewhere = attempt('bob@example.com', PASSWORD, ip='203.0.113.100')
expect('while a different address is unaffected', LIMITED in elsewhere, False)

# ── A success clears that email's count, and only that ───────────────
reset()
for i in range(main.LOGIN_MAX_PER_EMAIL - 1):
    attempt('bob@example.com', WRONG, ip='203.0.113.50')
# A failure against a different address from the same place, which must survive.
attempt('someone-else@example.com', WRONG, ip='203.0.113.50')
ok = attempt('bob@example.com', PASSWORD, ip='203.0.113.50')
expect('signing in correctly after some misses works', LIMITED in ok, False)
with main.app.app_context():
    mine = (main.db.session.query(main.LoginAttempt)
            .filter(main.LoginAttempt.email == 'bob@example.com').count())
    others = (main.db.session.query(main.LoginAttempt)
              .filter(main.LoginAttempt.email != 'bob@example.com').count())
expect("and clears that email's failures so they do not accumulate", mine, 0)
expect('while leaving failures against other addresses from the same place',
       others, 1)

# ── A success must not refund the address budget ─────────────────────
# The attack this prevents: someone with an account of their own guesses up to
# the address limit, signs in to their own account to reset the count, and
# repeats, so the address limit never engages. A success clears the email's
# failures, not the address's, which is what closes it.
reset()
ATTACKER_IP = '203.0.113.123'
for cycle in range(3):
    for i in range(main.LOGIN_MAX_PER_EMAIL - 1):
        attempt(f'victim{cycle}-{i}@example.com', WRONG, ip=ATTACKER_IP)
    # Their own account, correct password, from the same address.
    attempt('bob@example.com', PASSWORD, ip=ATTACKER_IP)

after_cycles = attempt('one-more@example.com', WRONG, ip=ATTACKER_IP)
expect('guessing cannot be resumed indefinitely by signing in between rounds',
       LIMITED in after_cycles, True)
with main.app.app_context():
    budget = (main.db.session.query(main.LoginAttempt)
              .filter(main.LoginAttempt.ip == ATTACKER_IP).count())
if budget < main.LOGIN_MAX_PER_IP:
    failures.append(f'only {budget} attempts are counted against the address after '
                    f'{3 * (main.LOGIN_MAX_PER_EMAIL - 1)} guesses, so signing in '
                    'between rounds is refunding the address budget')

# ── Old attempts stop counting, and are pruned ────────────────────────
reset()
with main.app.app_context():
    stale = main._utcnow() - main.LOGIN_ATTEMPT_WINDOW - main.timedelta(minutes=1)
    for _ in range(main.LOGIN_MAX_PER_EMAIL + 5):
        main.db.session.add(main.LoginAttempt(ip='203.0.113.77',
                                              email='alice@example.com',
                                              created_at=stale))
    main.db.session.commit()
not_limited = attempt('alice@example.com', WRONG, ip='203.0.113.77')
expect('attempts older than the window do not count',
       LIMITED in not_limited, False)
with main.app.app_context():
    remaining = main.db.session.query(main.LoginAttempt).count()
expect('and writing prunes them rather than letting the table grow',
       remaining, 1)

os.unlink(_db.name)

if failures:
    print('Login rate limit check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'Login rate limit check OK — {main.LOGIN_MAX_PER_EMAIL} per address and '
      f'{main.LOGIN_MAX_PER_IP} per IP over {int(main.LOGIN_ATTEMPT_WINDOW.total_seconds() // 60)} '
      'minutes, with no enumeration and no collateral lockout.')
