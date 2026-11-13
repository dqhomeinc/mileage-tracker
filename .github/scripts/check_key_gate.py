"""Check the password gate in front of creating and widening an API key.

An API key is a credential that outlives the session which created it, so the
password re-entry in front of minting one -- or giving an existing one more
permissions -- is the only thing between a stolen session and lasting access.
That makes it the place a password guess is cheap, so the gate is throttled:

  - a wrong password is refused, and enough of them lock the gate
  - the lock holds even for the correct password, or it is a speed bump
  - it covers both routes that spend the password, creating and widening
  - a lockout blocks only issuing keys; the rest of the site keeps working
  - the failure count is exact under parallel guesses, not a read-modify-write
  - one account's lockout does not touch another's

Run as a script so it fits the other checks in this directory; no test runner.
Also run against real Postgres in CI: SQLite serialises writers, so the
concurrent case only asserts the invariant there, while Postgres lets the
guesses genuinely interleave.
"""
import os
import sys
import tempfile
import threading

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'key-gate-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'
WRONG = 'Nope123!'


def expect(label, actual, wanted):
    if callable(actual):
        try:
            actual = actual()
        except Exception as exc:  # noqa: BLE001 — reporting, not handling
            actual = f'raised {type(exc).__name__}: {exc}'
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


main.app.config['TESTING'] = True
main.app.config['WTF_CSRF_ENABLED'] = False
# See check_api_keys.py: otherwise a 500 re-raises and aborts the script instead
# of being reported as the failure it is.
main.app.config['PROPAGATE_EXCEPTIONS'] = False
with main.app.app_context():
    main.db.create_all()


def make_user(name):
    with main.app.app_context():
        user = main.User(username=name, email=f'{name}@example.com')
        user.set_password(PASSWORD)
        main.db.session.add(user)
        main.db.session.commit()
    client = main.app.test_client()
    client.post('/login', data={'email': f'{name}@example.com', 'password': PASSWORD},
                follow_redirects=True)
    return client


def mint(client, password, scopes=('vehicles:read',)):
    return client.post('/profile/api-keys',
                       json={'name': 'gate check', 'password': password,
                             'scopes': list(scopes)})


def gate_state(email):
    with main.app.app_context():
        row = main.User.query.filter_by(email=email).first()
        return (row.key_reveal_fails or 0), row.key_reveal_locked_until


alice = make_user('alice')

# ── The gate is throttled ───────────────────────────────────────────────
throttled = make_user('throttled')
codes = [mint(throttled, WRONG).status_code for _ in range(main.KEY_GATE_MAX_ATTEMPTS)]
expect('every attempt up to the limit is refused as a bad password',
       codes, [403] * main.KEY_GATE_MAX_ATTEMPTS)

locked = mint(throttled, WRONG)
expect('the next attempt is locked out rather than answered', locked.status_code, 429)
expect('and says how long to wait',
       'Try again in' in (locked.get_json().get('error') or ''), True)

# The lockout has to hold against the *right* password too, or it is only a
# speed bump on the wrong one and the oracle is still open.
still = mint(throttled, PASSWORD)
expect('the lockout holds even for the correct password', still.status_code, 429)
expect('so no key is issued during a lockout', 'key' in (still.get_json() or {}), False)
with main.app.app_context():
    owner = main.User.query.filter_by(email='throttled@example.com').first()
    expect('and none was stored',
           main.ApiKey.query.filter_by(user_id=owner.id).count(), 0)

# Logging, and the rest of the site, keep working through a lockout. That is
# the whole reason the throttle is here and not on the trip routes.
expect('a locked-out user can still log a trip',
       throttled.post('/log', json={'start': 'A', 'end': 'B', 'distance_miles': 5,
                                    'trip_date': '2026-10-02',
                                    'start_time': '08:00'}).status_code, 200)
expect('and still load their profile', throttled.get('/profile').status_code, 200)

# Once the window passes, the gate reopens and the counter is clear.
with main.app.app_context():
    user = main.User.query.filter_by(email='throttled@example.com').first()
    user.key_reveal_locked_until = main._utcnow() - main.timedelta(seconds=1)
    main.db.session.commit()
expect('the gate reopens once the window has passed',
       mint(throttled, PASSWORD).status_code, 200)
fails, until = gate_state('throttled@example.com')
expect('and a success clears the lockout', until, None)
expect('and the failure count with it', fails, 0)

# ── Widening is behind the same gate ────────────────────────────────────
# Giving a key more permissions spends the password just as minting does, so it
# must feed the same counter and respect the same lock -- otherwise the lock on
# one route is bypassed through the other.
widen = make_user('widen')
key_id = mint(widen, PASSWORD).get_json()['api_key']['id']
for _ in range(main.KEY_GATE_MAX_ATTEMPTS):
    r = widen.patch(f'/profile/api-keys/{key_id}',
                    json={'scopes': ['vehicles:read', 'trips:create'], 'password': WRONG})
    expect('a wrong password when widening is refused', r.status_code, 403)
expect('and locks the gate',
       widen.patch(f'/profile/api-keys/{key_id}',
                   json={'scopes': ['vehicles:read', 'trips:create'],
                         'password': PASSWORD}).status_code, 429)
expect('which also blocks minting a new key', mint(widen, PASSWORD).status_code, 429)
expect('but narrowing, which needs no password, still works',
       widen.patch(f'/profile/api-keys/{key_id}',
                   json={'scopes': ['vehicles:read']}).status_code, 200)

# A correct password mid-way must reset the count, so ordinary mistyping never
# accumulates into a lockout over days of use.
patient = make_user('patient')
for _ in range(main.KEY_GATE_MAX_ATTEMPTS - 1):
    mint(patient, WRONG)
expect('a correct password after some misses is accepted',
       mint(patient, PASSWORD).status_code, 200)
for _ in range(main.KEY_GATE_MAX_ATTEMPTS - 1):
    mint(patient, WRONG)
expect('and the count started over, so this is still not a lockout',
       mint(patient, PASSWORD).status_code, 200)

# One user's lockout must not touch another's gate.
expect('a lockout is per account, not global', mint(alice, PASSWORD).status_code, 200)

# ── The failure count is exact, not a read-modify-write ────────────────
# The count is incremented inside one UPDATE. Done in Python instead -- read,
# add one, write back -- a burst of parallel guesses would all read the same
# value and all write the same value back, earning one counted failure per
# burst rather than per request, and the lock might never engage.
counted = make_user('counted')
for n in range(1, main.KEY_GATE_MAX_ATTEMPTS):
    mint(counted, WRONG)
    expect(f'failure {n} is counted exactly once', gate_state('counted@example.com')[0], n)
    expect(f'and the gate is still open after {n}', gate_state('counted@example.com')[1], None)

mint(counted, WRONG)
fails, until = gate_state('counted@example.com')
expect('the last failure engages the lock', until is not None, True)
expect('and resets the count so the next window starts clean', fails, 0)

# Fired concurrently, the lock must still engage. On SQLite writers are
# serialised, so this does not reproduce a true interleaving -- but a single
# atomic UPDATE is what makes the interleaving harmless, and this asserts the
# invariant that would break if the increment went back to read-modify-write.
burst = make_user('burst')
results = []
lock = threading.Lock()


def guess():
    client = main.app.test_client()
    client.post('/login', data={'email': 'burst@example.com', 'password': PASSWORD},
                follow_redirects=True)
    code = mint(client, WRONG).status_code
    with lock:
        results.append(code)


threads = [threading.Thread(target=guess) for _ in range(main.KEY_GATE_MAX_ATTEMPTS)]
for t in threads:
    t.start()
for t in threads:
    t.join()

expect('every concurrent guess was refused',
       all(c in (403, 429) for c in results), True)
expect('none of them issued a key', any(c == 200 for c in results), False)
_, burst_until = gate_state('burst@example.com')
expect('and the lock engaged despite the guesses arriving together',
       burst_until is not None, True)

# ── The per-trip logging key is gone ────────────────────────────────────
# Logging and editing a trip no longer ask for a code, and nothing offers one.
# Pinned so that neither the requirement nor its leftovers quietly come back.
trip = {'start': 'Gone A', 'end': 'Gone B', 'distance_miles': 5,
        'trip_date': '2026-10-03', 'start_time': '09:00'}
made = alice.post('/log', json=trip)
expect('a trip logs with no key at all', made.status_code, 200)
trip_id = (made.get_json() or {}).get('trip', {}).get('id')
expect('and can be edited with no key',
       alice.patch(f'/history/{trip_id}', json={**trip, 'notes': 'edited'}).status_code, 200)
expect('a stray logging_key in the body is ignored, not required or refused',
       alice.post('/log', json={**trip, 'start_time': '10:00', 'logging_key': 'WHATEVER'}
                  ).status_code, 200)
for method in ('post', 'put', 'get'):
    expect(f'/profile/logging-key no longer exists ({method.upper()})',
           getattr(alice, method)('/profile/logging-key', json={'password': PASSWORD}).status_code, 404)
profile = alice.get('/profile').get_data(as_text=True)
home = alice.get('/').get_data(as_text=True)
expect('the profile page no longer offers a logging key', 'Logging Key' in profile, False)
expect('and the trip form no longer asks for one',
       ('Logging Key' in home, 'LoggingKey' in home), (False, False))

os.unlink(_db.name)

if failures:
    print('Key gate check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('Key gate check OK — creating and widening a key both cost the password, '
      'wrong guesses lock the gate, the lock holds, the count is exact under '
      'parallel guesses, and the rest of the site keeps working.')
