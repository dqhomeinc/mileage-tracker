"""Check the per-user logging key that gates logging and editing a trip.

The key is the only thing standing between a session and a scripted write to
/log, so the rules around it are worth pinning down: the code is never rendered
into a page, revealing or rotating it costs the account password, the comparison
accepts the formatting a user will actually type, one account's key must not
work on another's, and both write routes must refuse a request without it.

Each of those is a line or two of code, and getting any of them wrong either
removes the gate entirely or locks a legitimate user out of logging trips.
A template render or a plain import cannot see any of it, so this drives the
real routes through a Flask test client against a throwaway SQLite database.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import re
import sys
import tempfile

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'logging-key-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'


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


alice = make_user('alice')
bob = make_user('bob')


def trip_body(key, **extra):
    body = {'start': 'Charlotte, NC', 'end': 'Concord, NC',
            'distance_miles': 12.5, 'trip_date': '2026-10-02'}
    if key is not None:
        body['logging_key'] = key
    body.update(extra)
    return body


# ── The key generator ─────────────────────────────────────────────────────
key = main.generate_logging_key()
expect('a generated key is the declared length', len(key), main.LOGGING_KEY_LENGTH)
expect('and uses only the unambiguous alphabet',
       set(key) <= set(main._LOGGING_KEY_ALPHABET), True)
# I, L, O, U, 0 and 1 are excluded because the code is read off a screen and
# typed back; letting them in is how a key becomes unenterable.
expect('which excludes the characters that get misread',
       set('ILOU01') & set(main._LOGGING_KEY_ALPHABET), set())
expect('two keys are not the same',
       main.generate_logging_key() != main.generate_logging_key(), True)

# ── Normalising what the user types ──────────────────────────────────────
expect('a key is compared without its dash',
       main.normalize_logging_key('ABCD-2345'), 'ABCD2345')
expect('case does not matter', main.normalize_logging_key('abcd2345'), 'ABCD2345')
expect('nor does a pasted space', main.normalize_logging_key(' ABCD 2345 '), 'ABCD2345')
expect('an empty value normalises to empty', main.normalize_logging_key(None), '')
expect('the display form is grouped in the middle',
       main.format_logging_key('ABCD2345'), 'ABCD-2345')
expect('and an absent key displays as nothing', main.format_logging_key(None), '')

# ── Revealing the key costs the password ─────────────────────────────────
expect('the key is not revealed without a password',
       alice.post('/profile/logging-key', json={}).status_code, 403)
expect('nor with the wrong one',
       alice.post('/profile/logging-key', json={'password': 'Wrongpass123!'}).status_code, 403)

r = alice.post('/profile/logging-key', json={'password': PASSWORD})
expect('but is revealed with the right one', r.status_code, 200)
alice_shown = r.get_json()['logging_key']
expect('and comes back in its display form',
       bool(re.fullmatch(r'[A-Z0-9]{4}-[A-Z0-9]{4}', alice_shown)), True)
expect('revealing it twice gives the same key',
       alice.post('/profile/logging-key', json={'password': PASSWORD})
            .get_json()['logging_key'], alice_shown)

# The whole point of the password gate: the key must not be sitting in a page
# that a session alone can fetch.
for page in ('/profile', '/'):
    body = alice.get(page).get_data(as_text=True)
    expect(f'the key is not rendered into {page}',
           main.normalize_logging_key(alice_shown) in main.normalize_logging_key(body), False)

expect('an anonymous caller cannot ask for a key',
       main.app.test_client().post('/profile/logging-key',
                                   json={'password': PASSWORD}).status_code in (302, 401), True)

# ── Logging a trip ───────────────────────────────────────────────────────
alice_key = main.normalize_logging_key(alice_shown)

expect('a trip cannot be logged with no key',
       alice.post('/log', json=trip_body(None)).status_code, 403)
expect('nor with an empty one', alice.post('/log', json=trip_body('')).status_code, 403)
expect('nor with a wrong one', alice.post('/log', json=trip_body('ZZZZ9999')).status_code, 403)
# A prefix must not pass: a comparison that stopped at the shorter string would
# accept one.
expect('nor with a prefix of the real one',
       alice.post('/log', json=trip_body(alice_key[:4])).status_code, 403)
expect('nor with the right key plus trailing characters',
       alice.post('/log', json=trip_body(alice_key + 'X')).status_code, 403)

expect('but can be logged with the right key',
       alice.post('/log', json=trip_body(alice_key)).status_code, 200)
expect('and the key may be typed in its display form',
       alice.post('/log', json=trip_body(alice_shown)).status_code, 200)
expect('or in lower case',
       alice.post('/log', json=trip_body(alice_shown.lower())).status_code, 200)

# ── One account's key is useless on another's ────────────────────────────
bob_key = main.normalize_logging_key(
    bob.post('/profile/logging-key', json={'password': PASSWORD}).get_json()['logging_key'])
expect('two accounts get different keys', bob_key != alice_key, True)
expect("alice's key does not work for bob",
       bob.post('/log', json=trip_body(alice_key)).status_code, 403)

# ── Editing a trip ──────────────────────────────────────────────────────
trip_id = alice.get('/history').get_json()[0]['id']
expect('an edit cannot be saved with no key',
       alice.patch(f'/history/{trip_id}', json=trip_body(None)).status_code, 403)
expect('nor with a wrong one',
       alice.patch(f'/history/{trip_id}', json=trip_body('ZZZZ9999')).status_code, 403)
expect('but can be saved with the right one',
       alice.patch(f'/history/{trip_id}', json=trip_body(alice_key)).status_code, 200)
expect("and another user's key does not reach this trip at all",
       bob.patch(f'/history/{trip_id}', json=trip_body(bob_key)).status_code, 404)

# ── Rotating the key ────────────────────────────────────────────────────
expect('rotating needs the password too',
       alice.put('/profile/logging-key', json={'password': 'Wrongpass123!'}).status_code, 403)
rotated = alice.put('/profile/logging-key', json={'password': PASSWORD}).get_json()['logging_key']
expect('rotating returns a different key', rotated != alice_shown, True)
expect('the old key stops working at once',
       alice.post('/log', json=trip_body(alice_key)).status_code, 403)
expect('and the new one works',
       alice.post('/log', json=trip_body(main.normalize_logging_key(rotated))).status_code, 200)

# ── An account from before the column existed ──────────────────────────
# logging_key is null for those, and nothing backfills it, so the first read
# has to mint one rather than leaving the user unable to log anything.
with main.app.app_context():
    legacy = main.User(username='legacy', email='legacy@example.com')
    legacy.set_password(PASSWORD)
    legacy.logging_key = None
    main.db.session.add(legacy)
    main.db.session.commit()
legacy_client = main.app.test_client()
legacy_client.post('/login', data={'email': 'legacy@example.com', 'password': PASSWORD},
                   follow_redirects=True)
minted = legacy_client.post('/profile/logging-key', json={'password': PASSWORD})
expect('an account with no key is given one on first read', minted.status_code, 200)
expect('and it is a real key',
       len(main.normalize_logging_key(minted.get_json()['logging_key'])),
       main.LOGGING_KEY_LENGTH)
expect('which then works for logging',
       legacy_client.post('/log', json=trip_body(
           main.normalize_logging_key(minted.get_json()['logging_key']))).status_code, 200)
# A blank key must never be what the comparison accepts for such an account.
with main.app.app_context():
    blank = main.User(username='blank', email='blank@example.com')
    blank.set_password(PASSWORD)
    main.db.session.add(blank)
    main.db.session.commit()
blank_client = main.app.test_client()
blank_client.post('/login', data={'email': 'blank@example.com', 'password': PASSWORD},
                  follow_redirects=True)
expect('an account with no key still cannot log without one',
       blank_client.post('/log', json=trip_body(None)).status_code, 403)
expect('and an empty key is not accepted as matching a null column',
       blank_client.post('/log', json=trip_body('')).status_code, 403)

# ── Deleting is deliberately not gated ─────────────────────────────────
# Worth asserting so the choice is visible rather than looking like an
# oversight: a delete removes a trip, it cannot invent mileage.
expect('deleting a trip does not require the key',
       alice.delete(f'/history/{trip_id}').status_code, 200)

# ── The client and the server must agree on the format ─────────────────
template = open('templates/index.html', encoding='utf-8').read()
match = re.search(r'const LOGGING_KEY_LENGTH = (\d+);', template)
expect('the page declares the key length', bool(match), True)
if match:
    expect('and it matches the server', int(match.group(1)), main.LOGGING_KEY_LENGTH)
expect('both write routes send the key',
       template.count('logging_key: loggingKey'), 2)

os.unlink(_db.name)

if failures:
    print('Logging key check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('Logging key check OK — generation, normalising, the password gate, '
      'both write routes and rotation all hold.')
