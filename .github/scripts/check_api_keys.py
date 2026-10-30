"""Check the API keys that let an agent log trips without the account password.

A key is a credential that outlives the session which created it, so the
properties that make it narrower than a password are the whole point and every
one of them fails silently:

  - the secret is never stored and never rendered into a page
  - a revoked key stops working, immediately
  - one account's key cannot touch another's data
  - a key authenticates an API request and does NOT establish a session, so it
    cannot be used to reach anything @login_required protects
  - the API does not require the per-trip logging key, and /log still does
  - minting costs the account password; revoking deliberately does not
  - distance is measured rather than taken from the request
  - a key's requests are bounded, including the ones that fail validation

Run as a script so it fits the other checks in this directory; no test runner.
"""
import math
import os
import re
import sys
import tempfile
from unittest.mock import patch

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'api-key-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'


def field(resp, name, default=None):
    """One field from a JSON response, or `default` if it has no such field.

    Never a direct subscript on resp.get_json(). A check that expected one
    shape and got another reads whatever actually came back: a success body
    that is a list, or a 500 whose body is HTML so get_json() is None. Both
    raise, and a raise here aborts the script and silently skips every later
    check -- which is how a run can look shorter than it is. Every response
    read in this file goes through here for that reason.
    """
    try:
        body = resp.get_json()
    except Exception:  # noqa: BLE001 -- a non-JSON body simply has no fields
        return default
    if not isinstance(body, dict):
        return default
    return body.get(name, default)


def err(resp):
    """The error message from a response, or '' if it has none."""
    return field(resp, 'error', '')


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


main.app.config['TESTING'] = True
# TESTING alone makes Flask re-raise a view's exception instead of returning
# 500, so a check asserting "the client gets a sensible response" would crash
# on the very bug it is looking for rather than reporting it. Turning
# propagation off makes the client see what a real client would: a 500, which
# then reads as a named failure beside the others.
main.app.config['PROPAGATE_EXCEPTIONS'] = False
with main.app.app_context():
    main.db.create_all()
    for name in ('jane', 'bob'):
        user = main.User(username=name, email=f'{name}@example.com')
        user.set_password(PASSWORD)
        main.db.session.add(user)
    main.db.session.commit()
    jane = main.User.query.filter_by(email='jane@example.com').first()
    bob = main.User.query.filter_by(email='bob@example.com').first()
    jane_vehicle = main.Vehicle(user_id=jane.id, name='Civic', year='2020',
                                make='Honda', model='Civic')
    bob_vehicle = main.Vehicle(user_id=bob.id, name='Truck')
    main.db.session.add_all([jane_vehicle, bob_vehicle])
    main.db.session.commit()
    JANE_ID, BOB_ID = jane.id, bob.id
    JANE_VEHICLE, BOB_VEHICLE = jane_vehicle.id, bob_vehicle.id


def signed_in(email):
    client = main.app.test_client()
    client.post('/login', data={'email': email, 'password': PASSWORD},
                follow_redirects=True)
    return client


def mint(client, name='AJ', password=PASSWORD):
    return client.post('/profile/api-keys', json={'name': name, 'password': password})


def auth(key):
    return {'Authorization': f'Bearer {key}'}


# Measuring reaches Google in the real app. Stubbed so these checks never
# depend on a network or a billable call, and so the measured value is
# distinguishable from anything a request could have supplied.
MEASURED = (42.5, 1800, None)
measure_patch = patch.object(main, 'calculate_driving_miles', return_value=MEASURED)
measure_patch.start()

jane_client = signed_in('jane@example.com')
bob_client = signed_in('bob@example.com')

# ── Minting is behind the password ───────────────────────────────────────
expect('minting with no password is refused',
       mint(jane_client, password='').status_code, 403)
expect('minting with the wrong password is refused',
       mint(jane_client, password='Wrongpass123!').status_code, 403)
expect('a key needs a name', mint(jane_client, name='').status_code, 400)
expect('an anonymous caller cannot mint',
       main.app.test_client().post('/profile/api-keys',
                                   json={'name': 'x', 'password': PASSWORD}
                                   ).status_code in (302, 401), True)

minted = mint(jane_client)
expect('minting with the right password works', minted.status_code, 200)
JANE_KEY = field(minted, 'key')
JANE_KEY_ID = (field(minted, 'api_key') or {})['id']
expect('the key has the documented shape',
       bool(re.fullmatch(r'mtk_[0-9a-f]{12}\.[A-Za-z0-9_-]{40,}', JANE_KEY)), True)
expect('the response does not echo the secret under another name',
       'secret' in str((field(minted, 'api_key') or {})).lower(), False)

# ── The secret is never stored, and never rendered ──────────────────────
JANE_SECRET = JANE_KEY.split('.', 1)[1]
with main.app.app_context():
    row = main.ApiKey.query.filter_by(id=JANE_KEY_ID).first()
    expect('the database holds a hash, not the secret',
           JANE_SECRET in (row.secret_hash or ''), False)
    expect('and that hash is the sha256 of the secret',
           row.secret_hash, main._hash_api_secret(JANE_SECRET))
    expect('the public half is stored so the row can be found without scanning',
           row.public_id, JANE_KEY.split('.')[0][len(main.API_KEY_PREFIX):])

for page in ('/profile', '/'):
    body = jane_client.get(page).get_data(as_text=True)
    expect(f'the secret is not rendered into {page}', JANE_SECRET in body, False)

# ── The key works, and only for what it is allowed ──────────────────────
expect('the key can read its owner\'s vehicles',
       jane_client and main.app.test_client().get('/api/v1/vehicles',
                                                  headers=auth(JANE_KEY)).status_code, 200)
anon = main.app.test_client()
listed = anon.get('/api/v1/vehicles', headers=auth(JANE_KEY)).get_json()
expect('and sees only its own', [v['name'] for v in listed], ['Civic'])
expect('it can read businesses too',
       anon.get('/api/v1/businesses', headers=auth(JANE_KEY)).status_code, 200)

# A key is not a session. This is the property that keeps "cannot read trips"
# true without relying on hiding a page.
for path in ('/', '/history', '/profile', '/my-vehicles'):
    resp = anon.get(path, headers=auth(JANE_KEY))
    expect(f'a key does not open {path}', resp.status_code in (302, 401), True)

# There is no API route that writes reference data or touches trips.
for method, path in (('POST', '/api/v1/vehicles'), ('DELETE', '/api/v1/vehicles'),
                     ('POST', '/api/v1/businesses'), ('GET', '/api/v1/trips'),
                     ('DELETE', '/api/v1/trips')):
    code = anon.open(path, method=method, headers=auth(JANE_KEY)).status_code
    expect(f'{method} {path} is not a route', code, 405)

# ── Creating a trip ────────────────────────────────────────────────────
BODY = {'start_location': 'Lexington, MA', 'end_location': 'Newton, MA',
        'started_at': '2026-10-08T08:29', 'ended_at': '2026-10-08T09:10',
        'notes': 'site visit', 'vehicle_id': JANE_VEHICLE}

created = anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=BODY)
expect('a trip is created', created.status_code, 201)
TRIP_ID = field(created, 'id')
with main.app.app_context():
    trip = main.db.session.get(main.Trip, TRIP_ID)
    expect('for the key\'s owner', trip.user_id, JANE_ID)
    expect('the ISO datetime becomes the trip date', trip.trip_date, '2026-10-08')
    expect('and the start time', trip.start_time, '08:29')
    expect('and the end time', trip.end_time, '09:10')
    expect('and the end date', trip.end_date, '2026-10-08')
    expect('the vehicle is attached', trip.vehicle_id, JANE_VEHICLE)

# Measured, not asserted. A supplied value must lose to the measurement.
supplied = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                     json={**BODY, 'miles': 999.0})
expect('a supplied mileage does not override the measurement',
       field(supplied, 'miles'), MEASURED[0])

# ...but is used when measuring produces nothing, which is the whole point of
# keeping it in the contract.
measure_patch.stop()
with patch.object(main, 'calculate_driving_miles', side_effect=RuntimeError('no route')):
    fell_back = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                          json={**BODY, 'miles': 8.47})
    expect('a supplied mileage is used when measuring fails',
           field(fell_back, 'miles'), 8.47)
    no_value = anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=BODY)
    expect('and a trip with neither is still recorded, without a distance',
           (no_value.status_code, field(no_value, 'miles')), (201, None))
measure_patch.start()

# ── Numbers arriving as JSON ──────────────────────────────────────────
# This endpoint takes arbitrary JSON, so float() and int() on its values are
# not conversions but trust. json parses the bare NaN and Infinity literals,
# and a NaN stored as a mileage poisons every total it is summed into -- then
# jsonify emits it back as a bare NaN, which is not valid JSON at all, so the
# history stops parsing rather than showing a wrong number.
with patch.object(main, 'calculate_driving_miles', side_effect=RuntimeError('no route')):
    for bad, label in ((float('nan'), 'NaN'), (float('inf'), 'Infinity'),
                       ('nan', 'the string "nan"'), ('inf', 'the string "inf"'),
                       (-5, 'a negative mileage'), (10 ** 9, 'an absurd mileage'),
                       ('abc', 'a non-numeric mileage'), ([1], 'a list')):
        resp = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                         json={**BODY, 'miles': bad})
        expect(f'{label} is refused rather than stored', resp.status_code, 422)

    # And nothing non-finite reached the database on the way to being refused.
    with main.app.app_context():
        stored = [t.distance_miles for t in main.Trip.query.all()
                  if t.distance_miles is not None]
        expect('no stored mileage is non-finite',
               all(math.isfinite(m) for m in stored), True)
        expect('and none is negative', all(m >= 0 for m in stored), True)

# An id that is not an id must drop the attribution, not return a 500.
for bad, label in (('abc', 'a non-numeric vehicle_id'), ('1.5', 'a fractional id'),
                   ([1], 'a list as an id'), (True, 'a boolean as an id')):
    resp = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                     json={**BODY, 'vehicle_id': bad})
    expect(f'{label} does not crash the request', resp.status_code, 201)
    expect(f'{label} attaches no vehicle', field(resp, 'vehicle'), None)

resp = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                 json={**BODY, 'business_id': 'abc'})
expect('a non-numeric business_id does not crash either', resp.status_code, 201)
expect('and attaches no business', field(resp, 'business'), None)

# ── The payload contract ──────────────────────────────────────────────
old_spec = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                     json={'start': 'a', 'end': 'b', 'from': 'c', 'to': 'd'})
expect('the earlier draft\'s field names are refused', old_spec.status_code, 422)
expect('and the error says which fields to use instead',
       'started_at' in field(old_spec, 'error'), True)
expect('and explains the collision rather than only listing fields',
       'locations here' in field(old_spec, 'error'), True)

tz = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
               json={**BODY, 'started_at': '2026-10-08T08:29+00:00'})
expect('an offset-aware datetime is refused rather than converted', tz.status_code, 422)
expect('and says why', 'local' in field(tz, 'error'), True)

for bad, label in (({**BODY, 'start_location': ''}, 'a blank start location'),
                   ({**BODY, 'started_at': 'yesterday'}, 'an unparseable datetime'),
                   ({k: v for k, v in BODY.items() if k != 'started_at'}, 'a missing start')):
    expect(f'{label} is refused',
           anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=bad).status_code, 422)
expect('a non-object body is refused',
       anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=[1, 2]).status_code, 422)

# ── The logging key relationship ─────────────────────────────────────
# The API deliberately does not ask for it; the form still must.
expect('the API does not require the per-trip logging key',
       anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=BODY).status_code, 201)
expect('while /log still does',
       jane_client.post('/log', json={'start': 'a', 'end': 'b',
                                      'trip_date': '2026-10-08'}).status_code, 403)

# ── One account's key cannot reach another's ─────────────────────────
bob_key = field(mint(bob_client, name='bob script'), 'key')
expect('a key cannot attach another user\'s vehicle',
       field(anon.post('/api/v1/trips', headers=auth(bob_key),
                       json={**BODY, 'vehicle_id': JANE_VEHICLE}), 'vehicle'), None)
with main.app.app_context():
    expect('and the trip belongs to the key\'s owner, not the vehicle\'s',
           main.Trip.query.order_by(main.Trip.id.desc()).first().user_id, BOB_ID)
expect('one user cannot revoke another\'s key',
       bob_client.delete(f'/profile/api-keys/{JANE_KEY_ID}').status_code, 404)

# ── Bad keys ────────────────────────────────────────────────────────
for label, header in (('a missing header', {}),
                      ('a non-bearer scheme', {'Authorization': f'Basic {JANE_KEY}'}),
                      ('a malformed key', {'Authorization': 'Bearer mtk_nodot'}),
                      ('an unknown public id', {'Authorization': 'Bearer mtk_ffffffffffff.whatever'}),
                      ('the right public id with a wrong secret',
                       {'Authorization': f'Bearer {JANE_KEY.split(".")[0]}.wrongsecret'})):
    resp = anon.post('/api/v1/trips', headers=header, json=BODY)
    expect(f'{label} is refused', resp.status_code, 401)
    expect(f'{label} gets the same message as any other',
           field(resp, 'error'), 'Invalid or missing API key.')

# ── Revoking ───────────────────────────────────────────────────────
expect('revoking does not need the password',
       jane_client.delete(f'/profile/api-keys/{JANE_KEY_ID}').status_code, 200)
expect('a revoked key stops working at once',
       anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=BODY).status_code, 401)
with main.app.app_context():
    row = main.ApiKey.query.filter_by(id=JANE_KEY_ID).first()
    expect('the row survives revocation so its history stays visible',
           row is not None and row.revoked_at is not None, True)
expect('revoking twice is not an error',
       jane_client.delete(f'/profile/api-keys/{JANE_KEY_ID}').status_code, 200)

# ── last_used_at ───────────────────────────────────────────────────
fresh = mint(jane_client, name='fresh').get_json()
with main.app.app_context():
    expect('a new key has never been used',
           main.ApiKey.query.filter_by(id=fresh['api_key']['id']).first().last_used_at, None)
anon.get('/api/v1/vehicles', headers=auth(fresh['key']))
with main.app.app_context():
    expect('and records its use, which is the only monitoring this design has',
           main.ApiKey.query.filter_by(id=fresh['api_key']['id']).first().last_used_at
           is not None, True)

# A rejected request still counts as use: the question is whether something is
# using the key, not whether it is succeeding.
bad_body = mint(jane_client, name='rejected').get_json()
anon.post('/api/v1/trips', headers=auth(bad_body['key']), json={'start': 'x'})
with main.app.app_context():
    expect('a rejected request still marks the key as used',
           main.ApiKey.query.filter_by(id=bad_body['api_key']['id']).first().last_used_at
           is not None, True)

# ── The per-key rate limit ──────────────────────────────────────────
# Bounds a runaway loop or a key being used by something other than what it
# was issued to. Counted on the key's own row, so these checks also confirm
# the window rolls over rather than only that a limit exists.
limited = mint(jane_client, name='busy').get_json()
LIMITED_KEY = limited['key']
LIMITED_ID = limited['api_key']['id']

codes = [anon.get('/api/v1/vehicles', headers=auth(LIMITED_KEY)).status_code
         for _ in range(main.API_RATE_LIMIT)]
expect('every request up to the limit is served', set(codes), {200})

over = anon.get('/api/v1/vehicles', headers=auth(LIMITED_KEY))
expect('the next one is refused', over.status_code, 429)
expect('and says what the limit is',
       str(main.API_RATE_LIMIT) in err(over), True)
expect('writing is refused too, not just reading',
       anon.post('/api/v1/trips', headers=auth(LIMITED_KEY), json=BODY).status_code, 429)

# A different key must have its own budget, or one busy client would stop
# every other.
other = mint(jane_client, name='quiet').get_json()['key']
expect('another key of the same account is unaffected',
       anon.get('/api/v1/vehicles', headers=auth(other)).status_code, 200)

# The window rolls over rather than locking the key out for ever.
with main.app.app_context():
    row = main.ApiKey.query.filter_by(id=LIMITED_ID).first()
    row.window_started_at = main._utcnow() - main.API_RATE_WINDOW - main.timedelta(minutes=1)
    main.db.session.commit()
expect('once the window has passed the key works again',
       anon.get('/api/v1/vehicles', headers=auth(LIMITED_KEY)).status_code, 200)
with main.app.app_context():
    expect('and the count restarted rather than carrying over',
           main.ApiKey.query.filter_by(id=LIMITED_ID).first().window_count, 1)

# A rejected body still spends budget: a loop sending malformed requests is
# exactly what the limit is for.
spender = mint(jane_client, name='malformed').get_json()
for _ in range(3):
    anon.post('/api/v1/trips', headers=auth(spender['key']), json={'start': 'x'})
with main.app.app_context():
    expect('requests that fail validation are still counted',
           main.ApiKey.query.filter_by(id=spender['api_key']['id']).first().window_count, 3)

# A revoked key must not be countable at all -- it never reaches the counter.
revoked = mint(jane_client, name='doomed').get_json()
jane_client.delete(f"/profile/api-keys/{revoked['api_key']['id']}")
anon.get('/api/v1/vehicles', headers=auth(revoked['key']))
with main.app.app_context():
    expect('a revoked key is rejected before it can spend anything',
           main.ApiKey.query.filter_by(id=revoked['api_key']['id']).first().window_count,
           None)

measure_patch.stop()
os.unlink(_db.name)

if failures:
    print('API key check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('API key check OK — keys are hashed and never rendered, scoped to their '
      f'owner, not a session, revocable, and capped at {main.API_RATE_LIMIT} '
      'requests per window.')
