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
  - a trip logged by a key is identifiable as such afterwards, by which key
  - a key can do only what it was created with, and each scope gates exactly
    the routes that need it

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


def mint(client, name='AJ', password=PASSWORD, scopes=tuple(main.API_SCOPES)):
    # Every permission unless a check says otherwise, so the checks that are
    # about something other than permissions are not also testing them.
    return client.post('/profile/api-keys',
                       json={'name': name, 'password': password, 'scopes': list(scopes)})


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
                     ('POST', '/api/v1/businesses'), ('PATCH', '/api/v1/trips'),
                     ('DELETE', '/api/v1/trips')):
    code = anon.open(path, method=method, headers=auth(JANE_KEY)).status_code
    expect(f'{method} {path} is not a route', code, 405)

# ── Creating a trip ────────────────────────────────────────────────────
BODY = {'start_location': 'Lexington, MA', 'end_location': 'Newton, MA',
        'started_at': '2026-10-08T08:29', 'ended_at': '2026-10-08T09:10',
        'notes': 'site visit', 'vehicle_id': JANE_VEHICLE}

_body_day = [0]


def body(extra=None):
    """BODY on a day of its own, plus any overrides.

    The API now refuses a trip that overlaps one already logged, so the many
    checks below that each post "a trip" would refuse each other if they all
    used the same hours. Each call moves a day on; the first is BODY exactly.
    """
    from datetime import date, timedelta
    day = date(2026, 10, 8) + timedelta(days=_body_day[0])
    _body_day[0] += 1
    shifted = {**BODY,
               'started_at': f'{day}T08:29', 'ended_at': f'{day}T09:10'}
    return {**shifted, **(extra or {})}


created = anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=body())
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
                     json=body({'miles': 999.0}))
expect('a supplied mileage does not override the measurement',
       field(supplied, 'miles'), MEASURED[0])

# ...but is used when measuring produces nothing, which is the whole point of
# keeping it in the contract.
measure_patch.stop()
with patch.object(main, 'calculate_driving_miles', side_effect=RuntimeError('no route')):
    fell_back = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                          json=body({'miles': 8.47}))
    expect('a supplied mileage is used when measuring fails',
           field(fell_back, 'miles'), 8.47)
    no_value = anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=body())
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
                         json=body({'miles': bad}))
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
                     json=body({'vehicle_id': bad}))
    expect(f'{label} does not crash the request', resp.status_code, 201)
    expect(f'{label} attaches no vehicle', field(resp, 'vehicle'), None)

resp = anon.post('/api/v1/trips', headers=auth(JANE_KEY),
                 json=body({'business_id': 'abc'}))
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
               json=body({'started_at': '2026-10-08T08:29+00:00'}))
expect('an offset-aware datetime is refused rather than converted', tz.status_code, 422)
expect('and says why', 'local' in field(tz, 'error'), True)

for bad, label in ((body({'start_location': ''}), 'a blank start location'),
                   (body({'started_at': 'yesterday'}), 'an unparseable datetime'),
                   ({k: v for k, v in BODY.items() if k != 'started_at'}, 'a missing start')):
    expect(f'{label} is refused',
           anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=bad).status_code, 422)
expect('a non-object body is refused',
       anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=[1, 2]).status_code, 422)

# ── The logging key relationship ─────────────────────────────────────
# The API deliberately does not ask for it; the form still must.
expect('the API does not require the per-trip logging key',
       anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=body()).status_code, 201)
expect('while /log still does',
       jane_client.post('/log', json={'start': 'a', 'end': 'b',
                                      'trip_date': '2026-10-08'}).status_code, 403)

# ── One account's key cannot reach another's ─────────────────────────
bob_key = field(mint(bob_client, name='bob script'), 'key')
expect('a key cannot attach another user\'s vehicle',
       field(anon.post('/api/v1/trips', headers=auth(bob_key),
                       json=body({'vehicle_id': JANE_VEHICLE})), 'vehicle'), None)
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
    resp = anon.post('/api/v1/trips', headers=header, json=body())
    expect(f'{label} is refused', resp.status_code, 401)
    expect(f'{label} gets the same message as any other',
           field(resp, 'error'), 'Invalid or missing API key.')

# ── Revoking ───────────────────────────────────────────────────────
expect('revoking does not need the password',
       jane_client.delete(f'/profile/api-keys/{JANE_KEY_ID}').status_code, 200)
expect('a revoked key stops working at once',
       anon.post('/api/v1/trips', headers=auth(JANE_KEY), json=body()).status_code, 401)
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
       anon.post('/api/v1/trips', headers=auth(LIMITED_KEY), json=body()).status_code, 429)

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

# ── The audit trail ────────────────────────────────────────────────
# The point of a key being narrow is undermined if nobody can tell afterwards
# what it did. A trip has to be traceable to the key that logged it, and to
# stay traceable after that key is revoked.
audited = mint(jane_client, name='auditor').get_json()
made = anon.post('/api/v1/trips', headers=auth(audited['key']), json=body())
AUDIT_TRIP = made.get_json()['id']

with main.app.app_context():
    trip = main.db.session.get(main.Trip, AUDIT_TRIP)
    expect('an API-logged trip records that it came from the API',
           trip.created_via, 'api')
    expect('and which key logged it',
           trip.created_by_key_id, audited['api_key']['id'])

rows = {t['id']: t for t in jane_client.get('/history').get_json()}
expect('the history marks it', rows[AUDIT_TRIP]['via_api'], True)
expect('and names the key', rows[AUDIT_TRIP]['via_api_key'], 'auditor')

# Revoking must not erase the attribution: "logged by a key, since revoked" is
# exactly what someone reviewing the log needs.
jane_client.delete(f"/profile/api-keys/{audited['api_key']['id']}")
rows = {t['id']: t for t in jane_client.get('/history').get_json()}
expect('revoking the key leaves the trip attributed to it',
       rows[AUDIT_TRIP]['via_api_key'], 'auditor')
expect('and still marked as API-logged', rows[AUDIT_TRIP]['via_api'], True)

# A form-logged trip is distinguishable, which is the other half of the point.
logging_key = main.normalize_logging_key(
    jane_client.post('/profile/logging-key', json={'password': PASSWORD})
    .get_json()['logging_key'])
web = jane_client.post('/log', json={'start': 'C', 'end': 'D',
                                     'trip_date': '2026-10-08',
                                     'logging_key': logging_key})
expect('a form-logged trip still logs', web.status_code, 200)
WEB_TRIP = web.get_json()['trip']['id']
rows = {t['id']: t for t in jane_client.get('/history').get_json()}
expect('and is not marked as API-logged', rows[WEB_TRIP]['via_api'], False)
expect('with no key attributed', rows[WEB_TRIP]['via_api_key'], None)
with main.app.app_context():
    expect('recorded as coming from the web',
           main.db.session.get(main.Trip, WEB_TRIP).created_via, 'web')

# ── Per-key permissions ─────────────────────────────────────────────────
def scoped_key(*scopes):
    resp = mint(jane_client, name='scoped ' + '+'.join(scopes), scopes=scopes)
    expect(f'a key with {scopes} is created', resp.status_code, 200)
    return field(resp, 'key')


_made = [0]


def make_trip(user_id=None, **over):
    """A trip row inserted directly, on a day of its own, and its id."""
    from datetime import date, timedelta
    _made[0] += 1
    day = date(2025, 1, 1) + timedelta(days=_made[0])
    fields = dict(user_id=user_id or JANE_ID, start_location='M1', end_location='M2',
                  trip_date=str(day), start_time='08:00', end_time='09:00',
                  end_date=str(day), distance_miles=5.0, duration_seconds=1800,
                  created_via='web')
    fields.update(over)
    with main.app.app_context():
        t = main.Trip(**fields)
        main.db.session.add(t)
        main.db.session.commit()
        return t.id


ROUTES = {
    'trips:create':    lambda c, k: c.post('/api/v1/trips', headers=auth(k),
                                           json=body({'started_at': '2026-11-01T08:00',
                                                 'ended_at': '2026-11-01T08:30'})),
    'trips:read':      lambda c, k: c.get('/api/v1/trips', headers=auth(k)),
    'trips:update':    lambda c, k: c.patch(f'/api/v1/trips/{make_trip()}', headers=auth(k),
                                            json={'notes': 'edited'}),
    'trips:delete':    lambda c, k: c.delete(f'/api/v1/trips/{make_trip()}', headers=auth(k)),
    'vehicles:read':   lambda c, k: c.get('/api/v1/vehicles', headers=auth(k)),
    'businesses:read': lambda c, k: c.get('/api/v1/businesses', headers=auth(k)),
}
expect('every scope has a route under test', set(ROUTES), set(main.API_SCOPES))

# Each key holds exactly one scope; it must open its own route and no other.
for held in main.API_SCOPES:
    k = scoped_key(held)
    for needed, call in ROUTES.items():
        code = call(anon, k).status_code
        if needed == held:
            expect(f'a key holding only {held} opens {needed}', code in (200, 201), True)
        else:
            expect(f'a key holding only {held} is refused {needed}', code, 403)

refused = ROUTES['trips:create'](anon, scoped_key('vehicles:read'))
expect('the refusal names the missing permission',
       'trips:create' in err(refused), True)
with main.app.app_context():
    before = main.Trip.query.filter_by(user_id=JANE_ID).count()
ROUTES['trips:create'](anon, scoped_key('businesses:read'))
with main.app.app_context():
    expect('and a refused trip is not logged',
           main.Trip.query.filter_by(user_id=JANE_ID).count(), before)

# A refused request still spends the budget and shows the key as used: probing
# for what a key can reach must not be free.
probe = scoped_key('vehicles:read')
ROUTES['trips:create'](anon, probe)
with main.app.app_context():
    row = main.ApiKey.query.filter_by(
        public_id=main.parse_api_key(probe)[0]).first()
    expect('a refused request still counts as use', row.last_used_at is not None, True)
    expect('and spends the budget', row.window_count, 1)

# A bad key is still a 401, not a 403: a missing scope must not be how someone
# learns that a key exists.
expect('an unknown key is 401 on a scoped route',
       ROUTES['trips:create'](anon, 'mtk_000000000000.' + 'a' * 43).status_code, 401)

both = scoped_key('vehicles:read', 'businesses:read')
expect('a key can hold several permissions at once',
       (ROUTES['vehicles:read'](anon, both).status_code,
        ROUTES['businesses:read'](anon, both).status_code,
        ROUTES['trips:create'](anon, both).status_code), (200, 200, 403))

# Creation must say what the key may do.
for label, body in (('no scopes field', {}),
                    ('an empty list', {'scopes': []}),
                    ('a string instead of a list', {'scopes': 'trips:create'}),
                    ('a non-string entry', {'scopes': [1]}),
                    ('an unknown scope', {'scopes': ['trips:create', 'trips:purge']}),
                    ('only unknown scopes', {'scopes': ['admin']})):
    resp = jane_client.post('/profile/api-keys',
                            json={'name': 'x', 'password': PASSWORD, **body})
    expect(f'creating with {label} is refused', resp.status_code, 400)

with main.app.app_context():
    n = main.ApiKey.query.filter_by(user_id=JANE_ID).count()
jane_client.post('/profile/api-keys', json={'name': 'x', 'password': PASSWORD})
with main.app.app_context():
    expect('and a refused creation stores nothing',
           main.ApiKey.query.filter_by(user_id=JANE_ID).count(), n)

# Duplicates and ordering are normalised; the key is never widened by repeating.
dup = mint(jane_client, name='dup', scopes=['vehicles:read', 'vehicles:read'])
expect('repeating a scope is harmless', field(dup, 'api_key', {}).get('scopes'),
       ['vehicles:read'])

# The profile shows what each key holds, and the form offers every scope.
page = jane_client.get('/profile').get_data(as_text=True)
for name in main.API_SCOPES:
    expect(f'the profile form offers {name}', f'value="{name}"' in page, True)

# A blank or unrecognised stored value grants nothing, never everything.
expect('a blank stored value grants nothing', main.parse_scopes(''), [])
expect('a missing stored value grants nothing', main.parse_scopes(None), [])
expect('unrecognised names are dropped', main.parse_scopes('trips:create,root'),
       ['trips:create'])

# The decorator refuses to be applied without a real scope, so a route cannot
# be added that is open to every key by accident.
for bad in ('trips:purge', None):
    try:
        main.api_key_required(bad)
        expect(f'api_key_required({bad!r}) is rejected', 'accepted', 'rejected')
    except ValueError:
        pass
try:
    main.api_key_required(lambda: None)
    expect('using the decorator bare is rejected', 'accepted', 'rejected')
except ValueError:
    pass

# ── Duplicates through the API ──────────────────────────────────────────
dkey = scoped_key(*main.API_SCOPES)
DUP = {'start_location': 'Dup Start', 'end_location': 'Dup End',
       'started_at': '2026-09-01T09:00', 'ended_at': '2026-09-01T10:00'}
first = anon.post('/api/v1/trips', headers=auth(dkey), json=DUP)
expect('a fresh trip logs', first.status_code, 201)
with main.app.app_context():
    count = main.Trip.query.filter_by(user_id=JANE_ID).count()

again = anon.post('/api/v1/trips', headers=auth(dkey), json=DUP)
expect('the identical trip again is refused', again.status_code, 409)
expect('and cannot be confirmed through', field(again, 'can_confirm'), False)
expect('and describes the first', field(again, 'existing', {}).get('id'), field(first, 'id'))
overlap = anon.post('/api/v1/trips', headers=auth(dkey),
                    json={**DUP, 'started_at': '2026-09-01T09:30', 'ended_at': '2026-09-01T10:30'})
expect('an overlapping window is refused', overlap.status_code, 409)
with main.app.app_context():
    expect('none of those was logged', main.Trip.query.filter_by(user_id=JANE_ID).count(), count)

after = anon.post('/api/v1/trips', headers=auth(dkey),
                  json={**DUP, 'started_at': '2026-09-01T10:00', 'ended_at': '2026-09-01T11:00'})
expect('back-to-back on the same route is a genuine pair', after.status_code, 201)
reverse = anon.post('/api/v1/trips', headers=auth(dkey),
                    json={**DUP, 'start_location': 'Dup End', 'end_location': 'Dup Start'})
expect('the return leg is not a duplicate', reverse.status_code, 201)

# No end time: an identical start still overlaps as an instant.
UNTIMED = {'start_location': 'U1', 'end_location': 'U2', 'started_at': '2026-09-02T09:00'}
expect('a trip with no end time logs', anon.post('/api/v1/trips', headers=auth(dkey), json=UNTIMED).status_code, 201)
again_u = anon.post('/api/v1/trips', headers=auth(dkey), json=UNTIMED)
expect('the same start again is refused', (again_u.status_code, field(again_u, 'can_confirm')), (409, False))
expect('confirm_duplicate is not a field', anon.post('/api/v1/trips', headers=auth(dkey),
       json={**UNTIMED, 'confirm_duplicate': True}).status_code, 422)

# Another account's identical trip is not a duplicate.
bob_key = field(mint(bob_client, name='bobs'), 'key')
expect('another account may log the same trip',
       anon.post('/api/v1/trips', headers=auth(bob_key), json=DUP).status_code, 201)

# A refused duplicate must not spend a Routes call.
calls = []
with patch.object(main, 'calculate_driving_miles',
                  side_effect=lambda *a, **k: calls.append(1) or MEASURED):
    anon.post('/api/v1/trips', headers=auth(dkey), json=DUP)
expect('a refused duplicate makes no distance lookup', calls, [])

# ── Reading trips ───────────────────────────────────────────────────────
tk = scoped_key('trips:read', 'trips:update', 'trips:delete')
bob_trip = make_trip(user_id=BOB_ID, notes='bobs secret')
with main.app.app_context():
    jane_total = main.Trip.query.filter_by(user_id=JANE_ID).count()

listing = anon.get('/api/v1/trips', headers=auth(tk)).get_json()
expect('the list reports the owner\'s total', listing['total'], jane_total)
expect('and returns the default page', len(listing['trips']), min(50, jane_total))
expect('the list never includes another account\'s trips',
       bob_trip in [t['id'] for t in listing['trips']], False)
expect('nor their notes', 'bobs secret' in str(listing), False)
# By date, then most recently logged -- the order the history page uses.
dates = [(t['started_at'] or '')[:10] for t in listing['trips']]
expect('newest first', dates, sorted(dates, reverse=True))
sample = listing['trips'][0]
expect('a trip carries the API\'s own field names',
       {'id', 'start_location', 'end_location', 'started_at', 'ended_at', 'miles',
        'notes', 'stops', 'vehicle_id', 'business_id', 'logged_via'} <= set(sample), True)
expect('and no attachments or place ids',
       {'attachments', 'start_place_id', 'end_place_id'} & set(sample), set())
one = anon.get(f'/api/v1/trips/{TRIP_ID}', headers=auth(tk)).get_json()
expect('one trip reads back with ISO times', (one['started_at'], one['ended_at']),
       ('2026-10-08T08:29', '2026-10-08T09:10'))
expect('and says it was logged by the API', one['logged_via'], 'api')
expect('another account\'s trip is a 404, like one that does not exist',
       (anon.get(f'/api/v1/trips/{bob_trip}', headers=auth(tk)).status_code,
        anon.get('/api/v1/trips/999999', headers=auth(tk)).status_code), (404, 404))

page = anon.get('/api/v1/trips?limit=2&offset=1', headers=auth(tk)).get_json()
expect('paging honours limit', len(page['trips']), 2)
expect('and offset', [t['id'] for t in page['trips']],
       [t['id'] for t in listing['trips'][1:3]])
for q in ('limit=0', 'limit=201', 'limit=abc', 'offset=-1', 'limit=1.5'):
    expect(f'?{q} is refused', anon.get(f'/api/v1/trips?{q}', headers=auth(tk)).status_code, 422)

# ── Editing trips ───────────────────────────────────────────────────────
def edit(trip_id, body, key=None):
    return anon.patch(f'/api/v1/trips/{trip_id}', headers=auth(key or tk), json=body)

t1 = make_trip(start_location='E1', end_location='E2', trip_date='2026-08-01',
               start_time='09:00', end_time='10:00', end_date='2026-08-01', notes='orig')
t2 = make_trip(start_location='E1', end_location='E2', trip_date='2026-08-01',
               start_time='11:00', end_time='12:00', end_date='2026-08-01')
calls = []
with patch.object(main, 'calculate_driving_miles',
               side_effect=lambda *a, **k: calls.append(a) or (7.7, 900, None)):
    r = edit(t1, {'notes': 'changed'})
    expect('a notes-only edit succeeds', (r.status_code, field(r, 'notes')), (200, 'changed'))
    expect('and leaves everything else', (field(r, 'start_location'), field(r, 'miles')), ('E1', 5.0))
    expect('and does not re-measure', calls, [])
    expect('a null note clears it', field(edit(t1, {'notes': None}), 'notes'), None)

    r = edit(t1, {'end_location': 'E9'})
    expect('changing a location re-measures server-side',
           (r.status_code, field(r, 'miles'), field(r, 'duration_seconds')), (200, 7.7, 900))
    expect('with one measurement', len(calls), 1)
    r = edit(t1, {'end_location': 'E2', 'miles': 999})
    expect('a supplied mileage never overrides a measurement', field(r, 'miles'), 7.7)
    r = edit(t1, {'notes': 'x', 'miles': 999})
    expect('and is ignored when the route did not change', field(r, 'miles'), 7.7)

with patch.object(main, 'calculate_driving_miles', side_effect=RuntimeError('no route')):
    r = edit(t1, {'end_location': 'E8'})
    expect('an unmeasurable new route leaves no stale mileage', field(r, 'miles'), None)
    r = edit(t1, {'end_location': 'E7', 'miles': 12.5})
    expect('the supplied mileage is only the fallback', field(r, 'miles'), 12.5)
    expect('a bad fallback is refused', edit(t1, {'end_location': 'E6', 'miles': -1}).status_code, 422)

# Times move together, and obey the same validators as logging.
expect('started_at without ended_at is refused',
       edit(t1, {'started_at': '2026-08-01T09:00'}).status_code, 422)
expect('ended_at without started_at is refused',
       edit(t1, {'ended_at': '2026-08-01T10:00'}).status_code, 422)
expect('an offset-aware time is refused',
       edit(t1, {'started_at': '2026-08-01T09:00+00:00', 'ended_at': None}).status_code, 422)
expect('an end before the start is refused',
       edit(t1, {'started_at': '2026-08-01T09:00', 'ended_at': '2026-08-01T08:00'}).status_code, 422)
moved = edit(t1, {'started_at': '2026-08-02T09:00', 'ended_at': '2026-08-02T10:15'})
expect('times move together', (moved.status_code, field(moved, 'started_at'), field(moved, 'ended_at')),
       (200, '2026-08-02T09:00', '2026-08-02T10:15'))
cleared = edit(t1, {'started_at': '2026-08-02T09:00', 'ended_at': None})
expect('ended_at may be cleared', field(cleared, 'ended_at'), None)

# The overlap rule, and that a trip never collides with itself.
with patch.object(main, 'calculate_driving_miles', return_value=(5.0, 900, None)):
    edit(t1, {'end_location': 'E2', 'started_at': '2026-08-01T09:00', 'ended_at': '2026-08-01T10:00'})
    own = edit(t1, {'started_at': '2026-08-01T09:15', 'ended_at': '2026-08-01T09:45'})
    expect('moving a trip within its own hours is allowed', own.status_code, 200)
    into = edit(t1, {'started_at': '2026-08-01T11:30', 'ended_at': '2026-08-01T11:45'})
    expect('moving into another trip\'s hours is refused', into.status_code, 409)
    expect('and cannot be confirmed through', field(into, 'can_confirm'), False)
    expect('and names the trip in the way', field(into, 'existing', {}).get('id'), t2)
    kept = anon.get(f'/api/v1/trips/{t1}', headers=auth(tk)).get_json()
    expect('a refused edit changes nothing', kept['started_at'], '2026-08-01T09:15')
    adj = edit(t1, {'started_at': '2026-08-01T10:00', 'ended_at': '2026-08-01T10:30'})
    expect('moving to an adjacent free slot is allowed', adj.status_code, 200)
    # The overlap rule is only applied when the route or hours move.
    # Inserted straight into the table, as one logged before the overlap rule
    # existed would be: it overlaps t2 (11:00-12:00) and always has.
    t3 = make_trip(start_location='E1', end_location='E2', trip_date='2026-08-01',
                   start_time='11:30', end_time='11:45', end_date='2026-08-01')
    with main.app.app_context():
        row = main.db.session.get(main.Trip, t3)
        clash = main.find_overlapping_trip(
            JANE_ID, 'E1', 'E2', '2026-08-01',
            main._trip_window('2026-08-01', '11:30', '11:45', '2026-08-01', None),
            exclude_trip_id=t3)
        expect('(t3 overlaps t2)', clash.id if clash else None, t2)
    expect('a notes-only edit is not refused for a pre-existing overlap',
           edit(t3, {'notes': 'ok'}).status_code, 200)

# Vehicles and businesses on an edit.
other_vehicle = main.app.test_client()
with main.app.app_context():
    bobs_v = main.Vehicle.query.filter_by(user_id=BOB_ID).first().id
r = edit(t2, {'vehicle_id': JANE_VEHICLE})
expect('a vehicle can be attached', (r.status_code, field(r, 'vehicle_id')), (200, JANE_VEHICLE))
expect('a mistyped vehicle id is refused, not silently cleared',
       edit(t2, {'vehicle_id': 987654}).status_code, 422)
expect('another account\'s vehicle is refused', edit(t2, {'vehicle_id': bobs_v}).status_code, 422)
expect('and the vehicle was kept',
       anon.get(f'/api/v1/trips/{t2}', headers=auth(tk)).get_json()['vehicle_id'], JANE_VEHICLE)
expect('null clears the vehicle', field(edit(t2, {'vehicle_id': None}), 'vehicle_id'), None)
expect('a bad business id is refused', edit(t2, {'business_id': 987654}).status_code, 422)

# Malformed edits.
for label, body in (('an empty object', {}), ('an unknown field', {'color': 'red'}),
                    ('the old names', {'start': 'x'}), ('a non-string note', {'notes': 5}),
                    ('a non-string location', {'start_location': 5}),
                    ('a blank location', {'start_location': '  '}),
                    ('too many stops', {'stops': ['s'] * 11})):
    expect(f'an edit with {label} is refused', edit(t2, body).status_code, 422)
expect('a list body is refused', anon.patch(f'/api/v1/trips/{t2}', headers=auth(tk),
                                            json=[1]).status_code, 422)
expect('another account\'s trip cannot be edited', edit(bob_trip, {'notes': 'pwned'}).status_code, 404)
with main.app.app_context():
    expect('and was not', main.db.session.get(main.Trip, bob_trip).notes, 'bobs secret')

# ── Deleting trips ──────────────────────────────────────────────────────
doomed = make_trip()
with main.app.app_context():
    main.db.session.add(main.TripAttachment(trip_id=doomed, filename='r.png',
                                            mimetype='image/png', byte_size=3, data=b'abc'))
    main.db.session.commit()
gone = anon.delete(f'/api/v1/trips/{doomed}', headers=auth(tk))
expect('a trip is deleted', (gone.status_code, field(gone, 'deleted')), (200, doomed))
with main.app.app_context():
    expect('the trip is gone', main.db.session.get(main.Trip, doomed), None)
    expect('and so are its attachments',
           main.TripAttachment.query.filter_by(trip_id=doomed).count(), 0)
expect('deleting it again is a 404',
       anon.delete(f'/api/v1/trips/{doomed}', headers=auth(tk)).status_code, 404)
expect('another account\'s trip cannot be deleted',
       anon.delete(f'/api/v1/trips/{bob_trip}', headers=auth(tk)).status_code, 404)
with main.app.app_context():
    expect('and survives', main.db.session.get(main.Trip, bob_trip) is not None, True)

# Holding one of the three does not grant the others.
only_read = scoped_key('trips:read')
victim = make_trip()
expect('a read-only key cannot edit', edit(victim, {'notes': 'x'}, key=only_read).status_code, 403)
expect('or delete',
       anon.delete(f'/api/v1/trips/{victim}', headers=auth(only_read)).status_code, 403)
with main.app.app_context():
    expect('and the trip is untouched', main.db.session.get(main.Trip, victim).notes, None)
only_delete = scoped_key('trips:delete')
expect('a delete-only key cannot read', 
       anon.get(f'/api/v1/trips/{victim}', headers=auth(only_delete)).status_code, 403)

# Old keys keep exactly what they had, and nothing newer.
expect('the new scopes are opt-in at creation',
       set(main.API_DEFAULT_SCOPES) & {'trips:read', 'trips:update', 'trips:delete'}, set())
expect('and legacy keys are backfilled with only the original three',
       set(main.API_LEGACY_SCOPES), {'trips:create', 'vehicles:read', 'businesses:read'})
page = jane_client.get('/profile').get_data(as_text=True)
for name in ('trips:read', 'trips:update', 'trips:delete'):
    tag = [l for l in page.splitlines() if f'value="{name}"' in l][0]
    expect(f'{name} is not pre-ticked in the form', 'checked' in tag, False)
expect('trips:create is pre-ticked',
       'checked' in [l for l in page.splitlines() if 'value="trips:create"' in l][0], True)

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
