"""Check that no request an API key can make breaks the app.

A key is a credential handed to something outside the browser -- a script, an
assistant -- so unlike a form it cannot be assumed to send what the page would.
It can send anything, and what matters is that the worst it can do is be
refused:

  - no input produces a server error (a 500 is a bug a caller can trigger)
  - no input stores something the production database cannot hold or the pages
    cannot cope with: a lone surrogate or NUL byte (Postgres refuses both), or
    a string large enough to bloat every page that lists it
  - one runaway key cannot fill an account's history

SQLite, which CI and local development use, accepts all of those, so a check
that only looked for 500s would pass on exactly the inputs that fail in
production. The stored data is inspected as well as the status code.

Driven from the URL map rather than a hand-kept list, so a route added later is
fuzzed without anyone remembering to add it here.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import json
import os
import re
import sys
import tempfile
from datetime import date, timedelta
from unittest.mock import patch

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'api-robustness-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


main.app.config['TESTING'] = True
# See check_api_keys.py: without this a 500 re-raises and aborts the script
# instead of being reported as the failure it is.
main.app.config['PROPAGATE_EXCEPTIONS'] = False
# Thousands of deliberately bad requests; the failures are reported below, so
# the per-request log lines are only noise.
main.app.logger.setLevel('CRITICAL')

with main.app.app_context():
    main.db.create_all()
    user = main.User(username='fuzz', email='fuzz@example.com')
    user.set_password(PASSWORD)
    main.db.session.add(user)
    main.db.session.commit()
    USER_ID = user.id
    vehicle = main.Vehicle(user_id=USER_ID, name='Civic')
    business = main.Business(user_id=USER_ID, name='Acme')
    main.db.session.add_all([vehicle, business])
    main.db.session.commit()
    VEHICLE_ID, BUSINESS_ID = vehicle.id, business.id

browser = main.app.test_client()
browser.post('/login', data={'email': 'fuzz@example.com', 'password': PASSWORD},
             follow_redirects=True)

patch.object(main, 'calculate_driving_miles', return_value=(10.0, 600, None)).start()
# The per-key request limit would answer 429 to nearly everything after the first
# few dozen requests, and the handlers behind it would never be reached. Lifted
# for the fuzzing; the volume section below measures the limits that matter.
rate_patch = patch.object(main, 'API_RATE_LIMIT', 10 ** 9)
rate_patch.start()

# A key holding every permission there is, so every route is reachable and the
# fuzzing exercises the handler rather than being stopped at the scope check.
minted = browser.post('/profile/api-keys', json={
    'name': 'fuzz', 'password': PASSWORD, 'scopes': list(main.API_SCOPES)})
KEY = (minted.get_json() or {}).get('key')
if not KEY:
    print('API robustness check FAILED:')
    print(f'  - could not mint a key to test with: {minted.status_code} {minted.get_data(as_text=True)[:200]}')
    sys.exit(1)
HEADERS = {'Authorization': f'Bearer {KEY}'}
anon = main.app.test_client()

# ── Hostile values ──────────────────────────────────────────────────────
# JSON cannot carry NaN or Infinity as literals, but Python's parser accepts
# them and 1e999, so they are sent as raw text below as well.
HOSTILE = [
    None, 0, -1, 1.5, True, False, [], {}, ['x'], [1, 2], {'label': 5}, [{'label': 5}],
    '', ' ', 'x' * 5000, 'x' * 200_000, '\x00', 'a\x00b', '\ud800', '\U0001f600',
    '‮', '\n' * 50, 2 ** 70, -(2 ** 70), '9' * 5000, '../../etc/passwd',
    "'; DROP TABLE trip; --", '<script>alert(1)</script>', '{{7*7}}',
]
RAW_BODIES = [
    b'', b'null', b'[]', b'"text"', b'5', b'true', b'{', b'{"a":', b'\xff\xfe',
    b'{"miles": NaN}', b'{"miles": Infinity}', b'{"miles": 1e999}',
    b'[' * 5000 + b']' * 5000,
]
FIELDS = ['start_location', 'end_location', 'started_at', 'ended_at', 'notes',
          'vehicle_id', 'business_id', 'stops', 'miles', 'name', 'year', 'make',
          'model', 'scopes', 'password', 'limit', 'offset']

_day = [0]


def fresh_day():
    _day[0] += 1
    return date(2024, 1, 1) + timedelta(days=_day[0] % 700)


def base_body(rule, method):
    """A body that is valid for the route, so a single hostile field is what
    decides the outcome."""
    day = fresh_day()
    if rule == '/api/v1/trips' and method == 'POST':
        return {'start_location': 'Fuzz A', 'end_location': 'Fuzz B',
                'started_at': f'{day}T08:00', 'ended_at': f'{day}T09:00'}
    if rule.startswith('/api/v1/trips/') and method == 'PATCH':
        return {'notes': 'edited'}
    if rule == '/api/v1/vehicles' and method == 'POST':
        return {'name': f'V{day}'}
    if rule == '/api/v1/businesses' and method == 'POST':
        return {'name': f'B{day}'}
    if rule.startswith('/api/v1/vehicles/') and method == 'PATCH':
        return {'make': 'Ford'}
    if rule.startswith('/api/v1/businesses/') and method == 'PATCH':
        return {'name': f'B{day}x'}
    return {}


def make_trip():
    day = fresh_day()
    with main.app.app_context():
        t = main.Trip(user_id=USER_ID, start_location='S', end_location='E',
                      trip_date=str(day), start_time='08:00', end_time='09:00',
                      end_date=str(day), distance_miles=1.0, created_via='web')
        main.db.session.add(t)
        main.db.session.commit()
        return t.id


def make_vehicle():
    with main.app.app_context():
        v = main.Vehicle(user_id=USER_ID, name=f'Spare {fresh_day()}')
        main.db.session.add(v)
        main.db.session.commit()
        return v.id


def make_business():
    with main.app.app_context():
        b = main.Business(user_id=USER_ID, name=f'Spare {fresh_day()}')
        main.db.session.add(b)
        main.db.session.commit()
        return b.id


def make_decoy_key():
    """A key to aim the key-management routes at, never the one under test --
    revoking that one mid-run would turn every later request into a 401."""
    resp = browser.post('/profile/api-keys', json={
        'name': 'decoy', 'password': PASSWORD, 'scopes': ['trips:create']})
    # If minting is refused (the account is at its key limit) aim at an id that
    # does not exist rather than at 1, which is the key under test.
    return (resp.get_json() or {}).get('api_key', {}).get('id', 10 ** 9)


def fill(rule, huge=False):
    """The rule with a real id in each placeholder, or an absurd one."""
    def pick(m):
        if huge:
            return '9' * 40
        kind = rule.split('/')[3] if rule.startswith('/api/v1/') else ''
        return str({'trips': make_trip, 'vehicles': make_vehicle,
                    'businesses': make_business}.get(kind, make_trip)())
    return re.sub(r'<[^>]+>', pick, rule)


def send(client, method, path, *, headers=None, body=None, raw=None):
    kwargs = {'headers': headers or {}}
    if raw is not None:
        kwargs.update(data=raw, content_type='application/json')
    elif body is not None:
        kwargs['data'] = json.dumps(body, allow_nan=True)
        kwargs['content_type'] = 'application/json'
    try:
        return client.open(path, method=method, **kwargs)
    except Exception as exc:  # noqa: BLE001 -- a crash here is the finding
        message = f'{type(exc).__name__}: {exc}'

        class Crashed:
            status_code = 599

            def get_data(self, **_):
                return message
        return Crashed()


def check(label, resp):
    if resp.status_code >= 500:
        failures.append(f'{label}: server error {resp.status_code} '
                        f'({resp.get_data(as_text=True)[:100]!r})')


# The routes under test: everything a key can reach, and the session-only
# routes that manage keys, which a hostile browser session reaches too.
api_rules = []
for rule in main.app.url_map.iter_rules():
    for method in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
        if str(rule).startswith('/api/v1'):
            api_rules.append((str(rule), method))
expect('the URL map yields API routes to fuzz', len(api_rules) >= 5, True)

# ── 1. Every route, hostile bodies ──────────────────────────────────────
for rule, method in api_rules:
    for raw in RAW_BODIES:
        check(f'{method} {rule} raw {raw[:24]!r}',
              send(anon, method, fill(rule), headers=HEADERS, raw=raw))
    if method in ('POST', 'PATCH', 'PUT'):
        for field in FIELDS:
            for value in HOSTILE:
                body = {**base_body(rule, method), field: value}
                check(f'{method} {rule} {field}={str(value)[:20]!r}',
                      send(anon, method, fill(rule), headers=HEADERS, body=body))
    # An absurd id in the path must be a refusal, not an overflow.
    if '<' in rule:
        check(f'{method} {rule} with a 40-digit id',
              send(anon, method, fill(rule, huge=True), headers=HEADERS,
                   body=base_body(rule, method)))

# Query strings on the read routes.
for rule, method in api_rules:
    if method == 'GET':
        for q in ('limit=abc', 'limit=' + '9' * 5000, 'offset=-1', 'offset=' + '9' * 40,
                  'limit=\x00', 'limit=1&limit=2', 'limit[]=1', 'limit=%ff', 'limit=1e9'):
            check(f'GET {rule}?{q[:20]}', send(anon, 'GET', fill(rule) + '?' + q, headers=HEADERS))

# ── 2. The Authorization header itself ──────────────────────────────────
for value in ('', 'Bearer', 'Bearer ', 'Bearer  ', 'bearer ' + KEY, 'Basic ' + KEY,
              'Bearer ' + 'x' * 100_000, 'Bearer mtk_.', 'Bearer mtk_' + 'g' * 12 + '.' + 'a' * 43,
              'Bearer éé', 'Bearer ' + KEY + ' extra', 'Bearer\t' + KEY,
              'Bearer mtk_' + '0' * 12 + '.' + 'ÿ' * 43):
    check(f'Authorization {value[:24]!r}',
          send(anon, 'GET', '/api/v1/trips', headers={'Authorization': value}))

# ── 3. The routes that manage keys, from a browser session ──────────────
key_rules = [(str(r), m) for r in main.app.url_map.iter_rules()
             if str(r).startswith('/profile/api-keys') for m in sorted(r.methods - {'HEAD', 'OPTIONS'})]
expect('the key-management routes are found', len(key_rules) >= 2, True)
for rule, method in key_rules:
    def target():
        return rule.replace('<id:key_id>', str(make_decoy_key()))
    for raw in RAW_BODIES:
        check(f'{method} {rule} raw {raw[:24]!r}', send(browser, method, target(), raw=raw))
    for field in ('name', 'password', 'scopes'):
        for value in HOSTILE:
            body = {'name': 'n', 'password': PASSWORD, 'scopes': ['trips:create'], field: value}
            check(f'{method} {rule} {field}={str(value)[:20]!r}',
                  send(browser, method, target(), body=body))
    if '<' in rule:
        check(f'{method} {rule} with a 40-digit id',
              send(browser, method, rule.replace('<id:key_id>', '9' * 40),
                   body={'scopes': ['trips:create']}))

# ── 4. What actually got stored ─────────────────────────────────────────
# A 2xx does not mean the data is safe to keep. Production is Postgres, which
# refuses NUL bytes and lone surrogates in text, and every page that lists a
# record pays for its size.
MAX_STORED = 2000


def unstorable(text):
    if text is None:
        return False
    if '\x00' in text:
        return True
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        return True
    return False


with main.app.app_context():
    rows = []
    for t in main.Trip.query.filter_by(user_id=USER_ID).all():
        rows += [('trip.start_location', t.start_location), ('trip.end_location', t.end_location),
                 ('trip.notes', t.notes), ('trip.stops', t.stops)]
    for v in main.Vehicle.query.filter_by(user_id=USER_ID).all():
        rows += [('vehicle.name', v.name), ('vehicle.make', v.make),
                 ('vehicle.model', v.model), ('vehicle.year', v.year)]
    for b in main.Business.query.filter_by(user_id=USER_ID).all():
        rows += [('business.name', b.name)]
    for k in main.ApiKey.query.filter_by(user_id=USER_ID).all():
        rows += [('api_key.name', k.name)]
    bad = sorted({label for label, text in rows if unstorable(text)})
    expect('nothing Postgres would refuse was stored (NUL / lone surrogate)', bad, [])
    big = sorted({(label, len(text)) for label, text in rows
                  if text is not None and len(text) > MAX_STORED})
    expect(f'nothing over {MAX_STORED} characters was stored', big, [])
    stored_stop_counts = [len(main._stops_from_db(t.stops))
                          for t in main.Trip.query.filter_by(user_id=USER_ID).all()]
    expect('no trip stores more stops than the cap',
           [n for n in stored_stop_counts if n > main.MAX_STOPS], [])
    # Every stored column that is a fixed-width string in the model must fit,
    # because Postgres enforces what SQLite ignores.
    overflows = []
    for model in (main.Trip, main.Vehicle, main.Business, main.ApiKey):
        for column in model.__table__.columns:
            width = getattr(column.type, 'length', None)
            if not width:
                continue
            for row in model.query.all():
                value = getattr(row, column.name, None)
                if isinstance(value, str) and len(value) > width:
                    overflows.append(f'{model.__name__}.{column.name}')
    expect('no stored value overflows its column', sorted(set(overflows)), [])

# ── 5. Volume: one key cannot fill an account's history ─────────────────
cap = getattr(main, 'API_MAX_TRIPS_PER_DAY', None)
expect('there is a daily cap on trips a key can create', cap is not None, True)
if cap:
    with main.app.app_context():
        # Fresh key and a clean slate, so only this section counts.
        main.Trip.query.filter_by(user_id=USER_ID).delete()
        main.db.session.commit()
    # The fuzzing above minted keys of its own; clear them so the account is
    # under its active-key limit and the flood key can be created.
    with main.app.app_context():
        for k in main.ApiKey.query.filter_by(user_id=USER_ID, revoked_at=None).all():
            if main.parse_api_key(KEY)[0] != k.public_id:
                k.revoked_at = main._utcnow()
        main.db.session.commit()
    flood = browser.post('/profile/api-keys', json={
        'name': 'flood', 'password': PASSWORD, 'scopes': ['trips:create']})
    if not (flood.get_json() or {}).get('key'):
        failures.append(f'could not mint the flood key: {flood.status_code}')
        cap = None
if cap:
    FLOOD_HEADERS = {'Authorization': f"Bearer {flood.get_json()['key']}"}
    # The per-window request limit is already lifted at the top of this script,
    # so it is the daily cap that is measured here.
    statuses = []
    for i in range(cap + 5):
        day = date(2020, 1, 1) + timedelta(days=i)
        r = anon.post('/api/v1/trips', headers=FLOOD_HEADERS, json={
            'start_location': 'F1', 'end_location': 'F2',
            'started_at': f'{day}T08:00', 'ended_at': f'{day}T09:00'})
        statuses.append(r.status_code)
    expect('a key may create up to the cap', statuses[:cap].count(201), cap)
    expect('and is refused beyond it', set(statuses[cap:]), {429})
    with main.app.app_context():
        expect('nothing beyond the cap was stored',
               main.Trip.query.filter_by(user_id=USER_ID).count(), cap)

# ── 6. Bodies are bounded ───────────────────────────────────────────────
huge = send(anon, 'POST', '/api/v1/trips', headers=HEADERS,
            raw=json.dumps({'start_location': 'A', 'end_location': 'B',
                            'started_at': '2024-02-01T08:00',
                            'notes': 'n' * 2_000_000}).encode())
expect('a multi-megabyte body is refused outright', huge.status_code, 413)

os.unlink(_db.name)

if failures:
    shown = failures if os.environ.get('ROBUSTNESS_VERBOSE') else failures[:40]
    print(f'API robustness check FAILED ({len(failures)} problem(s)):')
    for f in shown:
        print(f'  - {f}')
    if len(failures) > len(shown):
        print(f'  ... and {len(failures) - len(shown)} more')
    sys.exit(1)

print('API robustness check OK — hostile input to every API and key-management '
      'route is refused rather than crashing or stored, and a key cannot flood '
      'an account.')
