"""Check that logging the same trip twice is caught and queried, not silently
accepted or silently refused.

A user reported logging one journey twice. The Log Trip button is already
disabled synchronously before the first await, so two requests cannot leave one
page load from a double click -- which means the duplicate came from re-entry:
a slow request on a sleeping instance looks like nothing happening, so the trip
gets typed in again, and then both land.

That shapes the fix. It has to be server-side, because the two entries may come
from different page loads that never saw each other's result. And it has to
*ask* rather than refuse, because two visits to the same client on one day are
a genuine pair of trips that no comparison of fields can distinguish from one
trip entered twice.

So the properties worth pinning down are both directions of that: the same trip
is caught, and trips that merely resemble each other are not.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import sys
import tempfile
from unittest.mock import patch

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'duplicate-trip-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []
PASSWORD = 'Testpass123!'
MEASURED = (12.0, 900, None)


def field(resp, name, default=None):
    """One field from a JSON response, or `default`.

    Total on purpose: a check expecting one shape and getting another would
    otherwise raise and abort the run, skipping every later check silently.
    """
    try:
        body = resp.get_json()
    except Exception:  # noqa: BLE001 -- a non-JSON body has no fields
        return default
    return body.get(name, default) if isinstance(body, dict) else default


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


main.app.config['TESTING'] = True
# So a view's exception reaches the client as a 500 rather than aborting this
# script on the very bug it is looking for.
main.app.config['PROPAGATE_EXCEPTIONS'] = False

with main.app.app_context():
    main.db.create_all()
    for name in ('jane', 'bob'):
        user = main.User(username=name, email=f'{name}@example.com')
        user.set_password(PASSWORD)
        main.db.session.add(user)
    main.db.session.commit()

measure = patch.object(main, 'calculate_driving_miles', return_value=MEASURED)
measure.start()


def signed_in(email):
    client = main.app.test_client()
    client.post('/login', data={'email': email, 'password': PASSWORD},
                follow_redirects=True)
    key = main.normalize_logging_key(
        field(client.post('/profile/logging-key', json={'password': PASSWORD}),
              'logging_key', ''))
    return client, key


jane, jane_key = signed_in('jane@example.com')
bob, bob_key = signed_in('bob@example.com')


def trip(key, **overrides):
    body = {'start': 'Lexington, MA', 'end': 'Clinton Street, Newton',
            'trip_date': '2026-10-08', 'start_time': '08:29', 'logging_key': key}
    body.update(overrides)
    return body


def log(client, key, **overrides):
    return client.post('/log', json=trip(key, **overrides))


def trip_count():
    with main.app.app_context():
        return main.Trip.query.count()


# ── The reported case ─────────────────────────────────────────────────────
expect('the first entry is logged', log(jane, jane_key).status_code, 200)
before = trip_count()

second = log(jane, jane_key)
expect('an identical second entry is refused', second.status_code, 409)
expect('and says so in a way the client can act on', field(second, 'duplicate'), True)
expect('and nothing was stored', trip_count(), before)

# The client needs enough to describe what is already on record, and it has to
# come from the stored trip rather than be echoed back from the request.
existing = field(second, 'existing') or {}
expect('the existing trip is described', existing.get('start'), 'Lexington, MA')
expect('with its date', existing.get('trip_date'), '2026-10-08')
expect('its time', existing.get('start_time'), '08:29')
expect('its measured mileage, which the request never sent',
       existing.get('miles'), MEASURED[0])
expect('and its id', isinstance(existing.get('id'), int), True)

# Refused before the distance lookup: a trip about to be rejected must not
# spend a billable Routes call first.
calls = main.calculate_driving_miles.call_count
log(jane, jane_key)
expect('a refused duplicate spends no distance lookup',
       main.calculate_driving_miles.call_count, calls)

# ── Confirming is the only way through ──────────────────────────────────
confirmed = log(jane, jane_key, confirm_duplicate=True)
expect('confirming logs it', confirmed.status_code, 200)
expect('and it is stored', trip_count(), before + 1)

# ── Trips that only resemble each other are not duplicates ─────────────
# This is the half that matters for not becoming an obstacle. Each of these is
# a real second trip.
cases = [
    ({'start_time': '14:00'}, 'a second visit later the same day'),
    ({'trip_date': '2026-10-09'}, 'the same journey on another day'),
    ({'start': 'Clinton Street, Newton', 'end': 'Lexington, MA'},
     'the return leg, with the locations reversed'),
    ({'end': 'Somewhere Else, MA'}, 'a different destination'),
]
for overrides, label in cases:
    count = trip_count()
    resp = log(jane, jane_key, **overrides)
    expect(f'{label} is not treated as a duplicate', resp.status_code, 200)
    expect(f'{label} is stored', trip_count(), count + 1)

# ── One user's trip is not another's duplicate ────────────────────────
count = trip_count()
expect("another account logging the same journey is unaffected",
       log(bob, bob_key).status_code, 200)
expect('and it is stored', trip_count(), count + 1)

# ── Untimed trips ────────────────────────────────────────────────────
# The weakest signal, and the reason this asks rather than refuses: two
# untimed trips between the same places on one day could be real. A timed
# entry and an untimed one must never be taken for each other, though.
count = trip_count()
expect('an untimed trip logs', log(jane, jane_key, start_time=None).status_code, 200)
expect('a second untimed trip between the same places is queried',
       log(jane, jane_key, start_time=None).status_code, 409)
expect('and can be confirmed through',
       log(jane, jane_key, start_time=None, confirm_duplicate=True).status_code, 200)
expect('only the two intended trips were stored', trip_count(), count + 2)

# A timed trip must not match the untimed one just logged.
count = trip_count()
expect('a timed trip is not a duplicate of an untimed one',
       log(jane, jane_key, start_time='19:45').status_code, 200)
expect('and is stored', trip_count(), count + 1)

# ── The detector itself ─────────────────────────────────────────────
with main.app.app_context():
    jane_id = main.User.query.filter_by(email='jane@example.com').first().id
    expect('a trip with no date cannot be matched, since it identifies nothing',
           main.find_duplicate_trip(jane_id, 'A', 'B', None, '08:00'), None)
    expect('nor one with no locations',
           main.find_duplicate_trip(jane_id, '', 'B', '2026-10-08', '08:00'), None)
    found = main.find_duplicate_trip(jane_id, 'Lexington, MA',
                                     'Clinton Street, Newton', '2026-10-08', '08:29')
    expect('and a genuine match is found', found is not None, True)

# ── The gate is per request, not sticky ───────────────────────────
# Confirming once must not leave duplicate checking off for later trips.
count = trip_count()
log(jane, jane_key, trip_date='2026-10-20')
expect('a later identical trip is still queried',
       log(jane, jane_key, trip_date='2026-10-20').status_code, 409)
expect('and only the first was stored', trip_count(), count + 1)

measure.stop()
os.unlink(_db.name)

if failures:
    print('Duplicate trip check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('Duplicate trip check OK — a repeated entry is queried and nothing is '
      'stored until confirmed, and trips that merely resemble each other pass.')
