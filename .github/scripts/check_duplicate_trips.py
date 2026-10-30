"""Check that logging the same trip twice is caught and queried, not silently
accepted or silently refused.

A user reported logging one journey twice. The Log Trip button is already
disabled synchronously before the first await, so two requests cannot leave one
page load from a double click -- which means the duplicate came from re-entry:
a slow request on a sleeping instance looks like nothing happening, so the trip
gets typed in again, and then both land.

That shapes the fix. It has to be server-side, because the two entries may come
from different page loads that never saw each other's result -- and matching on
an equal start time is not enough, because the form autofills the start time to
the current clock, so a trip typed in again six minutes later carries a
different one.

What it matches on instead is overlap. The same route over overlapping hours
describes being in two places at once, so it is refused outright and the first
trip is kept; there is no answer a person could give that would make two of
them true. Only the untimed case is asked about, since without times there is
nothing to overlap and two untimed trips between the same places on one day
could be real.

The same rule applies to editing a trip, for the same reason -- the constraint
is about what the data can mean, not about which route produced it. Without it
the refusal on logging is only a speed bump: a trip could be logged at a free
time and then edited to the overlapping one it was refused at. An edit is
checked against every trip but itself, since a trip always overlaps itself and
leaving it in would refuse every save by the row being saved.

So the properties worth pinning down are: the reported case is caught and
cannot be forced through, genuine pairs are untouched, the ambiguous case is
asked rather than refused, and an edit is held to the same rule without
tripping over itself.

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
    # An explicit None means "no start time", which is a case under test, so it
    # has to survive rather than be defaulted back.
    return {k: v for k, v in body.items() if v is not None or k == 'start_time'}


def log(client, key, **overrides):
    return client.post('/log', json=trip(key, **overrides))


def trip_count():
    with main.app.app_context():
        return main.Trip.query.count()


# ── The reported case ─────────────────────────────────────────────────────
# A slow request, a re-entry six minutes later, and the autofilled start time
# differs. An equal-start-time match lets this through; this is the case the
# whole change exists for.
expect('the first entry is logged',
       log(jane, jane_key, start_time='08:29', end_time='09:10').status_code, 200)
before = trip_count()

again = log(jane, jane_key, start_time='08:35', end_time='09:16')
expect('a re-entry with a later start time is refused', again.status_code, 409)
expect('and is marked as a duplicate', field(again, 'duplicate'), True)
expect('and says it cannot be confirmed through', field(again, 'can_confirm'), False)
expect('nothing was stored', trip_count(), before)

# The point of refusing rather than asking: there is no way through, because
# the data it would create describes being in two places at once.
forced = log(jane, jane_key, start_time='08:35', end_time='09:16',
             confirm_duplicate=True)
expect('confirm_duplicate does not force an overlap through', forced.status_code, 409)
expect('and still stores nothing', trip_count(), before)

# The first recorded trip is the one kept, which is what makes this safe to do
# without asking: nothing already on record is replaced or altered.
kept = field(again, 'existing') or {}
expect('the trip kept is the first one', kept.get('start_time'), '08:29')
expect('described with its own end time', kept.get('end_time'), '09:10')
expect('and its measured mileage, which the refused request never sent',
       kept.get('miles'), MEASURED[0])

# Refused before the distance lookup, so a rejected trip costs no Routes call.
calls = main.calculate_driving_miles.call_count
log(jane, jane_key, start_time='08:40', end_time='09:21')
expect('a refused overlap spends no distance lookup',
       main.calculate_driving_miles.call_count, calls)

# ── An end time is not required for the window ──────────────────────────
# A trip entered without one still occupies the road for as long as the route
# takes, so the measured duration stands in for it.
# MEASURED is a 15-minute drive, so 08:00 occupies the road until 08:15. A
# re-entry at 08:05 lands inside that; one at 08:20 does not, and the second
# assertion matters as much as the first -- a derived window has a real edge,
# and treating it as unbounded would refuse perfectly ordinary later trips.
count = trip_count()
expect('an entry with no end time logs',
       log(jane, jane_key, trip_date='2026-10-02', start_time='08:00').status_code, 200)
expect('a re-entry inside its measured drive time is refused',
       log(jane, jane_key, trip_date='2026-10-02', start_time='08:05').status_code, 409)
expect('but one after the drive would have finished is allowed',
       log(jane, jane_key, trip_date='2026-10-02', start_time='08:20').status_code, 200)
expect('so only the two real trips were stored', trip_count(), count + 2)

# ── More than one overlapping trip ─────────────────────────────────────
# Two recorded trips can both overlap a new one without overlapping each other,
# which is the only way the ordering of the lookup is observable. Both are kept
# regardless -- nothing recorded is ever altered -- so what this pins down is
# which of them gets described back, and that nothing was touched.
count = trip_count()
first = log(jane, jane_key, trip_date='2026-10-05', start_time='08:00', end_time='08:30')
second = log(jane, jane_key, trip_date='2026-10-05', start_time='08:40', end_time='09:10')
expect('two non-overlapping trips on one route both log',
       (first.status_code, second.status_code), (200, 200))

straddling = log(jane, jane_key, trip_date='2026-10-05',
                 start_time='08:25', end_time='08:45')
expect('a trip straddling both is refused', straddling.status_code, 409)
expect('and the earliest of them is the one described',
       (field(straddling, 'existing') or {}).get('start_time'), '08:00')
expect('both recorded trips survive', trip_count(), count + 2)

with main.app.app_context():
    kept_rows = (main.Trip.query
                 .filter_by(trip_date='2026-10-05', user_id=main.User.query
                            .filter_by(email='jane@example.com').first().id)
                 .order_by(main.Trip.id).all())
    expect('and neither was altered',
           [(t.start_time, t.end_time) for t in kept_rows],
           [('08:00', '08:30'), ('08:40', '09:10')])

# ── Genuine pairs are untouched ────────────────────────────────────────
# The half that decides whether this is a safeguard or an obstacle. Each of
# these is a real second trip, and a refusal here would be worse than the bug.
cases = [
    ({'start_time': '09:10', 'end_time': '09:51'},
     'a back-to-back trip starting the moment the last one ended'),
    ({'start_time': '14:00', 'end_time': '14:41'},
     'a second visit that afternoon'),
    ({'trip_date': '2026-10-09', 'start_time': '08:29', 'end_time': '09:10'},
     'the same journey on another day'),
    ({'start': 'Clinton Street, Newton', 'end': 'Lexington, MA',
      'start_time': '08:35', 'end_time': '09:16'},
     'the return leg, overlapping but reversed'),
]
for overrides, label in cases:
    count = trip_count()
    resp = log(jane, jane_key, **overrides)
    expect(f'{label} is allowed', resp.status_code, 200)
    expect(f'{label} is stored', trip_count(), count + 1)

# Back-to-back is the one a sloppy inclusive comparison would wrongly refuse,
# so it is asserted at the boundary too: ending and starting on the same minute
# share an instant but no duration.
with main.app.app_context():
    a = main._trip_window('2026-10-08', '09:00', '09:30', None, None)
    b = main._trip_window('2026-10-08', '09:30', '10:00', None, None)
    expect('touching windows do not overlap', main._windows_overlap(a, b), False)
    expect('and overlapping ones do',
           main._windows_overlap(a, main._trip_window('2026-10-08', '09:29', '10:00', None, None)),
           True)
    expect('equal starts overlap whatever their lengths',
           main._windows_overlap(main._trip_window('2026-10-08', '09:00', None, None, None),
                                 main._trip_window('2026-10-08', '09:00', None, None, None)),
           True)

# ── Across midnight ───────────────────────────────────────────────────
# A trip beginning before midnight ends on the following date, so the dates
# have to be folded into the comparison rather than the clock compared alone.
count = trip_count()
expect('an overnight trip logs',
       log(jane, jane_key, trip_date='2026-10-11', start_time='23:30',
           end_time='00:11').status_code, 200)
expect('and one starting after midnight inside it is refused',
       log(jane, jane_key, trip_date='2026-10-12', start_time='00:00',
           end_time='00:41').status_code, 409)
expect('only the overnight trip was stored', trip_count(), count + 1)
expect('while one later that morning is allowed',
       log(jane, jane_key, trip_date='2026-10-12', start_time='07:00',
           end_time='07:41').status_code, 200)

# ── One user's trip is not another's ─────────────────────────────────
count = trip_count()
expect('another account logging the same journey over the same hours is fine',
       log(bob, bob_key, start_time='08:29', end_time='09:10').status_code, 200)
expect('and it is stored', trip_count(), count + 1)

# ── The untimed case is asked, not refused ──────────────────────────
# Nothing to overlap, so this one genuinely could be a real pair.
count = trip_count()
expect('an untimed trip logs',
       log(jane, jane_key, trip_date='2026-10-15', start_time=None).status_code, 200)
asked = log(jane, jane_key, trip_date='2026-10-15', start_time=None)
expect('a second untimed trip between the same places is queried',
       asked.status_code, 409)
expect('and this one can be confirmed through', field(asked, 'can_confirm'), True)
expect('confirming logs it',
       log(jane, jane_key, trip_date='2026-10-15', start_time=None,
           confirm_duplicate=True).status_code, 200)
expect('leaving both', trip_count(), count + 2)

# A timed trip must not be taken for an untimed one: there is no window to
# compare, so neither rule applies.
count = trip_count()
expect('a timed trip is not a duplicate of an untimed one',
       log(jane, jane_key, trip_date='2026-10-15', start_time='19:45',
           end_time='20:26').status_code, 200)
expect('and is stored', trip_count(), count + 1)

# ── The window helper ───────────────────────────────────────────────
with main.app.app_context():
    expect('a trip with no start time has no window',
           main._trip_window('2026-10-08', None, '09:10', None, None), None)
    expect('a stated end time is used',
           main._trip_window('2026-10-08', '08:00', '09:00', None, None)[1]
           - main._trip_window('2026-10-08', '08:00', '09:00', None, None)[0], 60)
    expect('the measured duration stands in when there is no end time',
           main._trip_window('2026-10-08', '08:00', None, None, 1800)[1]
           - main._trip_window('2026-10-08', '08:00', None, None, 1800)[0], 30)
    instant = main._trip_window('2026-10-08', '08:00', None, None, None)
    expect('and with neither the trip is an instant', instant[0], instant[1])

# ── Editing into an overlap ────────────────────────────────────────────
# The constraint is about the data, not the endpoint, so the edit route has to
# enforce it too -- otherwise the refusal on logging is sidestepped by logging
# at a free time and editing afterwards.
count = trip_count()
morning = log(jane, jane_key, trip_date='2026-10-18', start_time='08:00', end_time='08:41')
afternoon = log(jane, jane_key, trip_date='2026-10-18', start_time='14:00', end_time='14:41')
expect('two trips at different times of one day both log',
       (morning.status_code, afternoon.status_code), (200, 200))

with main.app.app_context():
    jane_id = main.User.query.filter_by(email='jane@example.com').first().id
    rows = (main.Trip.query
            .filter_by(user_id=jane_id, trip_date='2026-10-18')
            .order_by(main.Trip.id).all())
    MORNING_ID, AFTERNOON_ID = rows[0].id, rows[1].id


def edit(trip_id, **overrides):
    body = trip(jane_key, trip_date='2026-10-18', **overrides)
    body.setdefault('distance_miles', MEASURED[0])
    body.setdefault('duration_seconds', MEASURED[1])
    return jane.patch(f'/history/{trip_id}', json=body)


moved = edit(AFTERNOON_ID, start_time='08:10', end_time='08:51')
expect('editing the afternoon trip onto the morning one is refused',
       moved.status_code, 409)
expect('and marked as a duplicate', field(moved, 'duplicate'), True)
expect('with no way to confirm it through', field(moved, 'can_confirm'), False)
expect('and the trip it collided with is named',
       (field(moved, 'existing') or {}).get('start_time'), '08:00')

with main.app.app_context():
    unchanged = main.db.session.get(main.Trip, AFTERNOON_ID)
    expect('the edit was not applied', unchanged.start_time, '14:00')

# ── Self-exclusion ───────────────────────────────────────────────────
# Every ordinary edit depends on this: a trip always overlaps itself, so
# leaving it in the comparison would refuse every save by the row being saved.
# These are the cases that break first if the exclusion is wrong, and they are
# the common path rather than an edge.
expect('saving a trip unchanged is allowed',
       edit(AFTERNOON_ID, start_time='14:00', end_time='14:41').status_code, 200)
expect('editing only its notes is allowed',
       edit(AFTERNOON_ID, start_time='14:00', end_time='14:41',
            notes='client visit').status_code, 200)
expect('nudging its time so the new window overlaps its old one is allowed',
       edit(AFTERNOON_ID, start_time='14:05', end_time='14:46').status_code, 200)
expect('and so is editing the other trip unchanged',
       edit(MORNING_ID, start_time='08:00', end_time='08:41').status_code, 200)

# The exclusion must be by id, not by content: a trip whose values now match
# another trip's must still be refused.
expect('moving it to a genuinely free time is allowed',
       edit(AFTERNOON_ID, start_time='17:00', end_time='17:41').status_code, 200)
expect('but moving it back onto the morning trip is still refused',
       edit(AFTERNOON_ID, start_time='08:20', end_time='09:01').status_code, 409)

# ── Edits that only resemble an overlap ────────────────────────────
expect('editing to back-to-back with the morning trip is allowed',
       edit(AFTERNOON_ID, start_time='08:41', end_time='09:22').status_code, 200)
expect('and editing to the reversed route over the same hours is allowed',
       edit(AFTERNOON_ID, start='Clinton Street, Newton', end='Lexington, MA',
            start_time='08:10', end_time='08:51').status_code, 200)

# ── One user's trip cannot block another's edit ──────────────────
bob_trip = log(bob, bob_key, trip_date='2026-10-18', start_time='08:00', end_time='08:41')
expect("another account's identical trip logs", bob_trip.status_code, 200)
with main.app.app_context():
    bob_id = main.User.query.filter_by(email='bob@example.com').first().id
    bob_row = (main.Trip.query.filter_by(user_id=bob_id, trip_date='2026-10-18')
               .order_by(main.Trip.id).first())
    BOB_TRIP_ID = bob_row.id
expect("and bob can edit it onto the same hours jane uses",
       bob.patch(f'/history/{BOB_TRIP_ID}',
                 json=trip(bob_key, trip_date='2026-10-18', start_time='08:10',
                           end_time='08:51', distance_miles=MEASURED[0],
                           duration_seconds=MEASURED[1])).status_code, 200)
expect("while one user still cannot reach another's trip at all",
       bob.patch(f'/history/{MORNING_ID}',
                 json=trip(bob_key, trip_date='2026-10-18',
                           start_time='09:00')).status_code, 404)

measure.stop()
os.unlink(_db.name)

if failures:
    print('Duplicate trip check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('Duplicate trip check OK — an overlapping entry or edit is refused and '
      'the first kept, an edit never collides with itself, and genuine pairs '
      'pass.')
