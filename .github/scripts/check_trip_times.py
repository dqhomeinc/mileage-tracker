"""Check the trip date/time rules that nothing else exercises.

These four functions decide what a trip's dates and times mean to each other —
whether it crossed midnight, which day it ended on, how long it took, and which
combinations are even coherent. They are pure, they have a lot of edge cases
(midnight, month and year boundaries, leap days, multi-night trips, missing
values), and getting one wrong changes recorded mileage data or silently
suppresses the feasibility warning. A plain import check cannot see any of that.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import sys
import tempfile

# A throwaway SQLite file, so importing the app never touches a real database.
_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


def expect_error(label, actual, fragment):
    if not actual or fragment not in actual:
        failures.append(f'{label}: expected an error containing {fragment!r}, got {actual!r}')


# ── _ends_next_day: did the clock wrap? ───────────────────────────────────
expect('a morning trip does not wrap', main._ends_next_day('09:00', '10:30'), False)
expect('a near-midnight trip wraps',   main._ends_next_day('23:30', '01:00'), True)
expect('a minute either side wraps',   main._ends_next_day('23:59', '00:01'), True)
expect('equal times do not wrap',      main._ends_next_day('09:00', '09:00'), False)
expect('a missing end does not wrap',  main._ends_next_day('09:00', None), False)
expect('a missing start does not wrap', main._ends_next_day(None, '09:00'), False)
expect('unparseable times do not wrap', main._ends_next_day('nope', '09:00'), False)

# ── _derived_end_date: the day implied by the times alone ─────────────────
expect('a same-day trip keeps its date',
       main._derived_end_date('2026-10-02', '09:00', '10:30'), '2026-10-02')
expect('an overnight trip gains a day',
       main._derived_end_date('2026-10-02', '23:30', '01:00'), '2026-10-03')
expect('across a month', main._derived_end_date('2026-10-31', '23:30', '00:30'), '2026-11-01')
expect('across a year',  main._derived_end_date('2026-12-31', '23:30', '00:30'), '2027-01-01')
expect('onto a leap day', main._derived_end_date('2028-02-28', '23:30', '00:30'), '2028-02-29')
expect('no trip date gives nothing',
       main._derived_end_date(None, '23:30', '01:00'), None)
expect('no end time gives nothing',
       main._derived_end_date('2026-10-02', '09:00', None), None)

# ── _elapsed_seconds: how long it took ───────────────────────────────────
expect('a 90-minute trip', main._elapsed_seconds('09:00', '10:30'), 5400)
expect('an overnight trip, from the clock alone',
       main._elapsed_seconds('23:30', '01:00'), 5400)
expect('an overnight trip, from its dates',
       main._elapsed_seconds('23:30', '01:00', '2026-10-02', '2026-10-03'), 5400)
expect('two nights counts every hour',
       main._elapsed_seconds('08:00', '14:00', '2026-10-02', '2026-10-03'), 108000)
expect('three days',
       main._elapsed_seconds('08:00', '08:00', '2026-10-02', '2026-10-05'), 259200)
expect('equal times on one day are zero',
       main._elapsed_seconds('09:00', '09:00', '2026-10-02', '2026-10-02'), 0)
expect('a missing time is unknown', main._elapsed_seconds(None, '10:30'), None)
expect('an unparseable time is unknown', main._elapsed_seconds('9am', '10:30'), None)

# ── validate_end_date: which combinations are coherent ───────────────────
expect('no end date is fine', main.validate_end_date(None, '2026-10-02'), None)
expect('the same day is fine',
       main.validate_end_date('2026-10-02', '2026-10-02', '09:00', '10:30'), None)
expect('the next day is fine',
       main.validate_end_date('2026-10-03', '2026-10-02', '23:30', '01:00'), None)
expect('a multi-night trip is fine',
       main.validate_end_date('2026-10-05', '2026-10-02', '08:00', '14:00'), None)
# A trip is logged as it is taken, so its end may not have happened yet.
expect('a future end date is allowed',
       main.validate_end_date('2099-01-02', '2099-01-01', '23:30', '01:00'), None)
expect_error('a backwards end date',
             main.validate_end_date('2026-10-01', '2026-10-02', '09:00', '10:30'), 'before')
expect_error('an absurd span',
             main.validate_end_date('2027-10-02', '2026-10-02', '09:00', '10:30'), 'longer than')
expect_error('a nonsense date',
             main.validate_end_date('2026-02-30', '2026-02-01', '09:00', '10:30'), 'not a valid date')
expect_error('an end date with no end time',
             main.validate_end_date('2026-10-03', '2026-10-02', '09:00', None), 'needs an end time')
# Reachable only through the API: the UI derives the date from the times.
expect_error('the same day, ending before it starts',
             main.validate_end_date('2026-10-02', '2026-10-02', '14:00', '08:00'), 'before it starts')

# ── check_trip_feasibility: the dates must reach it ───────────────────────
expect('a plausible overnight trip is quiet',
       main.check_trip_feasibility('23:30', '01:00', 60.0, 5400,
                                   trip_date='2026-10-02', end_date='2026-10-03'), None)
if main.check_trip_feasibility('08:00', '14:00', 500.0, 28800,
                               trip_date='2026-10-02', end_date='2026-10-03') is None:
    failures.append('a 500-mile drive taking 30 hours should be flagged as too slow')
expect('the same times on one day are plausible',
       main.check_trip_feasibility('08:00', '14:00', 500.0, 28800,
                                   trip_date='2026-10-02', end_date='2026-10-02'), None)

os.unlink(_db.name)

if failures:
    print('Trip date/time check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('Trip date/time check OK — dates, times, elapsed spans and validation all agree.')
