"""Check that a deployed app refuses to start without SECRET_KEY.

SECRET_KEY signs session cookies, the remember-me cookie and password-reset
tokens. When it was absent the app fell back to a constant written in main.py,
which is a public file -- so the app started, looked healthy, and signed every
cookie with a value anyone could read. That is the failure this guards.

The guard has to hold in three directions, and getting any of them wrong is
quiet rather than loud:

  - deployed with no key  -> refuse to start, or the hole is back
  - deployed with a key   -> start, or every deploy is broken
  - local with no key     -> start, or nobody can run the app without setup

Each is checked in its own subprocess, because the condition is evaluated once
at import and cannot be re-tested inside a process that has already imported.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import subprocess
import sys
import tempfile

failures = []

# main.py counts a DATABASE_URL that is not SQLite as a deployment, so this has
# to be a server URL. Nothing ever connects to it: the guard runs near the top
# of the module and raises long before the database is opened at the bottom.
#
# Which means the *refusal* cases below are testable here, but "deployed with a
# key starts" is not -- that would reach the connection and fail for an
# unrelated reason. Each refusal is therefore matched on its message, so a
# connection error cannot pass as the guard firing, and the positive case is
# left to the postgres-integration job, which has a real server.
DEPLOYED_URL = 'postgresql://user:pass@127.0.0.1:1/never_connected'

# A SQLite URL is what the other check scripts set, and must read as local.
_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
LOCAL_DB_URL = f'sqlite:///{_db.name}'


def run(label, env, expect_ok, expect_in_stderr=None):
    """Import the app in a subprocess under `env` and check how it went."""
    child = dict(os.environ)
    child.pop('SECRET_KEY', None)
    child.pop('DATABASE_URL', None)
    child.update(env)
    # Importing is enough: the guard is module-level, so a clean exit means it
    # allowed startup and a non-zero exit means it refused.
    proc = subprocess.run(
        [sys.executable, '-c', 'import main'],
        env=child, capture_output=True, text=True, cwd=os.getcwd(),
    )
    started = proc.returncode == 0
    if started != expect_ok:
        failures.append(
            f'{label}: expected {"start" if expect_ok else "refusal"}, '
            f'got {"start" if started else "refusal"}'
            + ('' if started else f'\n      stderr tail: {proc.stderr.strip().splitlines()[-1:]}')
        )
        return
    if expect_in_stderr and expect_in_stderr not in proc.stderr:
        failures.append(f'{label}: the error does not mention {expect_in_stderr!r}; '
                        f'got {proc.stderr.strip()[-300:]!r}')


# ── Deployed without a key: the case that caused this ─────────────────────
run('a deployed app with no SECRET_KEY refuses to start',
    {'DATABASE_URL': DEPLOYED_URL}, expect_ok=False,
    expect_in_stderr='SECRET_KEY is not set')

# The message is what someone reads at 2am off a failed deploy, so it has to
# say where to set it rather than only that something is missing.
run('and the refusal says where to set it',
    {'DATABASE_URL': DEPLOYED_URL}, expect_ok=False, expect_in_stderr='Render')

# An empty string is a real way for this to be set wrong -- an env var defined
# with no value -- and must not count as present.
run('an empty SECRET_KEY counts as missing',
    {'DATABASE_URL': DEPLOYED_URL, 'SECRET_KEY': ''}, expect_ok=False,
    expect_in_stderr='SECRET_KEY is not set')

# ── Deployed with a key: every deploy depends on this ────────────────────
# Covered by the postgres-integration job rather than here: it has a real
# server, so it can prove a deployed app with a key actually starts.

# ── Local: no setup should be required to run the app ────────────────────
run('a local app with no SECRET_KEY still starts', {}, expect_ok=True)
run('and a local app with one starts too', {'SECRET_KEY': 'whatever'}, expect_ok=True)

# The case that broke check_trip_times.py when this guard keyed off the mere
# presence of DATABASE_URL: a check script pointing it at a throwaway SQLite
# file is not a deployment and must not be made to invent a secret.
run('a check script using a SQLite DATABASE_URL is not a deployment',
    {'DATABASE_URL': LOCAL_DB_URL}, expect_ok=True)

# ── The fallback must never be reachable while deployed ─────────────────
# Belt and braces on the guard above: whatever the fallback is, asking for it
# under a deployed environment must not produce a usable app.
probe = subprocess.run(
    [sys.executable, '-c',
     'import main; print(main.app.config["SECRET_KEY"])'],
    env={**{k: v for k, v in os.environ.items()
            if k not in ('SECRET_KEY', 'DATABASE_URL')},
         'DATABASE_URL': DEPLOYED_URL},
    capture_output=True, text=True, cwd=os.getcwd(),
)
if probe.returncode == 0:
    failures.append('a deployed app handed out a SECRET_KEY it was never given: '
                    f'{probe.stdout.strip()!r}')

# And the value used locally must not be one that reads as production-ready, so
# that finding it in a deployed process is unmistakable.
local = subprocess.run(
    [sys.executable, '-c', 'import main; print(main.app.config["SECRET_KEY"])'],
    env={k: v for k, v in os.environ.items()
         if k not in ('SECRET_KEY', 'DATABASE_URL')},
    capture_output=True, text=True, cwd=os.getcwd(),
)
if local.returncode != 0:
    failures.append(f'could not read the local fallback: {local.stderr.strip()[-200:]}')
elif 'dev' not in local.stdout.lower():
    failures.append('the local fallback should name itself as development-only, '
                    f'got {local.stdout.strip()!r}')

os.unlink(_db.name)

if failures:
    print('SECRET_KEY guard check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('SECRET_KEY guard check OK — a deployed app without one refuses to start, '
      'and local runs still need no setup.')
