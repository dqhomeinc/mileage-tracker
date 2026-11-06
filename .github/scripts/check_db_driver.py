"""Check that the Postgres driver and its SCRAM dependency actually fit together.

Every deploy failed with `module 'scramp' has no attribute
'make_channel_binding'` and no commit to blame. pg8000 asks only for
scramp>=1.4.5, so when scramp 1.5.0 removed that function a new version was
installed without anything in this repository changing.

The reason CI did not catch it is worth stating, because it is structural
rather than an oversight: the call lives behind `if resp == "S"` in pg8000's
_make_socket -- it runs only when the server *accepts* SSL. The Postgres
container in postgres-integration serves plaintext and answers "N", so that
branch never executes there, while Neon requires TLS and always takes it. A
real connection in CI therefore proves nothing about the one production makes.

So this checks the fit directly instead: every attribute pg8000 reads from
scramp must exist on the installed scramp, whether or not any code path here
reaches it. That is exactly the mismatch that broke production, and it needs no
database at all.

It also covers how the app behaves when the database does not answer. The
schema is prepared at import, so a connect with no timeout blocks the import
for ever: gunicorn never binds a port and the platform reports "no open ports
detected" with nothing to diagnose, which is how a later deploy failed. A
timeout and a bounded retry turn that into a named error in seconds, and
tolerate the one slow case that is expected -- waking a suspended compute.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import os
import pathlib
import re
import sys
import tempfile
from importlib.metadata import version

failures = []

# A throwaway SQLite file, so importing the app never touches a real database.
# The startup assertions below rely on this being the local, non-server path.
_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'db-driver-check-secret')
sys.path.insert(0, os.getcwd())

# Imported defensively, so a missing driver reads as a named failure rather
# than a traceback that takes the rest of the script with it. In CI all three
# are installed from requirements.txt; locally they may not be.
try:
    import pg8000.core
    import scramp

    import main
except ImportError as exc:
    print('Database driver check FAILED:')
    print(f'  - could not import the app, the driver or its SCRAM dependency '
          f'({exc}). Install from requirements.txt first.')
    sys.exit(1)


def pinned(requirement):
    """The version requirements.txt pins for `requirement`, or None."""
    text = pathlib.Path('requirements.txt').read_text()
    found = re.search(rf'^{re.escape(requirement)}==(\S+)\s*$', text, re.MULTILINE)
    return found.group(1) if found else None


# ── The pins are what is actually installed ──────────────────────────────
# Both are pinned on purpose: pg8000 for the driver, scramp because pg8000's
# own floor lets a breaking release in underneath a pinned driver.
for package in ('pg8000', 'scramp'):
    want = pinned(package)
    if not want:
        failures.append(f'{package} is not pinned in requirements.txt, so a '
                        'release of it can change what deploys without any '
                        'commit here')
        continue
    have = version(package)
    if have != want:
        failures.append(f'{package} {have} is installed but requirements.txt '
                        f'pins {want}')

# ── Everything pg8000 reads from scramp exists ──────────────────────────
source = pathlib.Path(pg8000.core.__file__).read_text()
referenced = sorted(set(re.findall(r'\bscramp\.([A-Za-z_][A-Za-z0-9_]*)', source)))

if not referenced:
    failures.append('no scramp references were found in pg8000.core, so this '
                    'check is no longer looking at anything -- the driver or '
                    'its layout must have changed')

for attribute in referenced:
    if not hasattr(scramp, attribute):
        failures.append(
            f'pg8000 {version("pg8000")} calls scramp.{attribute}(), which '
            f'scramp {version("scramp")} does not have. This is the failure '
            'that took production down: it only shows when the server accepts '
            'SSL, so no test against a plaintext Postgres will reveal it.'
        )

# ── Not answering is a named error, not a hang ──────────────────────────
timeout = getattr(main, 'DB_CONNECT_TIMEOUT', None)
if not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
    failures.append(f'DB_CONNECT_TIMEOUT is {timeout!r}; without a sane connect '
                    'timeout a database that never answers blocks the import for '
                    'ever and the platform reports only "no open ports detected"')

attempts = getattr(main, 'DB_STARTUP_ATTEMPTS', None)
if not isinstance(attempts, int) or attempts < 2:
    failures.append(f'DB_STARTUP_ATTEMPTS is {attempts!r}; waking a suspended '
                    'compute is an expected slow path, so the first failure '
                    'should not end the deploy')

# SQLite takes a `timeout` too, but it means how long to wait for a file lock.
# CI runs this against SQLite, so the absence here is the check.
opts = main.app.config.get('SQLALCHEMY_ENGINE_OPTIONS', {})
if main.app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
    if 'connect_args' in opts:
        failures.append('a SQLite URL was given a connect timeout, which means '
                        'a file-lock wait rather than a network timeout')
elif (opts.get('connect_args') or {}).get('timeout') != timeout:
    failures.append('a server URL was not given the connect timeout, so an '
                    'unreachable database would hang instead of erroring')

# ── The retry recovers, and also gives up ─────────────────────────────
real_migrate = main._migrate_db
calls = {'n': 0}


def waking_up():
    """Fails once, as a compute being woken does, then succeeds."""
    calls['n'] += 1
    if calls['n'] == 1:
        raise RuntimeError('connection refused (compute waking)')
    return real_migrate()


main._migrate_db = waking_up
try:
    main._prepare_database()
    if calls['n'] < 2:
        failures.append('the first failure was not retried, so a cold database '
                        'would fail the deploy rather than being waited for')
except Exception as exc:  # noqa: BLE001 — reporting
    failures.append(f'a database that failed once then recovered still broke '
                    f'startup: {type(exc).__name__}: {exc}')

main._migrate_db = lambda: (_ for _ in ()).throw(RuntimeError('always down'))
try:
    main._prepare_database()
    failures.append('a database that never answers did not fail the deploy; the '
                    'app would serve requests against a schema it could not '
                    'prepare')
except RuntimeError as exc:
    if 'Could not reach the database' not in str(exc):
        failures.append(f'giving up did not say why: {exc}')
finally:
    main._migrate_db = real_migrate

os.unlink(_db.name)

if failures:
    print('Database driver check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'Database driver check OK — pg8000 {version("pg8000")} with scramp '
      f'{version("scramp")}, all {len(referenced)} scramp attributes present, '
      f'and an unreachable database errors within {attempts} attempts rather '
      'than hanging.')
