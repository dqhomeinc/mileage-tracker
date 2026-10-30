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

Run as a script so it fits the other checks in this directory; no test runner.
"""
import pathlib
import re
import sys
from importlib.metadata import version

failures = []

# Imported defensively, so a missing driver reads as a named failure rather
# than a traceback that takes the rest of the script with it. In CI both are
# always installed from requirements.txt; locally they may not be.
try:
    import pg8000.core
    import scramp
except ImportError as exc:
    print('Database driver check FAILED:')
    print(f'  - could not import the driver or its SCRAM dependency ({exc}). '
          'Install from requirements.txt first.')
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

if failures:
    print('Database driver check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'Database driver check OK — pg8000 {version("pg8000")} with scramp '
      f'{version("scramp")}, and all {len(referenced)} scramp attributes it '
      'uses are present.')
