"""Check that production and CI agree on the Python version.

They did not. render.yaml declares PYTHON_VERSION 3.11.0, but that file is only
applied to a service created from it as a Blueprint, and this service was not --
every build log says "Using Python version 3.14.3 (default)", and the word
default is the proof: no version was set on the service at all.

So CI tested on 3.11 while production ran 3.14, resolving the same
requirements.txt under a different interpreter. That is how a dependency problem
reaches production having passed every check, and it is the general case of the
scramp break: the environments were never the same.

A .python-version file in the repository root is applied regardless of whether
the service came from a Blueprint, so it is the one place the version can be
pinned by committing something. This asserts it exists and matches what the
workflows test on, because the value of pinning it is entirely that the two
agree.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import pathlib
import re
import sys

failures = []

pinned_file = pathlib.Path('.python-version')
if not pinned_file.exists():
    failures.append('.python-version is missing, so Render uses its own default '
                    '-- currently 3.14.x -- and production runs an interpreter '
                    'nothing here tests')
    pinned = None
else:
    pinned = pinned_file.read_text().strip()
    if not re.fullmatch(r'\d+\.\d+(\.\d+)?', pinned or ''):
        failures.append(f'.python-version reads {pinned!r}, which is not a '
                        'version Render will accept')
        pinned = None

# Every workflow job that installs the app has to test the version that runs it.
workflow_versions = set()
for workflow in sorted(pathlib.Path('.github/workflows').glob('*.yml')):
    for found in re.findall(r'python-version:\s*["\']?([\d.]+)["\']?',
                            workflow.read_text()):
        workflow_versions.add(found)

if not workflow_versions:
    failures.append('no python-version was found in any workflow, so there is '
                    'nothing to compare the pin against')
elif len(workflow_versions) > 1:
    failures.append(f'the workflows test on more than one version '
                    f'({", ".join(sorted(workflow_versions))}), so "the version '
                    'CI tests" is not a single thing')
elif pinned:
    tested = workflow_versions.pop()
    # Compared on major.minor: the file may omit the patch, and Render then
    # takes the latest patch of that line, which is what CI's setup-python
    # does too.
    if tested.split('.')[:2] != pinned.split('.')[:2]:
        failures.append(f'CI tests on Python {tested} but .python-version pins '
                        f'{pinned}; production would run an interpreter no '
                        'check here exercises')

# render.yaml's declaration is kept for a Blueprint-created service, but it must
# not contradict the file that actually takes effect.
render_yaml = pathlib.Path('render.yaml')
if render_yaml.exists() and pinned:
    declared = re.search(r'key:\s*PYTHON_VERSION\s*\n\s*value:\s*([\d.]+)',
                         render_yaml.read_text())
    if declared and declared.group(1).split('.')[:2] != pinned.split('.')[:2]:
        failures.append(f'render.yaml declares PYTHON_VERSION '
                        f'{declared.group(1)} but .python-version pins {pinned}; '
                        'whichever is applied, they should not disagree')

if failures:
    print('Python version check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'Python version check OK — pinned to {pinned} and tested on the same.')
