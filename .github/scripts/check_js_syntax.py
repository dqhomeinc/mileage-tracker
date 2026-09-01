"""Syntax-check every inline <script> block across the rendered templates.

Templates mix Jinja and JS in the same <script> tags (e.g. profile.html uses
{{ username|tojson }} inside its script block), so scripts must be rendered
through Jinja first to resolve template syntax before the remaining content
is valid JS to check. External <script src="..."> tags (CDN-loaded libs) are
skipped since there's no inline content to check.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATES_WITH_CONTEXT = {
    'register.html': {},
    'login.html': {},
    'forgot_password.html': {},
    'reset_password.html': {'token': 'dummy-token'},
    'index.html': {'username': 'tester', 'photo_data': None,
                   'maps_browser_key': 'test-browser-key'},
    'vehicles.html': {'username': 'tester', 'photo_data': None},
    'profile.html': {'username': 'tester', 'email': 't@example.com', 'photo_data': None},
}

SCRIPT_RE = re.compile(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)

env = Environment(loader=FileSystemLoader('templates'))
env.globals['get_flashed_messages'] = lambda **kwargs: (
    [('danger', 'Sample flash message.')] if kwargs.get('with_categories') else []
)

failures = []
checked = 0

with tempfile.TemporaryDirectory() as tmpdir:
    for name, context in TEMPLATES_WITH_CONTEXT.items():
        html = env.get_template(name).render(**context, show_time_toggle=True)
        for i, script in enumerate(SCRIPT_RE.findall(html)):
            if not script.strip():
                continue
            checked += 1
            js_file = Path(tmpdir) / f'{name}.{i}.js'
            js_file.write_text(script)
            result = subprocess.run(
                ['node', '--check', str(js_file)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                failures.append(f'{name} (script block {i}):\n{result.stderr.strip()}')

if failures:
    print('JS syntax check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'JS syntax check OK — {checked} inline script block(s) checked cleanly.')
