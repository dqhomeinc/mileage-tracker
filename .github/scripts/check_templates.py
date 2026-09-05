"""Render every routable template with representative context to catch
Jinja errors (undefined vars, bad syntax, broken includes) that a plain
`import app` never exercises, since render_template() only runs at
request time, not import time.
"""
import sys

from jinja2 import Environment, FileSystemLoader, TemplateError

TEMPLATES_WITH_CONTEXT = {
    'register.html': {},
    'login.html': {},
    'forgot_password.html': {},
    'reset_password.html': {'token': 'dummy-token'},
    'index.html': {'username': 'tester', 'photo_data': None,
                   'maps_browser_key': 'test-browser-key'},
    'vehicles.html': {'username': 'tester', 'photo_data': None},
    'businesses.html': {'username': 'tester', 'photo_data': None},
    'profile.html': {'username': 'tester', 'email': 't@example.com', 'photo_data': None},
}

env = Environment(loader=FileSystemLoader('templates'))
# Flask injects this automatically at request time; stub it for standalone
# rendering. Exercise both the empty case and an actual flash message.
env.globals['get_flashed_messages'] = lambda **kwargs: (
    [('danger', 'Sample flash message.')] if kwargs.get('with_categories') else []
)
failures = []

for name, context in TEMPLATES_WITH_CONTEXT.items():
    for photo in (None, 'data:image/png;base64,AAAA'):
        ctx = {**context, **({'photo_data': photo} if 'photo_data' in context else {})}
        try:
            env.get_template(name).render(**ctx, show_time_toggle=True)
        except TemplateError as e:
            failures.append(f'{name} (photo_data={photo!r}): {e}')

if failures:
    print('Template render check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'Template render check OK — {len(TEMPLATES_WITH_CONTEXT)} templates rendered cleanly.')
