"""Render every routable template with representative context to catch
Jinja errors (undefined vars, bad syntax, broken includes) that a plain
`import app` never exercises, since render_template() only runs at
request time, not import time.
"""
import sys

from jinja2 import Environment, FileSystemLoader

from template_context import TEMPLATES_WITH_CONTEXT  # noqa: E402

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
        except Exception as e:  # noqa: BLE001 — reporting, not handling
            # Not just TemplateError. A filter can raise something else
            # entirely -- |tojson on an undefined variable raises TypeError --
            # and catching only Jinja's own errors let that abort the script
            # with a traceback, taking every template after it unchecked.
            failures.append(f'{name} (photo_data={photo!r}): {type(e).__name__}: {e}')

if failures:
    print('Template render check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print(f'Template render check OK — {len(TEMPLATES_WITH_CONTEXT)} templates rendered cleanly.')
