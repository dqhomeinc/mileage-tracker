"""Representative render context for every routable template.

Shared by check_templates.py and check_js_syntax.py, which both have to render
the templates before they can check anything. Kept in one place because it was
previously copied into both: adding a variable to a route then broke whichever
check was edited second, and the failure pointed at Jinja rather than at the
stale table.

Each entry should mirror what the route actually passes. A variable missing
here is indistinguishable from one the route forgot.
"""

TEMPLATES_WITH_CONTEXT = {
    'register.html': {},
    'login.html': {},
    'forgot_password.html': {},
    'reset_password.html': {'token': 'dummy-token'},
    'index.html': {'username': 'tester', 'photo_data': None,
                   'maps_browser_key': 'test-browser-key'},
    'vehicles.html': {'username': 'tester', 'photo_data': None},
    'businesses.html': {'username': 'tester', 'photo_data': None},
    # Both an active and a revoked key, since the panel renders them
    # differently and the dict shape is what |tojson has to serialise.
    'profile.html': {'username': 'tester', 'email': 't@example.com', 'photo_data': None,
                     'api_base_url': 'https://example.test',
                     'api_keys': [
                         {'id': 1, 'name': 'AJ', 'public_id': 'a1b2c3d4e5f6',
                          'created_at': 'Oct 08, 2026',
                          'last_used_at': 'Oct 09, 2026 at 08:30', 'active': True},
                         {'id': 2, 'name': 'old script', 'public_id': 'f6e5d4c3b2a1',
                          'created_at': 'Sep 01, 2026',
                          'last_used_at': None, 'active': False},
                     ]},
}
