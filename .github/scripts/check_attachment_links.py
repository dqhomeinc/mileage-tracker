"""Check the signed attachment links that an exported PDF carries.

/attachment/shared/<token> is the only route in the app that serves a user's
data with no session. The token is the entire access control: it is minted only
after an ownership check, it names exactly one attachment, and it expires. Each
of those is one line of code, and getting any of them wrong hands one account's
receipts to another, or hands them to anyone forever.

That is not something a plain import check or a template render can see, so this
drives the two routes through a real Flask test client against a throwaway
SQLite database: two users, each with a trip and a receipt, and a run through
the cases that matter — minting someone else's id, replaying a token with no
session, an edited token, a token signed for another purpose, and an expired one.

Run as a script so it fits the other checks in this directory; no test runner.
"""
import io
import os
import re
import sys
import tempfile

_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_db.name}')
os.environ.setdefault('SECRET_KEY', 'attachment-link-check-secret')
sys.path.insert(0, os.getcwd())

import main  # noqa: E402

failures = []


def expect(label, actual, wanted):
    if actual != wanted:
        failures.append(f'{label}: expected {wanted!r}, got {actual!r}')


def register(client, name):
    client.post('/register', data={
        'username': name, 'email': f'{name}@example.com',
        'password': 'Testpass123!', 'confirm_password': 'Testpass123!',
    }, follow_redirects=True)
    client.post('/login', data={'email': f'{name}@example.com',
                                'password': 'Testpass123!'}, follow_redirects=True)


main.app.config['TESTING'] = True
main.app.config['WTF_CSRF_ENABLED'] = False

with main.app.app_context():
    main.db.create_all()

# Two accounts, each with one trip holding one receipt, created directly so the
# check does not depend on the upload route's own validation.
ids = {}
with main.app.app_context():
    for owner in ('alice', 'bob'):
        user = main.User(username=owner, email=f'{owner}@example.com')
        user.set_password('Testpass123!')
        main.db.session.add(user)
        main.db.session.commit()
        trip = main.Trip(user_id=user.id, start_location='A', end_location='B',
                         distance_miles=10.0, trip_date='2026-10-02')
        main.db.session.add(trip)
        main.db.session.commit()
        att = main.TripAttachment(trip_id=trip.id, filename=f'{owner}.png',
                                  mimetype='image/png', byte_size=4, data=b'\x89PNG')
        main.db.session.add(att)
        main.db.session.commit()
        ids[owner] = att.id

alice = main.app.test_client()
alice.post('/login', data={'email': 'alice@example.com', 'password': 'Testpass123!'},
           follow_redirects=True)

# ── Minting: ownership is checked here, because nothing checks it later ────
r = alice.post('/attachments/links', json={'ids': [ids['alice'], ids['bob']]})
expect('minting succeeds for a logged-in user', r.status_code, 200)
links = r.get_json().get('links', {})
expect('a link is minted for the caller\'s own attachment',
       str(ids['alice']) in links, True)
expect('no link is minted for another user\'s attachment',
       str(ids['bob']) in links, False)
expect('the expiry is reported so the PDF can say so',
       r.get_json().get('expires_in'), main.ATTACHMENT_LINK_MAX_AGE)

expect('a non-list ids is refused',
       alice.post('/attachments/links', json={'ids': 'all'}).status_code, 400)
expect('a missing ids is refused',
       alice.post('/attachments/links', json={}).status_code, 400)
expect('a non-numeric id is refused',
       alice.post('/attachments/links', json={'ids': ['x']}).status_code, 400)
expect('more ids than the cap is refused rather than truncated',
       alice.post('/attachments/links',
                  json={'ids': list(range(main.MAX_LINKS_PER_REQUEST + 1))}).status_code, 400)
expect('an empty list is fine and mints nothing',
       alice.post('/attachments/links', json={'ids': []}).get_json()['links'], {})

anon = main.app.test_client()
expect('minting without a session is not allowed',
       anon.post('/attachments/links', json={'ids': [ids['alice']]}).status_code in (302, 401), True)

# ── Redeeming: the token stands in for the session, and nothing else ───────
url = links[str(ids['alice'])]
path = url[url.index('/attachment/shared/'):]
token = path.rsplit('/', 1)[-1]

r = anon.get(path)
expect('the link serves the file with no session at all', r.status_code, 200)
expect('and serves the real bytes', r.data, b'\x89PNG')
expect('as a download, never rendered in the app\'s origin',
       r.headers['Content-Disposition'].startswith('attachment;'), True)
expect('with sniffing off', r.headers.get('X-Content-Type-Options'), 'nosniff')
expect('and kept out of search engines',
       'noindex' in r.headers.get('X-Robots-Tag', ''), True)
expect('the type decided at upload is the type served', r.headers['Content-Type'], 'image/png')

expect('an edited token is rejected', anon.get(path[:-1] + 'x').status_code, 404)
expect('a bare id is not a token', anon.get(f'/attachment/shared/{ids["alice"]}').status_code, 404)

# A token signed for a different purpose must not work here, even though it is
# signed with the same key — the salt is what separates them.
other = main._serializer().dumps(ids['alice'], salt='pw-reset-salt')
expect('a token signed for another purpose is rejected',
       anon.get(f'/attachment/shared/{other}').status_code, 404)

# A token for an attachment that has since been deleted must 404, not 500.
with main.app.app_context():
    gone = main.TripAttachment.query.filter_by(id=ids['bob']).first()
    main.db.session.delete(gone)
    main.db.session.commit()
bob_token = main._serializer().dumps(ids['bob'], salt=main.ATTACHMENT_LINK_SALT)
expect('a link to a deleted attachment is a clean 404',
       anon.get(f'/attachment/shared/{bob_token}').status_code, 404)

# A payload that is not an attachment id must not reach the query.
for payload in ('nonsense', True, [1, 2], {'id': 1}):
    bad = main._serializer().dumps(payload, salt=main.ATTACHMENT_LINK_SALT)
    expect(f'a token carrying {payload!r} is rejected',
           anon.get(f'/attachment/shared/{bad}').status_code, 404)

# ── Expiry: enforced on redemption, not merely promised in the PDF ────────
expect('the link window is the 30 days the UI promises',
       main.ATTACHMENT_LINK_MAX_AGE, 30 * 24 * 3600)

real_max_age = main.ATTACHMENT_LINK_MAX_AGE
try:
    main.ATTACHMENT_LINK_MAX_AGE = -1   # everything already signed is now old
    expect('an expired token is refused, and says so distinctly from a bad one',
           anon.get(path).status_code, 410)
finally:
    main.ATTACHMENT_LINK_MAX_AGE = real_max_age

expect('and works again once the window is restored', anon.get(path).status_code, 200)

# ── The client's batch size must not drift past the server's cap ──────────
# The export splits its ids into batches of LINK_BATCH_SIZE. A batch larger
# than the server accepts is refused whole, so every link in it is lost — and
# silently, since the export carries on without them.
template = io.open('templates/index.html', encoding='utf-8').read()
match = re.search(r'const LINK_BATCH_SIZE = (\d+);', template)
expect('the export declares a batch size', bool(match), True)
if match:
    expect('and it is within the cap the server enforces',
           int(match.group(1)) <= main.MAX_LINKS_PER_REQUEST, True)

# ── The logged-in route is untouched and still scoped to the owner ────────
bob = main.app.test_client()
bob.post('/login', data={'email': 'bob@example.com', 'password': 'Testpass123!'},
         follow_redirects=True)
expect('one user still cannot fetch another\'s attachment while logged in',
       bob.get(f'/attachment/{ids["alice"]}').status_code, 404)

os.unlink(_db.name)

if failures:
    print('Attachment link check FAILED:')
    for f in failures:
        print(f'  - {f}')
    sys.exit(1)

print('Attachment link check OK — ownership, signature, scope and expiry all hold.')
