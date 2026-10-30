import base64
from functools import wraps
import hashlib
import hmac
import json
import math
import os
import re
import secrets
from datetime import datetime, date, timedelta, timezone
import requests
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import (Flask, render_template, request, redirect, url_for, jsonify, flash,
                   session, Response, g)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import defer
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
_database_url = os.environ.get('DATABASE_URL')

# Deployed, as opposed to running from a local checkout or a check script.
# Derived from configuration that already has to be correct for the app to work
# at all, rather than a flag of its own that could be forgotten in exactly the
# deployment it is meant to guard.
#
# A SQLite URL is local by definition -- it names a file on this machine, and
# the scripts in .github/scripts point DATABASE_URL at a throwaway one. Only a
# deployment has a real database server behind it. Testing merely whether
# DATABASE_URL was set treated every one of those scripts as production.
IS_DEPLOYED = bool(_database_url) and not _database_url.startswith('sqlite')

# Signs session cookies, the "remember me" cookie and password-reset tokens. A
# known value therefore lets anyone mint a session for any account and forge a
# password reset for any address.
#
# This used to fall back to a constant written in this file, which is public. A
# service created without the environment variable started anyway, looked
# entirely healthy, and signed every cookie with a value anyone could read.
#
# The fallback is kept for local development, where there is nothing to protect
# and requiring a secret would mean setup before `python main.py` runs at all.
# Deployed, its absence is fatal instead: a failed deploy is obvious and fixed
# in a minute, whereas a service running on a published key gives no signal.
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    if IS_DEPLOYED:
        raise RuntimeError(
            'SECRET_KEY is not set. It signs session cookies and password-reset '
            'tokens, so starting without it would sign them with a value published '
            'in this repository, letting anyone forge a session for any account. '
            'Set SECRET_KEY in the Render dashboard (Environment) to a long random '
            'value -- for example the output of '
            '`python -c "import secrets; print(secrets.token_hex(32))"`.'
        )
    _secret_key = 'dev-only-key-never-deployed'
app.config['SECRET_KEY'] = _secret_key

MAX_PHOTO_BYTES = 2 * 1024 * 1024  # 2MB
# Receipts are photographed on phones, where 2MB is a routine single image, so
# attachments get their own larger ceiling. Both counts are enforced per file
# and per trip: the bytes live in Postgres, and Neon's free tier is ~0.5GB, so
# an unbounded number of 5MB files would fill it rather than fail gracefully.
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024  # 5MB
MAX_ATTACHMENTS_PER_TRIP = 10
MAX_FILENAME_LENGTH = 120
# Rejected at the Werkzeug layer before the body is ever buffered into memory,
# rather than checked after a full read(). This cap is global, so it has to be
# the largest upload any route accepts; +64KB covers multipart boundary and
# header overhead around the raw file bytes.
app.config['MAX_CONTENT_LENGTH'] = max(MAX_PHOTO_BYTES, MAX_ATTACHMENT_BYTES) + 64 * 1024

# Use PostgreSQL (via pg8000, pure-Python driver) when DATABASE_URL is set; SQLite locally.
# pg8000 needs the +pg8000 dialect prefix and has no system library dependencies.
_db_url = _database_url or 'sqlite:///mileage.db'
if _db_url.startswith('postgres://'):
    _db_url = 'postgresql+pg8000://' + _db_url[len('postgres://'):]
elif _db_url.startswith('postgresql://'):
    _db_url = 'postgresql+pg8000://' + _db_url[len('postgresql://'):]
# pg8000 negotiates SSL automatically and doesn't accept a sslmode kwarg,
# so strip query params like Neon's default "?sslmode=require".
_db_url = _db_url.split('?', 1)[0]
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Neon's free tier autosuspends the compute after a few minutes idle, which
# leaves stale connections sitting in the pool. pool_pre_ping catches those
# with a cheap check before use instead of failing mid-query; pool_recycle
# avoids handing out connections idle long enough to be suspect anyway.
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 280,
}

# Brevo (HTTPS email API) — Railway blocks outbound SMTP on non-Pro plans,
# so password reset emails are sent over HTTPS instead of raw SMTP.
app.config['BREVO_API_KEY'] = os.environ.get('BREVO_API_KEY')
app.config['BREVO_SENDER_EMAIL'] = os.environ.get('BREVO_SENDER_EMAIL')
# Google Maps Platform. Two keys with different exposure: the browser key is
# served to the page for Places Autocomplete and is restricted by HTTP
# referrer; the server key never leaves the backend and is restricted to the
# Routes API.
app.config['GOOGLE_MAPS_BROWSER_KEY'] = os.environ.get('GOOGLE_MAPS_BROWSER_KEY')
app.config['GOOGLE_MAPS_SERVER_KEY'] = os.environ.get('GOOGLE_MAPS_SERVER_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    photo_data = db.Column(db.Text, nullable=True)
    # The vehicle preselected when logging a new trip, null until the user picks
    # one — nothing sets it implicitly. Held here rather than as
    # an is_default flag on Vehicle so "at most one default" is a property of
    # the shape of the data instead of something the write path has to remember
    # to maintain by unsetting the previous one. Deliberately not a foreign key:
    # user and vehicle would then reference each other, and the raw ALTER TABLE
    # in _migrate_db() can't add a constraint. Ownership is checked in the route
    # and delete_vehicle() clears it, so a stale id can't outlive its vehicle.
    default_vehicle_id = db.Column(db.Integer, nullable=True)
    # The code the user types to log or edit a trip. Null for accounts that
    # existed before this column; logging_key_for() mints one on first use
    # rather than a backfill over every row inside _migrate_db().
    logging_key = db.Column(db.String(32), nullable=True)
    # Failed attempts at the password gate in front of the key, and the time
    # that gate reopens. On the user row rather than in memory because Render
    # restarts and may run more than one worker, either of which would reset an
    # in-process counter and hand the attempts back.
    key_reveal_fails = db.Column(db.Integer, nullable=True)
    key_reveal_locked_until = db.Column(db.DateTime, nullable=True)
    # The business preselected when logging a new trip. Same reasoning as
    # default_vehicle_id above: a scalar here rather than a flag per row, so
    # only one business can be the default by construction.
    default_business_id = db.Column(db.Integer, nullable=True)
    trips    = db.relationship('Trip', backref='user', lazy=True, cascade='all, delete-orphan')
    vehicles = db.relationship('Vehicle', backref='owner', lazy=True, cascade='all, delete-orphan')
    businesses = db.relationship('Business', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ApiKey(db.Model):
    """A scoped credential a user issues so an agent can log trips for them.

    The point of it is what it *cannot* do. A user who wants a script or an
    assistant to log trips on their behalf would otherwise have to hand over
    their password, which is complete account access. A key is create-trips
    and read-reference-data only, belongs to one account, and can be revoked
    without touching the password or signing anyone out.

    Stored as a hash, unlike User.logging_key, because the two have opposite
    requirements: a logging key has to be displayable in the profile for ever,
    while an API key is shown once at creation and never again. So a database
    leak yields working logging keys but not working API keys.

    That means the secret itself cannot be looked up, which is what public_id
    is for -- it is the non-secret half of the key, stored plaintext and
    indexed, so a request finds its row in one query and only then compares
    the hash. Hashing the whole key would mean scanning every row.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    # What the key is for, so a user with several can tell them apart when
    # deciding which to revoke.
    name = db.Column(db.String(60), nullable=False)
    public_id = db.Column(db.String(32), nullable=False, unique=True, index=True)
    secret_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    # How a dormant or unexpectedly active key becomes visible. The only
    # monitoring this design has, and the reason no expiry is needed.
    last_used_at = db.Column(db.DateTime, nullable=True)
    # Set rather than deleted, so a revoked key's name and last use can still
    # be shown -- "this key was being used until Tuesday" is the useful fact
    # after revoking one.
    revoked_at = db.Column(db.DateTime, nullable=True)
    # A fixed-window request counter, held on the key itself rather than in a
    # table of requests. The row is already loaded to authenticate, so counting
    # here costs no extra query and nothing accumulates to prune.
    window_started_at = db.Column(db.DateTime, nullable=True)
    window_count = db.Column(db.Integer, nullable=True)

    @property
    def active(self):
        return self.revoked_at is None


class Vehicle(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name    = db.Column(db.String(100), nullable=False)
    year    = db.Column(db.String(4))
    make    = db.Column(db.String(60))
    model   = db.Column(db.String(60))
    trips   = db.relationship('Trip', backref='vehicle', lazy=True)


class TripAttachment(db.Model):
    """A receipt or document kept with a trip.

    The bytes live here rather than on disk because Render's filesystem is
    ephemeral — a redeploy or an idle spin-down would take every file with it.
    Stored as bytea rather than a base64 string like the profile photo: these
    are served through a download route instead of being inlined into HTML, so
    there is nothing to gain from text encoding and 33% of the size to lose.
    """
    id         = db.Column(db.Integer, primary_key=True)
    trip_id    = db.Column(db.Integer, db.ForeignKey('trip.id'), nullable=False)
    filename   = db.Column(db.String(MAX_FILENAME_LENGTH), nullable=False)
    mimetype   = db.Column(db.String(100), nullable=False)
    byte_size  = db.Column(db.Integer, nullable=False)
    data       = db.Column(db.LargeBinary, nullable=False)
    uploaded_at = db.Column(db.DateTime, server_default=db.func.now())


class Business(db.Model):
    """A business a trip's mileage is attributed to.

    Only a name: unlike Vehicle there is no year/make/model to describe, and a
    mileage log needs the attribution, not a company record.
    """
    id      = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name    = db.Column(db.String(100), nullable=False)
    trips   = db.relationship('Trip', backref='business', lazy=True)


class Trip(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_location = db.Column(db.Text, nullable=False)
    end_location   = db.Column(db.Text, nullable=False)
    distance_miles = db.Column(db.Float, nullable=True)
    timestamp      = db.Column(db.DateTime, server_default=db.func.now())
    vehicle_id     = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=True)
    business_id    = db.Column(db.Integer, db.ForeignKey('business.id'), nullable=True)
    trip_date      = db.Column(db.String(10), nullable=True)
    start_time     = db.Column(db.String(5),  nullable=True)
    end_time       = db.Column(db.String(5),  nullable=True)
    # The day the trip ended. Usually the trip date, the day after when the
    # clock crossed midnight, and later still for a drive spanning more than one
    # night — which two time fields and a single date cannot express. Null for a
    # trip with no end time, and for rows logged before this column existed,
    # where it is derived on read instead.
    end_date       = db.Column(db.String(10), nullable=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    # Free-text note for the trip: purpose, client, anything worth recalling
    # when the log is reviewed months later. Capped in the route rather than by
    # the column type, so the limit can be stated back to the user.
    notes          = db.Column(db.Text, nullable=True)
    # How the trip was recorded: 'web' for the form, 'api' for a key. Null for
    # every trip logged before this column existed, which reads as "not known
    # to be from a key" -- the honest answer, since the API did not exist then.
    created_via = db.Column(db.String(8), nullable=True)
    # Which key, so a trip can be traced to one agent when an account has
    # several. Deliberately not a foreign key: a revoked key's row is kept, but
    # if one were ever deleted the trips it logged must not go with it.
    created_by_key_id = db.Column(db.Integer, nullable=True)
    # Intermediate stops between start and end, in the order visited, as a JSON
    # list of {"label", "place_id"}. A column rather than a table: stops are
    # only ever read with their trip, are few, and are ordered, so a join would
    # add a query per history load and a position column to keep straight.
    stops          = db.Column(db.Text, nullable=True)
    # Google Places IDs for the locations, when the user picked them from
    # autocomplete. Stored so a recalculation routes the same two places
    # instead of re-resolving the display text; null for free-typed trips and
    # for every trip logged before the Routes migration.
    start_place_id = db.Column(db.String(255), nullable=True)
    end_place_id   = db.Column(db.String(255), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

# `owner` is passed by the API routes, which authenticate by key and so have no
# current_user to read the default from. The signed-in paths leave it out.
def _vehicle_dict(v, owner=None):
    owner = owner or current_user
    sub = ' '.join(filter(None, [v.year, v.make, v.model]))
    return {'id': v.id, 'name': v.name, 'year': v.year, 'make': v.make,
            'model': v.model, 'sub': sub,
            'is_default': v.id == owner.default_vehicle_id}


def _business_dict(b, owner=None):
    owner = owner or current_user
    return {'id': b.id, 'name': b.name,
            'is_default': b.id == owner.default_business_id}


def _api_key_name_for(trip):
    """The name of the key that logged this trip, or None.

    Looked up by id rather than joined, because only API-logged trips have one
    and a history page is mostly web-logged. Returns the name even for a
    revoked key, which is the point -- "logged by AJ, since revoked" is what
    someone reviewing the log needs to see.
    """
    if not trip.created_by_key_id:
        return None
    key = db.session.get(ApiKey, trip.created_by_key_id)
    return key.name if key else None


def _trip_dict(trip, vehicle_name=None, vehicle_sub=None, business_name=None,
               attachments=None):
    """attachments is passed in by callers listing several trips, which fetch
    them for the whole page in one query; a single-trip caller leaves it out and
    one lookup is done here."""
    return {
        'id':           trip.id,
        # Only 'api' is surfaced. Older trips have no value and web trips are
        # the norm, so the history marks what is unusual rather than badging
        # every row with where it came from.
        'via_api':      trip.created_via == 'api',
        'via_api_key':  _api_key_name_for(trip),
        'start':        trip.start_location,
        'end':          trip.end_location,
        'miles':        trip.distance_miles,
        'timestamp':    trip.timestamp.strftime('%b %d, %Y %I:%M %p') if trip.timestamp else '',
        'vehicle_id':   trip.vehicle_id,
        'vehicle_name': vehicle_name,
        'vehicle_sub':  vehicle_sub,
        'business_id':   trip.business_id,
        'business_name': business_name,
        'trip_date':    trip.trip_date,
        'start_time':   trip.start_time,
        'end_time':     trip.end_time,
        # Stored on the trip, falling back to what its times imply for rows
        # logged before the column existed. Sent from here so the history row,
        # the edit modal and all three exports read one value rather than each
        # working it out again.
        'end_date':      _trip_end_date(trip),
        'ends_next_day': (_trip_end_date(trip) or trip.trip_date) != trip.trip_date,
        'duration_seconds': trip.duration_seconds,
        'notes':        trip.notes,
        'stops':        _stops_from_db(trip.stops),
        'start_place_id': trip.start_place_id,
        'end_place_id':   trip.end_place_id,
        'attachments':  (attachments if attachments is not None
                         else _attachments_by_trip([trip.id]).get(trip.id, [])),
    }


def _migrate_db():
    """Add new columns/tables to existing databases without dropping data.

    Note: distance_miles was relaxed to nullable so a trip can be logged even
    when distance calculation fails. Postgres can drop the NOT NULL
    constraint in place; SQLite cannot (ALTER COLUMN isn't supported), so the
    SQLite branch only warns — local dev DBs hold no real data and can just
    be deleted so db.create_all() recreates the table from the model.
    """
    dialect = db.engine.dialect.name
    with db.engine.connect() as conn:
        if dialect == 'sqlite':
            result = conn.execute(db.text('PRAGMA table_info(trip)'))
            info = list(result)
            existing = {row[1] for row in info}
            notnull = {row[1]: row[3] for row in info}
            additions = [
                ('vehicle_id', 'INTEGER'),
                ('business_id', 'INTEGER'),
                ('notes', 'TEXT'),
                ('stops', 'TEXT'),
                ('trip_date',  'VARCHAR(10)'),
                ('start_time', 'VARCHAR(5)'),
                ('end_time',   'VARCHAR(5)'),
                ('end_date',   'VARCHAR(10)'),
                ('duration_seconds', 'INTEGER'),
                ('start_place_id', 'VARCHAR(255)'),
                ('end_place_id',   'VARCHAR(255)'),
                ('created_via', 'VARCHAR(8)'),
                ('created_by_key_id', 'INTEGER'),
            ]
            for col, typ in additions:
                if col not in existing:
                    conn.execute(db.text(f'ALTER TABLE trip ADD COLUMN {col} {typ}'))
            if notnull.get('distance_miles') == 1:
                app.logger.warning(
                    "Local SQLite 'trip' table still enforces distance_miles NOT NULL "
                    "(SQLite can't drop that constraint via ALTER TABLE). Delete "
                    "mileage.db and restart — db.create_all() will recreate it from "
                    "the updated model. Safe for local dev; it holds no production data."
                )
        else:
            result = conn.execute(db.text(
                "SELECT column_name, is_nullable FROM information_schema.columns "
                "WHERE table_name = 'trip'"
            ))
            columns = {row[0]: row[1] for row in result}
            existing = set(columns)
            additions = [
                ('vehicle_id', 'INTEGER'),
                ('business_id', 'INTEGER'),
                ('notes', 'TEXT'),
                ('stops', 'TEXT'),
                ('trip_date',  'VARCHAR(10)'),
                ('start_time', 'VARCHAR(5)'),
                ('end_time',   'VARCHAR(5)'),
                ('end_date',   'VARCHAR(10)'),
                ('duration_seconds', 'INTEGER'),
                ('start_place_id', 'VARCHAR(255)'),
                ('end_place_id',   'VARCHAR(255)'),
                ('created_via', 'VARCHAR(8)'),
                ('created_by_key_id', 'INTEGER'),
            ]
            for col, typ in additions:
                if col not in existing:
                    conn.execute(db.text(f'ALTER TABLE trip ADD COLUMN {col} {typ}'))
            if columns.get('distance_miles') == 'NO':
                conn.execute(db.text('ALTER TABLE trip ALTER COLUMN distance_miles DROP NOT NULL'))

        if dialect == 'sqlite':
            result = conn.execute(db.text('PRAGMA table_info(user)'))
            existing_user_cols = {row[1] for row in result}
        else:
            result = conn.execute(db.text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'user'"
            ))
            existing_user_cols = {row[0] for row in result}
        if 'photo_data' not in existing_user_cols:
            conn.execute(db.text('ALTER TABLE "user" ADD COLUMN photo_data TEXT'))
        if 'default_vehicle_id' not in existing_user_cols:
            conn.execute(db.text('ALTER TABLE "user" ADD COLUMN default_vehicle_id INTEGER'))
        if 'default_business_id' not in existing_user_cols:
            conn.execute(db.text('ALTER TABLE "user" ADD COLUMN default_business_id INTEGER'))
        # api_key is a new table, so db.create_all() builds it complete -- but a
        # deployment that already ran the first version of it has the table
        # without these two columns, which create_all() will not add.
        if dialect == 'sqlite':
            result = conn.execute(db.text('PRAGMA table_info(api_key)'))
            existing_key_cols = {row[1] for row in result}
        else:
            result = conn.execute(db.text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'api_key'"
            ))
            existing_key_cols = {row[0] for row in result}
        # Empty when the table does not exist yet, in which case create_all()
        # has already made it with both columns and there is nothing to add.
        if existing_key_cols:
            if 'window_started_at' not in existing_key_cols:
                conn.execute(db.text('ALTER TABLE api_key ADD COLUMN window_started_at TIMESTAMP'))
            if 'window_count' not in existing_key_cols:
                conn.execute(db.text('ALTER TABLE api_key ADD COLUMN window_count INTEGER'))

        if 'logging_key' not in existing_user_cols:
            conn.execute(db.text('ALTER TABLE "user" ADD COLUMN logging_key VARCHAR(32)'))
        if 'key_reveal_fails' not in existing_user_cols:
            conn.execute(db.text('ALTER TABLE "user" ADD COLUMN key_reveal_fails INTEGER'))
        if 'key_reveal_locked_until' not in existing_user_cols:
            conn.execute(db.text('ALTER TABLE "user" ADD COLUMN key_reveal_locked_until TIMESTAMP'))

        conn.commit()


# ---------------------------------------------------------------------------
# Per-user logging key
# ---------------------------------------------------------------------------
#
# A short code the user has to type to log or edit a trip, to stop trips being
# written by a script rather than a person.
#
# What this does and does not do is worth being exact about, because the shape
# of it invites being read as more than it is. It is not an authentication
# factor. The goal is that logging cannot be automated *incidentally* -- only
# by a user who deliberately hands their own key to a script, which is a choice
# they have made rather than something that falls out of the app being easy to
# POST to.
#
# So: it stops a script that simply POSTs to /log, because the code is nowhere
# in the page it would be scraping. It would not stop a script driving a stolen
# session either -- except that the code is deliberately not printed on the
# profile page; revealing it costs the account password (see
# reveal_logging_key), so reading it off the profile is not something a session
# alone can do. And it does not stop the account holder giving the code to
# their own script, which nothing held by the user ever could. That last case
# is accepted: it makes automation a deliberate act instead of a free one.
#
# The code is required on every log and every edit for the same reason. A value
# cached between trips would make the first entry the deliberate act and every
# trip after it free again.

LOGGING_KEY_LENGTH = 8

# No I, L, O, U, 0 or 1. The code is read off a screen and typed back, and
# those are the characters that get read back wrong.
_LOGGING_KEY_ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ23456789'

_LOGGING_KEY_STRIP = re.compile(r'[^A-Z0-9]')


def generate_logging_key():
    return ''.join(secrets.choice(_LOGGING_KEY_ALPHABET) for _ in range(LOGGING_KEY_LENGTH))


def normalize_logging_key(value):
    """What the user typed, reduced to what is actually compared.

    The code is shown grouped ("ABCD-2345") and will be typed back with or
    without the dash, in either case, and often with a stray space from a
    copy-paste. Those are all the same code, and refusing them would read as
    the feature being broken.
    """
    return _LOGGING_KEY_STRIP.sub('', (value or '').upper())


def format_logging_key(key):
    """The code as it is displayed: one dash in the middle, which is most of
    why anyone copies eight characters correctly."""
    if not key:
        return ''
    half = LOGGING_KEY_LENGTH // 2
    return f'{key[:half]}-{key[half:]}'


def logging_key_for(user):
    """The user's code, minted on first use.

    Accounts that existed before the column have none, and backfilling them
    would mean a write over every row inside _migrate_db(). Minting on the
    first read keeps the migration to one ALTER TABLE, at the cost of this
    function being the only way the rest of the app should read the column.
    """
    if not user.logging_key:
        user.logging_key = generate_logging_key()
        db.session.commit()
    return user.logging_key


def check_logging_key(data):
    """None if the request carried the right code, else the message to return.

    Compared with compare_digest rather than ==, so the comparison does not
    stop early on the first wrong character.

    Deliberately not rate-limited *here*. The code is eight characters from a
    thirty-character alphabet, so guessing it over HTTP is not a threat worth a
    lockout, and a lockout on this route would stop a legitimate user logging
    their trips -- a worse outcome than the one it would prevent.

    The password gate in front of the key is throttled instead, which is where
    the guessing is actually cheap; see _check_key_gate.
    """
    supplied = normalize_logging_key((data or {}).get('logging_key'))
    if not supplied:
        return 'Enter your logging key to save this trip. You can find it in your profile.'
    if not hmac.compare_digest(supplied, logging_key_for(current_user)):
        return 'That logging key is not correct. Check it in your profile and try again.'
    return None


# The password gate in front of the key is the only thing standing between a
# session and the key, so it is the thing worth throttling -- not the key itself.
# A guess at an eight-character key is hopeless; a guess at a password that is
# weak or reused is not, and without a limit these two routes are an unlimited
# password oracle for whoever already holds the session.
#
# A lockout is cheap here in a way it would not be on /log: it blocks looking
# the key up, not logging trips, so a user who trips it can still work.
LOGGING_KEY_MAX_ATTEMPTS = 5
LOGGING_KEY_LOCKOUT = timedelta(minutes=15)


def _utcnow():
    """Naive UTC, matching how these columns are written and read.

    datetime.utcnow() does the same thing but is deprecated from 3.12, and
    storing an aware value would not survive the SQLite round trip as one.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _key_gate_state():
    """The gate columns as the database currently holds them.

    Read with a column query rather than off current_user, because the counter
    below is incremented in SQL: the loaded attribute is stale the moment it is.
    """
    row = (db.session.query(User.key_reveal_fails, User.key_reveal_locked_until)
           .filter(User.id == current_user.id).one())
    return (row[0] or 0), row[1]


def _record_key_gate_failure():
    """Count one failed attempt, locking the gate if that reaches the limit.

    One UPDATE, which is the whole point. Reading the count into Python,
    incrementing it and writing it back would let a burst of parallel guesses
    all read the same value and all write the same value back -- so an attacker
    sending N at a time would earn one counted failure per burst rather than
    per request, and the lock might never engage at all. Deciding the new count
    and the lock inside the statement leaves nothing to interleave.
    """
    nxt = db.func.coalesce(User.key_reveal_fails, 0) + 1
    reached = nxt >= LOGGING_KEY_MAX_ATTEMPTS
    db.session.execute(
        db.update(User)
        .where(User.id == current_user.id)
        .values(
            # Reset to zero as the lock goes on, so the next window starts clean.
            key_reveal_fails=db.case((reached, 0), else_=nxt),
            key_reveal_locked_until=db.case(
                (reached, _utcnow() + LOGGING_KEY_LOCKOUT),
                else_=User.key_reveal_locked_until,
            ),
        )
    )
    db.session.commit()


def _clear_key_gate():
    """Forget the failures, and any lock that has expired."""
    db.session.execute(
        db.update(User)
        .where(User.id == current_user.id)
        .values(key_reveal_fails=0, key_reveal_locked_until=None)
    )
    db.session.commit()


def _check_key_gate(password):
    """None if the password is right and the gate is open, else (message, status).

    A correct password clears the count, so ordinary mistyping never
    accumulates towards a lockout across days.

    Requests already in flight when the lock engages are not stopped -- the
    check and the lock cannot be one statement when a password hash has to be
    verified between them. The count itself is exact, so the lock engages after
    the right number of failures regardless of how they were spread out, which
    is what bounds the guessing.
    """
    _, locked_until = _key_gate_state()
    now = _utcnow()
    if locked_until and locked_until > now:
        minutes = max(1, int((locked_until - now).total_seconds() // 60) + 1)
        return (f'Too many incorrect attempts. Try again in {minutes} minute'
                f'{"" if minutes == 1 else "s"}.', 429)

    if not current_user.check_password(password):
        _record_key_gate_failure()
        return ('Password is incorrect.', 403)

    # Clearing an expired lock here too, so the row does not keep a stale
    # timestamp that the branch above has to keep comparing against.
    fails, locked_until = _key_gate_state()
    if fails or locked_until:
        _clear_key_gate()
    return None


@app.route('/profile/logging-key', methods=['POST'])
@login_required
def reveal_logging_key():
    """The code, shown only once the account password is re-entered.

    This is what makes the code worth having at all. A script driving a stolen
    session can already reach /log, so a code printed on the profile page could
    just be read off it. Behind the password, that script needs the password
    too -- at which point it is not the thing this was meant to stop.

    Which means this route is where a guess is cheap, so it is throttled; the
    key route is not. See _check_key_gate.
    """
    data = request.get_json(silent=True) or {}
    refused = _check_key_gate(data.get('password') or '')
    if refused:
        message, status = refused
        return jsonify({'error': message}), status
    return jsonify({'logging_key': format_logging_key(logging_key_for(current_user))})


@app.route('/profile/logging-key', methods=['PUT'])
@login_required
def regenerate_logging_key():
    """A fresh code, which immediately invalidates the old one.

    Also behind the password: rotating someone's code is a way to lock them out
    of logging trips until they look it up again.
    """
    data = request.get_json(silent=True) or {}
    refused = _check_key_gate(data.get('password') or '')
    if refused:
        message, status = refused
        return jsonify({'error': message}), status
    current_user.logging_key = generate_logging_key()
    db.session.commit()
    return jsonify({'logging_key': format_logging_key(current_user.logging_key)})


# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

_PW_SPECIAL = re.compile(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]')

def validate_password(password):
    errors = []
    if len(password) < 6:
        errors.append('at least 6 characters')
    if not re.search(r'[a-z]', password):
        errors.append('one lowercase letter (a–z)')
    if not re.search(r'[A-Z]', password):
        errors.append('one uppercase letter (A–Z)')
    if not re.search(r'\d', password):
        errors.append('one number (0–9)')
    if not _PW_SPECIAL.search(password):
        errors.append('one special character (!@#$…)')
    return errors


def validate_username(username):
    if not username:
        return 'Username is required.'
    if len(username) > 80:
        return 'Username must be 80 characters or fewer.'
    return None


def username_taken(username):
    return User.query.filter_by(username=username).first() is not None


# ---------------------------------------------------------------------------
# Password reset tokens (1-hour expiry via itsdangerous)
# ---------------------------------------------------------------------------

def _serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(email):
    return _serializer().dumps(email, salt='pw-reset-salt')

def verify_reset_token(token, max_age=3600):
    try:
        return _serializer().loads(token, salt='pw-reset-salt', max_age=max_age)
    except (SignatureExpired, BadSignature):
        return None

BREVO_API_URL = 'https://api.brevo.com/v3/smtp/email'


def _send_email(to, subject, html):
    resp = requests.post(
        BREVO_API_URL,
        headers={'api-key': app.config['BREVO_API_KEY'], 'Content-Type': 'application/json'},
        json={
            'sender': {'email': app.config['BREVO_SENDER_EMAIL']},
            'to': [{'email': to}],
            'subject': subject,
            'htmlContent': html,
        },
        timeout=10
    )
    resp.raise_for_status()


def send_reset_email(user, token):
    reset_url = url_for('reset_password', token=token, _external=True)
    if not _mail_config_ok():
        app.logger.info('DEV — password reset URL: %s', reset_url)
        return
    _send_email(
        to=user.email,
        subject='Mileage Tracker — Password Reset',
        html=(
            f'<p>Hi {user.username},</p>'
            f'<p>Click the link below to reset your password. '
            f'The link expires in 1 hour.</p>'
            f'<p><a href="{reset_url}">{reset_url}</a></p>'
            f'<p>If you did not request this, you can ignore this email.</p>'
        )
    )


def _mail_config_ok():
    return bool(app.config.get('BREVO_API_KEY') and app.config.get('BREVO_SENDER_EMAIL'))


# ---------------------------------------------------------------------------
# Distance calculation: Google Routes API
# ---------------------------------------------------------------------------
# Routing is done by Places place ID whenever the user picked a suggestion from
# autocomplete, so the distance is computed for the exact place they chose and
# no geocoding step happens at all. Free-typed and voice-entered text falls
# back to an address string, which Routes geocodes itself.
#
# Both paths now resolve through one provider. The previous split — Nominatim
# autocomplete on the client, Geocodio geocoding on the server — resolved the
# same trip two different ways: the client found the right place, discarded its
# coordinates, and the server re-resolved a rebuilt label string with a
# geocoder that has no POI data. That could overstate a trip by 50%+.

ROUTES_API_URL = 'https://routes.googleapis.com/directions/v2:computeRoutes'

# Only the fields we use. The SKU is set by the features a request uses —
# traffic-aware routing, more than 10 waypoints, two-wheel — not by the field
# mask, so these leg coordinates bill the same Essentials SKU as distance and
# duration alone. They are what lets the client bias address autocomplete
# toward where the user actually drives; see /calculate.
ROUTES_FIELD_MASK = (
    'routes.distanceMeters,routes.duration,'
    'routes.legs.startLocation,routes.legs.endLocation'
)

METERS_PER_MILE = 1609.344


def _route_waypoint(place_id, address):
    """A Routes waypoint: place ID when we have one, else raw address text."""
    return {'placeId': place_id} if place_id else {'address': address}


def _parse_route_duration(value):
    """Routes returns duration as a string like '1978s'. None if unparseable."""
    if not isinstance(value, str) or not value.endswith('s'):
        return None
    try:
        return int(float(value[:-1]))
    except ValueError:
        return None


def _leg_latlng(route, which):
    """{'lat': .., 'lng': ..} for the first leg's start or the last leg's end,
    or None if Routes didn't return it."""
    legs = route.get('legs') or []
    if not legs:
        return None
    leg = legs[0] if which == 'start' else legs[-1]
    pt = (leg.get('startLocation' if which == 'start' else 'endLocation') or {}).get('latLng') or {}
    if 'latitude' not in pt or 'longitude' not in pt:
        return None
    return {'lat': pt['latitude'], 'lng': pt['longitude']}


def calculate_driving_miles(start_text, end_text,
                            start_place_id=None, end_place_id=None, stops=None):
    """(miles, duration_seconds, endpoints) for the driving route between two
    points, through any stops in the order given. endpoints holds the resolved
    'start'/'end' coordinates, either of which may be None.
    The duration is driving time only.

    Raises ValueError when the route can't be determined — the caller turns
    that into a user-facing message.
    """
    body = {
        'origin':      _route_waypoint(start_place_id, start_text),
        'destination': _route_waypoint(end_place_id, end_text),
        'travelMode': 'DRIVE',
        'units': 'IMPERIAL',
        # routingPreference is deliberately left unset. TRAFFIC_AWARE moves
        # the request to the Compute Routes Pro SKU, and a mileage log
        # shouldn't record a different distance depending on traffic.
    }
    if stops:
        # Visited in the order given. optimizeWaypointOrder is deliberately left
        # unset: order changes the mileage a lot (Charlotte to Concord via
        # Kannapolis then Huntersville is 67.9 mi; the reverse is 38.8), so the
        # route must be the one the user drove, not the shortest available.
        body['intermediates'] = [_route_waypoint(st.get('place_id'), st['label']) for st in stops]
    resp = requests.post(
        ROUTES_API_URL,
        headers={
            'Content-Type': 'application/json',
            'X-Goog-Api-Key': app.config['GOOGLE_MAPS_SERVER_KEY'],
            'X-Goog-FieldMask': ROUTES_FIELD_MASK,
        },
        json=body,
        timeout=10,
    )
    if resp.status_code == 400:
        raise ValueError('Could not find a driving route between those locations.')
    resp.raise_for_status()

    # A location Routes can't geocode comes back as HTTP 200 with an empty JSON
    # body rather than an error status, so an empty result is a real failure
    # and not something to pass along as a valid route.
    routes = resp.json().get('routes')
    if not routes:
        raise ValueError(
            'Could not find a driving route between those locations. '
            'Try picking each address from the suggestions.'
        )

    route = routes[0]
    # Routes omits distanceMeters entirely when it is zero, so a trip whose two
    # ends resolve to the same point comes back as {'duration': '0s'} and a
    # direct subscript raises. Easy to hit with named locations: two different
    # names for one site, or a name that geocodes onto the other endpoint.
    miles = round(route.get('distanceMeters', 0) / METERS_PER_MILE, 2)
    endpoints = {'start': _leg_latlng(route, 'start'), 'end': _leg_latlng(route, 'end')}
    return miles, _parse_route_duration(route.get('duration')), endpoints


def _minutes_of_day(value):
    """Minutes since midnight for an 'HH:MM' string, or None."""
    try:
        h, m = map(int, (value or '').split(':'))
    except (ValueError, AttributeError):
        return None
    return h * 60 + m


def _ends_next_day(start_time, end_time):
    """Whether a trip's end time falls on the day after its start.

    Mirrored by endsNextDay() in index.html, as _derived_end_date,
    _elapsed_seconds and validate_end_date are by their own counterparts —
    the form has to show an answer before it submits one. Keep the pairs in step;
    .github/scripts/check_trip_times.py is the record of what these rules are.

    A trip that leaves at 23:30 and arrives at 01:00 has an end time earlier
    than its start, which is the only way a single trip date can express
    crossing midnight. Strictly earlier: equal times are a zero-length trip, not
    a twenty-four-hour one.
    """
    start, end = _minutes_of_day(start_time), _minutes_of_day(end_time)
    if start is None or end is None:
        return False
    return end < start


def _derived_end_date(trip_date, start_time, end_time):
    """The end date implied by the times alone: the trip date, or the day after
    when the clock wrapped past midnight.

    Used for trips stored before end_date existed, and as the default when the
    client does not send one. It can only ever say "same day" or "next day",
    which is why a trip spanning more than one night needs the column.
    """
    parsed = _parse_iso_date(trip_date)
    if not parsed or not end_time:
        return None
    if _ends_next_day(start_time, end_time):
        parsed += timedelta(days=1)
    return parsed.isoformat()


def _trip_end_date(trip):
    """A trip's end date: the stored one, or the one its times imply."""
    return trip.end_date or _derived_end_date(trip.trip_date, trip.start_time, trip.end_time)


def _elapsed_seconds(start_time, end_time, trip_date=None, end_date=None):
    """Seconds from start to end.

    With both dates the span is measured between them, so a drive of more than
    one night counts every hour of it. Without them only the clock is available,
    and an end earlier than the start is read as the next day — which is all a
    single date can mean. None if either time is missing or unparseable.
    """
    start_min, end_min = _minutes_of_day(start_time), _minutes_of_day(end_time)
    if start_min is None or end_min is None:
        return None
    start_day, end_day = _parse_iso_date(trip_date), _parse_iso_date(end_date)
    if start_day and end_day:
        return ((end_day - start_day).days * 1440 + end_min - start_min) * 60
    if end_min < start_min:
        end_min += 24 * 60
    return (end_min - start_min) * 60


FEASIBILITY_MIN_RATIO = 0.5  # flag "too fast" if elapsed < 50% of the Routes API's expected duration
FEASIBILITY_MAX_RATIO = 3.0  # flag "too slow" if elapsed > 300% of the Routes API's expected duration

# Routes' duration is driving only, and how long someone spends at a stop is
# unknown. Each stop adds this much headroom before a trip counts as
# implausibly slow — enough for a meeting or a site visit — while a 12-hour
# AM/PM slip is still caught on a short trip with up to about three stops.
# Stops can only add time, never remove it, so the too-fast bound is unchanged.
# The client mirrors this in feasibilityWarning(); keep the two in step.
STOP_DWELL_ALLOWANCE_SECONDS = 2 * 60 * 60


def check_trip_feasibility(start_time, end_time, distance_miles, duration_seconds,
                           stop_count=0, trip_date=None, end_date=None):
    """Warning string if the clock-time gap is implausible (too fast or too
    slow) for the distance, else None. Pure function, never raises — non-blocking.

    The dates are passed so a trip spanning more than one night is judged on the
    hours it really took; without them a 30-hour drive reads as 6 and a genuine
    warning goes unraised.
    """
    if duration_seconds is None or not distance_miles:
        return None
    elapsed = _elapsed_seconds(start_time, end_time, trip_date, end_date)
    if elapsed is None or elapsed <= 0:
        return None
    elapsed_min, expected_min = round(elapsed / 60), round(duration_seconds / 60)
    if elapsed < duration_seconds * FEASIBILITY_MIN_RATIO:
        return (f'{distance_miles} miles in {elapsed_min} min is much faster than the '
                f'typical ~{expected_min} min for this route — double check the times.')
    max_elapsed = duration_seconds * FEASIBILITY_MAX_RATIO + stop_count * STOP_DWELL_ALLOWANCE_SECONDS
    if elapsed > max_elapsed:
        if stop_count:
            hours = STOP_DWELL_ALLOWANCE_SECONDS // 3600
            return (f'{distance_miles} miles in {elapsed_min} min is much longer than '
                    f'~{expected_min} min of driving, even allowing {hours} h at each of '
                    f'{stop_count} stop{"" if stop_count == 1 else "s"} — double check the times.')
        return (f'{distance_miles} miles in {elapsed_min} min is much longer than the '
                f'typical ~{expected_min} min for this route — double check the times.')
    return None


def _parse_iso_date(value):
    """A date.date, or None if value is missing/not a valid YYYY-MM-DD string."""
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return None


# A sane ceiling on how long one trip can run, so a mistyped year is still
# caught. Not a judgement about real trips: anything within a month is accepted.
MAX_TRIP_DAYS = 30


def validate_end_date(end_date, trip_date, start_time=None, end_time=None):
    """Error string if end_date is unusable, else None. Optional, like the trip
    date: None/empty means "derive it from the times".

    Deliberately not refused for being in the future. A trip is logged as it is
    taken — the start time defaults to now — so one that sets out at 23:30 and
    arrives at 01:00 is logged before it ends, and its end date is tomorrow. The
    trip must already have started, which validate_trip_date enforces; when it
    finishes is a consequence of its length, not something to police. A mistyped
    year is caught by the span instead.

    The times are checked alongside the dates because the four values have to
    agree with each other, and only some combinations are reachable through the
    UI. An API client is not bound by what the form happens to allow.
    """
    if not end_date:
        return None
    parsed = _parse_iso_date(end_date)
    if not parsed:
        return f'"{end_date}" is not a valid date.'
    # An end date describes when an end time happened, so one without the other
    # would be stored and reported as a day the trip ended on, for a trip that
    # has no recorded end.
    if not end_time:
        return 'An end date needs an end time.'
    start = _parse_iso_date(trip_date)
    if start:
        if parsed < start:
            return 'End date cannot be before the trip date.'
        if (parsed - start).days > MAX_TRIP_DAYS:
            return f'A trip cannot run longer than {MAX_TRIP_DAYS} days.'
        # The two together must describe forward motion. Same day with an end
        # time earlier than the start is the case that slips through: elapsed
        # comes out negative, and check_trip_feasibility treats anything at or
        # below zero as unknown and says nothing at all. The UI cannot produce
        # it, which is exactly why the server has to.
        #
        # None rather than a number means the span is unknown — a missing or
        # unparseable start time — and there is then nothing for the dates to
        # contradict. Compared explicitly, because None < 0 raises.
        elapsed = _elapsed_seconds(start_time, end_time, trip_date, end_date)
        if elapsed is not None and elapsed < 0:
            return 'The trip cannot end before it starts.'
    return None


def validate_trip_date(trip_date, client_today=None):
    """Error string if trip_date is set but isn't a real calendar date or is
    in the future, else None. A trip date is optional, so None/empty is fine.

    "In the future" is judged against the client's own local date when the
    client sends one (client_today, raw request string — validated here, not
    by the caller), falling back to the server's date otherwise. The server
    and a browser can legitimately disagree on what day it is near midnight
    if they're in different timezones, so trusting the server's own clock as
    ground truth would risk rejecting a trip the client already considers
    "today" and reports as such.
    """
    if not trip_date:
        return None
    try:
        parsed = datetime.strptime(trip_date, '%Y-%m-%d').date()
    except ValueError:
        return f'"{trip_date}" is not a valid date.'
    today = _parse_iso_date(client_today) or date.today()
    if parsed > today:
        return 'Trip date cannot be in the future.'
    return None


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        username_err = validate_username(username)
        if username_err:
            flash(username_err, 'danger')
            return render_template('register.html')
        if username_taken(username):
            flash('That username is already taken.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('An account with that email already exists.', 'danger')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        pw_errors = validate_password(password)
        if pw_errors:
            flash('Password must include: ' + ', '.join(pw_errors) + '.', 'danger')
            return render_template('register.html')

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))

    return render_template('register.html')


# Verifying a password costs real time by design -- scrypt is deliberately slow.
# So returning early for an address that has no account made the response
# noticeably faster than one for an address that does, and the timing answered
# the question the wording had just stopped answering. Hashing against a
# throwaway digest spends the same work either way.
#
# Computed once at import rather than per request: it proves nothing about any
# user, and generating a fresh one per attempt would itself make the
# no-such-user path the slower of the two.
_ABSENT_USER_HASH = generate_password_hash('password-for-no-account')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == '1'
        user = User.query.filter_by(email=email).first()
        # Exactly one password hash either way. Checking the real one only when
        # a user exists, and a throwaway otherwise, is what keeps the two cases
        # the same length -- hashing the real one and then also the throwaway
        # would simply invert the difference.
        if user:
            authenticated = user.check_password(password)
        else:
            check_password_hash(_ABSENT_USER_HASH, password)
            authenticated = False

        if authenticated:
            login_user(user, remember=remember)
            return redirect(url_for('index'))

        # One message for both failures. Saying "no account is associated with
        # that email" confirmed which addresses are registered here, which turns
        # guessing an email *and* a password into guessing only the password,
        # and lets a leaked address list be tested against this app. The reset
        # form already refuses to answer the same question.
        #
        # This wording cannot be narrowed later without undoing the fix:
        # anything that distinguishes the two cases is the same leak reworded.
        flash('Email or password is incorrect.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    # Not @login_required: signing out is a session/cookie operation and
    # should never fail just because a DB lookup (via current_user, which
    # logout_user() touches) hits a transient error — e.g. Neon's free tier
    # autosuspending mid-request. Always end up logged out regardless.
    try:
        logout_user()
    except Exception:
        # logout_user() itself resolves current_user first, so the same DB
        # hiccup can throw before its own cleanup runs — which is what would
        # normally flag the "remember me" cookie for deletion. Without this,
        # a remembered session would silently re-authenticate on the next
        # request despite looking signed out.
        session.clear()
        resp = redirect(url_for('login'))
        resp.delete_cookie(app.config.get('REMEMBER_COOKIE_NAME', 'remember_token'))
        return resp
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            try:
                send_reset_email(user, token)
            except Exception as e:
                app.logger.error('Failed to send reset email: %s', e)
                flash('Could not send email. Please try again later.', 'danger')
                return render_template('forgot_password.html')
        # Always show the same message to prevent user enumeration
        flash('If that email is registered, a reset link has been sent. Check your inbox (and spam folder).', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    email = verify_reset_token(token)
    if not email:
        flash('This reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        pw_errors = validate_password(password)
        if pw_errors:
            flash('Password must include: ' + ', '.join(pw_errors) + '.', 'danger')
            return render_template('reset_password.html', token=token)

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Account not found.', 'danger')
            return redirect(url_for('login'))

        user.set_password(password)
        db.session.commit()
        flash('Password updated successfully. Please sign in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# ---------------------------------------------------------------------------
# Main app routes
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username,
                           photo_data=current_user.photo_data,
                           maps_browser_key=app.config['GOOGLE_MAPS_BROWSER_KEY'] or '')


@app.route('/calculate', methods=['POST'])
@login_required
def calculate():
    data = request.get_json()
    start = (data.get('start') or '').strip()
    end = (data.get('end') or '').strip()
    if not start or not end:
        return jsonify({'error': 'Both start and end locations are required.'}), 400
    try:
        stops = _clean_stops(data.get('stops'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    try:
        miles, duration_seconds, endpoints = calculate_driving_miles(
            start, end,
            start_place_id=(data.get('start_place_id') or None),
            end_place_id=(data.get('end_place_id') or None),
            stops=stops,
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 422
    except Exception:
        return jsonify({'error': 'Failed to calculate distance. Please try again.'}), 500
    return jsonify({
        'distance_miles': miles,
        'start': start,
        'end': end,
        'duration_seconds': duration_seconds,
        # Where these two locations actually resolved to. The client keeps the
        # latest pair so it can bias address autocomplete toward the user's own
        # area: unbiased, a query like "Home Depot" is resolved against the
        # requester's IP and can land on a different branch — or a different
        # state — than the one they meant.
        'endpoints': endpoints,
    })


# A ceiling on one trip's mileage. Not a judgement about real journeys -- it
# is three times the circumference of the Earth -- but a mistyped or crafted
# value has to land somewhere, and an unbounded one flows into every total.
MAX_TRIP_MILES = 100_000


def parse_miles(value):
    """A finite, non-negative mileage, or raise ValueError. None stays None.

    float() alone is not enough. It accepts 'nan', 'inf' and negatives, and
    Python's json parses the bare NaN and Infinity literals, so a request can
    send one straight through. A NaN stored as a trip's mileage then poisons
    every total it is summed into -- and jsonify would emit it back as a bare
    NaN, which is not valid JSON, so the history page would fail to parse
    rather than merely show a wrong number.
    """
    if value is None:
        return None
    try:
        miles = float(value)
    except (TypeError, ValueError):
        raise ValueError('Mileage must be a number.')
    if not math.isfinite(miles):
        raise ValueError('Mileage must be a finite number.')
    if miles < 0:
        raise ValueError('Mileage cannot be negative.')
    if miles > MAX_TRIP_MILES:
        raise ValueError(f'Mileage must be at most {MAX_TRIP_MILES:,} miles.')
    return miles


def _as_id(value):
    """An integer id from client input, or None if it is not one.

    None rather than an exception, because every caller already treats an id it
    cannot resolve as "no attribution" -- a bad vehicle id should drop the
    vehicle, not fail the trip. A bare int() raised ValueError on 'abc' or a
    list, which reached the client as a 500.

    A float is refused rather than truncated: int(1.5) is 1, which would
    attribute a trip to whichever vehicle happened to have that id.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip('-').isdigit():
        return int(value.strip())
    return None


MAX_NOTE_LENGTH = 500


def _clean_notes(value):
    """Trimmed note text, or None when blank.

    Truncated rather than rejected: a note is incidental to the trip, and
    failing the whole save over its length would lose the mileage too.
    """
    text = (value or '').strip()
    return text[:MAX_NOTE_LENGTH] or None


# Routes bills a request with up to 10 intermediate waypoints as Essentials;
# 11 to 25 move it to Pro at twice the price per request. Capped here so a
# stop-heavy trip never changes what a calculation costs.
MAX_STOPS = 10


def _clean_stops(value):
    """Ordered stops as [{'label', 'place_id'}], with blank entries dropped.

    Raises ValueError past MAX_STOPS. An overlong note is trimmed, but a stop
    can't be: dropping one would route a different trip than the one entered
    and record mileage that silently doesn't match it.
    """
    stops = []
    for item in value or []:
        if isinstance(item, str):
            label, place_id = item, None
        elif isinstance(item, dict):
            label, place_id = item.get('label'), item.get('place_id')
        else:
            continue
        label = (label or '').strip()
        if label:
            stops.append({'label': label, 'place_id': (place_id or '').strip() or None})
    if len(stops) > MAX_STOPS:
        raise ValueError(f'A trip can have at most {MAX_STOPS} stops.')
    return stops


def _stops_from_db(raw):
    """Stored stops back to a list; anything unreadable reads as no stops."""
    if not raw:
        return []
    try:
        stops = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return stops if isinstance(stops, list) else []


def _resolve_business_for(user_id, business_id):
    """(id, name) for a business `user_id` owns, else (None, None).

    Scoped to the owner so a trip can't be attributed to another user's
    business by passing its id. An unknown id drops the attribution rather
    than failing the trip, matching how an unknown vehicle id is handled.

    Takes the owner rather than reading current_user because the API routes
    authenticate by key and have no session at all.
    """
    business_id = _as_id(business_id)
    if not business_id:
        return None, None
    b = Business.query.filter_by(id=business_id, user_id=user_id).first()
    return (b.id, b.name) if b else (None, None)


def _resolve_business(business_id):
    """As above, for the signed-in user."""
    return _resolve_business_for(current_user.id, business_id)


def _resolve_vehicle_for(user_id, vehicle_id):
    """(id, name, subtitle) for a vehicle `user_id` owns, else (None, None, None)."""
    vehicle_id = _as_id(vehicle_id)
    if not vehicle_id:
        return None, None, None
    v = Vehicle.query.filter_by(id=vehicle_id, user_id=user_id).first()
    if not v:
        return None, None, None
    return v.id, v.name, ' '.join(filter(None, [v.year, v.make, v.model]))


def _absolute_minutes(date_str, time_str):
    """Minutes since an arbitrary epoch day, or None.

    Dates are folded into the number so two trips can be compared across
    midnight: an overnight trip starting on the 7th and one starting just after
    midnight on the 8th are an hour apart, which a minutes-of-day comparison
    would read as twenty-three.
    """
    day = _parse_iso_date(date_str)
    minute = _minutes_of_day(time_str)
    if day is None or minute is None:
        return None
    return day.toordinal() * 1440 + minute


def _trip_window(trip_date, start_time, end_time, end_date, duration_seconds):
    """(start, end) in absolute minutes for a trip, or None if it has no start.

    The end comes from the stated end time where there is one, and from the
    measured drive time where there is not -- a trip entered without an end
    time still occupies the road for as long as the route takes. Failing both,
    the trip is a single instant: two instants at different times do not
    overlap, which is the right answer when there is nothing to say how long
    either lasted.
    """
    begin = _absolute_minutes(trip_date, start_time)
    if begin is None:
        return None
    if end_time:
        finish = _absolute_minutes(end_date or _derived_end_date(trip_date, start_time, end_time),
                                   end_time)
        if finish is not None and finish >= begin:
            return begin, finish
    if duration_seconds:
        return begin, begin + max(0, round(duration_seconds / 60))
    return begin, begin


def _windows_overlap(a, b):
    """Whether two (start, end) windows describe overlapping time.

    Strictly, so that back-to-back trips are not caught: one ending at 09:30
    and the next starting at 09:30 share an instant but no duration, and are a
    perfectly ordinary pair.

    Equal starts are caught regardless of length, because two trips departing
    at the same minute cannot both have happened even if neither says how long
    it took.
    """
    if a[0] == b[0]:
        return True
    return a[0] < b[1] and b[0] < a[1]


def find_overlapping_trip(user_id, start, end, trip_date, window):
    """A trip on the same route whose time overlaps `window`, or None.

    This is the case that cannot be explained away. Two visits to one client in
    a day are a real pair of trips and differ by when they began; a return leg
    has its locations reversed. But the same route at the same time, twice, is
    not something that happened -- so the caller refuses it rather than asking,
    because there is no answer a person could give that would make it true.

    Neighbouring dates are considered as well as the trip's own, since a trip
    that began before midnight ends on the following date and can overlap one
    starting after it.

    Every trip already recorded is kept either way -- only the new one is
    refused, and nothing existing is altered. Ordering by id therefore decides
    only which trip gets described back to the caller when more than one
    overlaps, and the earliest is the clearer answer to "you already logged
    this".
    """
    if not (start and end and trip_date and window):
        return None
    day = _parse_iso_date(trip_date)
    if day is None:
        return None
    nearby = [(day + timedelta(days=offset)).isoformat() for offset in (-1, 0, 1)]

    candidates = (Trip.query
                  .filter_by(user_id=user_id, start_location=start, end_location=end)
                  .filter(Trip.trip_date.in_(nearby))
                  .order_by(Trip.id)
                  .all())
    for candidate in candidates:
        other = _trip_window(candidate.trip_date, candidate.start_time,
                             candidate.end_time, _trip_end_date(candidate),
                             candidate.duration_seconds)
        if other and _windows_overlap(window, other):
            return candidate
    return None


def find_duplicate_trip(user_id, start, end, trip_date, start_time):
    """An existing trip that looks like the same journey, or None.

    Matched on the owner, both locations, the date and the start time. Those
    five together are what make this precise rather than merely suggestive: two
    site visits to the same client on one day are a genuine pair of trips and
    differ by when they began, while two entries of a single journey agree on
    all five. A round trip logged as two legs has its locations reversed, so it
    does not match either.

    Deliberately not the mileage. It is derived from the locations, so two
    entries of one trip agree on it by construction -- it would make the match
    look stricter while discriminating nothing.

    A trip with no start time is matched only against others with no start
    time: filter_by(start_time=None) is IS NULL, so a timed entry and an
    untimed one are never taken for each other. That is the weakest case --
    two untimed trips between the same places on one day could be real -- which
    is why the caller asks rather than refuses.
    """
    if not (start and end and trip_date):
        return None
    return (Trip.query
            .filter_by(user_id=user_id, start_location=start, end_location=end,
                       trip_date=trip_date, start_time=start_time)
            .order_by(Trip.id.desc())
            .first())


def _duplicate_summary(trip):
    """Enough of the existing trip for the client to describe it back."""
    return {
        'id': trip.id,
        'start': trip.start_location,
        'end': trip.end_location,
        'trip_date': trip.trip_date,
        'start_time': trip.start_time,
        'end_time': trip.end_time,
        'miles': trip.distance_miles,
    }


@app.route('/log', methods=['POST'])
@login_required
def log_trip():
    data = request.get_json()
    # Before anything else, including the distance lookup: a request without
    # the key should not be able to spend a Routes call.
    key_error = check_logging_key(data)
    if key_error:
        return jsonify({'error': key_error}), 403

    start = (data.get('start') or '').strip()
    end   = (data.get('end')   or '').strip()
    if not start or not end:
        return jsonify({'error': 'Missing trip data.'}), 400

    trip_date  = (data.get('trip_date') or '').strip() or None
    date_error = validate_trip_date(trip_date, client_today=data.get('client_today'))
    if date_error:
        return jsonify({'error': date_error}), 400

    # Parsed here rather than further down, because the end date is only valid
    # in relation to the times it describes.
    start_time = (data.get('start_time') or '').strip() or None
    end_time   = (data.get('end_time')   or '').strip() or None
    end_date   = (data.get('end_date')   or '').strip() or None
    date_error = validate_end_date(end_date, trip_date, start_time, end_time)
    if date_error:
        return jsonify({'error': date_error}), 400

    # Before the distance lookup, like the key check above: a trip that is
    # about to be refused should not spend a billable Routes call first.
    #
    # Refused with 409 rather than silently dropped or silently accepted. The
    # client asks the user and sends the same trip back with
    # confirm_duplicate, which is the only way to express "yes, I did drive
    # that twice" -- and the reason this is not a hard reject.
    # The same route at an overlapping time is refused outright, and cannot be
    # confirmed through: it describes being in two places at once, so there is
    # no answer a person could give that would make it true. The first trip
    # recorded is the one kept -- a correction belongs in an edit of that trip,
    # not in a second copy of it.
    window = _trip_window(trip_date, start_time, end_time, end_date,
                          data.get('duration_seconds'))
    clash = find_overlapping_trip(current_user.id, start, end, trip_date, window)
    if clash:
        return jsonify({
            'duplicate': True,
            'can_confirm': False,
            'error': 'You have already logged this trip, over the same hours. '
                     'Only the first was kept.',
            'existing': _duplicate_summary(clash),
        }), 409

    # Without times there is nothing to overlap, so an identical untimed entry
    # is only ever suspicious: two untimed trips between the same places on one
    # day could be real. That one is asked about rather than refused.
    if window is None and not data.get('confirm_duplicate'):
        existing = find_duplicate_trip(current_user.id, start, end, trip_date, start_time)
        if existing:
            return jsonify({
                'duplicate': True,
                'can_confirm': True,
                'error': 'You have already logged this trip.',
                'existing': _duplicate_summary(existing),
            }), 409

    start_place_id = (data.get('start_place_id') or '').strip() or None
    end_place_id   = (data.get('end_place_id')   or '').strip() or None
    try:
        stops = _clean_stops(data.get('stops'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    distance_miles   = data.get('distance_miles')
    duration_seconds = data.get('duration_seconds')
    distance_error   = None
    endpoints        = None
    if distance_miles is not None:
        try:
            distance_miles = parse_miles(distance_miles)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
    else:
        try:
            distance_miles, duration_seconds, endpoints = calculate_driving_miles(
                start, end,
                start_place_id=start_place_id,
                end_place_id=end_place_id,
                stops=stops,
            )
        except ValueError as e:
            distance_error = str(e)
        except Exception:
            distance_error = 'Could not calculate distance automatically. Edit this trip to add it later.'

    vehicle_id  = _as_id(data.get('vehicle_id'))
    vehicle_name = vehicle_sub = None
    if vehicle_id:
        v = Vehicle.query.filter_by(id=vehicle_id, user_id=current_user.id).first()
        if v:
            vehicle_name = v.name
            vehicle_sub  = ' '.join(filter(None, [v.year, v.make, v.model]))
        else:
            vehicle_id = None

    business_id, business_name = _resolve_business(data.get('business_id'))

    warning = None
    if distance_miles is not None:
        warning = check_trip_feasibility(start_time, end_time, distance_miles, duration_seconds,
                                         stop_count=len(stops),
                                         trip_date=trip_date, end_date=end_date)

    trip = Trip(
        user_id=current_user.id,
        created_via='web',
        start_location=start,
        end_location=end,
        distance_miles=distance_miles,
        vehicle_id=vehicle_id,
        business_id=business_id,
        notes=_clean_notes(data.get('notes')),
        trip_date=trip_date,
        start_time=start_time,
        end_time=end_time,
        end_date=end_date or _derived_end_date(trip_date, start_time, end_time),
        duration_seconds=duration_seconds,
        start_place_id=start_place_id,
        end_place_id=end_place_id,
        stops=json.dumps(stops) if stops else None,
    )
    db.session.add(trip)
    db.session.commit()
    resp = {'success': True, 'trip': _trip_dict(trip, vehicle_name, vehicle_sub, business_name)}
    # Same purpose as /calculate's: the client keeps the latest resolved
    # coordinates so address autocomplete can be biased to the user's own area.
    if endpoints:
        resp['endpoints'] = endpoints
    if warning:
        resp['warning'] = warning
    if distance_error:
        resp['distance_error'] = distance_error
    return jsonify(resp)


@app.route('/history')
@login_required
def history():
    trips = Trip.query.filter_by(user_id=current_user.id).all()
    # Sort by the trip's actual date (falling back to when it was logged, for
    # trips with no trip_date) so the list reflects trip recency rather than
    # data-entry order — a back-dated trip logged today shouldn't jump to the
    # top. Ties (same date) break by id, i.e. most-recently-logged first.
    trips.sort(
        key=lambda t: (t.trip_date or (t.timestamp.strftime('%Y-%m-%d') if t.timestamp else ''), t.id),
        reverse=True
    )
    # One query for the whole page's attachments rather than one per trip.
    attachments = _attachments_by_trip([t.id for t in trips])
    return jsonify([
        _trip_dict(
            t,
            t.vehicle.name if t.vehicle else None,
            ' '.join(filter(None, [t.vehicle.year, t.vehicle.make, t.vehicle.model])) if t.vehicle else None,
            t.business.name if t.business else None,
            attachments=attachments.get(t.id, []),
        )
        for t in trips
    ])


@app.route('/history/<int:trip_id>', methods=['PATCH'])
@login_required
def update_trip(trip_id):
    trip = Trip.query.filter_by(id=trip_id, user_id=current_user.id).first()
    if not trip:
        return jsonify({'error': 'Trip not found.'}), 404
    data           = request.get_json()
    key_error      = check_logging_key(data)
    if key_error:
        return jsonify({'error': key_error}), 403

    start          = (data.get('start') or '').strip()
    end            = (data.get('end')   or '').strip()
    distance_miles = data.get('distance_miles')
    if not start or not end:
        return jsonify({'error': 'Missing fields.'}), 400

    trip_date  = (data.get('trip_date') or '').strip() or None
    date_error = validate_trip_date(trip_date, client_today=data.get('client_today'))
    if date_error:
        return jsonify({'error': date_error}), 400

    # Parsed here rather than further down, because the end date is only valid
    # in relation to the times it describes.
    start_time = (data.get('start_time') or '').strip() or None
    end_time   = (data.get('end_time')   or '').strip() or None
    end_date   = (data.get('end_date')   or '').strip() or None
    date_error = validate_end_date(end_date, trip_date, start_time, end_time)
    if date_error:
        return jsonify({'error': date_error}), 400

    try:
        distance_miles = parse_miles(distance_miles)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    vehicle_id  = _as_id(data.get('vehicle_id'))
    vehicle_name = vehicle_sub = None
    if vehicle_id:
        v = Vehicle.query.filter_by(id=vehicle_id, user_id=current_user.id).first()
        if v:
            vehicle_name = v.name
            vehicle_sub  = ' '.join(filter(None, [v.year, v.make, v.model]))
        else:
            vehicle_id = None

    business_id, business_name = _resolve_business(data.get('business_id'))

    # A client that doesn't send stops at all leaves them as they were, so an
    # edit from a page loaded before this change can't erase a trip's route.
    if 'stops' in data:
        try:
            stops = _clean_stops(data.get('stops'))
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
    else:
        stops = _stops_from_db(trip.stops)

    # Fall back to the trip's already-stored duration when the client didn't
    # send a fresh one (i.e. the route wasn't recalculated this edit).
    duration_seconds = data.get('duration_seconds') or trip.duration_seconds
    warning = None
    if distance_miles is not None:
        warning = check_trip_feasibility(start_time, end_time, distance_miles, duration_seconds,
                                         stop_count=len(stops),
                                         trip_date=trip_date, end_date=end_date)

    # The client sends a place ID back only for a location it left untouched;
    # editing the text clears it, so the trip falls back to address routing
    # rather than staying pinned to the place the old text resolved to.
    trip.start_place_id = (data.get('start_place_id') or '').strip() or None
    trip.end_place_id   = (data.get('end_place_id')   or '').strip() or None

    trip.start_location = start
    trip.end_location   = end
    trip.distance_miles = distance_miles
    trip.vehicle_id     = vehicle_id
    trip.business_id    = business_id
    trip.notes          = _clean_notes(data.get('notes'))
    trip.stops          = json.dumps(stops) if stops else None
    trip.trip_date      = trip_date
    trip.end_date       = end_date or _derived_end_date(trip_date, start_time, end_time)
    trip.start_time     = start_time
    trip.end_time       = end_time
    trip.duration_seconds = duration_seconds
    db.session.commit()
    resp = _trip_dict(trip, vehicle_name, vehicle_sub, business_name)
    if warning:
        resp['warning'] = warning
    return jsonify(resp)


@app.route('/history/<int:trip_id>', methods=['DELETE'])
@login_required
def delete_trip(trip_id):
    trip = Trip.query.filter_by(id=trip_id, user_id=current_user.id).first()
    if not trip:
        return jsonify({'error': 'Trip not found.'}), 404
    # No database-level cascade: the schema is built with plain ALTER TABLE and
    # has no ON DELETE, so the attachments are removed here. Left behind they
    # would be unreachable rows still holding their bytes.
    TripAttachment.query.filter_by(trip_id=trip.id).delete()
    db.session.delete(trip)
    db.session.commit()
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# Trip attachments
# ---------------------------------------------------------------------------

def _owned_trip(trip_id):
    """The trip if the current user owns it, else None. Scoping every lookup
    through user_id is what stops one account reaching another's receipts."""
    return Trip.query.filter_by(id=trip_id, user_id=current_user.id).first()


def _owned_attachment(att_id, with_data=True):
    """The attachment if the current user owns the trip it belongs to.

    with_data=False leaves the bytes in the database, for callers that only need
    to know the row exists and is theirs — deleting it, say, which otherwise
    reads up to 5MB out of Postgres on its way to discarding it.
    """
    query = TripAttachment.query
    if not with_data:
        query = query.options(defer(TripAttachment.data))
    return (query
            .join(Trip, TripAttachment.trip_id == Trip.id)
            .filter(TripAttachment.id == att_id, Trip.user_id == current_user.id)
            .first())


# Characters that reorder the text around them without being visible. Left in a
# filename, U+202E turns "harmless\u202Egpj.exe" into something that reads as
# "harmlessexe.jpg" wherever it is displayed, which is the whole point of using
# one in a filename. Stripped rather than escaped, since no legitimate name needs
# them. Includes the bidi overrides and embeddings and the isolate controls.
_BIDI_CONTROLS = re.compile(r'[\u200e\u200f\u202a-\u202e\u2066-\u2069]')


def _clean_filename(name):
    """A display-safe filename: no path, no control or bidi characters,
    length-capped.

    The name is only ever shown and sent in a Content-Disposition header, never
    used to open a file, but a name carrying a path or a newline could still
    split the header, and one carrying a bidi override could misrepresent what
    the file is.
    """
    name = (name or '').replace('\\', '/').split('/')[-1]
    name = re.sub(r'[\x00-\x1f\x7f"]', '', name)
    name = _BIDI_CONTROLS.sub('', name).strip()
    if len(name) > MAX_FILENAME_LENGTH:
        stem, dot, ext = name.rpartition('.')
        name = (stem[:MAX_FILENAME_LENGTH - len(ext) - 1] + dot + ext) if dot else name[:MAX_FILENAME_LENGTH]
    return name or 'attachment'


@app.route('/trip/<int:trip_id>/attachments', methods=['POST'])
@login_required
def upload_attachment(trip_id):
    trip = _owned_trip(trip_id)
    if not trip:
        return jsonify({'error': 'Trip not found.'}), 404

    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'No file provided.'}), 400

    existing = TripAttachment.query.filter_by(trip_id=trip.id).count()  # COUNT only, no bytes
    if existing >= MAX_ATTACHMENTS_PER_TRIP:
        return jsonify({'error': f'A trip can have at most {MAX_ATTACHMENTS_PER_TRIP} attachments.'}), 400

    raw = file.read()
    if not raw:
        return jsonify({'error': 'That file is empty.'}), 400
    if len(raw) > MAX_ATTACHMENT_BYTES:
        mb = MAX_ATTACHMENT_BYTES // (1024 * 1024)
        return jsonify({'error': f'Each file must be smaller than {mb}MB.'}), 400

    mimetype = sniff_attachment_type(raw)
    if not mimetype:
        return jsonify({'error': 'Only images (JPEG, PNG, WEBP, GIF, HEIC) and PDFs can be attached.'}), 400

    att = TripAttachment(trip_id=trip.id, filename=_clean_filename(file.filename),
                         mimetype=mimetype, byte_size=len(raw), data=raw)
    db.session.add(att)
    db.session.commit()
    return jsonify({'success': True, 'attachment': _attachment_dict(att)})


@app.route('/attachment/<int:att_id>', methods=['GET'])
@login_required
def download_attachment(att_id):
    att = _owned_attachment(att_id)
    if not att:
        return jsonify({'error': 'Attachment not found.'}), 404
    # inline so an image or PDF opens in the browser; the filename still rides
    # along for a save. Sniffing is disabled because the type here was decided
    # from the bytes, and letting the browser guess again could turn an
    # unexpected upload into something it executes in this origin.
    return Response(att.data, mimetype=att.mimetype, headers={
        'Content-Disposition': f'inline; filename="{att.filename}"',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'private, max-age=3600',
    })


@app.route('/attachment/<int:att_id>', methods=['DELETE'])
@login_required
def delete_attachment(att_id):
    att = _owned_attachment(att_id, with_data=False)
    if not att:
        return jsonify({'error': 'Attachment not found.'}), 404
    db.session.delete(att)
    db.session.commit()
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# Vehicle routes
# ---------------------------------------------------------------------------

@app.route('/vehicles', methods=['GET'])
@login_required
def get_vehicles():
    vs = Vehicle.query.filter_by(user_id=current_user.id).order_by(Vehicle.name).all()
    return jsonify([_vehicle_dict(v) for v in vs])


@app.route('/vehicles', methods=['POST'])
@login_required
def create_vehicle():
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Vehicle name is required.'}), 400
    existing = Vehicle.query.filter(
        Vehicle.user_id == current_user.id,
        db.func.lower(Vehicle.name) == name.lower()
    ).first()
    if existing:
        return jsonify({'error': f'You already have a vehicle named "{name}".'}), 409
    v = Vehicle(
        user_id=current_user.id,
        name=name,
        year=(data.get('year')  or '').strip() or None,
        make=(data.get('make')  or '').strip() or None,
        model=(data.get('model') or '').strip() or None,
    )
    # Adding a vehicle never sets it as the default, not even the first one:
    # the default only ever changes because someone chose it. That keeps one
    # rule for the whole feature rather than an implicit case to reason about.
    db.session.add(v)
    db.session.commit()
    return jsonify(_vehicle_dict(v)), 201


@app.route('/vehicles/<int:vehicle_id>', methods=['PATCH'])
@login_required
def update_vehicle(vehicle_id):
    v = Vehicle.query.filter_by(id=vehicle_id, user_id=current_user.id).first()
    if not v:
        return jsonify({'error': 'Vehicle not found.'}), 404
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Vehicle name is required.'}), 400
    existing = Vehicle.query.filter(
        Vehicle.user_id == current_user.id,
        Vehicle.id != vehicle_id,
        db.func.lower(Vehicle.name) == name.lower()
    ).first()
    if existing:
        return jsonify({'error': f'You already have a vehicle named "{name}".'}), 409
    v.name  = name
    v.year  = (data.get('year')  or '').strip() or None
    v.make  = (data.get('make')  or '').strip() or None
    v.model = (data.get('model') or '').strip() or None
    db.session.commit()
    return jsonify(_vehicle_dict(v))


@app.route('/vehicles/<int:vehicle_id>', methods=['DELETE'])
@login_required
def delete_vehicle(vehicle_id):
    v = Vehicle.query.filter_by(id=vehicle_id, user_id=current_user.id).first()
    if not v:
        return jsonify({'error': 'Vehicle not found.'}), 404
    Trip.query.filter_by(vehicle_id=vehicle_id).update({'vehicle_id': None})
    # Clear the default alongside the trips, or the id would outlive the row it
    # points at and the trip form would try to preselect a vehicle that is gone.
    if current_user.default_vehicle_id == vehicle_id:
        current_user.default_vehicle_id = None
    db.session.delete(v)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/vehicles/default', methods=['PUT'])
@login_required
def set_default_vehicle():
    """Set or clear the vehicle preselected when logging a new trip.

    One endpoint for both: a null vehicle_id clears the default, which is how
    the UI toggles off the vehicle that is currently set.
    """
    data = request.get_json() or {}
    vehicle_id = data.get('vehicle_id')

    if vehicle_id is None:
        current_user.default_vehicle_id = None
        db.session.commit()
        return jsonify({'default_vehicle_id': None})

    # Look the vehicle up scoped to the owner, so one user can't point their
    # default at another user's vehicle by guessing an id.
    v = Vehicle.query.filter_by(id=int(vehicle_id), user_id=current_user.id).first()
    if not v:
        return jsonify({'error': 'Vehicle not found.'}), 404
    current_user.default_vehicle_id = v.id
    db.session.commit()
    return jsonify({'default_vehicle_id': v.id})


@app.route('/my-vehicles')
@login_required
def vehicles_page():
    return render_template('vehicles.html', username=current_user.username, photo_data=current_user.photo_data)


# ---------------------------------------------------------------------------
# Business routes
# ---------------------------------------------------------------------------
# Mirrors the vehicle routes, including the single-default model: the default
# lives as a scalar on User, is never set implicitly, and is cleared when the
# business it points at is deleted.

@app.route('/businesses', methods=['GET'])
@login_required
def get_businesses():
    bs = Business.query.filter_by(user_id=current_user.id).order_by(Business.name).all()
    return jsonify([_business_dict(b) for b in bs])


@app.route('/businesses', methods=['POST'])
@login_required
def create_business():
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Business name is required.'}), 400
    existing = Business.query.filter(
        Business.user_id == current_user.id,
        db.func.lower(Business.name) == name.lower()
    ).first()
    if existing:
        return jsonify({'error': f'You already have a business named "{name}".'}), 409
    b = Business(user_id=current_user.id, name=name)
    # Adding a business never makes it the default, not even the first one.
    db.session.add(b)
    db.session.commit()
    return jsonify(_business_dict(b)), 201


@app.route('/businesses/<int:business_id>', methods=['PATCH'])
@login_required
def update_business(business_id):
    b = Business.query.filter_by(id=business_id, user_id=current_user.id).first()
    if not b:
        return jsonify({'error': 'Business not found.'}), 404
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Business name is required.'}), 400
    existing = Business.query.filter(
        Business.user_id == current_user.id,
        db.func.lower(Business.name) == name.lower(),
        Business.id != business_id
    ).first()
    if existing:
        return jsonify({'error': f'You already have a business named "{name}".'}), 409
    b.name = name
    db.session.commit()
    return jsonify(_business_dict(b))


@app.route('/businesses/<int:business_id>', methods=['DELETE'])
@login_required
def delete_business(business_id):
    b = Business.query.filter_by(id=business_id, user_id=current_user.id).first()
    if not b:
        return jsonify({'error': 'Business not found.'}), 404
    # Unlink the trips and drop the default in the same commit as the delete,
    # so no id can outlive the row it points at.
    Trip.query.filter_by(business_id=business_id).update({'business_id': None})
    if current_user.default_business_id == business_id:
        current_user.default_business_id = None
    db.session.delete(b)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/businesses/default', methods=['PUT'])
@login_required
def set_default_business():
    """Set or clear the business preselected when logging a new trip."""
    data = request.get_json() or {}
    business_id = data.get('business_id')

    if business_id is None:
        current_user.default_business_id = None
        db.session.commit()
        return jsonify({'default_business_id': None})

    b = Business.query.filter_by(id=int(business_id), user_id=current_user.id).first()
    if not b:
        return jsonify({'error': 'Business not found.'}), 404
    current_user.default_business_id = b.id
    db.session.commit()
    return jsonify({'default_business_id': b.id})


@app.route('/my-businesses')
@login_required
def businesses_page():
    return render_template('businesses.html', username=current_user.username,
                           photo_data=current_user.photo_data)


# ---------------------------------------------------------------------------
# Profile routes
# ---------------------------------------------------------------------------

def _api_key_dict(key):
    """A key as the profile shows it. Never includes the secret: the secret is
    not stored, only its hash, so there is nothing here that could leak one."""
    return {
        'id': key.id,
        'name': key.name,
        'public_id': key.public_id,
        'created_at': key.created_at.strftime('%b %d, %Y') if key.created_at else None,
        'last_used_at': key.last_used_at.strftime('%b %d, %Y at %H:%M')
                        if key.last_used_at else None,
        'active': key.active,
    }


def _owned_api_keys():
    return (ApiKey.query.filter_by(user_id=current_user.id)
            .order_by(ApiKey.revoked_at.isnot(None), ApiKey.created_at.desc())
            .all())


@app.route('/profile')
@login_required
def profile():
    return render_template(
        'profile.html',
        username=current_user.username,
        email=current_user.email,
        photo_data=current_user.photo_data,
        api_keys=[_api_key_dict(k) for k in _owned_api_keys()],
        api_base_url=request.url_root.rstrip('/'),
    )


@app.route('/profile/api-keys', methods=['POST'])
@login_required
def create_api_key():
    """Mint a key and return it once.

    Behind the password for the same reason revealing the logging key is: a
    stolen session should not be able to issue itself a credential that
    outlives the session and survives a password change.
    """
    data = request.get_json(silent=True) or {}
    refused = _check_key_gate(data.get('password') or '')
    if refused:
        message, status = refused
        return jsonify({'error': message}), status

    name = (data.get('name') or '').strip()
    name = _BIDI_CONTROLS.sub('', re.sub(r'[\x00-\x1f\x7f]', '', name))[:60].strip()
    if not name:
        return jsonify({'error': 'Give the key a name, so you can tell it apart later.'}), 400

    active = ApiKey.query.filter_by(user_id=current_user.id, revoked_at=None).count()
    if active >= MAX_ACTIVE_API_KEYS:
        return jsonify({'error': f'You already have {MAX_ACTIVE_API_KEYS} active keys. '
                                 'Revoke one before creating another.'}), 400

    public_id, secret, full_key = generate_api_key()
    key = ApiKey(user_id=current_user.id, name=name, public_id=public_id,
                 secret_hash=_hash_api_secret(secret), created_at=_utcnow())
    db.session.add(key)
    db.session.commit()

    # The only time the full key is ever sent anywhere. It is not stored, so
    # this response cannot be reproduced -- losing it means revoking and
    # minting again, which is why minting is cheap.
    return jsonify({'key': full_key, 'api_key': _api_key_dict(key)})


@app.route('/profile/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def revoke_api_key(key_id):
    """Revoke a key. Takes effect on its next request.

    No password: revoking is the safe direction, and putting a gate in front of
    it would slow down the one action someone takes when they think a key has
    leaked. Scoped to the owner, so one account cannot revoke another's.

    Marked rather than deleted, so the name and last use survive -- "this was
    being used until Tuesday" is the useful fact after revoking something.
    """
    key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first()
    if not key:
        return jsonify({'error': 'Key not found.'}), 404
    if key.active:
        key.revoked_at = _utcnow()
        db.session.commit()
    return jsonify({'success': True, 'api_key': _api_key_dict(key)})


@app.route('/profile/check-username')
@login_required
def check_username():
    username = (request.args.get('username') or '').strip()
    err = validate_username(username)
    if err:
        return jsonify({'available': False, 'error': err})
    if username == current_user.username:
        return jsonify({'available': True, 'unchanged': True})
    return jsonify({'available': not username_taken(username)})


@app.route('/profile/update-username', methods=['POST'])
@login_required
def update_username():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    err = validate_username(username)
    if err:
        return jsonify({'error': err}), 400
    if username != current_user.username:
        if username_taken(username):
            return jsonify({'error': 'That username is already taken.'}), 409
        current_user.username = username
        try:
            db.session.commit()
        except IntegrityError:
            # Another request claimed this username between our check and commit.
            db.session.rollback()
            return jsonify({'error': 'That username is already taken.'}), 409
    return jsonify({'success': True, 'username': current_user.username})


# Signature-sniffed from actual file bytes, not the client-supplied
# Content-Type header, so a mislabeled non-image file can't pass this check.
_IMAGE_SIGNATURES = {
    b'\xff\xd8\xff':          'image/jpeg',
    b'\x89PNG\r\n\x1a\n':     'image/png',
    b'GIF87a':                'image/gif',
    b'GIF89a':                'image/gif',
}


def sniff_image_type(raw):
    for signature, mimetype in _IMAGE_SIGNATURES.items():
        if raw.startswith(signature):
            return mimetype
    if raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        return 'image/webp'
    return None


# What an attachment may be, again decided by the bytes rather than by the
# filename or the browser's Content-Type. HEIC is accepted because it is what
# an iPhone produces when a photo is picked from Files rather than the camera;
# no browser renders it, so the client offers it for download instead of
# previewing it.
def sniff_attachment_type(raw):
    image = sniff_image_type(raw)
    if image:
        return image
    if raw.startswith(b'%PDF-'):
        return 'application/pdf'
    # ISO base-media container: 'ftyp' at offset 4, then the brand. HEIC and
    # HEIF share the box structure, so the brand is what distinguishes them.
    if raw[4:8] == b'ftyp' and raw[8:12] in (b'heic', b'heix', b'hevc', b'heim',
                                             b'heis', b'hevm', b'mif1', b'msf1'):
        return 'image/heic'
    return None


# Attachment metadata for any number of trips, in one query, grouped by trip.
#
# The data column is deferred, and that matters more than it looks: a listing
# needs names and sizes only, and selecting the bytes would pull every receipt
# the user owns out of Postgres to render a paperclip count — up to 10 files of
# 5MB per trip, per request. Taking them a trip at a time made it an N+1 on top.
def _attachments_by_trip(trip_ids):
    if not trip_ids:
        return {}
    rows = (TripAttachment.query
            .options(defer(TripAttachment.data))
            .filter(TripAttachment.trip_id.in_(trip_ids))
            .order_by(TripAttachment.trip_id, TripAttachment.id)
            .all())
    grouped = {}
    for row in rows:
        grouped.setdefault(row.trip_id, []).append(_attachment_dict(row))
    return grouped


def _attachment_dict(att):
    return {
        'id': att.id,
        'filename': att.filename,
        'mimetype': att.mimetype,
        'byte_size': att.byte_size,
        # Only these render in an <img>; everything else is a download link.
        'previewable': att.mimetype in ('image/jpeg', 'image/png', 'image/webp', 'image/gif'),
    }


@app.errorhandler(413)
def request_too_large(_e):
    limit_mb = max(MAX_PHOTO_BYTES, MAX_ATTACHMENT_BYTES) // (1024 * 1024)
    return jsonify({'error': f'That file is too large — the limit is {limit_mb}MB.'}), 413


@app.route('/profile/photo', methods=['POST'])
@login_required
def upload_photo():
    file = request.files.get('photo')
    if not file or not file.filename:
        return jsonify({'error': 'No photo provided.'}), 400
    raw = file.read()
    if len(raw) > MAX_PHOTO_BYTES:
        return jsonify({'error': 'Photo must be smaller than 2MB.'}), 400
    mimetype = sniff_image_type(raw)
    if not mimetype:
        return jsonify({'error': 'File does not appear to be a valid JPEG, PNG, WEBP, or GIF image.'}), 400
    encoded = base64.b64encode(raw).decode('ascii')
    current_user.photo_data = f'data:{mimetype};base64,{encoded}'
    db.session.commit()
    return jsonify({'success': True, 'photo_data': current_user.photo_data})


@app.route('/profile/photo', methods=['DELETE'])
@login_required
def delete_photo():
    current_user.photo_data = None
    db.session.commit()
    return jsonify({'success': True})


@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    current_password = data.get('current_password') or ''
    new_password     = data.get('new_password') or ''
    confirm_password = data.get('confirm_password') or ''

    if not current_user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect.'}), 400
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match.'}), 400
    pw_errors = validate_password(new_password)
    if pw_errors:
        return jsonify({'error': 'Password must include: ' + ', '.join(pw_errors) + '.'}), 400

    current_user.set_password(new_password)
    db.session.commit()
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

# A key reads mtk_<public_id>.<secret>. The prefix makes one recognisable in a
# log or a config file, and the dot separates the two halves unambiguously --
# the secret is urlsafe base64, which contains '-' and '_' but never '.', so
# splitting on an underscore would have been ambiguous.
API_KEY_PREFIX = 'mtk_'
API_KEY_PUBLIC_BYTES = 6    # 12 hex characters
API_KEY_SECRET_BYTES = 32   # 256 bits

# How many keys one account may hold at once, counting only active ones. High
# enough never to be met in normal use; it exists so minting cannot be used to
# fill the table.
MAX_ACTIVE_API_KEYS = 20


def _hash_api_secret(secret):
    """SHA-256 of the secret half, hex.

    Deliberately not a password hash. Slow hashing protects secrets that can be
    guessed -- a password has maybe 40 bits of entropy, so scrypt's cost is what
    makes an offline attack impractical. This secret is 256 random bits and
    cannot be brute-forced at any speed, so a slow hash would buy nothing and
    cost something real: every request, including every wrong one, would spend
    tens of milliseconds, which is an easy way to exhaust a single-worker
    instance.
    """
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()


def generate_api_key():
    """A new (public_id, secret, full_key). The full key is never stored."""
    public_id = secrets.token_hex(API_KEY_PUBLIC_BYTES)
    secret = secrets.token_urlsafe(API_KEY_SECRET_BYTES)
    return public_id, secret, f'{API_KEY_PREFIX}{public_id}.{secret}'


def parse_api_key(token):
    """(public_id, secret) from a presented key, or (None, None).

    Whitespace is stripped because a key that has been copied out of a panel
    and pasted into a config file routinely arrives with some.
    """
    token = (token or '').strip()
    if not token.startswith(API_KEY_PREFIX):
        return None, None
    body = token[len(API_KEY_PREFIX):]
    public_id, dot, secret = body.partition('.')
    if not dot or not public_id or not secret:
        return None, None
    return public_id, secret


def _api_key_from_request():
    """The ApiKey this request presents, or None.

    Only ever reached from /api/v1 routes. A key authenticates one request; it
    never establishes a session, so holding one does not make the browser-facing
    pages reachable.
    """
    header = request.headers.get('Authorization', '')
    scheme, _, token = header.partition(' ')
    if scheme.lower() != 'bearer':
        return None

    public_id, secret = parse_api_key(token)
    if not public_id:
        return None

    key = ApiKey.query.filter_by(public_id=public_id).first()
    if not key or not key.active:
        return None
    if not hmac.compare_digest(key.secret_hash, _hash_api_secret(secret)):
        return None
    return key


# How many requests one key may make per window. An assistant logging a handful
# of trips a day is nowhere near this; it exists to bound a runaway loop or a
# key being used by something other than what it was issued to.
#
# A fixed window rather than a sliding one: the worst case is twice the limit
# across a boundary, which at this size is not worth a table of timestamps to
# avoid. Counted on the key's own row, so it costs no query the authentication
# did not already make and leaves nothing to prune.
API_RATE_LIMIT = 60
API_RATE_WINDOW = timedelta(hours=1)


def _count_api_request(key):
    """Record this request against the key's window and return the new count.

    One UPDATE, which decides in SQL whether the window has rolled over. Read,
    increment and write back would let concurrent requests all read the same
    count and all write the same value, so a burst would be counted as one.
    """
    now = _utcnow()
    cutoff = now - API_RATE_WINDOW
    rolled_over = db.or_(ApiKey.window_started_at.is_(None),
                         ApiKey.window_started_at < cutoff)
    db.session.execute(
        db.update(ApiKey)
        .where(ApiKey.id == key.id)
        .values(
            window_started_at=db.case((rolled_over, now), else_=ApiKey.window_started_at),
            window_count=db.case((rolled_over, 1),
                                 else_=db.func.coalesce(ApiKey.window_count, 0) + 1),
            # Folded into the same statement rather than assigned separately, so
            # one write records both and neither can be left behind.
            last_used_at=now,
        )
    )
    db.session.commit()
    # Read back rather than trusting the loaded attribute, which the SQL-side
    # update left stale.
    return (db.session.query(ApiKey.window_count)
            .filter(ApiKey.id == key.id).scalar() or 0)


def api_key_required(view):
    """Authenticate by API key, or refuse.

    Sets g.api_key and g.api_user. Does not touch the login session: these
    routes are for clients that have no browser, and a key must not become a
    way to reach anything that only @login_required protects.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        key = _api_key_from_request()
        if not key:
            # Not rate-limited, deliberately. A rejected request costs one
            # indexed lookup and one SHA-256, both cheap -- the reason to
            # throttle failed authentication is usually that verifying a
            # credential is expensive, and here it is not. The secret itself is
            # 256 random bits, so there is no guessing to slow down either.
            # One message for a missing, malformed, unknown and revoked key
            # alike. Distinguishing them would tell someone probing which of
            # their guesses had named a real key.
            return jsonify({'error': 'Invalid or missing API key.'}), 401

        user = db.session.get(User, key.user_id)
        if not user:
            return jsonify({'error': 'Invalid or missing API key.'}), 401

        # Counted before the work, so a request that fails validation still
        # shows the key as used and still spends its budget -- the question
        # last_used answers is "is something using this key", not "is it
        # succeeding", and a loop sending malformed bodies is exactly what the
        # limit is for.
        used = _count_api_request(key)
        if used > API_RATE_LIMIT:
            minutes = max(1, int(API_RATE_WINDOW.total_seconds() // 60))
            return jsonify({
                'error': f'Rate limit exceeded: at most {API_RATE_LIMIT} requests '
                         f'per {minutes} minutes for this key.'
            }), 429

        g.api_key = key
        g.api_user = user
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# API v1 — for identified clients with no browser
# ---------------------------------------------------------------------------

def _split_iso_datetime(value, field):
    """('YYYY-MM-DD', 'HH:MM') from an ISO datetime, or raise ValueError.

    Naive datetimes only. The app stores a trip's date and time as local
    wall-clock values -- it has no notion of the user's timezone anywhere -- so
    an offset-aware value could not be converted to what these columns mean
    without inventing one. Refusing it is the honest answer; silently dropping
    the offset would shift a trip by hours.
    """
    text = (value or '').strip()
    if not text:
        raise ValueError(f'{field} is required.')
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f'{field} must be an ISO datetime such as '
                         f'"2026-10-08T08:29", got {text!r}.')
    if parsed.tzinfo is not None:
        raise ValueError(f'{field} must not carry a UTC offset. Trips are stored '
                         'as local wall-clock time, so send the local time.')
    return parsed.strftime('%Y-%m-%d'), parsed.strftime('%H:%M')


# Field names the earlier draft of this API used, which mean different things
# here: it used start/end for times, while this app has always used them for
# places. Accepting either as an alias would eventually write a timestamp into
# a location column, so they are refused by name instead -- an agent can act on
# being told the right field, and cannot act on a trip logged wrongly.
_API_TRIP_ALIASES = {'start', 'end', 'from', 'to', 'date', 'start_date'}

_API_TRIP_FIELDS = {'start_location', 'end_location', 'started_at', 'ended_at',
                    'notes', 'vehicle_id', 'business_id', 'stops', 'miles'}


@app.route('/api/v1/trips', methods=['POST'])
@api_key_required
def api_create_trip():
    """Log one trip for the key's owner.

    Deliberately does not require the per-trip logging key. That exists so a
    trip logged through the browser is a deliberate human act; a request here is
    already identified by a credential the account holder issued on purpose, so
    asking for both would be redundant rather than safer.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Send a JSON object with Content-Type: application/json.'}), 422

    unknown = set(data) - _API_TRIP_FIELDS
    if unknown:
        hint = (' Note that start/end are locations here, and times are '
                'started_at/ended_at.' if unknown & _API_TRIP_ALIASES else '')
        return jsonify({'error': f'Unknown fields: {", ".join(sorted(unknown))}. '
                                 f'Expected: {", ".join(sorted(_API_TRIP_FIELDS))}.{hint}'}), 422

    start = (data.get('start_location') or '').strip()
    end = (data.get('end_location') or '').strip()
    if not start or not end:
        return jsonify({'error': 'start_location and end_location are required.'}), 422

    try:
        trip_date, start_time = _split_iso_datetime(data.get('started_at'), 'started_at')
        end_date, end_time = (None, None)
        if data.get('ended_at'):
            end_date, end_time = _split_iso_datetime(data.get('ended_at'), 'ended_at')
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 422

    # The same validators the form uses, so the two paths cannot disagree about
    # what a coherent trip is. client_today is the trip's own date: there is no
    # browser clock to consult, and the server's date is the only one available.
    date_error = validate_trip_date(trip_date, client_today=trip_date)
    if date_error:
        return jsonify({'error': date_error}), 422
    date_error = validate_end_date(end_date, trip_date, start_time, end_time)
    if date_error:
        return jsonify({'error': date_error}), 422

    try:
        stops = _clean_stops(data.get('stops'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 422

    user = g.api_user
    vehicle_id, vehicle_name, vehicle_sub = _resolve_vehicle_for(user.id, data.get('vehicle_id'))
    business_id, business_name = _resolve_business_for(user.id, data.get('business_id'))

    # Measured here rather than taken from the request. A caller asserting its
    # own mileage is the thing the logging key exists to prevent, and there is
    # no reason to reintroduce it for a client that can simply be measured.
    distance_miles = duration_seconds = None
    try:
        distance_miles, duration_seconds, _endpoints = calculate_driving_miles(
            start, end, stops=stops)
    except Exception:
        # A supplied value is used only when measuring produced nothing, so a
        # trip is still recorded rather than lost. Worth knowing that a caller
        # willing to send an unroutable address can reach this branch
        # deliberately and name its own mileage; the addresses it sent stay on
        # the trip, so that is visible afterwards rather than silent.
        supplied = data.get('miles')
        if supplied is not None:
            try:
                distance_miles = parse_miles(supplied)
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 422

    # The same cleaner the form path uses, so the two cannot disagree about what
    # a valid note is: over-long notes are truncated rather than refused,
    # because losing the mileage over the length of an incidental note would be
    # the wrong trade.
    notes = _clean_notes(data.get('notes'))

    trip = Trip(
        user_id=user.id,
        start_location=start,
        end_location=end,
        distance_miles=distance_miles,
        duration_seconds=duration_seconds,
        trip_date=trip_date,
        start_time=start_time,
        end_time=end_time,
        end_date=end_date,
        notes=notes,
        stops=json.dumps(stops) if stops else None,
        vehicle_id=vehicle_id,
        business_id=business_id,
        created_via='api',
        created_by_key_id=g.api_key.id,
    )
    db.session.add(trip)
    db.session.commit()

    warning = None
    if distance_miles is not None:
        warning = check_trip_feasibility(start_time, end_time, distance_miles,
                                         duration_seconds, stop_count=len(stops),
                                         trip_date=trip_date, end_date=end_date)

    return jsonify({
        'id': trip.id,
        'miles': distance_miles,
        'measured': duration_seconds is not None,
        'vehicle': vehicle_name,
        'business': business_name,
        'warning': warning,
    }), 201


@app.route('/api/v1/vehicles', methods=['GET'])
@api_key_required
def api_list_vehicles():
    """The key owner's vehicles, so a client can send a valid vehicle_id.

    Read only. There is no API route that creates, changes or deletes one.
    """
    vs = (Vehicle.query.filter_by(user_id=g.api_user.id)
          .order_by(Vehicle.name).all())
    return jsonify([_vehicle_dict(v, owner=g.api_user) for v in vs])


@app.route('/api/v1/businesses', methods=['GET'])
@api_key_required
def api_list_businesses():
    """The key owner's businesses. Read only, as above."""
    bs = (Business.query.filter_by(user_id=g.api_user.id)
          .order_by(Business.name).all())
    return jsonify([_business_dict(b, owner=g.api_user) for b in bs])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    _migrate_db()

if __name__ == '__main__':
    app.run(debug=True)
