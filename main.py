import base64
import os
import re
from datetime import datetime, date
import requests
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-key')

MAX_PHOTO_BYTES = 2 * 1024 * 1024  # 2MB
# Reject oversized request bodies at the Werkzeug layer before they're ever
# buffered into memory, rather than only checking size after a full read().
# +64KB covers multipart boundary/header overhead around the raw file bytes.
app.config['MAX_CONTENT_LENGTH'] = MAX_PHOTO_BYTES + 64 * 1024

# Use PostgreSQL (via pg8000, pure-Python driver) when DATABASE_URL is set; SQLite locally.
# pg8000 needs the +pg8000 dialect prefix and has no system library dependencies.
_db_url = os.environ.get('DATABASE_URL') or 'sqlite:///mileage.db'
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
app.config['GEOCODIO_API_KEY'] = os.environ.get('GEOCODIO_API_KEY')

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
    trips    = db.relationship('Trip', backref='user', lazy=True, cascade='all, delete-orphan')
    vehicles = db.relationship('Vehicle', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Vehicle(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name    = db.Column(db.String(100), nullable=False)
    year    = db.Column(db.String(4))
    make    = db.Column(db.String(60))
    model   = db.Column(db.String(60))
    trips   = db.relationship('Trip', backref='vehicle', lazy=True)


class Trip(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_location = db.Column(db.Text, nullable=False)
    end_location   = db.Column(db.Text, nullable=False)
    distance_miles = db.Column(db.Float, nullable=True)
    timestamp      = db.Column(db.DateTime, server_default=db.func.now())
    vehicle_id     = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=True)
    trip_date      = db.Column(db.String(10), nullable=True)
    start_time     = db.Column(db.String(5),  nullable=True)
    end_time       = db.Column(db.String(5),  nullable=True)
    duration_seconds = db.Column(db.Integer, nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _vehicle_dict(v):
    sub = ' '.join(filter(None, [v.year, v.make, v.model]))
    return {'id': v.id, 'name': v.name, 'year': v.year, 'make': v.make,
            'model': v.model, 'sub': sub}


def _trip_dict(trip, vehicle_name=None, vehicle_sub=None):
    return {
        'id':           trip.id,
        'start':        trip.start_location,
        'end':          trip.end_location,
        'miles':        trip.distance_miles,
        'timestamp':    trip.timestamp.strftime('%b %d, %Y %I:%M %p') if trip.timestamp else '',
        'vehicle_id':   trip.vehicle_id,
        'vehicle_name': vehicle_name,
        'vehicle_sub':  vehicle_sub,
        'trip_date':    trip.trip_date,
        'start_time':   trip.start_time,
        'end_time':     trip.end_time,
        'duration_seconds': trip.duration_seconds,
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
                ('trip_date',  'VARCHAR(10)'),
                ('start_time', 'VARCHAR(5)'),
                ('end_time',   'VARCHAR(5)'),
                ('duration_seconds', 'INTEGER'),
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
                ('trip_date',  'VARCHAR(10)'),
                ('start_time', 'VARCHAR(5)'),
                ('end_time',   'VARCHAR(5)'),
                ('duration_seconds', 'INTEGER'),
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

        conn.commit()


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
# Distance calculation: Geocodio geocoding + driving distance
# ---------------------------------------------------------------------------

GEOCODIO_BASE_URL = 'https://api.geocod.io/v2'


def _geocodio_headers():
    return {'Authorization': f'Bearer {app.config["GEOCODIO_API_KEY"]}'}


def geocode(address):
    resp = requests.get(
        f'{GEOCODIO_BASE_URL}/geocode',
        params={'q': address, 'limit': 1},
        headers=_geocodio_headers(),
        timeout=8
    )
    if resp.status_code == 422:
        raise ValueError(f'Could not geocode address: "{address}"')
    resp.raise_for_status()
    results = resp.json().get('results')
    if not results:
        raise ValueError(f'Could not geocode address: "{address}"')
    location = results[0]['location']
    return location['lat'], location['lng']


def calculate_driving_miles(start_text, end_text):
    start_lat, start_lon = geocode(start_text)
    end_lat, end_lon = geocode(end_text)

    resp = requests.get(
        f'{GEOCODIO_BASE_URL}/distance',
        params={
            'origin': f'{start_lat},{start_lon}',
            'destinations[]': f'{end_lat},{end_lon}',
            'mode': 'driving',
            'units': 'miles',
        },
        headers=_geocodio_headers(),
        timeout=10
    )
    resp.raise_for_status()
    destinations = resp.json().get('destinations')
    if not destinations:
        raise ValueError('Geocodio could not find a driving route between those locations.')
    dest = destinations[0]
    return round(dest['distance_miles'], 2), dest['duration_seconds']


def _elapsed_seconds(start_time, end_time):
    """Seconds between two 'HH:MM' strings, assuming midnight wraparound
    if end <= start. None if either is missing/unparseable."""
    if not start_time or not end_time:
        return None
    try:
        sh, sm = map(int, start_time.split(':'))
        eh, em = map(int, end_time.split(':'))
    except (ValueError, AttributeError):
        return None
    start_min, end_min = sh * 60 + sm, eh * 60 + em
    if end_min <= start_min:
        end_min += 24 * 60
    return (end_min - start_min) * 60


FEASIBILITY_MIN_RATIO = 0.5  # flag "too fast" if elapsed < 50% of Geocodio's expected duration
FEASIBILITY_MAX_RATIO = 3.0  # flag "too slow" if elapsed > 300% of Geocodio's expected duration


def check_trip_feasibility(start_time, end_time, distance_miles, duration_seconds):
    """Warning string if the clock-time gap is implausible (too fast or too
    slow) for the distance, else None. Pure function, never raises — non-blocking."""
    if duration_seconds is None or not distance_miles:
        return None
    elapsed = _elapsed_seconds(start_time, end_time)
    if elapsed is None or elapsed <= 0:
        return None
    elapsed_min, expected_min = round(elapsed / 60), round(duration_seconds / 60)
    if elapsed < duration_seconds * FEASIBILITY_MIN_RATIO:
        return (f'{distance_miles} miles in {elapsed_min} min is much faster than the '
                f'typical ~{expected_min} min for this route — double check the times.')
    if elapsed > duration_seconds * FEASIBILITY_MAX_RATIO:
        return (f'{distance_miles} miles in {elapsed_min} min is much longer than the '
                f'typical ~{expected_min} min for this route — double check the times.')
    return None


def validate_trip_date(trip_date):
    """Error string if trip_date is set but isn't a real calendar date or is
    in the future, else None. A trip date is optional, so None/empty is fine."""
    if not trip_date:
        return None
    try:
        parsed = datetime.strptime(trip_date, '%Y-%m-%d').date()
    except ValueError:
        return f'"{trip_date}" is not a valid date.'
    if parsed > date.today():
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == '1'
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account is associated with that email.', 'danger')
        elif not user.check_password(password):
            flash('Incorrect password.', 'danger')
        else:
            login_user(user, remember=remember)
            return redirect(url_for('index'))

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
    return render_template('index.html', username=current_user.username, photo_data=current_user.photo_data)


@app.route('/calculate', methods=['POST'])
@login_required
def calculate():
    data = request.get_json()
    start = (data.get('start') or '').strip()
    end = (data.get('end') or '').strip()
    if not start or not end:
        return jsonify({'error': 'Both start and end locations are required.'}), 400
    try:
        miles, duration_seconds = calculate_driving_miles(start, end)
    except ValueError as e:
        return jsonify({'error': str(e)}), 422
    except Exception:
        return jsonify({'error': 'Failed to calculate distance. Please try again.'}), 500
    return jsonify({
        'distance_miles': miles,
        'start': start,
        'end': end,
        'duration_seconds': duration_seconds,
    })


@app.route('/log', methods=['POST'])
@login_required
def log_trip():
    data = request.get_json()
    start = (data.get('start') or '').strip()
    end   = (data.get('end')   or '').strip()
    if not start or not end:
        return jsonify({'error': 'Missing trip data.'}), 400

    trip_date  = (data.get('trip_date') or '').strip() or None
    date_error = validate_trip_date(trip_date)
    if date_error:
        return jsonify({'error': date_error}), 400

    distance_miles   = data.get('distance_miles')
    duration_seconds = data.get('duration_seconds')
    distance_error   = None
    if distance_miles is not None:
        distance_miles = float(distance_miles)
    else:
        try:
            distance_miles, duration_seconds = calculate_driving_miles(start, end)
        except ValueError as e:
            distance_error = str(e)
        except Exception:
            distance_error = 'Could not calculate distance automatically. Edit this trip to add it later.'

    vehicle_id  = data.get('vehicle_id') or None
    start_time  = (data.get('start_time')  or '').strip() or None
    end_time    = (data.get('end_time')    or '').strip() or None

    vehicle_name = vehicle_sub = None
    if vehicle_id:
        v = Vehicle.query.filter_by(id=int(vehicle_id), user_id=current_user.id).first()
        if v:
            vehicle_name = v.name
            vehicle_sub  = ' '.join(filter(None, [v.year, v.make, v.model]))
        else:
            vehicle_id = None

    warning = None
    if distance_miles is not None:
        warning = check_trip_feasibility(start_time, end_time, distance_miles, duration_seconds)

    trip = Trip(
        user_id=current_user.id,
        start_location=start,
        end_location=end,
        distance_miles=distance_miles,
        vehicle_id=vehicle_id,
        trip_date=trip_date,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
    )
    db.session.add(trip)
    db.session.commit()
    resp = {'success': True, 'trip': _trip_dict(trip, vehicle_name, vehicle_sub)}
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
    return jsonify([
        _trip_dict(
            t,
            t.vehicle.name if t.vehicle else None,
            ' '.join(filter(None, [t.vehicle.year, t.vehicle.make, t.vehicle.model])) if t.vehicle else None
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
    start          = (data.get('start') or '').strip()
    end            = (data.get('end')   or '').strip()
    distance_miles = data.get('distance_miles')
    if not start or not end:
        return jsonify({'error': 'Missing fields.'}), 400

    trip_date  = (data.get('trip_date') or '').strip() or None
    date_error = validate_trip_date(trip_date)
    if date_error:
        return jsonify({'error': date_error}), 400

    distance_miles = float(distance_miles) if distance_miles is not None else None

    vehicle_id  = data.get('vehicle_id') or None
    start_time  = (data.get('start_time')  or '').strip() or None
    end_time    = (data.get('end_time')    or '').strip() or None

    vehicle_name = vehicle_sub = None
    if vehicle_id:
        v = Vehicle.query.filter_by(id=int(vehicle_id), user_id=current_user.id).first()
        if v:
            vehicle_name = v.name
            vehicle_sub  = ' '.join(filter(None, [v.year, v.make, v.model]))
        else:
            vehicle_id = None

    # Fall back to the trip's already-stored duration when the client didn't
    # send a fresh one (i.e. the route wasn't recalculated this edit).
    duration_seconds = data.get('duration_seconds') or trip.duration_seconds
    warning = None
    if distance_miles is not None:
        warning = check_trip_feasibility(start_time, end_time, distance_miles, duration_seconds)

    trip.start_location = start
    trip.end_location   = end
    trip.distance_miles = distance_miles
    trip.vehicle_id     = vehicle_id
    trip.trip_date      = trip_date
    trip.start_time     = start_time
    trip.end_time       = end_time
    trip.duration_seconds = duration_seconds
    db.session.commit()
    resp = _trip_dict(trip, vehicle_name, vehicle_sub)
    if warning:
        resp['warning'] = warning
    return jsonify(resp)


@app.route('/history/<int:trip_id>', methods=['DELETE'])
@login_required
def delete_trip(trip_id):
    trip = Trip.query.filter_by(id=trip_id, user_id=current_user.id).first()
    if not trip:
        return jsonify({'error': 'Trip not found.'}), 404
    db.session.delete(trip)
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
    db.session.delete(v)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/my-vehicles')
@login_required
def vehicles_page():
    return render_template('vehicles.html', username=current_user.username, photo_data=current_user.photo_data)


# ---------------------------------------------------------------------------
# Profile routes
# ---------------------------------------------------------------------------

@app.route('/profile')
@login_required
def profile():
    return render_template(
        'profile.html',
        username=current_user.username,
        email=current_user.email,
        photo_data=current_user.photo_data,
    )


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


@app.errorhandler(413)
def request_too_large(_e):
    return jsonify({'error': 'Photo must be smaller than 2MB.'}), 413


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
# Entry point
# ---------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    _migrate_db()

if __name__ == '__main__':
    app.run(debug=True)
