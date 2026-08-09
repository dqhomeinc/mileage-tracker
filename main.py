import os
import re
import time
import requests
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-key')

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

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
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
    distance_miles = db.Column(db.Float, nullable=False)
    timestamp      = db.Column(db.DateTime, server_default=db.func.now())
    vehicle_id     = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=True)
    trip_date      = db.Column(db.String(10), nullable=True)
    start_time     = db.Column(db.String(5),  nullable=True)
    end_time       = db.Column(db.String(5),  nullable=True)


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
    }


def _migrate_db():
    """Add new columns/tables to existing databases without dropping data."""
    dialect = db.engine.dialect.name
    with db.engine.connect() as conn:
        if dialect == 'sqlite':
            result = conn.execute(db.text('PRAGMA table_info(trip)'))
            existing = {row[1] for row in result}
            additions = [
                ('vehicle_id', 'INTEGER'),
                ('trip_date',  'VARCHAR(10)'),
                ('start_time', 'VARCHAR(5)'),
                ('end_time',   'VARCHAR(5)'),
            ]
            for col, typ in additions:
                if col not in existing:
                    conn.execute(db.text(f'ALTER TABLE trip ADD COLUMN {col} {typ}'))
        else:
            result = conn.execute(db.text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'trip'"
            ))
            existing = {row[0] for row in result}
            additions = [
                ('vehicle_id', 'INTEGER'),
                ('trip_date',  'VARCHAR(10)'),
                ('start_time', 'VARCHAR(5)'),
                ('end_time',   'VARCHAR(5)'),
            ]
            for col, typ in additions:
                if col not in existing:
                    conn.execute(db.text(f'ALTER TABLE trip ADD COLUMN {col} {typ}'))
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

def send_reset_email(user, token):
    reset_url = url_for('reset_password', token=token, _external=True)
    if not app.config.get('MAIL_USERNAME'):
        app.logger.info('DEV — password reset URL: %s', reset_url)
        return
    msg = Message(
        subject='Mileage Tracker — Password Reset',
        recipients=[user.email],
        html=(
            f'<p>Hi {user.username},</p>'
            f'<p>Click the link below to reset your password. '
            f'The link expires in 1 hour.</p>'
            f'<p><a href="{reset_url}">{reset_url}</a></p>'
            f'<p>If you did not request this, you can ignore this email.</p>'
        )
    )
    mail.send(msg)


# ---------------------------------------------------------------------------
# Distance calculation: Nominatim geocoding + OSRM routing
# ---------------------------------------------------------------------------

NOMINATIM_URL = 'https://nominatim.openstreetmap.org/search'
OSRM_URL = 'http://router.project-osrm.org/route/v1/driving'
HEADERS = {'User-Agent': 'mileage-tracker/1.0 (joseph.jia23@gmail.com)'}


def geocode(address):
    resp = requests.get(
        NOMINATIM_URL,
        params={'q': address, 'format': 'json', 'limit': 1},
        headers=HEADERS,
        timeout=8
    )
    resp.raise_for_status()
    results = resp.json()
    if not results:
        raise ValueError(f'Could not geocode address: "{address}"')
    return float(results[0]['lat']), float(results[0]['lon'])


def calculate_driving_miles(start_text, end_text):
    start_lat, start_lon = geocode(start_text)
    time.sleep(1)  # Nominatim rate limit: 1 req/s
    end_lat, end_lon = geocode(end_text)

    url = f'{OSRM_URL}/{start_lon},{start_lat};{end_lon},{end_lat}'
    resp = requests.get(url, params={'overview': 'false'}, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if data.get('code') != 'Ok' or not data.get('routes'):
        raise ValueError('OSRM could not find a driving route between those locations.')
    meters = data['routes'][0]['distance']
    return round(meters / 1609.344, 2)


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
        if User.query.filter_by(username=username).first():
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
        if user and user.check_password(password):
            login_user(user, remember=remember)
            return redirect(url_for('index'))
        flash('Invalid email or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
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
                flash('Could not send email. Check your MAIL_* settings in .env.', 'danger')
                return render_template('forgot_password.html')
        # Always show the same message to prevent user enumeration
        flash('If that email is registered, a reset link has been sent. Check your inbox (and spam folder).', 'info')
        if app.debug and not app.config.get('MAIL_USERNAME'):
            flash('DEV MODE: No email configured — check the terminal for the reset link.', 'warning')
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
    return render_template('index.html', username=current_user.username)


@app.route('/calculate', methods=['POST'])
@login_required
def calculate():
    data = request.get_json()
    start = (data.get('start') or '').strip()
    end = (data.get('end') or '').strip()
    if not start or not end:
        return jsonify({'error': 'Both start and end locations are required.'}), 400
    try:
        miles = calculate_driving_miles(start, end)
    except ValueError as e:
        return jsonify({'error': str(e)}), 422
    except Exception:
        return jsonify({'error': 'Failed to calculate distance. Please try again.'}), 500
    return jsonify({'distance_miles': miles, 'start': start, 'end': end})


@app.route('/log', methods=['POST'])
@login_required
def log_trip():
    data = request.get_json()
    start          = (data.get('start') or '').strip()
    end            = (data.get('end')   or '').strip()
    distance_miles = data.get('distance_miles')
    if not start or not end or distance_miles is None:
        return jsonify({'error': 'Missing trip data.'}), 400

    vehicle_id  = data.get('vehicle_id') or None
    trip_date   = (data.get('trip_date')   or '').strip() or None
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

    trip = Trip(
        user_id=current_user.id,
        start_location=start,
        end_location=end,
        distance_miles=float(distance_miles),
        vehicle_id=vehicle_id,
        trip_date=trip_date,
        start_time=start_time,
        end_time=end_time,
    )
    db.session.add(trip)
    db.session.commit()
    return jsonify({'success': True, 'trip': _trip_dict(trip, vehicle_name, vehicle_sub)})


@app.route('/history')
@login_required
def history():
    trips = Trip.query.filter_by(user_id=current_user.id)\
                      .order_by(Trip.timestamp.desc()).all()
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
    if not start or not end or distance_miles is None:
        return jsonify({'error': 'Missing fields.'}), 400

    vehicle_id  = data.get('vehicle_id') or None
    trip_date   = (data.get('trip_date')   or '').strip() or None
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

    trip.start_location = start
    trip.end_location   = end
    trip.distance_miles = float(distance_miles)
    trip.vehicle_id     = vehicle_id
    trip.trip_date      = trip_date
    trip.start_time     = start_time
    trip.end_time       = end_time
    db.session.commit()
    return jsonify(_trip_dict(trip, vehicle_name, vehicle_sub))


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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    _migrate_db()

if __name__ == '__main__':
    app.run(debug=True)
