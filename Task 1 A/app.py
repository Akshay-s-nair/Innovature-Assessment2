from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import jwt
import uuid 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asdfghjk12345678qwerty'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
ist = pytz.timezone('Asia/Kolkata')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique = True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(100), nullable=False)

def generate_token(pid):
    payload = {
        'exp': datetime.now(ist) + timedelta(days=1),
        'iat': datetime.now(ist),
        'sub': pid
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        token = token.replace('Bearer ', '')
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['sub']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except (jwt.InvalidTokenError, AttributeError):
            return jsonify({'message': 'Invalid token!'}), 401
        if not current_user:
            return jsonify({'message': 'User not found!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/', methods=['GET'])
def show_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            routes.append({'endpoint': rule.endpoint, 'methods': ','.join(rule.methods), 'path': str(rule)})
    return jsonify({'routes': routes})

@app.route('/getuser', methods =['GET'])
@token_required
def get_all_users(current_user):
	users = User.query.all()
	output = []
	for user in users:
		output.append({
			'public_id': user.public_id,
			'username' : user.username,
			'email' : user.email
		})

	return jsonify({'users': output})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists!'}), 400
    pid=str(uuid.uuid4())
    new_user = User(public_id=pid,username=username,email=email, password=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()

    token = generate_token(pid)

    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    auth = request.form
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 401

    user = User.query.filter_by(email=auth.get('email')).first()
    if not user:
        return jsonify({'message': 'user not exists!'}), 401
    
    if check_password_hash(user.password, auth.get('password')):
        token = generate_token(user.public_id)
        return jsonify({'message': 'User is now logged in', 'token': token})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/refresh_token', methods=['POST'])
@token_required
def refresh_token(current_user):
    token = generate_token(current_user.public_id)
    return jsonify({'token': token})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
