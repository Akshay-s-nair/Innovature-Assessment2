from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime, timedelta
from functools import wraps
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ritesh'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
ist = pytz.timezone('Asia/Kolkata')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

def generate_token(username):
    payload = {
        'exp': datetime.now(ist) + timedelta(days=1),
        'iat': datetime.now(ist),
        'sub': username
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
        print('Received Token:', token)
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print('Decoded Token:', data)
            current_user = User.query.filter_by(username=data['sub']).first()
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

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists!'}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    token = generate_token(username)

    return jsonify({'message': 'User registered successfully', 'token': token})

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Username and password are required!'}), 401

    user = User.query.filter_by(username=auth.username).first()
    if not user or user.password != auth.password:
        return jsonify({'message': 'Invalid credentials!'}), 401

    token = generate_token(user.username)
    return jsonify({'message': 'User is now logged in', 'token': token})

@app.route('/refresh_token', methods=['POST'])
@token_required
def refresh_token(current_user):
    token = generate_token(current_user.username)
    return jsonify({'token': token})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)