from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import uuid 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'zzx1keyaskfbj123asdaASas2233f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique = True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(70), unique = True)
    password_hash = db.Column(db.String(128), nullable=False)
    calculations = db.relationship('Calculation', backref='user', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Calculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.public_id'), nullable=False)
    operation = db.Column(db.String(10), nullable=False)
    num1 = db.Column(db.Float, nullable=False)
    num2 = db.Column(db.Float, nullable=False)
    result = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f"<Calculation {self.id}: {self.user_id} {self.operation} {self.num1} {self.num2} = {self.result}>"

with app.app_context():
    db.create_all()

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['user_pid']).first()
            
        except:
            return jsonify({'error': 'Invalid token'}), 401

        return func(current_user, *args, **kwargs)

    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User already exists'}), 400
    pid=str(uuid.uuid4())
    new_user = User(public_id=pid,username=username,email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'No user found'}), 401
    
    if not user.check_password(password):
        return jsonify({'error': 'Invalid username or password'}), 401

    token = jwt.encode({'user_pid': user.public_id}, app.config['SECRET_KEY'])
    return jsonify({'token': token}), 200

@app.route('/add', methods=['POST'])
@token_required
def add_operation(current_user):
    data = request.get_json()
    num1 = data['num1']
    num2 = data['num2']
    if type(num1)==str and type(num2)==str:
        return jsonify({'error': "Please provide numbers"})
    elif type(num1)==str or type(num2)==str:
        return jsonify({'error': "Please provide a number"})
    result = num1 + num2
    calculation = Calculation(user_id=current_user.id, operation='add', num1=num1, num2=num2, result=result)
    db.session.add(calculation)
    db.session.commit()
    return jsonify({'result': result})

@app.route('/subtract', methods=['POST'])
@token_required
def subtract_operation(current_user):
    data = request.get_json()
    num1 = data['num1']
    num2 = data['num2']
    if type(num1)==str and type(num2)==str:
        return jsonify({'error': "Please provide numbers"})
    elif type(num1)==str or type(num2)==str:
        return jsonify({'error': "Please provide a number"})
    result = num1 - num2
    calculation = Calculation(user_id=current_user.id, operation='subtract', num1=num1, num2=num2, result=result)
    db.session.add(calculation)
    db.session.commit()
    return jsonify({'result': result})

@app.route('/multiply', methods=['POST'])
@token_required
def multiply_operation(current_user):
    data = request.get_json()
    num1 = data['num1']
    num2 = data['num2']
    if type(num1)==str and type(num2)==str:
        return jsonify({'error': "Please provide numbers"})
    elif type(num1)==str or type(num2)==str:
        return jsonify({'error': "Please provide a number"})
    result = num1 * num2
    calculation = Calculation(user_id=current_user.id, operation='multiply', num1=num1, num2=num2, result=result)
    db.session.add(calculation)
    db.session.commit()
    return jsonify({'result': result})

@app.route('/divide', methods=['POST'])
@token_required
def divide_operation(current_user):
    data = request.get_json()
    num1 = data['num1']
    num2 = data['num2']
    if type(num1)==str and type(num2)==str:
        return jsonify({'error': "Please provide numbers"})
    elif type(num1)==str or type(num2)==str:
        return jsonify({'error': "Please provide a number"})
    
    if num2 == 0:
        return jsonify({'error': 'Division by zero is not allowed'}), 400
    result = num1 / num2
    calculation = Calculation(user_id=current_user.id, operation='divide', num1=num1, num2=num2, result=result)
    db.session.add(calculation)
    db.session.commit()
    return jsonify({'result': result})

@app.route('/calculations', methods=['GET'])
@token_required
def get_calculations(current_user):
    calculations = Calculation.query.filter_by(user_id=current_user.id).all()
    calculations_data = [{'id': calc.id, 'operation': calc.operation, 'num1': calc.num1, 'num2': calc.num2, 'result': calc.result} for calc in calculations]
    return jsonify({'calculations': calculations_data})

if __name__ == '__main__':
    app.run(debug=True)
