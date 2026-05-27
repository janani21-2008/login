from flask import Flask, request, jsonify

from flask_sqlalchemy import SQLAlchemy

from flask_bcrypt import Bcrypt

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from datetime import timedelta



app = Flask(__name__)

app.config['SECRET_KEY'] = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

app.config['JWT_SECRET_KEY'] = 'jwtsecretkey'

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)


db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

jwt = JWTManager(app)


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)



with app.app_context():
    db.create_all()


@app.route('/')

def home():

    return """
    
    <h1>Secure Login System</h1>

    <h3>Available Routes:</h3>

    <ul>
        <li>POST /register</li>
        <li>POST /login</li>
        <li>GET /dashboard</li>
        <li>GET /logout</li>
    </ul>

    """


@app.route('/register', methods=['POST'])

def register():

    data = request.get_json()

    username = data.get('username')

    email = data.get('email')

    password = data.get('password')


    if not username or not email or not password:

        return jsonify({
            "message": "All fields are required"
        }), 400


    if len(password) < 6:

        return jsonify({
            "message": "Password must be at least 6 characters"
        }), 400


    existing_user = User.query.filter_by(email=email).first()

    if existing_user:

        return jsonify({
            "message": "User already exists"
        }), 400


    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')


    new_user = User(
        username=username,
        email=email,
        password=hashed_password
    )

    db.session.add(new_user)

    db.session.commit()


    return jsonify({
        "message": "Registration Successful"
    }), 201


@app.route('/login', methods=['POST'])

def login():

    data = request.get_json()

    email = data.get('email')

    password = data.get('password')


    user = User.query.filter_by(email=email).first()


    if not user:

        return jsonify({
            "message": "Invalid Email or Password"
        }), 401


    if not bcrypt.check_password_hash(user.password, password):

        return jsonify({
            "message": "Invalid Email or Password"
        }), 401


    access_token = create_access_token(identity=user.email)


    return jsonify({

        "message": "Login Successful",

        "token": access_token

    })



@app.route('/dashboard', methods=['GET'])

@jwt_required()

def dashboard():

    current_user = get_jwt_identity()

    return jsonify({

        "message": "Welcome to Secure Dashboard",

        "user": current_user

    })



@app.route('/logout', methods=['GET'])

def logout():

    return jsonify({
        "message": "Logout Successful"
    })



if __name__ == '__main__':

    app.run(debug=True)
