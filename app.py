from flask import Flask, render_template, request, jsonify, abort, g
from flask_mongoengine import MongoEngine
from passlib.apps import custom_app_context as pwd_context
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from flask_httpauth import HTTPBasicAuth
import sys

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECRET_REGISTERABLE'] = True

#Hashing
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
#app.config['SECURITY_PASSWORD_SALT'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# MongoDB Config
app.config['MONGODB_DB'] = 'Journey'
app.config['MONGODB_HOST'] = 'localhost'
app.config['MONGODB_PORT'] = 27017

# Create database connection object
db = MongoEngine(app)
auth = HTTPBasicAuth()

class User(db.Document):
    name = db.StringField(max_length=32)
    surname = db.StringField(max_length=32)
    email = db.StringField(max_length=128, unique=True)
    password = db.StringField(max_length=128)
    active = db.BooleanField(default=True)


    def hash_password(self, pw_plain):
        self.password = pwd_context.encrypt(pw_plain)

    def verify_password(self, pw_plain):
        return pwd_context.verify(pw_plain, self.password)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': str(self.id)})

    
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.objects(id=data['id'])
        return user


@auth.verify_password
def verify_password(email_or_token, password):
    #try authenticate by token
    user = User.verify_auth_token(email_or_token)
    if not user:
        # try authenticate with username & password
        user = User.objects(email=email_or_token)
        if not user or not user.verify_password(password):
            return False
    #user found
    g.user = user
    return True

@app.route('/api/users', methods = ['GET'])
def get_users():
    return jsonify({"Users": User.objects().all()})

@app.route('/api/user', methods = ['GET'])
@auth.login_required
def get_user():
    return jsonify({"User": g.user})

@app.route('/api/register', methods = ['POST'])
def sign_up():
    data = request.get_json()
    name = data['name']
    surname = data['surname']
    email = data['email']
    password = data['password']
    if User.objects(email__exact = email):
        return jsonify({"Error": "User exsits", "User": User.objects(email=email)}), 400
    user = User(name= name, surname= surname, email = email)
    pw = user.hash_password(password)
    user.save()

    token = user.generate_auth_token()
    return jsonify({ 'token': token.decode('ascii')}), 201


#TODO: fix login - verify password not working properly
@app.route('/api/login', methods = ['POST'])
def sign_in():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = User()
    user = User.objects(email=email)[0]
    if user:
        if user.verify_password(password):
            token = user.generate_auth_token()
            return jsonify({ 'token': token.decode('ascii') }), 201

    return jsonify({"Error": "Incorret credentials"}), 400

    

if __name__ == '__main__':
    app.run(host='0.0.0.0')
