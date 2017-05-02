from __future__ import print_function
from flask import Flask, render_template, request, jsonify, abort, g
from flask_mongoengine import MongoEngine
from passlib.apps import custom_app_context as pwd_context
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from flask_httpauth import HTTPBasicAuth
import sys
import json


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


class AbstracMedia(db.EmbeddedDocument):
    #header
    creator = db.ReferenceField('User', required=True)
    datetime = db.DateTimeField(required=False)

    meta = {'allow_inheritance': True}

class Comment(AbstracMedia):
    #header
    text = db.StringField(required=True)
    likers = db.EmbeddedDocumentListField(AbstracMedia)


class Post(AbstracMedia):
    #header
    _id = db.ObjectIdField(required=True, default=lambda: ObjectId())

    #content
    text = db.StringField()
    image = db.ImageField()
    loc = db.GeoPointField()

    #info
    likers = db.EmbeddedDocumentListField(AbstracMedia)
    comments = db.EmbeddedDocumentListField(Comment)



    @property
    def profile_image(self):
        return creator.profile_image

    @property
    def likes(self):
        return len(likers)

    @property
    def comments(self):
        total_comments = len(comments)
        for comment in comments:
            total_comments += len(comment.comments)
        return total_comments

    

class User(db.Document):
    name = db.StringField(max_length=32)
    email = db.StringField(max_length=128, unique=True)
    password = db.StringField(max_length=128)
    active = db.BooleanField(default=True)
    folowing = db.ListField(db.ReferenceField('User'))
    folowers = db.ListField(db.ReferenceField('User'))
    profile_image = db.ImageField()
    images = db.ListField(db.ImageField())
    posts = db.EmbeddedDocumentListField(Post)
    feed = db.ListField(db.ReferenceField('Post'))



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
        users = User.objects(email=email_or_token)
        if not users or not users[0].verify_password(password):
            return False
        user = users[0]
    #user found
    g.user = user
    return True

# [{"_id": ObjectID, "name": str}]
@app.route('/api/search/<string:name_str>', methods = ['GET'])
@auth.login_required
def search_user():
    return User.objects(name__icontains=name_str).only('_id','name')

# {"post": post}
@app.route('/api/user/upload_post', methods = ['POST']) 
@auth.login_required
def upload_post():
    user = g.user
    
    post_data = request.get_json()  
    post = Post(**post_data) #
    user.save() #validation
    post.creator = user
    user.posts.append(post)
    user.save()

    #add post to folowers
    folowers = user.folowers
    for folow in folowers:
        folow.feed.append(post)

    return jsonify({"post": post}), 201


# {"posts": [post], "liked": [true/false]}
@app.route('/api/user/get_posts/<int:sent_posts>', methods = ['GET'])
@auth.login_required
def get_feed():
    user = g.user
    #a chunk of 10 posts requested by client
    start = sent_posts
    end = sent_posts + 10
    posts = user.feed.reverse()[start:end]
    liked = [p.creator._id is user._id for p in posts]

    return jsonify({"posts":posts, "liked":liked}), 201



@app.route('/api/user/like_post', methods = ['PUT'])
@auth.login_required
def like_post():
    user = g.user
    post_id = ObjectId(request.args.get('post_id'))
    creator_id = request.args.get('user_id')

    creator = User.objects(_id=ObjectId(creator_id))[0]
    creator_posts = creator.posts[::-1]

    creator_post = Post()
    for post in creator_posts:
        if post_id is post.id:
            creator_post = post
            break

    creator_post.likers.append(user.id)
    creator_post.save()
    return 201

@app.route('/api/users', methods = ['GET'])
def get_users():
    return jsonify({"Users": User.objects().all()})

@app.route('/api/user', methods = ['GET'])
@auth.login_required
def get_user():
    return jsonify({"User": g.user}), 201


@app.route('/api/register', methods = ['POST'])
def sign_up():
    data = request.get_json()
    name = data['name'] + " " + data['surname']
    email = data['email']
    password = data['password']
    if User.objects(email__exact = email):
        return jsonify({"Error": "User exsits", "User": User.objects(email=email)}), 400
    user = User(name= name, email = email)
    user.hash_password(password)
    user.save()

    token = user.generate_auth_token()
    return jsonify({ 'token': token.decode('ascii')}), 201


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
