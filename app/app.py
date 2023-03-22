from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config.from_pyfile("config.py")
mongo = PyMongo(app)
jwt = JWTManager(app)

# Define custom claims for different authorization levels
@jwt.user_claims_loader
def add_claims_to_access_token(user):
    if user.get("is_admin"):
        return {"is_admin": True}
    if user.get("is_subscriber"):
        return {"is_subscriber": True}
    return {"is_free_user": True}

# Load user identity from email instead of username
@jwt.user_identity_loader
def user_identity_lookup(user):
    return str(user["_id"])

# Load user from email instead of username
@jwt.user_loader_callback_loader
def user_loader_callback(identity):
    return mongo.db.users.find_one({"_id": identity})

# Initialize TV2 user
def initialize_tv2_user():
    email = os.environ.get("TV2_EMAIL")
    password = os.environ.get("TV2_PASSWORD")

    if mongo.db.users.find_one({"email": email}):
        return

    hashed_password = generate_password_hash(password, method="bcrypt")
    mongo.db.users.insert_one({
        "email": email,
        "password": hashed_password,
        "is_admin": True
    })

@app.route('/')
def index():
    return 'Welcome to the Auth API!'

# Login endpoint
@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    user = mongo.db.users.find_one({"email": email})
    if user and check_password_hash(user["password"], password):
        access_token = create_access_token(identity=user)
        return jsonify({"access_token": access_token}), 200

    return jsonify({"msg": "Invalid email or password"}), 401

# Signup endpoint
@app.route("/signup", methods=["POST"])
def signup():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"msg": "Email already registered"}), 409

    hashed_password = generate_password_hash(password, method="bcrypt")
    user_id = mongo.db.users.insert_one({
        "email": email,
        "password": hashed_password
    }).inserted_id

    access_token = create_access_token(identity={"_id": user_id, "email": email, "is_free_user": True})
    return jsonify({"access_token": access_token}), 201

# Protected endpoint for free users
@app.route("/protected/free", methods=["GET"])
@jwt_required()
def protected_free():
    claims = jwt.get_jwt_claims()
    if not claims.get("is_free_user"):
        return jsonify({"msg": "Insufficient permissions"}), 403
    return jsonify({"msg": "Access granted for free user"}), 200

# Protected endpoint for subscribers
@app.route("/protected/subscriber", methods=["GET"])
@jwt_required()
def protected_subscriber():
    claims = jwt.get_jwt_claims()
    if not claims.get("is_subscriber"):
        return jsonify({"msg": "Insufficient permissions"}), 403
    return jsonify({"msg": "Access granted for subscriber"}), 200

# Protected endpoint for TV2
@app.route("/protected/tv2", methods=["GET"])
@jwt_required()
def protected_tv2():
    claims = jwt.get_jwt_claims()
    if not claims.get("is_admin"):
        return jsonify({"msg": "Insufficient permissions"}), 403
    return jsonify({"msg": "Access granted for TV2"}), 200

