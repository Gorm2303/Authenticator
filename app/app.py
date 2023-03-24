from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os

app = Flask(__name__)
app.config.from_pyfile("config.py")
client = MongoClient(os.environ.get("MONGO_URI"))
db = client['usersdb']
usersCollection = db['users']
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)
SUBSCRIPTION_API_URL = os.environ.get("SUBSCRIPTION_API_URL")
# Define custom claims for different authorization levels
@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    if identity.get("role") == "admin":
        return {"role": "admin"}
    if identity.get("role") == "subscriber":
        return {"role": "subscriber"}
    return {"role": "user"}

# Load user identity from email
@jwt.user_identity_loader
def user_identity_lookup(user):
    return str(user["_id"])

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return usersCollection.find_one({"_id": identity})

# Initialize TV2 user
def initialize_tv2_user():
    email = os.environ.get("TV2_EMAIL")
    password = os.environ.get("TV2_PASSWORD")

    if usersCollection.find_one({"email": email}):
        return

    hashed_password = generate_password_hash(password, method="sha512")
    usersCollection.insert_one({
        "email": email,
        "password": hashed_password,
        "role": "admin"
    })

@app.route('/')
def index():
    return 'Welcome to the Auth API!'

# Login endpoint
@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    user = usersCollection.find_one({"email": email})
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

    if usersCollection.find_one({"email": email}):
        return jsonify({"msg": "Email already registered"}), 409

    hashed_password = generate_password_hash(password, method="sha512")
    user_id = usersCollection.insert_one({
        "email": email,
        "password": hashed_password,
        "role": "user"
    }).inserted_id

    access_token = create_access_token(identity={"_id": user_id, "email": email, "role": "user"})
    return jsonify({"access_token": access_token}), 201

@app.route("/create_subscription", methods=["POST"])
def create_subscription_proxy():
    # Parse the JSON body
    user_id = request.json.get("user_id", None)
    subscription_type_id = request.json.get("subscription_type_id", None)

    # Forward the data to the external API
    response = requests.post(
        f"{SUBSCRIPTION_API_URL}/subscriptions",
        json={"user_id": user_id, "subscription_type_id": subscription_type_id}
    )

    # If subscription was created successfully and user's role is "user", update the role to "subscriber"
    if response.status_code == 201:
        user = usersCollection.find_one({"_id": user_id})
        if user and user["role"] == "user":
            usersCollection.update_one({"_id": user_id}, {"$set": {"role": "subscriber"}})

    # Return the same response from the external API
    return jsonify(response.json()), response.status_code

# Protected endpoint for free users
@app.route("/protected/free", methods=["GET"])
@jwt_required()
def protected_free():
    claims = get_jwt()
    if not claims.get("roles") == "user":
        return jsonify({"msg": "Insufficient permissions"}), 403
    return jsonify({"msg": "Access granted for free user"}), 200

# Protected endpoint for subscribers
@app.route("/protected/subscriber", methods=["GET"])
@jwt_required()
def protected_subscriber():
    claims = get_jwt()
    if not claims.get("roles") == "subscriber":
        return jsonify({"msg": "Insufficient permissions"}), 403
    return jsonify({"msg": "Access granted for subscriber"}), 200

# Protected endpoint for TV2
@app.route("/protected/tv2", methods=["GET"])
@jwt_required()
def protected_tv2():
    claims = get_jwt()
    if not claims.get("roles") == "admin":
        return jsonify({"msg": "Insufficient permissions"}), 403
    return jsonify({"msg": "Access granted for TV2"}), 200


initialize_tv2_user()

if __name__ == "__main__":
    app.run(debug=True)
