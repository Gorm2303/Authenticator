from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import requests
import os
from datetime import timedelta

app = Flask(__name__)
client = MongoClient(os.environ.get("MONGO_URI"))
db = client['usersdb']
usersCollection = db['users']
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=4)
SUBSCRIPTION_API_URL = os.environ.get("SUBSCRIPTION_API_URL")
CACHER_API_URL = os.environ.get("CACHER_API_URL")
UPLOADER_API_URL = os.environ.get("UPLOADER_API_URL")
# Define custom claims for different authorization levels
@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    if identity.get("role") == "admin":
        return {"role": "admin"}
    if identity.get("role") == "subscriber":
        return {"role": "subscriber"}
    return {"role": "user"}

@jwt.user_identity_loader
def user_identity_lookup(user):
    return str(user["_id"])

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return usersCollection.find_one({"_id": ObjectId(identity)})

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
@app.route("/api/v1/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    user = usersCollection.find_one({"email": email})
    if user and check_password_hash(user["password"], password):
        # Check if user has an active subscription
        response = requests.get(f"{SUBSCRIPTION_API_URL}/subscriptions/{user['_id']}/active")

        # Update user role based on active subscription status
        if response.status_code == 200 and user["role"] == "user":
            usersCollection.update_one({"_id": user["_id"]}, {"$set": {"role": "subscriber"}})
            user["role"] = "subscriber"
        elif response.status_code != 200 and user["role"] == "subscriber":
            usersCollection.update_one({"_id": user["_id"]}, {"$set": {"role": "user"}})
            user["role"] = "user"

        access_token = create_access_token(identity=user)
        return jsonify({"access_token": access_token}), 200

    return jsonify({"msg": "Invalid email or password"}), 401

# Signup endpoint
@app.route("/api/v1/signup", methods=["POST"])
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

# SUBSCRIPTION PROXY ENDPOINTS

@app.route("/api/v1/create_subscription", methods=["POST"])
@jwt_required()
def create_subscription_proxy():
    claims = get_jwt()
    if not (claims.get("role") in ["user"]):
        return jsonify({"msg": "Insufficient permissions"}), 403
    
    user_id = request.json.get("user_id", None)
    subscription_type_id = request.json.get("subscription_type_id", None)

    response = requests.post(
        f"{SUBSCRIPTION_API_URL}/subscriptions",
        json={"user_id": user_id, "subscription_type_id": subscription_type_id}
    )

    # If subscription was created successfully and user's role is "user", update the role to "subscriber"
    if response.status_code == 201:
        user = usersCollection.find_one({"_id": ObjectId(user_id)})
        if user and user["role"] == "user":
            usersCollection.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": "subscriber"}})
            user["role"] = "subscriber"
            access_token = create_access_token(identity=user)
            return jsonify({"msg": "Subscription created successfully", "access_token": access_token}), 201

    # Return the same response from subscription API
    return jsonify(response.json()), response.status_code

@app.route("/api/v1/subscriptiontypes", methods=["GET"])
def get_subscription_types():
    response = requests.get(f"{SUBSCRIPTION_API_URL}/subscriptiontypes")

    return jsonify(response.json()), response.status_code

@app.route("/api/v1/cancel_subscription", methods=["PUT"])
@jwt_required()
def cancel_subscription_proxy():
    claims = get_jwt()
    if not (claims.get("role") in ["user", "subscriber"]):
        return jsonify({"msg": "Insufficient permissions"}), 403

    user_id = request.json.get("user_id", None)

    response = requests.put(
        f"{SUBSCRIPTION_API_URL}/subscriptions/{user_id}/cancel",
    )

    # If subscription was cancelled successfully and user's role is "subscriber", update the role to "user"
    if response.status_code == 200:
        user = usersCollection.find_one({"_id": ObjectId(user_id)})
        if user and user["role"] == "subscriber":
            usersCollection.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": "user"}})
            user["role"] = "user"
            access_token = create_access_token(identity=user)
            return jsonify({"msg": "Subscription cancelled successfully", "access_token": access_token}), 200

    # Return the same response from subscription API
    return jsonify(response.json()), response.status_code


# CACHER PROXY ENDPOINTS

@app.route('/api/v1/videometadata', methods=['GET'])
@jwt_required()
def get_videos_metadata_proxy():
    claims = get_jwt()
    if not (claims.get("role") in ["subscriber", "admin"]):
        return jsonify({"msg": "Insufficient permissions"}), 403

    response = requests.get(CACHER_API_URL + "/api/v1/videometadata")
    return jsonify(response.json()), response.status_code

@app.route('/api/v1/videometadata/<id>', methods=['GET'])
@jwt_required()
def get_video_metadata_proxy(id):
    claims = get_jwt()
    if not (claims.get("role") in ["subscriber", "admin"]):
        return jsonify({"msg": "Insufficient permissions"}), 403

    response = requests.get(CACHER_API_URL + f"/api/v1/videometadata/{id}")
    return jsonify(response.json()), response.status_code

@app.route('/api/v1/videometadata/search', methods=['GET'])
@jwt_required()
def search_videos_proxy():
    claims = get_jwt()
    if not (claims.get("role") in ["subscriber", "admin"]):
        return jsonify({"msg": "Insufficient permissions"}), 403

    query = request.args.get('q', '')
    response = requests.get(CACHER_API_URL + f"/api/v1/videometadata/search?q={query}")
    return jsonify(response.json()), response.status_code

# VIDEO UPLOADER PROXY ENDPOINTS

@app.route('/api/v1/videometadata', methods=['POST'])
@jwt_required()
def upload_video_metadata_proxy():
    claims = get_jwt()
    if not (claims.get("role") == "admin"):
        return jsonify({"msg": "Insufficient permissions"}), 403

    response = requests.post(UPLOADER_API_URL + "/api/v1/videometadata", json=request.json)
    return jsonify(response.json()), response.status_code

@app.route('/api/v1/videometadata', methods=['PUT'])
@jwt_required()
def update_video_metadata_proxy():
    claims = get_jwt()
    if not (claims.get("role") == "admin"):
        return jsonify({"msg": "Insufficient permissions"}), 403

    response = requests.put(UPLOADER_API_URL + "/api/v1/videometadata", json=request.json)
    return jsonify(response.json()), response.status_code

@app.route('/api/v1/poster', methods=['POST'])
@jwt_required()
def upload_image_proxy():
    claims = get_jwt()
    if not (claims.get("role") == "admin"):
        return jsonify({"msg": "Insufficient permissions"}), 403

    files = {'chunk': (request.files['chunk'].filename, request.files['chunk'].stream.read())}
    data = {
        'chunkIndex': request.form['chunkIndex'],
        'chunks': request.form['chunks'],
        'filename': request.form['filename']
    }

    response = requests.post(UPLOADER_API_URL + "/api/v1/poster", files=files, data=data)
    return jsonify(response.json()), response.status_code

@app.route('/api/v1/video', methods=['POST'])
@jwt_required()
def upload_video_proxy():
    claims = get_jwt()
    if not (claims.get("role") == "admin"):
        return jsonify({"msg": "Insufficient permissions"}), 403

    files = {'chunk': (request.files['chunk'].filename, request.files['chunk'].stream.read())}
    data = {
        'chunkIndex': request.form['chunkIndex'],
        'chunks': request.form['chunks'],
        'filename': request.form['filename']
    }

    response = requests.post(UPLOADER_API_URL + "/api/v1/video", files=files, data=data)
    return jsonify(response.json()), response.status_code

@app.route('/api/v1/video/<video_id>', methods=['DELETE'])
@jwt_required()
def delete_video_proxy(video_id):
    claims = get_jwt()
    if not (claims.get("role") == "admin"):
        return jsonify({"msg": "Insufficient permissions"}), 403

    response = requests.delete(UPLOADER_API_URL + f"/api/v1/video/{video_id}")
    return jsonify(response.json()), response.status_code


initialize_tv2_user()

if __name__ == "__main__":
    app.run(debug=True)
