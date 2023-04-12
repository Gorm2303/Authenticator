import pytest
import json
from app import app, usersCollection
from bson import ObjectId
from werkzeug.security import generate_password_hash
from unittest.mock import patch, Mock

@pytest.fixture
def client():
    return app.test_client()

# Test the index route
def test_index(client):
    response = client.get('/')
    assert response.status_code == 200
    assert response.data.decode('utf-8') == 'Welcome to the Auth API!'

# Test the signup route
def test_signup(client):
    email = "test@example.com"
    password = "testpassword"
    
    response = client.post('/api/v1/signup', json={"email": email, "password": password})
    assert response.status_code == 201
    data = json.loads(response.data)
    assert "access_token" in data

    # Cleanup
    user = usersCollection.find_one({"email": email})
    usersCollection.delete_one({"_id": ObjectId(user["_id"])})

# Test the login route
@patch('requests.get', return_value=Mock(status_code=200))
def test_login(mock_get, client):
    email = "login_test@example.com"
    password = "testpassword"
    hashed_password = generate_password_hash(password, method="sha512")
    user_id = usersCollection.insert_one({"email": email, "password": hashed_password, "role": "user"}).inserted_id

    with patch.dict('os.environ', {'SUBSCRIPTION_API_URL': 'http://fakeurl.com'}):
        response = client.post('/api/v1/login', json={"email": email, "password": password})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "access_token" in data

    # Cleanup
    usersCollection.delete_one({"_id": ObjectId(user_id)})
