import pytest
import json
import requests
from unittest.mock import Mock, patch
from app import app, usersCollection
from bson import ObjectId
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash
import os

@pytest.fixture
def client():
    return app.test_client()

@pytest.fixture
def tv2_user_token():
    email = os.environ.get("TV2_EMAIL")
    password = os.environ.get("TV2_PASSWORD")

    with patch.dict('os.environ', {'SUBSCRIPTION_API_URL': 'http://fakeurl.com'}):
        response = app.test_client().post('/api/v1/login', json={"email": email, "password": password})

    if response.status_code == 200:
        data = json.loads(response.data)
        return data["access_token"]
    return None


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

# Test get_videos_metadata_proxy
@patch('requests.get', return_value=Mock(status_code=200, json=lambda: [{"id": "1", "title": "Sample Video 1"}]))
def test_get_videos_metadata_proxy(mock_get, client):
    response = client.get('/api/v1/videometadata')
    assert response.status_code == 401  # Unauthenticated access
    headers = {'Authorization': f'Bearer {tv2_user_token}'}
    response = client.get('/api/v1/videometadata', headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["id"] == "1"

# Test get_video_metadata_proxy
@patch('requests.get', return_value=Mock(status_code=200, json=lambda: {"id": "1", "title": "Sample Video 1"}))
def test_get_video_metadata_proxy(mock_get, client):
    response = client.get('/api/v1/videometadata/1')
    assert response.status_code == 401  # Unauthenticated access
    headers = {'Authorization': f'Bearer {tv2_user_token}'}
    response = client.get('/api/v1/videometadata/1', headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "1"

# Test search_videos_proxy
@patch('requests.get', return_value=Mock(status_code=200, json=lambda: [{"id": "1", "title": "Sample Video 1"}]))
def test_search_videos_proxy(mock_get, client):
    response = client.get('/api/v1/videometadata/search?q=sample')
    assert response.status_code == 401  
    headers = {'Authorization': f'Bearer {tv2_user_token}'}
    response = client.get('/api/v1/videometadata/search?q=sample', headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 1
    assert data[0]["id"] == "1"
