import pytest
from fastapi.testclient import TestClient
from car_parking_app import app

# Create a test client to make requests to the FastAPI app
client = TestClient(app)

# Define test cases for some of your routes
def test_create_admin_signup():
    response = client.post("/signup/admin", json={"username": "admin_test", "password": "admin_password"})
    assert response.status_code == 200
    assert response.json() == {"message": "Admin registered successfully"}

def test_create_landlord_signup():
    response = client.post("/signup/landlord", json={"username": "landlord_test", "password": "landlord_password", "address": "landlord_address"})
    assert response.status_code == 200
    assert response.json() == {"message": "Landlord user registered successfully"}

# Add more test cases for other routes

# Test case for adding a complaint
def test_add_complaint():
    response = client.post("/add_complaint", json={
        "car_number": "AB123CD",
        "date_of_offense": "20231104",
        "picture": "example.jpg",
        "message_by_landlord": "Complaint message"
    })
    assert response.status_code == 200
    assert "pcn" in response.json()

# Add more test cases for other routes

# Example test case for an authenticated route
def test_get_complaint_by_pcn():
    response = client.get("/complaint/PCN123", json={"car_number": "AB123CD"})
    assert response.status_code == 200
    assert "pcn" in response.json()

# Add more test cases for other authenticated routes

# Run the tests with `pytest`
if __name__ == "__main__":
    pytest.main()
