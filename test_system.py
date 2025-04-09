import requests

def test_home():
    response = requests.get("http://localhost:5000/")
    assert response.status_code == 200

if __name__ == "__main__":
    test_home()
    print("System test passed!")
