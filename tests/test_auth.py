import unittest
from unittest.mock import patch, MagicMock
from flask_testing import TestCase
from main import app
import os
from main import bcrypt

class TestAuthRoutes(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        return app

    # Test user registration success
    @patch.dict(os.environ, {"MONGO_URI": "mongodb://mocked_mongo_uri"})
    @patch("main.users_collection")
    def test_register_user_success(self, mock_users_collection):
        test_data = {
            "full_name": "John Doe",
            "username": "johndoe",
            "email": "johndoe@example.com",
            "password": "securepassword123"
        }
        mock_users_collection.find_one.return_value = None
        mock_users_collection.insert_one.return_value = MagicMock()
        response = self.client.post('/register', json=test_data)

        self.assertEqual(response.status_code, 201)
        self.assertIn("User registered successfully", response.json["message"])
        mock_users_collection.insert_one.assert_called_once()

    # Test registration with existing email
    @patch.dict(os.environ, {"MONGO_URI": "mongodb://mocked_mongo_uri"})
    @patch("main.users_collection")
    def test_register_email_exists(self, mock_users_collection):
        test_data = {
            "full_name": "John Doe",
            "username": "johndoe",
            "email": "johndoe@example.com",
            "password": "securepassword123"
        }
        mock_users_collection.find_one.return_value = {"email": "johndoe@example.com"}
        response = self.client.post('/register', json=test_data)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Email already exists", response.json["message"])
        mock_users_collection.insert_one.assert_not_called()

    # USER login success
    @patch("main.users_collection")
    @patch("main.admin_collection")
    def test_user_login_success(self, mock_admin_collection, mock_users_collection):
        user_data = {
            "username": "johndoe",
            "password": "secure123"
        }

        mock_user = {
            "username": "johndoe",
            "email": "john@example.com",
            "password": bcrypt.generate_password_hash("secure123").decode('utf-8'),
            "status": "Active"
        }

        mock_users_collection.find_one.return_value = mock_user
        mock_admin_collection.find_one.return_value = None

        response = self.client.post("/login", json=user_data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["message"], "Login successful")
        self.assertEqual(response.json["role"], "User")
        self.assertIn("token", response.json)

    # USER login - account deactivated
    @patch("main.users_collection")
    @patch("main.admin_collection")
    def test_user_login_deactivated(self, mock_admin_collection, mock_users_collection):
        user_data = {
            "username": "johndoe",
            "password": "secure123"
        }

        mock_user = {
            "username": "johndoe",
            "email": "john@example.com",
            "password": bcrypt.generate_password_hash("secure123").decode('utf-8'),
            "status": "Deactivated"
}


        mock_users_collection.find_one.return_value = mock_user
        mock_admin_collection.find_one.return_value = None

        response = self.client.post("/login", json=user_data)
        self.assertEqual(response.status_code, 401)
        self.assertIn("deactivated", response.json["message"].lower())

    # ADMIN login success
    @patch("main.users_collection")
    @patch("main.admin_collection")
    def test_admin_login_success(self, mock_admin_collection, mock_users_collection):
        admin_data = {
            "username": "adminuser",
            "password": "adminpass"
        }

        mock_admin = {
            "username": "adminuser",
            "email": "admin@example.com",
            "password":  bcrypt.generate_password_hash("adminpass").decode('utf-8'),
        }

        mock_users_collection.find_one.return_value = None
        mock_admin_collection.find_one.return_value = mock_admin

        response = self.client.post("/login", json=admin_data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["message"], "Login successful")
        self.assertEqual(response.json["role"], "Admin")
        self.assertIn("token", response.json)

    # Invalid credentials
    @patch("main.users_collection")
    @patch("main.admin_collection")
    def test_login_invalid_credentials(self, mock_admin_collection, mock_users_collection):
        login_data = {
            "username": "unknownuser",
            "password": "wrongpass"
        }

        mock_users_collection.find_one.return_value = None
        mock_admin_collection.find_one.return_value = None

        response = self.client.post("/login", json=login_data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json["message"], "Invalid credentials")

# Run tests
if __name__ == '__main__':
    unittest.main()
