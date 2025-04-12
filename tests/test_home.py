import unittest
from main import app
from flask_testing import TestCase

class HomeTestCase(TestCase):
    def create_app(self):
        """Configure the Flask app for testing."""
        app.config['TESTING'] = True
        return app

    def test_home(self):
        """Test the home route."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome", response.data)

if __name__ == '__main__':
    unittest.main()
