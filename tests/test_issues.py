import unittest
from unittest.mock import patch
from main import app, db, users_collection, issues_collection
from flask_jwt_extended import create_access_token
from flask_testing import TestCase
from bson import ObjectId
from datetime import datetime, timezone


class TestIssues(TestCase):
    def create_app(self):
        app.config["TESTING"] = True
        return app

    def setUp(self):
        # Create a mock user and issue
        self.test_email = "testuser@example.com"
        self.access_token = create_access_token(identity=self.test_email)
        self.auth_header = {"Authorization": f"Bearer {self.access_token}"}

        users_collection.insert_one({
            "email": self.test_email,
            "full_name": "Test User",
            "role": "User"
        })

        self.issue_id = issues_collection.insert_one({
            "user_email": self.test_email,
            "title": "Test Issue",
            "description": "A test issue",
            "location": {"latitude": 0.0, "longitude": 0.0},
            "category": "Road",
            "status": "Closed",
            "reported_at": datetime.now(timezone.utc)
        }).inserted_id

    def tearDown(self):
        users_collection.delete_many({})
        issues_collection.delete_many({})

    @patch("main.get_address_from_coordinates", return_value="Mocked Address")
    def test_get_my_issues(self, mocked_address):
        response = self.client.get("/my-issues", headers=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(len(response.json) > 0)
        self.assertEqual(response.json[0]["location"], "Mocked Address")

    def test_reopen_issue(self):
        response = self.client.patch(f"/reopen_issue/{self.issue_id}", headers=self.auth_header)
        self.assertEqual(response.status_code, 200)
        updated_issue = issues_collection.find_one({"_id": self.issue_id})
        self.assertEqual(updated_issue["status"], "Pending")

    def test_edit_issue(self):
        update_data = {"title": "Updated Title"}
        response = self.client.put(
            f"/edit_issue/{self.issue_id}",
            json=update_data,
            headers=self.auth_header
        )
        self.assertEqual(response.status_code, 200)
        updated_issue = issues_collection.find_one({"_id": self.issue_id})
        self.assertEqual(updated_issue["title"], "Updated Title")

    def test_delete_issue(self):
        response = self.client.delete(f"/delete_issue/{self.issue_id}", headers=self.auth_header)
        self.assertEqual(response.status_code, 200)
        deleted_issue = issues_collection.find_one({"_id": self.issue_id})
        self.assertIsNone(deleted_issue)

    @patch("main.get_address_from_coordinates", return_value="Global Location")
    def test_get_all_issues(self, mocked_address):
        response = self.client.get("/issues")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(i["_id"] == str(self.issue_id) for i in response.json))


if __name__ == "__main__":
    unittest.main()
