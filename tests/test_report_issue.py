import io
import unittest
from unittest.mock import patch, MagicMock
from flask_testing import TestCase
from main import app, users_collection, issues_collection


class ReportIssueTestCase(TestCase):
    def create_app(self):
        app.config["TESTING"] = True
        return app

    @patch("main.get_jwt_identity")
    @patch.object(users_collection, "find_one")
    @patch("main.cloudinary.uploader.upload")
    @patch("main.get_address_from_coordinates")
    @patch.object(issues_collection, "insert_one")
    def test_report_issue_success(
        self,
        mock_insert,
        mock_get_address,
        mock_upload,
        mock_find_user,
        mock_identity
    ):
        mock_identity.return_value = "test@example.com"
        mock_find_user.return_value = {
            "email": "test@example.com",
            "full_name": "Test User"
        }
        mock_upload.return_value = {"secure_url": "http://image.url/test.jpg"}
        mock_get_address.return_value = "New Delhi, India"
        mock_insert.return_value = MagicMock(inserted_id="12345")

        data = {
            "title": "Test Issue",
            "description": "This is a test issue",
            "location": "28.644800, 77.216721",
            "category": "Infrastructure",
            "priority": "High",
            "tags": "pothole",
            "anonymous": "false"
        }

        response = self.client.post(
            "/report_issue",
            data={
                **data,
                "images": (io.BytesIO(b"fake image data"), "test.jpg")
            },
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 201)
        self.assertIn(b"Issue reported successfully", response.data)

    @patch("main.get_jwt_identity")
    @patch.object(users_collection, "find_one")
    def test_report_issue_missing_field(self, mock_find_user, mock_identity):
        mock_identity.return_value = "test@example.com"
        mock_find_user.return_value = {
            "email": "test@example.com",
            "full_name": "Test User"
        }

        data = {
            # Title is missing
            "description": "Missing title",
            "location": "28.644800, 77.216721",
            "category": "Road"
        }

        response = self.client.post(
            "/report_issue",
            data=data,
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"'title' is required", response.data)

    @patch("main.get_jwt_identity")
    @patch.object(users_collection, "find_one", return_value=None)
    def test_report_issue_user_not_found(self, mock_find_user, mock_identity):
        mock_identity.return_value = "nonexistent@example.com"

        data = {
            "title": "Test",
            "description": "Desc",
            "location": "Loc",
            "category": "General"
        }

        response = self.client.post(
            "/report_issue",
            data=data,
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"User not found", response.data)

    def test_report_issue_options_preflight(self):
        response = self.client.options("/report_issue")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CORS Preflight OK", response.data)


if __name__ == "__main__":
    unittest.main()
