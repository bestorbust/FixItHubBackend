from flask import Flask, request, jsonify , send_from_directory
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS , cross_origin
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
from bson import ObjectId
from geopy.distance import geodesic
import os
import requests
import time
# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = os.urandom(24)
jwt = JWTManager(app)
access_token = "pk.7717a7620b6c44435424f84074969fab"
# MongoDB Connection
# try:
#     client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
#     db = client["community_issue_platform"]
#     users_collection = db["users"]
#     issues_collection = db["issues"]
#     comments_collection = db["comments"]
#     admin_collection = db["admin"]
#     print(" Connected to MongoDB")

#     #  Add indexing for performance
#     users_collection.create_index("email", unique=True)
#     issues_collection.create_index("reported_at")
#     comments_collection.create_index("issue_id")

# except Exception as e:
#     print(f"MongoDB Connection Error: {str(e)}")

try:
    MONGO_URI = os.getenv("MONGO_URI")
    client = MongoClient(MONGO_URI)
    db = client["community_issue_platform"]
    users_collection = db["users"]
    issues_collection = db["issues"]
    comments_collection = db["comments"]
    admin_collection = db["admin"]
    print(" Connected to MongoDB Atlas!")

    # Add indexing for better performance
    users_collection.create_index("email", unique=True)
    issues_collection.create_index("reported_at")
    comments_collection.create_index("issue_id")

except Exception as e:
    print(f"MongoDB Connection Error: {str(e)}")

#  Ensure upload directory exists
UPLOAD_FOLDER = "uploads"
BASE_URL = "http://127.0.0.1:5000"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/uploads/<path:filename>')
def serve_image(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

#  Default Admin Setup
admin_email = "authority@gmail.com"
admin_password = bcrypt.generate_password_hash("authority").decode('utf-8')
if not admin_collection.find_one({"email": admin_email}):
    admin_collection.insert_one({"email": admin_email, "username": "admin", "password": admin_password, "role": "Admin"})
    print(" Default admin created")

def get_address_from_coordinates(lat, lon):
    """Fetch human-readable address from coordinates using LocationIQ API."""
    access_token = "pk.7717a7620b6c44435424f84074969fab"
    
    if not access_token:
        print(" ERROR: Missing LocationIQ API Key")
        return "API Key Missing"

    url = f"https://us1.locationiq.com/v1/reverse.php?key={access_token}&lat={lat}&lon={lon}&format=json"
    
    for attempt in range(3):  # Retry up to 3 times
        try:
            print(f"Requesting address for ({lat}, {lon})... Attempt {attempt+1}")
            response = requests.get(url, timeout=5)  # Set timeout
            if response.status_code == 200:
                data = response.json()
                print(f"Address Found: {data.get('display_name')}")
                return data.get("display_name", "Location not available")
            elif response.status_code == 429:  # Too many requests
                print("Rate limit exceeded. Retrying in 1 second...")
                time.sleep(1)
            else:
                print(f" ERROR: LocationIQ API returned {response.status_code} - {response.text}")
                break  # Stop retrying on other errors
        except requests.RequestException as e:
            print(f" ERROR: Network issue - {e}")
            break  # Stop retrying on network errors

    return "Location not available"

def parse_location(issue):
    """Parse and return either an address or coordinates converted to an address."""
    location = issue.get("location", {})

    # If 'location' is a string, assume it's an address and return as is
    if isinstance(location, str):
        return location

    # If 'location' is an object and has an address, return it directly
    if isinstance(location, dict):
        if "address" in location:
            return location["address"]

        # If location has latitude and longitude but no address, fetch it once and store
        if "latitude" in location and "longitude" in location:
            address = get_address_from_coordinates(location["latitude"], location["longitude"])

            # Update the issue in MongoDB with the fetched address (caching)
            issues_collection.update_one(
                {"_id": issue["_id"]},
                {"$set": {"location.address": address}}
            )

            return address

    return "Location not available"

@app.route('/api/latest-issues', methods=['GET'])
def get_latest_issues():
    """Fetch and return the latest reported issues with correct addresses."""
    try:
        latest_issues = list(issues_collection.find().sort("reported_at", -1).limit(10))

        for issue in latest_issues:
            issue["_id"] = str(issue["_id"])  # Convert ObjectId to string
            issue["location"] = parse_location(issue)  # Assign correct address

        return jsonify(latest_issues)
    
    except Exception as e:
        print("ERROR: Fetching issues failed:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/")
def home():
    return jsonify({"message": "Welcome to the API!"})

#  User Registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if users_collection.find_one({"email": data["email"]}):
            return jsonify({"message": "Email already exists"}), 400

        hashed_password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        user = {
            "full_name": data["full_name"],
            "username": data["username"],
            "email": data["email"],
            "password": hashed_password,
            "phone": data.get("phone", ""),
            "profile_pic": data.get("profile_pic", ""),
            "address": data.get("address", ""),
            "role": "User",
            "registered_at": datetime.utcnow()
        }
        users_collection.insert_one(user)
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#  User & Admin Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        user = users_collection.find_one({"$or": [{"username": data["username"]}, {"email": data["username"]}]})
        admin = admin_collection.find_one({"$or": [{"username": data["username"]}, {"email": data["username"]}]})

        if user and bcrypt.check_password_hash(user["password"], data["password"]):
            if user.get("status") =="Deactivated":
                return jsonify({"message": "Your account is deactivated"}), 401
            access_token = create_access_token(identity=user["email"])
            return jsonify({"message": "Login successful", "token": access_token, "role": "User","user_email":user["email"]}), 200
        if admin and bcrypt.check_password_hash(admin["password"], data["password"]):
            access_token = create_access_token(identity=admin["email"])
            return jsonify({"message": "Login successful", "token": access_token, "role": "Admin","user_email":admin["email"]}), 200
        return jsonify({"message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/report_issue', methods=['POST', 'OPTIONS'])
@jwt_required(optional=True)  # Optional for OPTIONS request to avoid auth error
def report_issue():
    if request.method == 'OPTIONS':
        response = jsonify({"message": "CORS Preflight OK"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        return response, 200  # Return a successful OPTIONS response

    try:
        # Handle POST request (your existing logic)
        current_user = get_jwt_identity()
        user = users_collection.find_one({"email": current_user})
        if not user:
            return jsonify({"message": "User not found"}), 404

        data = request.form
        files = request.files.getlist("images")

        required_fields = ["title", "description", "location", "category"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({"message": f"'{field}' is required"}), 400

        tags = request.form.getlist("tags")

        # Save images
        image_urls = []
        for file in files:
            if file:
                filename = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(filename)
                image_urls.append(filename)

        location_data = data["location"].strip()
        if "," in location_data:
            lat, lon = map(str.strip, location_data.split(","))
            address = get_address_from_coordinates(lat, lon)
            issue_location = {"latitude": float(lat), "longitude": float(lon), "address": address}
        else:
            issue_location = {"address": location_data}

        issue = {
            "user_email": current_user,
            "user_name": user.get("full_name", "Unknown") if not data.get("anonymous", False) else "Anonymous",
            "title": data["title"].strip(),
            "description": data["description"].strip(),
            "location": issue_location,
            "category": data["category"],
            "priority": data.get("priority", "Medium"),
            "tags": tags,
            "anonymous": data.get("anonymous") == "true",
            "images": image_urls,
            "status": "Pending",
            "reported_at": datetime.utcnow(),
            "votes": 0
        }

        result = issues_collection.insert_one(issue)
        return jsonify({"message": "Issue reported successfully", "issue_id": str(result.inserted_id)}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


#  View User's Reported Issues
@app.route('/my-issues', methods=['GET'])
@jwt_required()
def get_my_issues():
    try:
        current_user = get_jwt_identity()
        issues = list(issues_collection.find({"user_email": current_user}))

        for issue in issues:
            issue["_id"] = str(issue["_id"])
            issue["location"] = parse_location(issue)
        return jsonify(issues), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# Edit an Issue
@app.route('/edit_issue/<issue_id>', methods=['PUT'])
@jwt_required()
def edit_issue(issue_id):
    try:
        print(f"Received PUT request for issue ID: {issue_id}")
        data = request.json
        print("Incoming JSON data:", data)

        if not ObjectId.is_valid(issue_id):
            return jsonify({"message": "Invalid issue ID"}), 400

        current_user = get_jwt_identity()
        issue = issues_collection.find_one({"_id": ObjectId(issue_id), "user_email": current_user})

        if not issue:
            return jsonify({"message": "Issue not found or unauthorized"}), 404

        # Remove _id from the request data (MongoDB does not allow updating _id)
        if "_id" in data:
            del data["_id"]

        update_fields = {k: v for k, v in data.items() if v is not None and v != ""}

        if not update_fields:
            return jsonify({"message": "No valid fields to update"}), 400

        issues_collection.update_one({"_id": ObjectId(issue_id)}, {"$set": update_fields})
        return jsonify({"message": "Issue updated successfully"}), 200

    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route('/delete_issue/<issue_id>', methods=['DELETE'])
@jwt_required()
def delete_issue(issue_id):
    try:
        current_user = get_jwt_identity()

        try:
            obj_id = ObjectId(issue_id)
        except Exception as e:
            print(f"Invalid ObjectId conversion: {e}")  # Debug log
            return jsonify({"message": "Invalid issue ID"}), 400

        # Fetch the user role
        user = users_collection.find_one({"email": current_user})

        if not user:
            user = admin_collection.find_one({"email":current_user})

        if not user:
            print("User not found in database.")  # Debug log
            return jsonify({"message": "User not found"}), 404
        
        user_role = user.get("role", "User")  # Default role is "User"
        print(f"Current User: {current_user}, Role: {user_role}")  # Debug log

        # If user is Admin, allow deleting any issue
        issue = issues_collection.find_one({"_id": obj_id})
        print(f"Checking issue with ID: {issue_id} | Found: {issue}")  # Debug log

        if not issue:
            return jsonify({"message": "Issue not found"}), 404

        # Allow Admins to delete any issue
        if user_role == "Admin":
            issues_collection.delete_one({"_id": obj_id})
            print(f"Admin deleted issue: {issue_id}")  # Debug log
            return jsonify({"message": "Issue deleted successfully by Admin"}), 200

        # Allow Users to delete only their own issue
        if issue["user_email"] != current_user:
            return jsonify({"message": "Unauthorized to delete this issue"}), 403

        issues_collection.delete_one({"_id": obj_id})
        print(f"User deleted issue: {issue_id}")  # Debug log
        return jsonify({"message": "Issue deleted successfully"}), 200

    except Exception as e:
        print(f"Exception occurred: {str(e)}")  # Debug log
        return jsonify({"error": str(e)}), 500

# View All Issues
@app.route('/issues', methods=['GET'])
def get_issues():
    try:
        issues = list(issues_collection.find({}, {"_id": 1, "title": 1, "description": 1, "category": 1, "location": 1, "status": 1, "votes": 1,"images":1,"user_email":1}))
        for issue in issues:
            issue["_id"] = str(issue["_id"])
            issue["votes"] = issue.get("votes", 0)

            issue["reported_by"] = issue.get("user_email", "Unknown")
            
            try:
                issue["location"] = parse_location(issue)  # Safe location parsing
            except Exception as e:
                print(f"❌ Location Parsing Error: {e}")
                issue["location"] = "Location not available"

            if "images" in issue and isinstance(issue["images"], list):
                issue["images"] = [
                    f"http://127.0.0.1:5000/{img.replace(os.sep, '/')}" for img in issue["images"]
                    # f"http://127.0.0.1:5000/{img.replace('\\', '/')}" for img in issue["images"]
                ]
            else:
                issue["images"] = []

        return jsonify(issues), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/issues/<issue_id>/vote', methods=['POST', 'OPTIONS'])
@cross_origin()
# @app.route('/issues/<issue_id>/vote', methods=['POST'])
def vote_issue(issue_id):
    try:
        data = request.json
        vote_type = data.get("voteType")  # 'upvote' or 'downvote'

        if vote_type not in ["upvote", "downvote"]:
            return jsonify({"error": "Invalid vote type"}), 400

        issue = issues_collection.find_one({"_id": ObjectId(issue_id)})
        if not issue:
            return jsonify({"error": "Issue not found"}), 404

        # Update votes count
        if vote_type == "upvote":
            new_votes = issue.get("votes", 0) + 1
        else:
            new_votes = issue.get("votes", 0) - 1

        # Save updated votes
        issues_collection.update_one(
            {"_id": ObjectId(issue_id)},
            {"$set": {"votes": new_votes}}
        )

        return jsonify({"message": "Vote recorded", "votes": new_votes}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Add Comment to an Issue
@app.route('/comment', methods=['POST'])
@jwt_required()
def add_comment():
    try:
        data = request.json
        current_user = get_jwt_identity()
        issue = issues_collection.find_one({"_id": ObjectId(data["issue_id"])})

        if not issue:
            return jsonify({"message": "Issue not found"}), 404

        comment = {
            "issue_id": ObjectId(data["issue_id"]),
            "user_email": current_user,
            "comment": data["comment"],
            "timestamp": datetime.utcnow()
        }
        comments_collection.insert_one(comment)
        return jsonify({"message": "Comment added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get Comments for an Issue
@app.route('/comments/<issue_id>', methods=['GET'])
def get_comments(issue_id):
    try:
        comments = list(comments_collection.find({"issue_id": ObjectId(issue_id)}, {"_id": 1, "user_email": 1, "comment": 1, "timestamp": 1}))
        for comment in comments:
            comment["_id"] = str(comment["_id"])
        return jsonify(comments), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Delete a Comment
@app.route('/delete_comment/<comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(comment_id):
    try:
        current_user = get_jwt_identity()
        comment = comments_collection.find_one({"_id": ObjectId(comment_id), "user_email": current_user})
        if not comment:
            return jsonify({"message": "Comment not found or unauthorized"}), 404

        comments_collection.delete_one({"_id": ObjectId(comment_id)})
        return jsonify({"message": "Comment deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user/profile', methods=['GET', 'PUT'])
@jwt_required()
def user_profile():
    current_user = get_jwt_identity()
    user = users_collection.find_one({"email": current_user})

    if not user:
        return jsonify({"message": "User not found"}), 404
    
    if "profile_pic" in user and user["profile_pic"]:
        filename = os.path.basename(user["profile_pic"])
        user["profile_pic"] = f"http://127.0.0.1:5000/uploads/{filename}"
    else:
        user["profile_pic"] = "" 


    if request.method == 'GET':
        user.pop("_id", None)
        user.pop("password", None)
        return jsonify(user), 200

    elif request.method == 'PUT':
        data = request.form.to_dict()
        profile_pic_url = user.get("profile_pic", "")

        # Handle profile picture upload
        if "profile_pic" in request.files:
            file = request.files["profile_pic"]
            if file.filename:
                filename = f"{current_user}_{file.filename}"
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                profile_pic_url = f"/profile_pics/{filename}"  # Return relative URL

        update_data = {
            "full_name": data.get("full_name", user.get("full_name")),
            "username": data.get("username", user.get("username")),
            "phone": data.get("phone", user.get("phone")),
            "address": data.get("address", user.get("address")),
            "bio": data.get("bio", user.get("bio", "")),
            "gender": data.get("gender", user.get("gender", "")),
            "dob": data.get("dob", user.get("dob", "")),
            "occupation": data.get("occupation", user.get("occupation", "")),
            "social_links": data.get("social_links", user.get("social_links", [])),
            "profile_pic": profile_pic_url,
            "notifications": user.get("notifications", [])
        }

        users_collection.update_one({"email": current_user}, {"$set": update_data})
        return jsonify({"message": "Profile updated successfully", "profile_pic": profile_pic_url}), 200


@app.route('/admin/profile', methods=['GET', 'PUT'])
@jwt_required()
def admin_profile():
    current_admin = get_jwt_identity()
    admin = admin_collection.find_one({"email": current_admin})

    if not admin:
        return jsonify({"message": "Admin not found"}), 404

    # Convert profile_pic to full URL
    if "profile_pic" in admin and admin["profile_pic"]:
        filename = os.path.basename(admin["profile_pic"])
        admin["profile_pic"] = f"http://127.0.0.1:5000/uploads/{filename}"
    else:
        admin["profile_pic"] = ""  # Return empty if no profile pic exists

    if request.method == 'GET':
        admin.pop("_id", None)
        admin.pop("password", None)
        return jsonify(admin), 200

    elif request.method == 'PUT':
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename:
                filename = f"{current_admin}_{file.filename}"
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                profile_pic_url = f"http://127.0.0.1:5000/uploads/{filename}"
            else:
                profile_pic_url = admin.get("profile_pic", "")
        else:
            profile_pic_url = admin.get("profile_pic", "")

        data = request.form.to_dict()

        update_data = {
            "full_name": data.get("full_name", admin.get("full_name")),
            "username": data.get("username", admin.get("username")),
            "phone": data.get("phone", admin.get("phone")),
            "address": data.get("address", admin.get("address")),
            "bio": data.get("bio", admin.get("bio", "")),
            "profile_pic": profile_pic_url
        }

        admin_collection.update_one({"email": current_admin}, {"$set": update_data})

        return jsonify({"message": "Admin Profile updated successfully", "profile_pic": profile_pic_url}), 200

def get_admin_dashboard_data():
    try:
        total_issues = issues_collection.count_documents({})
        resolved_issues = issues_collection.count_documents({"status": {"$regex": "Resolved", "$options": "i"}})
        active_users = users_collection.count_documents({"role": "User"})  # Ensure role-based count

        print(f"Total Issues: {total_issues}, Resolved Issues: {resolved_issues}, Active Users: {active_users}")

        return {
            "total_issues": total_issues,
            "resolved_issues": resolved_issues,
            "active_users": active_users
        }
    except Exception as e:
        print("Error fetching admin dashboard data:", str(e))
        return {"total_issues": 0, "resolved_issues": 0, "active_users": 0}



@app.route('/admin/dashboard',methods=['GET'])
def admin_dashboard():
    try:
        data=get_admin_dashboard_data()
        return jsonify(data),200
    except Exception as e:
        return jsonify({"message":str(e)}),500

@app.route('/admin/issues/<issue_id>', methods=['PUT'])
def update_issue_status(issue_id):
    try:
        data = request.json
        new_status = data.get("status")

        if new_status not in ["Pending", "In Progress", "Resolved"]:
            return jsonify({"success": False, "error": "Invalid status"}), 400

        obj_id = ObjectId(issue_id)  # Convert to ObjectId
        result = issues_collection.update_one({"_id": obj_id}, {"$set": {"status": new_status}})
        
        if result.modified_count == 1:
            return jsonify({"success": True, "message": "Issue status updated"}), 200
        return jsonify({"success": False, "message": "Issue not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500    

@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """Fetch all users except admins"""
    current_user = get_jwt_identity()

    # Check if the current user is an admin
    admin = admin_collection.find_one({"email": current_user})
    if not admin:
        return jsonify({"message": "Unauthorized access"}), 403

    users = list(users_collection.find({}, {"_id": 0, "password": 0}))  # Exclude sensitive info
    return jsonify({"users": users}), 200

from datetime import datetime, timezone

@app.route('/admin/warn_user/<email>', methods=['POST'])
@jwt_required()
def warn_user(email):
    """Warn a user and notify them"""
    current_admin = get_jwt_identity()

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    warning_message = request.json.get("message", "You have received a warning from the admin.")

    current_warnings = int(user.get("warnings", 0)) if "warnings" in user else 0
    new_warnings = current_warnings + 1  

    # Create the warning notification
    warning_data = {
        "message": warning_message,
        "timestamp": datetime.now(timezone.utc),  # 🔥 Fix deprecated `utcnow()`
        "admin": current_admin,
        "seen": False  # Mark as unseen initially
    }

    # Update user document in MongoDB
    result = users_collection.update_one(
        {"email": email},
        {
            "$set": {"warnings": new_warnings},  # Ensure warnings are updated as an integer
            "$push": {"notifications": warning_data}  # Append new warning notification
        },
        upsert=True
    )

    # Check if the update was successful
    if result.modified_count == 0 and not result.upserted_id:
        return jsonify({"message": "Warning update failed. Check database connection."}), 500

    return jsonify({
        "message": f"User {email} has been warned.",
        "warnings": new_warnings
    }), 200

@app.route('/user/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    """Retrieve user notifications"""
    current_user = get_jwt_identity()
    user = users_collection.find_one({"email": current_user}, {"notifications": 1})

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"notifications": user.get("notifications", [])}), 200

@app.route('/admin/deactivate_user/<email>', methods=['POST'])
@jwt_required()
def deactivate_user(email):
    """Deactivate a user (prevent login)"""
    current_user = get_jwt_identity()

    # Ensure only admins can deactivate users
    admin = admin_collection.find_one({"email": current_user})
    if not admin:
        return jsonify({"message": "Unauthorized"}), 403

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    users_collection.update_one({"email": email}, {"$set": {"status": "Deactivated"}})

    return jsonify({"message": f"User {email} has been deactivated."}), 200

@app.route('/admin/activate_user/<email>', methods=['POST'])
@jwt_required()
def activate_user(email):
    """Activate a deactivated user"""
    current_user = get_jwt_identity()

    # Ensure only admins can activate users
    admin = admin_collection.find_one({"email": current_user})
    if not admin:
        return jsonify({"message": "Unauthorized"}), 403

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Check if the user is already active
    if user.get("status") == "Active":
        return jsonify({"message": "User is already active"}), 400

    users_collection.update_one({"email": email}, {"$set": {"status": "Active"}})

    return jsonify({"message": f"User {email} has been activated."}), 200

if __name__ == '__main__':
    app.run(debug=True)
