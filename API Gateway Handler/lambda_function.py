import json
import boto3
import os
import bcrypt
import jwt
import datetime

# --- Configuration (Environment Variables) ---
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "board-users")
JWT_SECRET = os.environ.get("JWT_SECRET", "your-default-secret-key")
REGION_NAME = os.environ.get("AWS_REGION", "us-east-1")

# --- DynamoDB Client ---
dynamodb = boto3.resource("dynamodb", region_name=REGION_NAME)
table = dynamodb.Table(DYNAMODB_TABLE)

# --- Helper Functions ---

def build_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json"
        },
        "body": json.dumps(body)
    }

def generate_jwt(user_data):
    payload = {
        'username': user_data['username'],
        'email': user_data.get('email'),
        'name': user_data.get('name'),
        'department': user_data.get('department'),
        'role': user_data.get('role'),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        return None
    except jwt.InvalidSignatureError:
        print("Invalid token signature.")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during token verification: {e}")
        return None
# --- Route Handlers ---

def register_user(event):
    try:
        body = json.loads(event["body"])
        username = body.get("username")
        email = body.get("email")
        name = body.get("name")
        password = body.get("password")
        department = body.get("department")
        role = body.get("role")

        if not all([username, email, name, password]):
            return build_response(400, {"error": "Missing required fields"})

        response = table.get_item(Key={"username": username})
        if "Item" in response:
            return build_response(409, {"error": "User already exists"})

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        table.put_item(
            Item={
                "username": username,
                "email": email,
                "name": name,
                "password": hashed_password,
                "department": department,
                "role": role
            }
        )
        return build_response(201, {"message": "User registered successfully"})

    except Exception as e:
        print(f"Registration error: {e}")
        return build_response(500, {"error": "Internal Server Error", "details": str(e)})

def login_user(event):
    try:
        body = json.loads(event["body"])
        username = body.get("username")
        password = body.get("password")

        if not username or not password:
            return build_response(400, {"error": "Missing username or password"})

        response = table.get_item(Key={"username": username})
        user_data = response.get("Item")

        if not user_data:
            return build_response(401, {"error": "Invalid credentials"})

        if bcrypt.checkpw(password.encode("utf-8"), user_data["password"].encode("utf-8")):
            token = generate_jwt(user_data)
            return build_response(200, {"token": token})
        else:
            return build_response(401, {"error": "Invalid credentials"})

    except Exception as e:
        print(f"Login error: {e}")
        return build_response(500, {"error": "Internal Server Error", "details": str(e)})

def verify_token_handler(event):
    """Handles the /verify endpoint to verify a token."""
    try:
        body = json.loads(event["body"])
        token = body.get("token")

        if not token:
            return build_response(400, {"error": "Missing token"})

        user_data = verify_jwt(token)

        if not user_data:
            return build_response(401, {"error": "Invalid or expired token"})

        return build_response(200, {"message": "Token is valid", "user": user_data})

    except Exception as e:
        print(f"Token verification error: {e}")
        return build_response(500, {"error": "Internal Server Error", "details": str(e)})

# --- Main Lambda Handler ---

def lambda_handler(event, context):
    """
    Main entry point for the Lambda function. Routes requests based on path and method.
    """
    health_path = "/health"
    register_path = "/register"
    login_path = "/login"
    verify_path = "/verify"

    http_method = event.get("httpMethod")
    path = event.get("path")
    print(f"Received event: {event}")

    if http_method == "GET" and path == health_path:
        return build_response(200, "Health Check OK")
    elif http_method == "POST" and path == register_path:
        return register_user(event)
    elif http_method == "POST" and path == login_path:
        return login_user(event)
    elif http_method == "POST" and path == verify_path:
        return verify_token_handler(event)
    else:
        return build_response(404, "404 Not Found")