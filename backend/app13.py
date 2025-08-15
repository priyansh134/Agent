from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
import duckdb
import pandas as pd
import os
import google.generativeai as genai
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
from cloudinary.utils import cloudinary_url
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from bson import ObjectId
import pymysql

# Load environment variables from .env file
load_dotenv()

# Configuration variables
google_api_key = os.getenv("GOOGLE_API_KEY")
cloudinary_cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME")
cloudinary_api_key = os.getenv("CLOUDINARY_API_KEY")
cloudinary_api_secret = os.getenv("CLOUDINARY_API_SECRET")

mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
print(mongodb_uri)
jwt_secret = os.getenv("JWT_SECRET", "your-secret-key-change-this")
database_name = "dashboard_agent"

# Cloudinary configuration
cloudinary.config(
    cloud_name=cloudinary_cloud_name,
    api_key=cloudinary_api_key,
    api_secret=cloudinary_api_secret,
    secure=True
)

# MongoDB connection
try:
    client = MongoClient(mongodb_uri)
    db = client[database_name]
    users_collection = db.users
    conversations_collection = db.conversations
    print("✅ Connected to MongoDB successfully")
except Exception as e:
    print(f"❌ Error connecting to MongoDB: {e}")
    db = None

# Initialize Flask app
app = Flask(__name__)

# Enable Cross-Origin Resource Sharing (CORS) for all routes
cors = CORS(app, origins="*")

# Ensure Authorization header is allowed for CORS preflight
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# JWT Token validation decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
            
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
            
        return f(current_user_id, *args, **kwargs)
    return decorated

# Health check route
@app.route('/', methods=['GET'])
def home():
    """
    Basic health check endpoint to confirm the server is operational.
    """
    return jsonify({"message": "Dashboard Agent API running successfully"})

# User Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user with email and password.
    """
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
        
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"{field} is required"}), 400
        
        name = data['name'].strip()
        email = data['email'].strip().lower()
        password = data['password']
        
        # Basic validation
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400
            
        if '@' not in email or '.' not in email:
            return jsonify({"error": "Please provide a valid email address"}), 400
        
        # Check if user already exists
        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            return jsonify({"error": "User with this email already exists"}), 400
        
        # Hash password
        hashed_password = generate_password_hash(password)
        
        # Create user document
        user_doc = {
            "name": name,
            "email": email,
            "password": hashed_password,
            "auth_method": "email",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "profile": {
                "firstName": name.split()[0] if name.split() else name,
                "lastName": " ".join(name.split()[1:]) if len(name.split()) > 1 else "",
                "picture": None
            }
        }
        
        # Insert user into database
        result = users_collection.insert_one(user_doc)
        user_id = str(result.inserted_id)
        
        # Generate JWT token
        token_payload = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "exp": datetime.utcnow() + timedelta(days=30)
        }
        
        token = jwt.encode(token_payload, jwt_secret, algorithm="HS256")
        
        # Return user data (excluding password)
        user_response = {
            "id": user_id,
            "name": name,
            "firstName": user_doc["profile"]["firstName"],
            "lastName": user_doc["profile"]["lastName"],
            "email": email,
            "picture": None,
            "auth_method": "email",
            "loginTime": datetime.utcnow().isoformat()
        }
        
        return jsonify({
            "message": "User registered successfully",
            "user": user_response,
            "token": token
        }), 201
        
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

# User Login endpoint
@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate user with email and password.
    """
    print("-----------------------------------------------------------------------------------------------------")
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
        
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('email') or not data.get('password'):
            return jsonify({"error": "Email and password are required"}), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        
        # Find user in database
        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Check password
        if not check_password_hash(user['password'], password):
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Update last login
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"updated_at": datetime.utcnow()}}
        )
        
        # Generate JWT token
        token_payload = {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "name": user["name"],
            "exp": datetime.utcnow() + timedelta(days=30)
        }
        
        token = jwt.encode(token_payload, jwt_secret, algorithm="HS256")
        
        # Return user data (excluding password)
        user_response = {
            "id": str(user["_id"]),
            "name": user["name"],
            "firstName": user["profile"]["firstName"],
            "lastName": user["profile"]["lastName"],
            "email": user["email"],
            "picture": user["profile"].get("picture"),
            "auth_method": user.get("auth_method", "email"),
            "loginTime": datetime.utcnow().isoformat()
        }
        
        return jsonify({
            "message": "Login successful",
            "user": user_response,
            "token": token
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

# Google OAuth user registration/login
@app.route('/auth/google', methods=['POST'])
def google_auth():
    """
    Handle Google OAuth authentication and store user data.
    """

    print("-----------------------------------------------------------------------------------------------------")
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
        
    try:
        data = request.get_json()
        google_token = data.get('google_token')
        
        if not google_token:
            return jsonify({"error": "Google token is required"}), 400
        
        # Here you would typically verify the Google token
        # For now, we'll assume the frontend has already verified it
        user_data = data.get('user_data')
        
        if not user_data:
            return jsonify({"error": "User data is required"}), 400
        
        email = user_data.get('email', '').lower()
        google_id = user_data.get('id')
        
        # Check if user exists
        existing_user = users_collection.find_one({
            "$or": [
                {"email": email},
                {"google_id": google_id}
            ]
        })
        
        if existing_user:
            # Update existing user
            users_collection.update_one(
                {"_id": existing_user["_id"]},
                {
                    "$set": {
                        "updated_at": datetime.utcnow(),
                        "google_id": google_id,
                        "profile.picture": user_data.get('picture')
                    }
                }
            )
            user_id = str(existing_user["_id"])
        else:
            # Create new user
            user_doc = {
                "name": user_data.get('name', ''),
                "email": email,
                "google_id": google_id,
                "auth_method": "google",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "profile": {
                    "firstName": user_data.get('given_name', ''),
                    "lastName": user_data.get('family_name', ''),
                    "picture": user_data.get('picture')
                }
            }
            
            result = users_collection.insert_one(user_doc)
            user_id = str(result.inserted_id)
        
        # Generate JWT token
        token_payload = {
            "user_id": user_id,
            "email": email,
            "name": user_data.get('name', ''),
            "exp": datetime.utcnow() + timedelta(days=30)
        }
        
        token = jwt.encode(token_payload, jwt_secret, algorithm="HS256")
        
        # Return user data
        user_response = {
            "id": user_id,
            "name": user_data.get('name', ''),
            "firstName": user_data.get('given_name', ''),
            "lastName": user_data.get('family_name', ''),
            "email": email,
            "picture": user_data.get('picture'),
            "auth_method": "google",
            "loginTime": datetime.utcnow().isoformat()
        }
        
        return jsonify({
            "message": "Google authentication successful",
            "user": user_response,
            "token": token
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Google authentication failed: {str(e)}"}), 500

# Get user profile (protected route)
@app.route('/user/profile', methods=['GET'])
@token_required
def get_profile(current_user_id):
    """
    Get current user profile information.
    """
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
        
    try:
        user = users_collection.find_one({"_id": ObjectId(current_user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        user_response = {
            "id": str(user["_id"]),
            "name": user["name"],
            "firstName": user["profile"]["firstName"],
            "lastName": user["profile"]["lastName"],
            "email": user["email"],
            "picture": user["profile"].get("picture"),
            "auth_method": user.get("auth_method", "email"),
            "created_at": user["created_at"].isoformat(),
            "updated_at": user["updated_at"].isoformat()
        }
        
        return jsonify({"user": user_response}), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to get profile: {str(e)}"}), 500

# Route for uploading files to Cloudinary
@app.route('/upload_file', methods=['POST'])
def upload_file():
    """
    Uploads files to Cloudinary as raw resources and provides the public URL of the uploaded file.
    """
    # Check if the file is present in the request
    if 'file' not in request.files:
        return jsonify({"error": "No file provided."}), 400

    csv_file = request.files['file']
    # Check if the user has selected a file
    if csv_file.filename == '':
        return jsonify({"error": "No selected file."}), 400

    try:
        # Upload the file to Cloudinary
        upload_result = cloudinary.uploader.upload(
            csv_file,
            resource_type="raw",
            public_id=csv_file.filename.split('.')[0]
        )
        # Return success message and file URL
        return jsonify({"message": "File uploaded successfully!", "filePath": upload_result["secure_url"]}), 200
    except Exception as e:
        # Handle errors during the upload process
        return jsonify({"error": f"Error uploading to Cloudinary: {str(e)}"}), 500

# ==========================
# MySQL integration
# ==========================

def get_mysql_connection(params):
    return pymysql.connect(
        host=params.get('host'),
        port=int(params.get('port', 3306)),
        user=params.get('user'),
        password=params.get('password'),
        database=params.get('database'),
        cursorclass=pymysql.cursors.Cursor,
        charset='utf8mb4',
        autocommit=True
    )

@app.route('/db/schema', methods=['POST'])
@token_required
def mysql_schema(current_user_id):
    payload = request.get_json() or {}
    required = ['host', 'port', 'user', 'password', 'database', 'table']
    missing = [k for k in required if not payload.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    # Attempt connection with clear error surfaced
    try:
        conn = get_mysql_connection(payload)
    except Exception as conn_err:
        return jsonify({"error": f"Connection failed: {str(conn_err)}"}), 400
    try:
        columns = []
        sample_rows = []
        headers = []
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
                ORDER BY ORDINAL_POSITION
                """,
                (payload['database'], payload['table'])
            )
            cols_info = cur.fetchall()  # tuples
            # If table not found, cols_info will be empty
            if cols_info is None:
                cols_info = []
            for col in cols_info:
                col_name = col[0]
                data_type = col[1]
                is_nullable = col[2]
                columns.append({
                    "name": col_name,
                    "type": data_type,
                    "non_null_count": None,
                    "null_count": None,
                    "unique_values": None,
                    "data_category": "numeric" if str(data_type).lower() in ("int","bigint","tinyint","smallint","mediumint","decimal","float","double") else ("datetime" if str(data_type).lower() in ("date","datetime","timestamp","time","year") else "text/categorical")
                })
            # Attempt a sample read
            try:
                cur.execute(f"SELECT * FROM `{payload['database']}`.`{payload['table']}` LIMIT 200")
                sample_rows = cur.fetchall() or []
                headers = [desc[0] for desc in cur.description] if cur.description else []
            except Exception as sample_err:
                # Provide hint if table might not exist
                sample_rows = []
                headers = [c[0] for c in cols_info] if cols_info else []
        # Build response
        if headers and sample_rows:
            df = pd.DataFrame(list(sample_rows), columns=headers)
            schema_info = get_schema_info(df)
        else:
            schema_info = {"columns": columns, "total_rows": len(sample_rows), "sample_data": []}
        schema_info['table_name'] = payload['table']
        # If still no columns, return explicit message
        if not schema_info['columns']:
            return jsonify({"error": f"No columns found. Check database '{payload['database']}' and table '{payload['table']}' exist and permissions allow access."}), 404
        return jsonify({"schema": schema_info}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch schema: {str(e)}"}), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass

def create_mysql_prompt(text_input, schema_info):
    schema_text = "TABLE SCHEMA (MySQL):\n"
    schema_text += f"Table Name: {schema_info.get('table_name','target_table')}\n"
    schema_text += f"Total Rows (sampled): {schema_info['total_rows']}\n\n"
    schema_text += "COLUMNS:\n"
    for col in schema_info['columns']:
        schema_text += f"- {col['name']} ({col['type']}, {col['data_category']})\n"
        schema_text += f"  Non-null: {col['non_null_count']}, Unique values: {col['unique_values']}\n"
        if col['data_category'] == 'text/categorical' and 'sample_values' in col:
            schema_text += f"  Sample values: {col['sample_values']}\n"
        elif col['data_category'] == 'numeric' and 'min_value' in col:
            schema_text += f"  Range: {col['min_value']} to {col['max_value']}, Average: {col['mean_value']}\n"
        elif col['data_category'] == 'datetime' and 'min_date' in col:
            schema_text += f"  Date range: {col['min_date']} to {col['max_date']}\n"
        schema_text += "\n"
    schema_text += "SAMPLE DATA (first 3 rows):\n"
    for i, row in enumerate(schema_info['sample_data'], 1):
        schema_text += f"Row {i}: {row}\n"
    prompt = f"""You are a SQL expert specializing in MySQL queries. Generate a precise MySQL SQL query based on the user request and schema information.

USER REQUEST: "{text_input}"

{schema_text}

INSTRUCTIONS:
1. Generate ONLY a valid MySQL SQL query - no explanations, comments, or additional text
2. Use table name: `{schema_info.get('table_name','target_table')}`
3. Keep column names EXACTLY as shown in schema; use backticks around identifiers when needed
4. Use appropriate aggregate functions (SUM, AVG, COUNT, MAX, MIN) and GROUP BY when requested
5. For filtering operations, use appropriate WHERE clauses based on data types
6. For date/time operations, use MySQL functions (DATE, YEAR, MONTH, etc.)
7. For text searches, use LIKE (case-insensitive via LOWER if needed)
8. Optimize for performance; include LIMIT if showing samples

QUERY ONLY (no other text):"""
    return prompt

@app.route('/generate_sql_mysql', methods=['POST'])
@token_required
def generate_sql_mysql(current_user_id):
    if not google_api_key:
        return jsonify({"error": "Google API key is not configured."}), 500
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    data = request.get_json() or {}
    required = ['text', 'host', 'port', 'user', 'password', 'database', 'table']
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    # Connection test first
    try:
        test_conn = get_mysql_connection(data)
        test_conn.close()
    except Exception as conn_err:
        return jsonify({"error": f"Connection failed: {str(conn_err)}"}), 400

    try:
        conn = get_mysql_connection(data)
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM `{data['database']}`.`{data['table']}` LIMIT 200")
            rows = cur.fetchall() or []
            headers = [desc[0] for desc in cur.description] if cur.description else []
        conn.close()
        if headers and rows:
            df = pd.DataFrame(list(rows), columns=headers)
            schema_info = get_schema_info(df)
        else:
            schema_info = {"columns": [], "total_rows": 0, "sample_data": []}
        schema_info['table_name'] = data['table']
    except Exception as e:
        return jsonify({"error": f"Error reading table sample: {str(e)}"}), 400

    try:
        prompt = create_mysql_prompt(data['text'], schema_info)
        response = model.generate_content(prompt)
        sql_query = response.text.strip()
    except Exception as e:
        return jsonify({"error": f"Error generating SQL: {str(e)}"}), 500

    sql_query = sql_query.replace("```sql", "").replace("```", "").strip()
    if sql_query.lower().startswith("sql:"):
        sql_query = sql_query[4:].strip()
    if sql_query.lower().startswith("query:"):
        sql_query = sql_query[6:].strip()

    # Execute against MySQL
    try:
        conn = get_mysql_connection(data)
        with conn.cursor() as cur:
            cur.execute(sql_query)
            result_rows = cur.fetchall() or []
            headers = [desc[0] for desc in cur.description] if cur.description else []
        conn.close()
        output_df = pd.DataFrame(list(result_rows), columns=headers)
        csv_data = output_df.to_csv(index=False)
        return Response(csv_data, mimetype='text/csv', headers={"Content-Disposition": "attachment; filename=output.csv"})
    except Exception as e:
        return jsonify({"error": f"Error executing SQL: {str(e)}", "generated_query": sql_query}), 400

# ==========================
# Conversation History APIs (Session-style)
# ==========================

@app.route('/conversations', methods=['GET'])
@token_required
def list_conversations(current_user_id):
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
    try:
        limit = request.args.get('limit', default=20, type=int)
        cursor = conversations_collection.find(
            {"user_id": current_user_id},
            {"created_at": 1, "title": 1, "queries": {"$slice": 1}, "query": 1}
        ).sort("created_at", -1).limit(limit)
        conversations = []
        for doc in cursor:
            # Fallback title from first query text
            first_query_text = None
            if isinstance(doc.get("queries"), list) and len(doc.get("queries")) > 0:
                first_query_text = doc["queries"][0].get("query")
            elif doc.get("query"):
                first_query_text = doc.get("query")
            conversations.append({
                "id": str(doc.get("_id")),
                "title": doc.get("title") or (first_query_text[:60] if first_query_text else "Untitled"),
                "created_at": doc.get("created_at").isoformat() if doc.get("created_at") else None
            })
        return jsonify({"conversations": conversations}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list conversations: {str(e)}"}), 500

@app.route('/conversations/<conv_id>', methods=['GET'])
@token_required
def get_conversation(current_user_id, conv_id):
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
    try:
        doc = conversations_collection.find_one({
            "_id": ObjectId(conv_id),
            "user_id": current_user_id
        })
        if not doc:
            return jsonify({"error": "Conversation not found"}), 404
        
        # Normalize queries for backward compatibility
        queries = doc.get("queries")
        if not isinstance(queries, list) or len(queries) == 0:
            # Old schema stored single query at top level
            single = {
                "id": str(ObjectId()),
                "query": doc.get("query", ""),
                "data": doc.get("data", []),
                "chartType": doc.get("chartType"),
                "customization": doc.get("customization", {}),
                "messages": [
                    {
                        "type": m.get("type"),
                        "message": m.get("message"),
                        "timestamp": (m.get("timestamp").isoformat() if isinstance(m.get("timestamp"), datetime) else m.get("timestamp"))
                    } for m in doc.get("messages", [])
                ],
                "created_at": doc.get("created_at").isoformat() if doc.get("created_at") else None
            }
            queries = [single]
        else:
            # Ensure ids are strings
            normalized = []
            for q in queries:
                normalized.append({
                    "id": str(q.get("id")) if q.get("id") else str(ObjectId()),
                    "query": q.get("query", ""),
                    "data": q.get("data", []),
                    "chartType": q.get("chartType"),
                    "customization": q.get("customization", {}),
                    "messages": [
                        {
                            "type": m.get("type"),
                            "message": m.get("message"),
                            "timestamp": (m.get("timestamp").isoformat() if isinstance(m.get("timestamp"), datetime) else m.get("timestamp"))
                        } for m in q.get("messages", [])
                    ],
                    "created_at": q.get("created_at").isoformat() if isinstance(q.get("created_at"), datetime) else q.get("created_at")
                })
            queries = normalized
        
        response = {
            "id": str(doc.get("_id")),
            "user_id": doc.get("user_id"),
            "title": doc.get("title"),
            "created_at": doc.get("created_at").isoformat() if doc.get("created_at") else None,
            "updated_at": doc.get("updated_at").isoformat() if doc.get("updated_at") else None,
            "queries": queries
        }
        return jsonify({"conversation": response}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to get conversation: {str(e)}"}), 500

@app.route('/conversations', methods=['POST'])
@token_required
def save_conversation(current_user_id):
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
    try:
        payload = request.get_json() or {}
        title = payload.get("title")
        initial_query = payload.get("initial_query")
        
        # Backward compatibility: if direct query/data present, treat as initial_query
        if not initial_query and payload.get("query") and isinstance(payload.get("data"), list):
            initial_query = {
                "query": payload.get("query"),
                "data": payload.get("data"),
                "chartType": payload.get("chartType"),
                "customization": payload.get("customization", {}),
                "messages": payload.get("messages", [])
            }
        
        queries_docs = []
        if initial_query:
            # Normalize messages timestamps to datetime
            normalized_messages = []
            for m in initial_query.get("messages", []):
                ts = m.get("timestamp")
                try:
                    ts_dt = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
                except Exception:
                    ts_dt = datetime.utcnow()
                normalized_messages.append({
                    "type": m.get("type"),
                    "message": m.get("message"),
                    "timestamp": ts_dt or datetime.utcnow()
                })
            queries_docs.append({
                "id": ObjectId(),
                "query": initial_query.get("query", ""),
                "data": initial_query.get("data", []),
                "chartType": initial_query.get("chartType"),
                "customization": initial_query.get("customization", {}),
                "messages": normalized_messages,
                "created_at": datetime.utcnow()
            })
        
        doc = {
            "user_id": current_user_id,
            "title": title or (initial_query.get("query")[:60] if initial_query else None) or "Untitled",
            "queries": queries_docs,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        result = conversations_collection.insert_one(doc)
        conv_id = str(result.inserted_id)
        resp = {"message": "Conversation created", "id": conv_id}
        if queries_docs:
            resp["query_id"] = str(queries_docs[0]["id"])
        return jsonify(resp), 201
    except Exception as e:
        return jsonify({"error": f"Failed to save conversation: {str(e)}"}), 500

@app.route('/conversations/<conv_id>/queries', methods=['POST'])
@token_required
def add_query(current_user_id, conv_id):
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
    try:
        payload = request.get_json() or {}
        # Validate conversation ownership
        doc = conversations_collection.find_one({
            "_id": ObjectId(conv_id),
            "user_id": current_user_id
        })
        if not doc:
            return jsonify({"error": "Conversation not found"}), 404
        qid = ObjectId()
        query_doc = {
            "id": qid,
            "query": payload.get("query", ""),
            "data": payload.get("data", []),
            "chartType": payload.get("chartType"),
            "customization": payload.get("customization", {}),
            "messages": [],
            "created_at": datetime.utcnow()
        }
        conversations_collection.update_one(
            {"_id": ObjectId(conv_id)},
            {"$push": {"queries": query_doc}, "$set": {"updated_at": datetime.utcnow()}}
        )
        return jsonify({"message": "Query added", "query_id": str(qid)}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to add query: {str(e)}"}), 500

@app.route('/conversations/<conv_id>/queries/<query_id>/messages', methods=['POST'])
@token_required
def add_query_messages(current_user_id, conv_id, query_id):
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
    try:
        payload = request.get_json() or {}
        msgs = payload.get("messages", [])
        if not isinstance(msgs, list) or len(msgs) == 0:
            return jsonify({"error": "messages must be a non-empty list"}), 400
        # Validate ownership
        doc = conversations_collection.find_one({
            "_id": ObjectId(conv_id),
            "user_id": current_user_id
        })
        if not doc:
            return jsonify({"error": "Conversation not found"}), 404
        # Normalize messages
        to_append = []
        for m in msgs:
            m_type = m.get("type")
            m_text = m.get("message")
            if m_type not in ["user", "ai"] or not isinstance(m_text, str):
                return jsonify({"error": "Each message must have type 'user' or 'ai' and a string 'message'"}), 400
            ts = m.get("timestamp")
            try:
                ts_dt = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
            except Exception:
                ts_dt = datetime.utcnow()
            to_append.append({
                "type": m_type,
                "message": m_text,
                "timestamp": ts_dt or datetime.utcnow()
            })
        # Update nested array element
        conversations_collection.update_one(
            {"_id": ObjectId(conv_id), "queries.id": ObjectId(query_id)},
            {"$push": {"queries.$.messages": {"$each": to_append}}, "$set": {"updated_at": datetime.utcnow()}}
        )
        return jsonify({"message": "Messages appended", "count": len(to_append)}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to append messages: {str(e)}"}), 500

# Backward-compat endpoints (per-conversation top-level messages)
@app.route('/conversations/<conv_id>/messages', methods=['POST'])
@token_required
def append_messages(current_user_id, conv_id):
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500
    try:
        payload = request.get_json() or {}
        msgs = payload.get("messages", [])
        if not isinstance(msgs, list) or len(msgs) == 0:
            return jsonify({"error": "messages must be a non-empty list"}), 400
        doc = conversations_collection.find_one({
            "_id": ObjectId(conv_id),
            "user_id": current_user_id
        })
        if not doc:
            return jsonify({"error": "Conversation not found"}), 404
        to_append = []
        for m in msgs:
            m_type = m.get("type")
            m_text = m.get("message")
            if m_type not in ["user", "ai"] or not isinstance(m_text, str):
                return jsonify({"error": "Each message must have type 'user' or 'ai' and a string 'message'"}), 400
            ts = m.get("timestamp")
            try:
                ts_dt = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
            except Exception:
                ts_dt = datetime.utcnow()
            to_append.append({
                "type": m_type,
                "message": m_text,
                "timestamp": ts_dt or datetime.utcnow()
            })
        conversations_collection.update_one(
            {"_id": ObjectId(conv_id)},
            {"$push": {"messages": {"$each": to_append}}, "$set": {"updated_at": datetime.utcnow()}}
        )
        return jsonify({"message": "Messages appended", "count": len(to_append)}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to append messages: {str(e)}"}), 500

# ==========================
# Data/AI routes
# ==========================

def get_schema_info(df):
    """
    Extract comprehensive schema information from the DataFrame.
    """
    schema_info = {
        "columns": [],
        "total_rows": len(df),
        "sample_data": df.head(3).to_dict('records')
    }
    
    for col in df.columns:
        col_info = {
            "name": col,
            "type": str(df[col].dtype),
            "non_null_count": df[col].count(),
            "null_count": df[col].isnull().sum(),
            "unique_values": df[col].nunique(),
        }
        
        # Add sample values for better context
        if df[col].dtype in ['object', 'string']:
            col_info["sample_values"] = df[col].dropna().unique()[:5].tolist()
            col_info["data_category"] = "text/categorical"
        elif df[col].dtype in ['int64', 'float64', 'int32', 'float32']:
            col_info["min_value"] = df[col].min()
            col_info["max_value"] = df[col].max()
            col_info["mean_value"] = round(df[col].mean(), 2) if pd.notna(df[col].mean()) else None
            col_info["data_category"] = "numeric"
        elif df[col].dtype in ['datetime64[ns]', 'datetime']:
            col_info["min_date"] = str(df[col].min())
            col_info["max_date"] = str(df[col].max())
            col_info["data_category"] = "datetime"
        else:
            col_info["data_category"] = "other"
            
        schema_info["columns"].append(col_info)
    
    return schema_info

def create_optimized_prompt(text_input, schema_info):
    """
    Create an optimized prompt for SQL query generation with comprehensive schema information.
    """
    # Format schema information
    schema_text = "TABLE SCHEMA:\n"
    schema_text += f"Table Name: uploaded_csv\n"
    schema_text += f"Total Rows: {schema_info['total_rows']}\n\n"
    
    schema_text += "COLUMNS:\n"
    for col in schema_info['columns']:
        schema_text += f"- {col['name']} ({col['type']}, {col['data_category']})\n"
        schema_text += f"  Non-null: {col['non_null_count']}, Unique values: {col['unique_values']}\n"
        
        if col['data_category'] == 'text/categorical' and 'sample_values' in col:
            schema_text += f"  Sample values: {col['sample_values']}\n"
        elif col['data_category'] == 'numeric' and 'min_value' in col:
            schema_text += f"  Range: {col['min_value']} to {col['max_value']}, Average: {col['mean_value']}\n"
        elif col['data_category'] == 'datetime' and 'min_date' in col:
            schema_text += f"  Date range: {col['min_date']} to {col['max_date']}\n"
        schema_text += "\n"
    
    # Sample data
    schema_text += "SAMPLE DATA (first 3 rows):\n"
    for i, row in enumerate(schema_info['sample_data'], 1):
        schema_text += f"Row {i}: {row}\n"
    
    # Create the optimized prompt
    prompt = f"""You are a SQL expert specializing in DuckDB queries. Generate a precise SQL query based on the user request and schema information.

USER REQUEST: "{text_input}"

{schema_text}

INSTRUCTIONS:
1. Generate ONLY a valid DuckDB SQL query - no explanations, comments, or additional text
2. Use table name: uploaded_csv
3. Keep column names EXACTLY as shown in schema (preserve spaces, case, special characters)
4. Use double quotes around column names if they contain spaces or special characters
5. When user requests aggregations (sum, count, average, max, min, group by), include appropriate aggregate functions
6. For filtering operations, use appropriate WHERE clauses based on data types
7. For date/time operations, use DuckDB date functions if needed
8. For text searches, use LIKE or ILIKE for case-insensitive matching
9. When joining or grouping, consider the data relationships shown in sample data
10. Optimize for performance with appropriate LIMIT clauses if displaying sample results

COMMON AGGREGATION PATTERNS:
- "total", "sum" → SUM()
- "average", "mean" → AVG()
- "count", "number of" → COUNT()
- "maximum", "highest" → MAX()
- "minimum", "lowest" → MIN()
- "by category", "group by" → GROUP BY
- "top N", "first N" → ORDER BY ... LIMIT N

QUERY ONLY (no other text):"""

    return prompt

# Route for generating SQL queries based on user input
@app.route('/generate_sql', methods=['POST'])
def generate_sql():
    """
   Generates an SQL query from user input and the structure of the uploaded CSV file, 
   executes it with DuckDB, and returns the result as a downloadable CSV.
    """
    # Configure the Generative AI model with the provided API key
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    # Parse JSON data from the request
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Missing text input."}), 400

    text_input = data['text']

    # Validate if the file path is included in the request
    if not data or 'filePath' not in data:
        return jsonify({"error": "No file uploaded. Please upload a file first."}), 400

    filePath = data['filePath']

    try:
        # Read the uploaded CSV file into a Pandas DataFrame
        df = pd.read_csv(filePath)
    except Exception as e:
        # Handle errors during file reading
        return jsonify({"error": f"Error reading CSV file: {str(e)}"}), 400

    try:
        # Get comprehensive schema information
        schema_info = get_schema_info(df)
        
        # Create optimized prompt with schema information
        prompt = create_optimized_prompt(text_input, schema_info)
        
        print(f"Optimized prompt: {prompt}")
        
        # Generate SQL query using the AI model
        response = model.generate_content(prompt)
        sql_query = response.text.strip()
        
        print(f"Generated SQL query: {sql_query}")
    except Exception as e:
        # Handle errors during query generation
        return jsonify({"error": f"Error generating SQL: {str(e)}"}), 500

    # Clean up the generated SQL query (remove any markdown or extra formatting)
    sql_query = sql_query.replace("```sql", "").replace("```", "").replace("\n", " ").strip()
    
    # Remove any common prefixes that might be added
    if sql_query.lower().startswith("sql:"):
        sql_query = sql_query[4:].strip()
    if sql_query.lower().startswith("query:"):
        sql_query = sql_query[6:].strip()
        
    # Ensure table name consistency
    sql_query = sql_query.replace("your_table_name", "uploaded_csv")
    sql_query = sql_query.replace("table_name", "uploaded_csv")

    # Execute the SQL query using DuckDB
    try:
        conn = duckdb.connect()
        conn.register('uploaded_csv', df)  # Register the DataFrame as a table in DuckDB
        output_table = conn.execute(sql_query).fetchdf()  # Execute the query and fetch the result
        
        print(f"Query executed successfully. Result shape: {output_table.shape}")
    except Exception as e:
        # Handle errors during query execution with more detailed error info
        return jsonify({
            "error": f"Error executing SQL: {str(e)}", 
            "generated_query": sql_query,
            "suggestion": "Please check your query syntax or try rephrasing your request."
        }), 500

    # Convert the result table to CSV format
    csv_data = output_table.to_csv(index=False)

    # Return the result as a downloadable CSV file
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment; filename=output.csv"}
    )

@app.route('/analyze_data', methods=['POST'])
def analyze_data():
    """
    Endpoint for AI-powered data analysis.
    Accepts output data and user query, returns intelligent insights.
    """
    print("📊 Analyze data endpoint called")
    
    if not google_api_key:
        return jsonify({"error": "Google API key is not configured."}), 500

    # Configure the Google Generative AI model
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    # Parse JSON data from the request
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request data."}), 400

    # Validate required fields
    if 'query' not in data or 'data' not in data:
        return jsonify({"error": "Missing query or data fields."}), 400

    original_query = data['query']
    output_data = data['data']
    
    try:
        # Convert the data to a more readable format for analysis
        if isinstance(output_data, list) and len(output_data) > 0:
            # Extract headers and a sample of rows for analysis
            headers = output_data[0] if output_data else []
            sample_rows = output_data[1:min(6, len(output_data))]  # Take first 5 data rows
            total_rows = len(output_data) - 1  # Subtract header row
            
            # Format data for analysis
            data_summary = f"Dataset Overview:\n"
            data_summary += f"- Total Columns: {len(headers)}\n"
            data_summary += f"- Total Rows: {total_rows}\n"
            data_summary += f"- Column Names: {', '.join(headers)}\n\n"
            
            data_summary += "Sample Data (first 5 rows):\n"
            for i, row in enumerate(sample_rows, 1):
                data_summary += f"Row {i}: {dict(zip(headers, row))}\n"
        else:
            data_summary = "No data available for analysis."

        # Create analysis prompt
        analysis_prompt = f"""
You are an expert data analyst. Analyze the following dataset and provide intelligent insights.

Original User Query: "{original_query}"

{data_summary}

Please provide a comprehensive analysis that includes:
1. **Key Insights**: What are the most important findings from this data?
2. **Data Patterns**: What patterns, trends, or correlations do you notice?
3. **Business Implications**: What do these results mean from a business perspective?
4. **Recommendations**: What actionable recommendations can you provide based on this analysis?
5. **Additional Questions**: What other questions should be explored with this data?

Make your response conversational, engaging, and easy to understand. Use emojis where appropriate to make it more visually appealing. Keep it concise but informative (aim for 3-4 paragraphs).
"""

        print(f"📝 Analysis prompt created for query: {original_query}")
        
        # Generate analysis using the AI model
        response = model.generate_content(analysis_prompt)
        analysis_text = response.text.strip()
        
        print(f"✅ Analysis generated successfully")
        
        return jsonify({
            "analysis": analysis_text,
            "success": True
        })
        
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        return jsonify({"error": f"Error generating analysis: {str(e)}"}), 500

@app.route('/chat_with_data', methods=['POST'])
def chat_with_data():
    """
    Endpoint for conversational AI chat about specific data.
    Allows users to ask questions and have a conversation about their dataset.
    """
    print("💬 Chat with data endpoint called")
    
    if not google_api_key:
        return jsonify({"error": "Google API key is not configured."}), 500

    # Configure the Google Generative AI model
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    # Parse JSON data from the request
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request data."}), 400

    # Validate required fields
    required_fields = ['user_question', 'data', 'original_query']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing {field} field."}), 400

    user_question = data['user_question']
    output_data = data['data']
    original_query = data['original_query']
    conversation_history = data.get('conversation_history', [])
    
    try:
        # Convert the data to a more readable format for analysis
        if isinstance(output_data, list) and len(output_data) > 0:
            # Extract headers and a sample of rows for analysis
            headers = output_data[0] if output_data else []
            sample_rows = output_data[1:min(11, len(output_data))]  # Take first 10 data rows for chat
            total_rows = len(output_data) - 1  # Subtract header row
            
            # Format data for analysis
            data_context = f"Dataset Context:\n"
            data_context += f"- Original Query: {original_query}\n"
            data_context += f"- Columns ({len(headers)}): {', '.join(headers)}\n"
            data_context += f"- Total Rows: {total_rows}\n\n"
            
            data_context += "Sample Data:\n"
            for i, row in enumerate(sample_rows, 1):
                data_context += f"Row {i}: {dict(zip(headers, row))}\n"
        else:
            data_context = "No data available for analysis."

        # Build conversation context
        conversation_context = ""
        if conversation_history:
            conversation_context = "\nPrevious Conversation:\n"
            for i, chat in enumerate(conversation_history[-3:], 1):  # Last 3 exchanges for context
                conversation_context += f"Q{i}: {chat.get('question', '')}\n"
                conversation_context += f"A{i}: {chat.get('answer', '')}\n\n"

        # Create conversational prompt
        chat_prompt = f"""
You are a friendly, expert data analyst having a conversation with a user about their data. You should:

1. Be conversational, warm, and helpful
2. Answer the user's specific question about the data
3. Provide insights, patterns, or explanations
4. Suggest follow-up questions when appropriate
5. Use a natural, speaking tone (this will be read aloud)
6. Keep responses concise but informative (2-3 sentences usually)
7. Use simple language and avoid technical jargon when possible

{data_context}
{conversation_context}

User's Current Question: "{user_question}"

Please provide a natural, conversational response that directly answers their question. If the question can't be answered with the available data, explain why and suggest what data might be needed.
"""

        print(f"💬 Chat prompt created for question: {user_question}")
        
        # Generate response using the AI model
        response = model.generate_content(chat_prompt)
        answer_text = response.text.strip()
        
        print(f"✅ Chat response generated successfully")
        
        return jsonify({
            "answer": answer_text,
            "success": True
        })
        
    except Exception as e:
        print(f"❌ Error during chat: {str(e)}")
        return jsonify({"error": f"Error generating response: {str(e)}"}), 500

@app.route('/generate_presentation_insights', methods=['POST'])
def generate_presentation_insights():
    try:
        data = request.get_json()
        charts_data = data.get('charts', [])
        
        if not charts_data:
            return jsonify({"error": "No charts data provided"}), 400
        
        insights = []
        
        for chart in charts_data:
            chart_data = chart.get('data', [])
            query = chart.get('query', '')
            chart_type = chart.get('customization', {}).get('chartType', 'bar')
            
            if not chart_data:
                continue
                
            # Create prompt for generating presentation insights
            prompt = f"""
            As a data analyst, create a concise presentation slide explanation for this chart:
            
            Query: {query}
            Chart Type: {chart_type}
            Data Sample: {chart_data[:5]}  # First 5 rows
            Total Data Points: {len(chart_data)}
            
            Provide:
            1. A clear title (max 8 words)
            2. Key insights (2-3 bullet points)
            3. One actionable recommendation
            4. Notable trends or patterns
            
            Keep it professional, concise, and presentation-ready.
            Format as:
            TITLE: [title]
            INSIGHTS:
            • [insight 1]
            • [insight 2]
            • [insight 3]
            RECOMMENDATION: [recommendation]
            PATTERN: [key pattern observed]
            """
            
            try:
                response = model.generate_content(prompt)
                insight_text = response.text.strip()
                
                insights.append({
                    "chart_id": chart.get('id'),
                    "query": query,
                    "chart_type": chart_type,
                    "insight": insight_text,
                    "data_points": len(chart_data)
                })
                
            except Exception as e:
                print(f"Error generating insight for chart: {str(e)}")
                insights.append({
                    "chart_id": chart.get('id'),
                    "query": query,
                    "chart_type": chart_type,
                    "insight": f"TITLE: {query}\nINSIGHTS:\n• Data analysis showing {chart_type} visualization\n• {len(chart_data)} data points analyzed\nRECOMMENDATION: Review the data trends for actionable insights\nPATTERN: Standard {chart_type} chart pattern observed",
                    "data_points": len(chart_data)
                })
        
        print(f"✅ Generated insights for {len(insights)} charts")
        
        return jsonify({
            "insights": insights,
            "success": True
        })
        
    except Exception as e:
        print(f"❌ Error generating presentation insights: {str(e)}")
        return jsonify({"error": f"Error generating insights: {str(e)}"}), 500

# Main entry point for the application
if __name__ == '__main__':
    # Run the Flask app on the specified port, defaulting to 8080
    # port = int(os.environ.get("PORT", 8080))  # Render requires 8080
    # app.run(host='0.0.0.0', port=port)
    app.run()