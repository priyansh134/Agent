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

# Load environment variables from .env file
load_dotenv()

# Configuration variables
google_api_key = os.getenv("GOOGLE_API_KEY")
cloudinary_cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME")
cloudinary_api_key = os.getenv("CLOUDINARY_API_KEY")
cloudinary_api_secret = os.getenv("CLOUDINARY_API_SECRET")
mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
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
    print("✅ Connected to MongoDB successfully")
except Exception as e:
    print(f"❌ Error connecting to MongoDB: {e}")
    db = None

# Initialize Flask app
app = Flask(__name__)

# Enable Cross-Origin Resource Sharing (CORS) for all routes
cors = CORS(app, origins="*")

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
        from bson import ObjectId
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

# Main entry point for the application
if __name__ == '__main__':
    # Run the Flask app on the specified port, defaulting to 8080
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=True)