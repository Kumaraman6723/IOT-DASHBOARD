import pymysql
from config import DB_CONFIG
from functools import wraps
import time
from collections import defaultdict
import requests
from flask import Flask, request, jsonify

def get_db_connection():
    return pymysql.connect(
        host=DB_CONFIG["HOST"],
        user=DB_CONFIG["USER"],
        password=DB_CONFIG["PASSWORD"],
        database=DB_CONFIG["DATABASE"],
        port=DB_CONFIG["PORT"]
    )

def fetch_email():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email FROM user_profiles")
    output = cur.fetchall()
    conn.close()
    return [i[0] for i in output]

def recover_passkey(new_password, email):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE user_profiles SET password = %s WHERE email = %s", (new_password, email))
    conn.commit()
    conn.close()

def fetch_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, password ,username FROM user_profiles")
    output = cur.fetchall()
    conn.close()
    return output






def fetch_email_from_user(email):
        
        if "@" not in email:
           
          connection = get_db_connection()
          cursor=connection.cursor()

          query = "select email from user_profiles where username = %s"
          cursor.execute(query,(email,))
          connection.commit()
          result = cursor.fetchone()
          email = result[0]
          connection.close()
          return email



def token_fn():
    con = get_db_connection()
    connection = con.cursor()
    query = "SELECT Token_id FROM token_device;"
    connection.execute(query)
    con.commit()
    result = connection.fetchall()
    all_token = [i[0] for i in result]
    connection.close()
    return all_token  

# Fixed Bearer token
BEARER_TOKEN = "aciuabscjhvasckbsaccnals&**&scscADVADVA"  # Replace with your actual fixed token

# Bearer token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Authorization header is missing!'}), 401
        
        try:
            token_type, token = auth_header.split()
            if token_type.lower() != 'bearer':
                return jsonify({'message': 'Invalid token type. Use Bearer token.'}), 401
            if token != BEARER_TOKEN:
                return jsonify({'message': 'Invalid token!'}), 401
        except ValueError:
            return jsonify({'message': 'Invalid Authorization header format!'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Rate limiting storage
rate_limit_storage = defaultdict(lambda: {'count': 0, 'reset_time': 0})

# Rate limiting decorator
def rate_limit(limit=100, per=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            if current_time > rate_limit_storage[client_ip]['reset_time']:
                rate_limit_storage[client_ip] = {
                    'count': 1,
                    'reset_time': current_time + per
                }
            else:
                rate_limit_storage[client_ip]['count'] += 1
            if rate_limit_storage[client_ip]['count'] > limit:
                return jsonify(error="Rate limit exceeded"), 429
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Token route function
@token_required
@rate_limit(limit=100, per=60)  # 100 requests per 60 seconds
def token_route():
    token = request.view_args.get('token')  # Get the token from the URL
    if request.method == 'POST':
        data = request.json
        return jsonify({
            "message": f"Data received for {token}",
            "received_data": data
        })
    else:
        return jsonify({"message": f"This is the GET route for {token}"})
