from flask import Flask, request, jsonify
from datetime import datetime,timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import hmac
from functools import wraps
import json
import hashlib
from flask import g

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here' 

users = {}

def base64url_encode(input):
	return base64.urlsafe_b64encode(input).rstrip(b'=')


def generate_jwt(username):
	header = {
		"alg": "HS256",
		"typ": "JWT"
	}
	exp_time = datetime.utcnow() + timedelta(hours=1)
	payload = {
		"sub": username,
		"iat": datetime.utcnow().timestamp(),
		"exp": exp_time.timestamp()
	}
	secret = app.config['JWT_SECRET_KEY']

	encoded_header = base64url_encode(json.dumps(header).encode('utf-8'))#convert header and payload to base64-URL
	encoded_payload = base64url_encode(json.dumps(payload).encode('utf-8'))

	signature = hmac.new(
		key=secret.encode('utf-8'),
		msg=f'{encoded_header.decode()}.{encoded_payload.decode()}'.encode('utf-8'),
		digestmod=hashlib.sha256
	).digest()

	encoded_signature = base64url_encode(signature)

	jwt_token = f'{encoded_header.decode()}.{encoded_payload.decode()}.{encoded_signature.decode()}'
	return jwt_token


def verify_jwt(token):
	secret = app.config['JWT_SECRET_KEY']

	parts = token.split('.')
	if len(parts) != 3:
		return False

	encoded_header, encoded_payload, signature = parts
	expected_signature = hmac.new( #check signature
		key=secret.encode('utf-8'),
		msg=f'{encoded_header}.{encoded_payload}'.encode('utf-8'),
		digestmod=hashlib.sha256
	).digest()

	expected_signature_encoded = base64url_encode(expected_signature).decode('utf-8')#compare the signature
	if not hmac.compare_digest(expected_signature_encoded, signature):
		return False

	payload_data = base64.urlsafe_b64decode(encoded_payload + '==')#decode payload
	payload = json.loads(payload_data)

	current_time = datetime.utcnow().timestamp()
	if current_time > payload.get('exp', current_time + 1):#check if token expires
		return False

	return payload


def jwt_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		auth_header = request.headers.get('Authorization', None)
		if not auth_header:
			return jsonify({'error': 'Authorization header is missing'}), 401

		parts = auth_header.split()
		if parts[0].lower() == 'bearer' and len(parts) == 2:# if include 'bearer'
			token = parts[1]
		elif len(parts) == 1:
			token = parts[0]  
		else:
			return jsonify({'error': 'Authorization header format is not valid'}), 401

		payload = verify_jwt(token)

		if not payload:
			return jsonify({'error': 'Invalid token'}), 403
		
		g.user = payload['sub']
		return f(*args, **kwargs)

	return decorated_function
@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if not username or not password:
        return jsonify({'error': 'No username or password provided in JSON data'}), 400

    if username in users:
        return jsonify({'detail': 'duplicate'}), 409

    password_h = generate_password_hash(password)

    users[username] = {
        'password': password_h
    }

    return jsonify({'message': 'New user created'}), 201

@app.route('/users/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if not username or not password:
        return jsonify({'error': 'No username or password provided in JSON data'}), 400

    if username in users and check_password_hash(users[username]['password'], password):
        token = generate_jwt(username)
        return jsonify({'token': token}), 200
    else:
        return jsonify({'detail': 'forbidden'}), 403

@app.route('/users', methods=['PUT'])
def change_password():
    data = request.get_json()
    username = data['username']
    password = data['password']
    new_password = data['new_password']

    if not username or not password or not new_password:
        return jsonify({'error': 'Missing fields in JSON data'}), 400

    if username in users and check_password_hash(users[username]['password'], password):
        users[username] = {
            'password': new_password
        }
        return jsonify({'message': 'New password set'}), 200
    else:
        return jsonify({'detail': 'forbidden'}), 403

if __name__ == "__main__":
	app.run(debug=True, port=5001)
