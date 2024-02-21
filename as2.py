from flask import Flask, request, jsonify,  abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime, timedelta
import json
import re
import hashlib
import base64
import hmac
from functools import wraps
from flask import g

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'  # 用你的密钥替换 'your_secret_key_here'



users = {
    'username': {
        'password': 'hashed_password',
        'urls': {
            'hash_id1': 'original_url1',
            'hash_id2': 'original_url2'
        }
    }
}
url_mapping = {}
url_to_id = {}

def base64url_encode(input):
    return base64.urlsafe_b64encode(input).rstrip(b'=')

def generate_jwt(username):
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    payload = {
        "sub": username,
        "iat": datetime.utcnow().timestamp()
    }
    secret = app.config['JWT_SECRET_KEY']

    # 将Header和Payload转换为Base64-URL
    encoded_header = base64url_encode(json.dumps(header).encode('utf-8'))
    encoded_payload = base64url_encode(json.dumps(payload).encode('utf-8'))

    # 创建签名
    signature = hmac.new(
        key=secret.encode('utf-8'),
        msg=f'{encoded_header.decode()}.{encoded_payload.decode()}'.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()

    # 将签名也转换为Base64-URL
    encoded_signature = base64url_encode(signature)

    # 拼接生成JWT
    jwt_token = f'{encoded_header.decode()}.{encoded_payload.decode()}.{encoded_signature.decode()}'
    return jwt_token

def verify_jwt(token):
    secret = app.config['JWT_SECRET_KEY']
    
    # 分割JWT为各部分
    parts = token.split('.')
    if len(parts) != 3:
        return False

    encoded_header, encoded_payload, signature = parts
    # 校验签名
    expected_signature = hmac.new(
        key=secret.encode('utf-8'),
        msg=f'{encoded_header}.{encoded_payload}'.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    
    # 比较实际的签名和预期的签名
    expected_signature_encoded = base64url_encode(expected_signature).decode('utf-8')
    if not hmac.compare_digest(expected_signature_encoded, signature):
        return False

    # 解码payload
    payload_data = base64.urlsafe_b64decode(encoded_payload + '==')
    payload = json.loads(payload_data)

    # 检查令牌是否过期
    current_time = datetime.utcnow().timestamp()
    if current_time > payload.get('exp', current_time + 1):
        return False

    return payload

def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', None)
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing'}), 401

        parts = auth_header.split()

        # 仅当 Authorization 头部存在，并尝试提取令牌
        # 如果头部不以 "Bearer" 开头，假定整个内容都是令牌
        if parts[0].lower() == 'bearer' and len(parts) == 2:
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]  # 直接将整个头部内容视为令牌
        else:
            return jsonify({'error': 'Authorization header format is not valid'}), 401

        payload = verify_jwt(token)

        if not payload:
            return jsonify({'error': 'Invalid token'}), 403

        # 将 payload 添加到 Flask 的全局 g 对象，以便在视图函数中使用
        g.user = payload['sub']
        return f(*args, **kwargs)

    return decorated_function


def generate_token(username):
    expires = datetime.utcnow() + timedelta(days=1)
    return create_access_token(identity=username, expires_delta=expires)

def is_valid_url(url): #Check URL validity with a regular expression
    regex = re.compile(
        
        r'^(https?|ftp):\/\/'  
        r'((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  
        r'localhost|'  
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  
        r'(?::\d+)?'  
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)  
    return re.match(regex, url) is not None
  
def generate_hash_id(url):
    hash_object = hashlib.sha256(url.encode())
    hash_id = hash_object.hexdigest()[:8]
    return hash_id

@app.route('/users', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    if username in users:
        return jsonify({'error': 'Username already exists.'}), 409

    users[username] = {
        'password': generate_password_hash(password),
        'urls': {}
    }
    return jsonify({'message': 'User created successfully.'}), 201


@app.route('/users/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = users.get(username)

    if user and check_password_hash(user['password'], password):
        token = generate_jwt(username)
        return jsonify({'token': token}), 200

    return jsonify({'error': 'Invalid credentials.'}), 403


@app.route('/users', methods=['PUT'])
def change_password():
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old-password')
    new_password = data.get('new-password')

    user = users.get(username)

    if user and check_password_hash(user['password'], old_password):
        users[username]['password'] = generate_password_hash(new_password)
        return jsonify({'message': 'Password updated successfully.'}), 200

    return jsonify({'error': 'Invalid credentials.'}), 403


@app.route('/', methods=['POST']) # Route to create a new URL entry.
@jwt_required
def create_url():
    current_user = g.user
    data = request.get_json()
    if 'value' not in data or not is_valid_url(data['value']):
        return jsonify({'error': 'Invalid URL'}), 400
    url = data['value']
    
    if url in url_to_id:# Check if the URL already exists
        hash_id = url_to_id[url]
    else:
        hash_id = generate_hash_id(url)
        while hash_id in url_mapping:# Ensure the hash ID is unique
            url += ' ' 
            hash_id = generate_hash_id(url) # Adjust the URL slightly to attempt a new hash ID
            if url_mapping.get(hash_id) == url: 
                break
        url_mapping[hash_id] = url
        url_to_id[url] = hash_id

    return jsonify({'id': hash_id}), 201

@app.route('/', methods=['DELETE'])# Route to delete all URL mappings.
@jwt_required
def delete_all_urls():
    current_user = g.user
    global url_mapping, url_to_id
    url_mapping.clear()  
    url_to_id.clear()             
    abort(404)

@app.route('/', methods=['GET'])# Route to list all stored URLs.
@jwt_required
def list_urls():
    current_user = g.user
    if not url_mapping:  
        return jsonify({"value": None}), 200  
    else:
        keys = list(url_mapping.keys())
        return jsonify({"value": keys}), 200  

@app.route('/<id>', methods=['GET'])# Route to redirect to the original URL based on its ID.
def redirect_to_url(id):
    url = url_mapping.get(id)
    if url:
        return jsonify(value=url), 301
    else:
        abort(404)

@app.route('/<id>', methods=['PUT'])# Route to update an existing URL mapping with a new URL.
@jwt_required
def update_url(id):
    current_user = g.user
    if id not in url_mapping:
            return jsonify({'error': 'id does not exist'}), 404
    
    data = request.get_data()
    data_str = data.decode('utf-8')
    data_dict = json.loads(data_str)

    if data is None:
        return jsonify({'error': 'No JSON data received'}), 400
    if 'url' not in data_dict:
        return jsonify({'error': 'No URL provided in JSON data'}), 400
    if not is_valid_url(data_dict['url']):
        return jsonify({'error': 'URL is not valid'}), 400
    if id in url_mapping:
        url_mapping[id] = data_dict['url']
        return jsonify({}), 200
    else:
        abort(404)

@app.route('/<id>', methods=['DELETE'])# Route to delete a specific URL mapping based on its ID.
@jwt_required
def delete_url(id):
    current_user = g.user
    if id in url_mapping:
        del url_mapping[id]
        return jsonify({}), 204
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True)
