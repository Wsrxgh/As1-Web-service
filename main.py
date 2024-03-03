from flask import Flask, request, jsonify,  abort
from auth import jwt_required
import json
import re
import hashlib
from flask import g
import os
import redis



app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
redis_db = redis.Redis.from_url(app.config['REDIS_URL'])

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

def create_url_mapping(hash_id, original_url, user_token):
    key = f"url:{hash_id}"
    value = json.dumps({"original_url": original_url, "user_token": user_token})
    redis_db.set(key, value)

def get_url_mapping(hash_id):
    key = f"url:{hash_id}"
    result = redis_db.get(key)
    if result:
        return json.loads(result)
    return None


@app.route('/', methods=['POST'])
@jwt_required
def create_url():
    current_user = g.user
    data = request.get_json()
    if 'value' not in data or not is_valid_url(data['value']):
        return jsonify({'error': 'Invalid URL'}), 400
    
    url = data['value']
    hash_id = generate_hash_id(url)  # Generate a hash ID for the URL
    existing_mapping = get_url_mapping(hash_id)  # Check if the mapping already exists in Redis

    if existing_mapping is None:
        create_url_mapping(hash_id, url, current_user)
    else:
        
        pass
    
    return jsonify({'id': hash_id}), 201


@app.route('/', methods=['DELETE'])
@jwt_required
def delete_all_urls():
    current_user = g.user
    prefix = f"url:"  
    for key in redis_db.scan_iter(f"{prefix}*"):
        mapping = get_url_mapping(key.decode().replace(prefix, ""))
        if mapping and mapping.get('user_token') == current_user:
            # Delete the mapping if it belongs to the current user
            redis_db.delete(key)

    abort(404)


@app.route('/', methods=['GET'])
@jwt_required
def list_urls():
    current_user = g.user
    prefix = "url:"  
    user_urls = []  

    for key in redis_db.scan_iter(f"{prefix}*"):
        mapping_data = redis_db.get(key)
        if mapping_data:
            mapping = json.loads(mapping_data)
            if mapping.get('user_token') == current_user:
                hash_id = key.decode().replace(prefix, "")
                user_urls.append(hash_id)

    if not user_urls:
        return jsonify({"value": None}), 200
    else:
        return jsonify({"value": user_urls}), 200




@app.route('/<id>', methods=['GET'])
def redirect_to_url(id):
    key = f"url:{id}"  
    result = redis_db.get(key)  
    if result:
        mapping = json.loads(result)  
        original_url = mapping.get('original_url')  
        return jsonify(value=original_url), 301  
    else:
        abort(404)  

@app.route('/<id>', methods=['PUT'])
@jwt_required
def update_url(id):
    current_user = g.user
    key = f"url:{id}"  
    result = redis_db.get(key)  

    if not result:
        return jsonify({'error': 'id does not exist or forbidden'}), 404

    mapping = json.loads(result.decode()) 

    if mapping['user_token'] != current_user:
        return jsonify({'error': 'id does not exist or forbidden'}), 404

    data = request.get_json()  

    if not data or 'url' not in data or not is_valid_url(data['url']):
        return jsonify({'error': 'No URL provided in JSON data or URL is not valid'}), 400

    updated_mapping = {'original_url': data['url'], 'user_token': current_user}
    redis_db.set(key, json.dumps(updated_mapping))  

    return jsonify({}), 200


@app.route('/<id>', methods=['DELETE'])
@jwt_required
def delete_url(id):
    current_user = g.user
    key = f"url:{id}"
    result = redis_db.get(key)
    
    if not result:
        return jsonify({'error': 'id does not exist'}), 404

    mapping = json.loads(result)
    if mapping['user_token'] != current_user:
        return jsonify({'detail': 'forbidden'}), 403
    redis_db.delete(key)

    return jsonify({}), 204

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
