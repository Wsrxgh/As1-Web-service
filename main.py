from flask import Flask, request, jsonify,  abort
from auth import jwt_required
import json
import re
import hashlib
from flask import g

app = Flask(__name__)

url_mapping = {}
url_to_id = {}
url_to_token = {}
token_to_url = {}

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
        url_to_token[hash_id] = current_user
        token_to_url[current_user] = hash_id
        url_to_id[url] = hash_id

    return jsonify({'id': hash_id}), 201

@app.route('/', methods=['DELETE'])# Route to delete all URL mappings.
@jwt_required
def delete_all_urls():
    current_user = g.user
    if not url_mapping:
        return jsonify({"value": None}), 404
    if current_user not in token_to_url:
        return jsonify({"value": None}), 404
    else:
        hash_ids_to_delete = []
        for hash_id, user_token in url_to_token.items():
            if user_token == current_user:
                hash_ids_to_delete.append(hash_id)

        for hash_id in hash_ids_to_delete:
            if hash_id in url_mapping:
                del url_mapping[hash_id]
            if hash_id in url_to_id.values():
                urls_to_delete = [url for url, h_id in url_to_id.items() if h_id == hash_id]
                for url in urls_to_delete:
                    del url_to_id[url]
    abort(404)

@app.route('/', methods=['GET'])# Route to list all stored URLs.
@jwt_required
def list_urls():
    current_user = g.user
    if not url_mapping:  
        return jsonify({"value": None}), 200
    if current_user not in token_to_url:
        return jsonify({"value": None}), 200
    else:
        keys = []
        for hash_id, user_token in url_to_token.items():
            if user_token == current_user:
                    keys.append(hash_id)
        return jsonify({"value": keys}),  200

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

    if url_to_token[id] != current_user:
        return jsonify({'detail': 'forbidden'}), 403
    
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
    if id not in url_mapping:
        return jsonify({'error': 'id does not exist'}), 404

    if url_to_token[id] != current_user:
        return jsonify({'detail': 'forbidden'}), 403

    if id in url_mapping:
        del url_mapping[id]
        return jsonify({}), 204
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True, port=8000)
