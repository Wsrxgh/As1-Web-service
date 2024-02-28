from flask import Flask, request, jsonify,  abort
from auth import jwt_required
import json
import re
import hashlib
from flask import g
from flask_sqlalchemy import SQLAlchemy
import os

DATABASE_PATH = os.environ.get('DATABASE_PATH', 'urls.db')
app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

url_mapping = {}
url_to_id = {}
url_to_token = {}
token_to_url = {}

class URLMapping(db.Model):
    __tablename__ = 'urls'
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(2048), nullable=False)
    hash_id = db.Column(db.String(8), unique=True, nullable=False)
    user_token = db.Column(db.String(256), nullable=False)

    def __repr__(self):
        return f'<URLMapping {self.original_url}>'

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
    existing_mapping = URLMapping.query.filter_by(original_url=url).first()
    if existing_mapping:
        hash_id = existing_mapping.hash_id
    else:
        hash_id = generate_hash_id(url)
        new_mapping = URLMapping(original_url=url, hash_id=hash_id, user_token=current_user)
        db.session.add(new_mapping)
        db.session.commit()
    return jsonify({'id': hash_id}), 201

@app.route('/', methods=['DELETE'])# Route to delete all URL mappings.
@jwt_required
def delete_all_urls():
    current_user = g.user
    URLMapping.query.filter_by(user_token=current_user).delete()
    db.session.commit()
    abort(404)

@app.route('/', methods=['GET'])# Route to list all stored URLs.
@jwt_required
def list_urls():
    current_user = g.user
    mappings = URLMapping.query.filter_by(user_token=current_user).all()
    if not mappings:
        return jsonify({"value": None}), 200
    keys = [mapping.hash_id for mapping in mappings]
    return jsonify({"value": keys}), 200

@app.route('/<id>', methods=['GET'])# Route to redirect to the original URL based on its ID.
def redirect_to_url(id):
    mapping = URLMapping.query.filter_by(hash_id=id).first()
    if mapping:
        return jsonify(value=mapping.original_url), 301
    else:
        abort(404)

@app.route('/<id>', methods=['PUT'])# Route to update an existing URL mapping with a new URL.
@jwt_required
def update_url(id):
    current_user = g.user
    mapping = URLMapping.query.filter_by(hash_id=id, user_token=current_user).first()

    if mapping is None:
        return jsonify({'error': 'id does not exist or forbidden'}), 404

    data = request.get_data()
    data_str = data.decode('utf-8')
    data_dict = json.loads(data_str)

    if data is None:
        return jsonify({'error': 'No JSON data received'}), 400
    if 'url' not in data_dict or not is_valid_url(data_dict['url']):
        return jsonify({'error': 'No URL provided in JSON data or URL is not valid'}), 400

    mapping.original_url = data_dict['url']
    db.session.commit()

    return jsonify({}), 200

@app.route('/<id>', methods=['DELETE'])# Route to delete a specific URL mapping based on its ID.
@jwt_required
def delete_url(id):
    current_user = g.user

    mapping = URLMapping.query.filter_by(hash_id=id).first()

    if mapping is None:
        return jsonify({'error': 'id does not exist'}), 404

    if mapping.user_token != current_user:
        return jsonify({'detail': 'forbidden'}), 403
    
    db.session.delete(mapping)
    db.session.commit()

    return jsonify({}), 204

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8000)
