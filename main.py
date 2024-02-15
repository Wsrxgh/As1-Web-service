from flask import Flask, request, jsonify,  abort
import json
import re

app = Flask(__name__)

url_mapping = {}
id_to_url = {}
next_id = 1  

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
  
def base62_encode(num): # Function to encode a numeric ID into a base62 string.
    characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    base = len(characters)
    encoded = ''
    while num > 0:
        num, rem = divmod(num, base)
        encoded = characters[rem] + encoded
    return encoded

@app.route('/', methods=['POST']) # Route to create a new URL entry.
def create_url():
    global next_id
    data = request.get_json()
    if 'value' not in data or not is_valid_url(data['value']):
        return jsonify({'error': 'Invalid URL'}), 400
    url = data['value']
    if url in id_to_url and id_to_url[url] in url_mapping:
            # If the URL already exists, return the corresponding ID.
            id = id_to_url[url]
    else:
            # Otherwise, create a new mapping.
            id = base62_encode(next_id+10)
            url_mapping[id] = url
            id_to_url[url] = id 
            next_id += 1
    
    return jsonify({'id': id}), 201

@app.route('/', methods=['DELETE'])# Route to delete all URL mappings.
def delete_all_urls():
    global url_mapping, id_to_url, next_id
    url_mapping.clear()  
    id_to_url.clear()    
    next_id = 1          
    abort(404)

@app.route('/', methods=['GET'])# Route to list all stored URLs.
def list_urls():
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
def update_url(id):
    if id not in url_mapping:
            return jsonify({'error': 'id does not exist'}), 404

    # 更新一个已存在的URL映射
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
def delete_url(id):
    if id in url_mapping:
        del url_mapping[id]
        return jsonify({}), 204
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True)
