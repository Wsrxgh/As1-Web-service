from flask import Flask, request, jsonify, redirect, abort
import hashlib
import json
import threading
import re

app = Flask(__name__)

url_mapping = {}# 这个字典将存储短URL到原始URL的映射
id_to_url = {}
next_id = 1  # 初始化自增ID

def is_valid_url(url):
    # 此正则表达式检查大部分常见的URL格式
    regex = re.compile(
        
        r'^(https?|ftp):\/\/'  
        r'((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  
        r'localhost|'  
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  
        r'(?::\d+)?'  
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)  
    return re.match(regex, url) is not None
  
def base62_encode(num): #基62编码
    characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    base = len(characters)
    encoded = ''
    while num > 0:
        num, rem = divmod(num, base)
        encoded = characters[rem] + encoded
    return encoded

@app.route('/', methods=['POST']) #创建映射
def create_url():
    global next_id
    data = request.get_json()
    if 'url' not in data or not is_valid_url(data['url']):
        return jsonify({'error': 'Invalid URL'}), 400
    
    original_url = data['url']
    if original_url in id_to_url:
            # 如果URL已存在，直接返回对应的ID
            short_id = id_to_url[original_url]
    else:
            # 否则，创建一个新的映射
            short_id = base62_encode(next_id)
            url_mapping[short_id] = original_url
            id_to_url[original_url] = short_id  # 保存URL到ID的映射
            next_id += 1
    
    return jsonify({'id': short_id}), 201

@app.route('/', methods=['DELETE'])
def delete_not_supported():
    abort(404)

@app.route('/', methods=['GET'])
def list_urls():
    # 列出所有映射的键
    keys = list(url_mapping.keys())
    return jsonify(keys), 200

@app.route('/<short_id>', methods=['GET'])
def redirect_to_url(short_id):
    # 根据提供的短ID重定向到URL
    original_url = url_mapping.get(short_id)
    if original_url:
        return redirect(original_url, code=301)
    else:
        abort(404)

@app.route('/<short_id>', methods=['PUT'])
def update_url(short_id):
    # 更新一个已存在的URL映射
    data = request.get_json()
    if 'url' not in data:
        return jsonify({'error': 'Error'}), 400
    if short_id in url_mapping:
        url_mapping[short_id] = data['url']
        return jsonify({}), 200
    else:
        abort(404)

@app.route('/<short_id>', methods=['DELETE'])
def delete_url(short_id):
    # 删除一个URL映射
    if short_id in url_mapping:
        del url_mapping[short_id]
        return jsonify({}), 204
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True)
