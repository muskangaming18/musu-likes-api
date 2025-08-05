from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

async def fetch_all_tokens():
    urls = [
        "https://free-fire-india-six.vercel.app/token",
        "https://free-fire-india-five.vercel.app/token",
        "https://free-fire-india-four.vercel.app/token",
        "https://free-fire-india-tthree.vercel.app/token",
        "https://free-fire-india-two.vercel.app/token"
    ]
    all_tokens = []
    try:
        async with aiohttp.ClientSession() as session:
            tasks = [session.get(url) for url in urls]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for response in responses:
                if isinstance(response, Exception):
                    continue
                if response.status != 200:
                    continue
                data = await response.json()
                tokens = data.get("tokens", [])
                if not tokens:
                    continue
                all_tokens.extend(tokens)
        return all_tokens if all_tokens else None
    except Exception as e:
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return await response.text() if response.status == 200 else None
    except Exception:
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if not protobuf_message:
            return None

        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid:
            return None

        tokens = await fetch_all_tokens()
        if not tokens:
            return None

        tasks = [send_request(encrypted_uid, token, url) for token in tokens]
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception:
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception:
        return None

def make_request(encrypt, server_name, token):
    try:
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow" if server_name == "IND" else \
              "https://client.us.freefiremobile.com/GetPlayerPersonalShow" if server_name in {"BR", "US", "SAC", "NA"} else \
              "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        return decode_protobuf(response.content)
    except Exception:
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()
    key = request.args.get("key")

    if not all([uid, server_name, key]):
        return jsonify({"error": "Missing parameters"}), 400

    if key != "2weekskeysforujjaiwal":
        return jsonify({"error": "Invalid API key"}), 403

    try:
        # Initial data fetch
        tokens_data = requests.get("https://free-fire-india-six.vercel.app/token").json()
        token = tokens_data.get("tokens", [None])[0]
        if not token:
            raise Exception("No tokens available")

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption failed")

        before = make_request(encrypted_uid, server_name, token)
        if not before:
            raise Exception("Initial request failed")

        # Like processing
        like_url = "https://client.ind.freefiremobile.com/LikeProfile" if server_name == "IND" else \
                  "https://client.us.freefiremobile.com/LikeProfile" if server_name in {"BR", "US", "SAC", "NA"} else \
                  "https://clientbp.ggblueshark.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, server_name, like_url))

        # Final data fetch
        after = make_request(encrypted_uid, server_name, token)
        if not after:
            raise Exception("Final request failed")

        return jsonify({
            "status": "success",
            "data": {
                "uid": uid,
                "region": server_name
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)