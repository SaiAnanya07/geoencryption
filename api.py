from flask import Flask, request, jsonify
from cs_proj import SecureCrypto, GPSLocation
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='audit.log'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
crypto = SecureCrypto()  # Initialize once; store master_key securely in production

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        logger.info(f"Received encryption request: {data}")
        
        message = data['message']
        
        # Only accept decryption location (no sender's location required)
        decryption_lat = float(data['decryption_latitude'])
        decryption_lon = float(data['decryption_longitude'])
        
        expiry = data.get('expiry', int(time.time()) + 86400)  # Default to 24 hours if not provided
        
        allowed_loc = GPSLocation(latitude=decryption_lat, longitude=decryption_lon)
        encrypted = crypto.encrypt(message, allowed_loc, expiry)
        logger.info(f"Encryption successful for decryption at ({decryption_lat}, {decryption_lon})")
        return jsonify(encrypted)
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        logger.info(f"Received decryption request: {data}")
        
        encrypted_package = {
            'metadata': data['metadata'],
            'ciphertext': data['ciphertext']
        }
        lat = float(data['latitude'])
        lon = float(data['longitude'])
        
        current_loc = GPSLocation(latitude=lat, longitude=lon)
        decrypted = crypto.decrypt(encrypted_package, current_loc)
        if decrypted:
            logger.info("Decryption successful, returning plaintext")
            return jsonify({'result': decrypted.decode('utf-8')})
        logger.warning("Decryption failed, returning Access denied")
        return jsonify({'result': 'Access denied'})
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    import time
    app.run(debug=True, host='0.0.0.0', port=5000)

'''
from flask import Flask, request, jsonify
from cs_proj import SecureCrypto, GPSLocation
import logging

# Set up logging (mirror crypto.py for consistency)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='audit.log'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
crypto = SecureCrypto()  # Initialize once; store master_key securely in production

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        logger.info(f"Received encryption request: {data}")
        
        message = data['message']
        
        # Get decryption location (optional; defaults to sender's location if not provided)
        decryption_lat = float(data.get('decryption_latitude', data['latitude']))
        decryption_lon = float(data.get('decryption_longitude', data['longitude']))
        
        lat = float(data['latitude'])  # Sender's location (for logging)
        lon = float(data['longitude'])
        expiry = data.get('expiry')
        
        allowed_loc = GPSLocation(latitude=decryption_lat, longitude=decryption_lon)
        encrypted = crypto.encrypt(message, allowed_loc, expiry)
        logger.info(f"Encryption successful for decryption at ({decryption_lat}, {decryption_lon})")
        return jsonify(encrypted)
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        logger.info(f"Received decryption request: {data}")
        
        encrypted_package = {
            'metadata': data['metadata'],
            'ciphertext': data['ciphertext']
        }
        lat = float(data['latitude'])
        lon = float(data['longitude'])
        
        current_loc = GPSLocation(latitude=lat, longitude=lon)
        decrypted = crypto.decrypt(encrypted_package, current_loc)
        if decrypted:
            logger.info("Decryption successful, returning plaintext")
            return jsonify({'result': decrypted.decode('utf-8')})
        logger.warning("Decryption failed, returning Access denied")
        return jsonify({'result': 'Access denied'})
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

    '''