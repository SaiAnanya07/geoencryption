from flask import Flask, render_template, request, redirect, session, jsonify
import firebase_admin
from firebase_admin import credentials, firestore
from geopy.distance import geodesic
from math import radians, sin, cos, sqrt, atan2
from cs_proj import SecureCrypto, GPSLocation
import logging
import time
import os

firebase_config = {
    "type": "service_account",
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace('\\n', '\n'),  # Ensure key formatting
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
}

cred = credentials.Certificate(firebase_config)
firebase_admin.initialize_app(cred)
app = Flask(__name__)
app.secret_key = 'your_secret_key'

db = firestore.client()
crypto = SecureCrypto()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='audit.log')
logger = logging.getLogger(__name__)

def haversine(lat1, lon1, lat2, lon2):
    R = 6371  # Radius of the Earth in km
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c 

@app.route('/')
def home():
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        users_ref = db.collection("users").document(username)
        
        if users_ref.get().exists:
            return "Username already exists. Choose another one."
        
        users_ref.set({
            'name': name,
            'email': email,
            'password': password
        })
        
        db.collection(username).document("info").set({})
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users_ref = db.collection("users").document(username).get()
        
        if users_ref.exists and users_ref.to_dict().get('password') == password:
            session['username'] = username
            return redirect('/profile')
        return "Invalid credentials. Try again."
    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']

    if request.method == 'POST':  # AJAX request to fetch messages
        data = request.get_json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        if latitude is None or longitude is None:
            return jsonify({"error": "Missing latitude or longitude"}), 400

        messages_ref = db.collection(username).document("messages").collection("inbox").stream()
        visible_messages = []

        for doc in messages_ref:
            msg_data = doc.to_dict()
            allowed_lat = msg_data.get('allowed_latitude')
            allowed_lon = msg_data.get('allowed_longitude')

            # Calculate distance between user location and allowed decryption location
            distance_km = haversine(latitude, longitude, allowed_lat, allowed_lon)
            print(f"User Location: ({latitude}, {longitude}), Allowed: ({allowed_lat}, {allowed_lon}), Distance: {distance_km} km")
            if distance_km <= 20:  # If within 500m (0.5km), decrypt message
                print(msg_data['metadata'])
                decrypted_message = crypto.decrypt(
                    {'metadata': msg_data['metadata'], 'ciphertext': msg_data['ciphertext']}, 
                    GPSLocation(allowed_lat, allowed_lon)
                )

                msg_data['message'] = decrypted_message.decode('utf-8') if decrypted_message else "Access Denied"
            else:
                msg_data['message'] = "Access Denied (Outside Allowed Location)"

            visible_messages.append({
                'sender': msg_data['sender'],
                'message': msg_data['message']
            })

        return jsonify({"messages": visible_messages})  # Return messages as JSON

    # If GET request, render the profile page
    return render_template('profile.html', username=username)

@app.route('/send_message', methods=['GET', 'POST'])
def send_message():
    if request.method == 'POST':
        if 'username' not in session:
            return redirect('/login')

        recipient = request.form.get('username')
        message = request.form.get('message')
        decryption_lat = request.form.get('latitude')
        decryption_lon = request.form.get('longitude')

        # Ensure values are not None before converting
        if decryption_lat is None or decryption_lon is None:
            return "Decryption latitude and longitude are required.", 400
        
        try:
            decryption_lat = round(float(decryption_lat), 4)
            decryption_lon = round(float(decryption_lon), 4)
        except ValueError:
            return "Invalid latitude or longitude format.", 400
        
        recipient_ref = db.collection(recipient).document("info").get()
        if not recipient_ref.exists:
            return "User does not exist."

        expiry_time = int(time.time()) + 86400  # 24 hours expiry
        
        allowed_loc = GPSLocation(latitude=decryption_lat, longitude=decryption_lon)
        encrypted = crypto.encrypt(message, allowed_loc, expiry_time)

        message_doc = db.collection(recipient).document("messages").collection("inbox").document()
        message_doc.set({
            'metadata': encrypted['metadata'],
            'ciphertext': encrypted['ciphertext'],
            'sender': session['username'],
            'expiry': expiry_time,
            'allowed_latitude': decryption_lat,
            'allowed_longitude': decryption_lon,
            'timestamp': int(time.time())  # Store message send time
        })

        return redirect('/profile')
    
    return render_template('send_message.html')
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
