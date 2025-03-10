import math
import os
import time
import base64
import json
import logging
from math import radians, sin, cos, sqrt, atan2
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dataclasses import dataclass
from typing import Optional, Dict, Union

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='audit.log'  # Optional: Logs to a file (remove for console-only)
)
logger = logging.getLogger(__name__)

@dataclass
class GPSLocation:
    latitude: float
    longitude: float
    
    def is_within_range(self, other_location: 'GPSLocation', tolerance_km: float = 1.0) -> bool:
        """Check if current location is within tolerance (in km) using Haversine formula"""
        R = 6371  # Earth's radius in km
        lat1, lon1 = radians(self.latitude), radians(self.longitude)
        lat2, lon2 = radians(other_location.latitude), radians(other_location.longitude)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance = R * c
        
        logger.info(f"Distance between ({self.latitude}, {self.longitude}) and "
                   f"({other_location.latitude}, {other_location.longitude}): {distance:.2f} km "
                   f"(Tolerance: {tolerance_km} km)")
        return distance <= tolerance_km

class SecureCrypto:
    def __init__(self, master_key: bytes = None):
        self.master_key = master_key if master_key else os.urandom(32)
        logger.info("SecureCrypto initialized with master key")

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a unique key from the master key using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(self.master_key)
        logger.info("Encryption key derived from master key and salt")
        return key

    def encrypt(self, data: Union[str, bytes], allowed_location: GPSLocation, expiry_time: Optional[int] = None) -> Dict[str, str]:
        """Encrypt data with ChaCha20, restricting decryption to a GPS location and optional expiry"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        nonce = os.urandom(12)
        salt = os.urandom(16)
        key = self._derive_key(salt)
        cipher = ChaCha20Poly1305(key)
        
        metadata = {
            'allowed_lat': allowed_location.latitude,
            'allowed_lon': allowed_location.longitude,
            'expiry': expiry_time,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8')
        }
        
        logger.info(f"Encrypting data for location ({allowed_location.latitude}, {allowed_location.longitude}) "
                   f"with expiry {expiry_time if expiry_time else 'None'}")
        encrypted_data = cipher.encrypt(
            nonce,
            data,
            json.dumps(metadata).encode('utf-8')
        )
        
        result = {
            'metadata': json.dumps(metadata),
            'ciphertext': base64.b64encode(encrypted_data).decode('utf-8')
        }
        logger.info("Encryption successful")
        return result

    def decrypt(self, encrypted_package: Dict[str, str], current_location: GPSLocation) -> Optional[bytes]:
        """Attempt to decrypt data if current location matches allowed location and not expired"""
        metadata = json.loads(encrypted_package['metadata'])
        ciphertext = base64.b64decode(encrypted_package['ciphertext'])
        
        logger.info(f"Attempting decryption for location ({current_location.latitude}, {current_location.longitude}) "
                   f"against allowed location ({metadata['allowed_lat']}, {metadata['allowed_lon']}) "
                   f"with expiry {metadata['expiry']}")
        
        # Check expiry
        if metadata['expiry'] and int(time.time()) > metadata['expiry']:
            logger.warning("Decryption failed: Message has expired")
            return None
        
        # Verify location
        allowed_location = GPSLocation(latitude=metadata['allowed_lat'], longitude=metadata['allowed_lon'])
        if not current_location.is_within_range(allowed_location):
            logger.warning("Decryption failed: Current location outside allowed zone")
            return None
        
        # Decrypt
        salt = base64.b64decode(metadata['salt'])
        key = self._derive_key(salt)
        nonce = base64.b64decode(metadata['nonce'])
        cipher = ChaCha20Poly1305(key)
        
        try:
            decrypted = cipher.decrypt(
                nonce,
                ciphertext,
                json.dumps(metadata).encode('utf-8')
            )
            logger.info("Decryption successful")
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed due to cryptographic error: {str(e)}")
            return None