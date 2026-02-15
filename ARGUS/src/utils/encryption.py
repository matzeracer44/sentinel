"""
Encryption utilities for ARGUS Security Tool
Provides AES-256 encryption for sensitive data
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import hashlib

class EncryptionManager:
    def __init__(self, password: str = None):
        self.password = password or os.environ.get('ARGUS_KEY', 'default-key-change-me')
        self.salt = b'argus_panoptes_2024'  # In production, use random salt per encryption
        self.key = self._derive_key()
        self.fernet = Fernet(self.key)
    
    def _derive_key(self) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not data:
            return data
        encrypted_data = self.fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        if not encrypted_data:
            return encrypted_data
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def encrypt_dict(self, data: dict) -> str:
        """Encrypt dictionary data"""
        json_str = json.dumps(data)
        return self.encrypt(json_str)
    
    def decrypt_dict(self, encrypted_data: str) -> dict:
        """Decrypt to dictionary"""
        decrypted_json = self.decrypt(encrypted_data)
        return json.loads(decrypted_json)
    
    def hash_data(self, data: str) -> str:
        """Create SHA-256 hash of data"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def generate_key(self) -> str:
        """Generate new encryption key"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()

# Global encryption instance
encryption = EncryptionManager()
