"""Append-only transcript + TranscriptHash helpers.""" 
"""
Utility Module - Helper Functions
Helper signatures: now_ms, b64e, b64d, sha256_hex and additional utilities.
"""

import os
import time
import base64
import secrets
import hashlib
import re

def now_ms():
    """Get current Unix timestamp in milliseconds."""
    return int(time.time() * 1000)

def b64e(b: bytes):
    """Base64 encode bytes."""
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str):
    """Base64 decode string."""
    return base64.b64decode(s)

def sha256_hex(data: bytes):
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def generate_nonce(length=16):
    """Generate a random nonce."""
    return secrets.token_bytes(length)

def generate_salt(length=16):
    """Generate a random salt for password hashing."""
    return secrets.token_bytes(length)

def bytes_to_base64(data):
    """Convert bytes to base64 string (alias for b64e)."""
    return b64e(data)

def base64_to_bytes(b64_string):
    """Convert base64 string to bytes (alias for b64d)."""
    return b64d(b64_string)

def format_certificate_info(cert_info):
    """Format certificate information for display."""
    return f"""
Certificate Information:
  Subject: {cert_info['subject']}
  Issuer: {cert_info['issuer']}
  Serial Number: {cert_info['serial_number']}
  Valid From: {cert_info['not_valid_before']}
  Valid Until: {cert_info['not_valid_after']}
  Fingerprint (SHA-256): {cert_info['fingerprint']}
    """.strip()

def send_message(socket, message):
    """Send a message over a socket with length prefix."""
    message_bytes = message.encode('utf-8')
    length = len(message_bytes)
    socket.sendall(length.to_bytes(4, byteorder='big'))
    socket.sendall(message_bytes)

def receive_message(socket):
    """Receive a message from a socket with length prefix."""
    length_bytes = _receive_exact(socket, 4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, byteorder='big')
    message_bytes = _receive_exact(socket, length)
    if not message_bytes:
        return None
    return message_bytes.decode('utf-8')

def _receive_exact(socket, length):
    """Receive exact number of bytes from socket."""
    data = b''
    while len(data) < length:
        chunk = socket.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def validate_email(email):
    """Basic email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Validate username (alphanumeric, underscore, 3-20 chars)."""
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def validate_password(password):
    """Validate password strength (min 8 chars)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    return True, "Password valid"

def clear_screen():
    """Clear console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner(title):
    """Print a formatted banner."""
    width = 60
    print("\n" + "=" * width)
    print(title.center(width))
    print("=" * width + "\n")

def constant_time_compare(a, b):
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
