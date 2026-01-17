"""
Test file with intentional security vulnerabilities
Used to test SemgrepGuard extension
"""
import os
import sqlite3
import subprocess
import hashlib

# SQL Injection Vulnerability
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# Command Injection Vulnerability
def run_command(filename):
    # VULNERABLE: Command injection
    os.system(f"cat {filename}")

# Hardcoded Secret
API_KEY = "sk-1234567890abcdef"  # VULNERABLE: Hardcoded secret
PASSWORD = "admin123"  # VULNERABLE: Hardcoded password

# Weak Hashing
def hash_password(password):
    # VULNERABLE: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# Insecure Deserialization
import pickle
def load_data(data):
    # VULNERABLE: Arbitrary code execution via pickle
    return pickle.loads(data)

# Path Traversal
def read_file(filename):
    # VULNERABLE: Path traversal
    with open(f"/app/data/{filename}", 'r') as f:
        return f.read()

# Subprocess Shell Injection
def process_input(user_input):
    # VULNERABLE: Shell injection
    subprocess.call(f"echo {user_input}", shell=True)

# Debug Mode Left On (example pattern)
DEBUG = True  # Should be False in production

if __name__ == "__main__":
    print("Test file for SemgrepGuard")
