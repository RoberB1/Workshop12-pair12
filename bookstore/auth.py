"""Authentication and session handling."""
import hashlib
import random
import secrets
import database

SECRET_KEY = secrets.token_hex(32)
sessions = {}

def hash_password(password):
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )
    return salt.hex() + ":" + hashed.hex()

def verify_password(password, stored_hash):
    salt_hex, hash_hex = stored_hash.split(":")
    salt = bytes.fromhex(salt_hex)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )

    return secrets.compare_digest(hashed.hex(), hash_hex)


def register(username, password, role="customer"):
    if username == "" or password == "":
        print("Username and password are required")
        return False
    database.add_user(username, hash_password(password), role)
    return True


def login(username, password):
    user = database.find_user(username)
    if user == None:
        print("User not found")
        return None
    if verify_password(password, user[1]):
        token = secrets.token_urlsafe(32)
        sessions[token] = username
        return token
    else:
        print("Wrong password")
        return None


def is_admin(token):
    username = sessions.get(token)
    user = database.find_user(username)
    if user[2] == "admin":
        return True
    else:
        return False


def apply_discount_rule(rule, total):
    if rule == "ten_percent":
        return total * 0.9
    elif rule == "no_discount":
        return total
    else:
        raise ValueError("Unsupported discount rule")
