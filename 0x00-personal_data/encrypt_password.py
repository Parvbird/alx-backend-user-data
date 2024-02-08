#!/usr/bin/env python3
"""
Defined hash_password function to return hashed password
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Returns hashed password
    Args:
        password (str): password to be hashed
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if password is valid
    Args:
        hashed_password (bytes): hashed password
        password (str): password string
    Return:
        a boolean
    """
    return bcrypt.checkpw(password.encode(), hashed_password)