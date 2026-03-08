# common/protocol.py

import json


# DHCP messages
DISCOVER = "DISCOVER"
OFFER = "OFFER"
REQUEST = "REQUEST"
ACK = "ACK"

# DNS messages
RESOLVE = "RESOLVE"
RESOLVE_OK = "RESOLVE_OK"

# FTP messages
FTP_LIST = "FTP_LIST"
FTP_GET = "FTP_GET"
FTP_PUT = "FTP_PUT"
FTP_OK = "FTP_OK"
FTP_DATA = "FTP_DATA"

# General messages
ERROR = "ERROR"


# All known message types
MESSAGE_TYPES = {
    DISCOVER,
    OFFER,
    REQUEST,
    ACK,
    RESOLVE,
    RESOLVE_OK,
    FTP_LIST,
    FTP_GET,
    FTP_PUT,
    FTP_OK,
    FTP_DATA,
    ERROR
}


def make_message(msg_type, payload=None):
    # Create a standard message in our protocol format
    if payload is None:
        payload = {}

    return {
        "type": msg_type,
        "payload": payload
    }


def make_error_message(error_text):
    # Create a simple error message
    return {
        "type": ERROR,
        "payload": {
            "message": error_text
        }
    }


def encode_message(message):
    # Convert Python dictionary into JSON bytes
    if not is_valid_message(message):
        raise ValueError("Invalid message format")

    return (json.dumps(message) + "\n").encode("utf-8")


def decode_message(data):
    # Convert bytes into Python dictionary
    if isinstance(data, bytes):
        data = data.decode("utf-8")

    # Remove extra spaces/newlines
    data = data.strip()

    # Convert JSON text into dictionary
    message = json.loads(data)

    if not is_valid_message(message):
        raise ValueError("Invalid message format")

    return message


def is_valid_message(message):
    # Check if the message format is correct
    if not isinstance(message, dict):
        return False

    if "type" not in message:
        return False

    if "payload" not in message:
        return False

    if not isinstance(message["type"], str):
        return False

    if not isinstance(message["payload"], dict):
        return False

    if message["type"] not in MESSAGE_TYPES:
        return False

    return True


def get_message_type(message):
    # Return the type of the message
    return message["type"]


def get_payload(message):
    # Return the payload of the message
    return message["payload"]


def is_message_type(message, msg_type):
    # Check if this message is from a certain type
    return get_message_type(message) == msg_type