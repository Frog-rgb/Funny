import base64
import json
import sys
import hmac
import hashlib


def base64url_decode(input_str):
    rem = len(input_str) % 4
    if rem > 0:
        input_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input_str.encode())


def decode_jwt(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        header = json.loads(base64url_decode(header_b64))
        payload = json.loads(base64url_decode(payload_b64))

        print("\n🔐 JWT Header:")
        print(json.dumps(header, indent=4))
        print("\n📦 JWT Payload:")
        print(json.dumps(payload, indent=4))
        print("\n🔏 JWT Signature (Base64):")
        print(signature_b64)

        return header, payload, signature_b64
    except Exception as e:
        print(f"[!] Failed to decode JWT: {e}")
        return None


def forge_jwt(header, payload, secret, algorithm='HS256'):
    try:
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

        if algorithm.upper() == 'HS256':
            sig = hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        else:
            raise ValueError("Only HS256 is supported in this module.")

        signature_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
        forged_token = f"{header_b64}.{payload_b64}.{signature_b64}"

        print("\n✅ Forged JWT:")
        print(forged_token)
        return forged_token
    except Exception as e:
        print(f"[!] Error forging JWT: {e}")


if __name__ == "__main__":
    print("=== JWT Decoder / Forger ===")
    choice = input("Do you want to (d)ecode or (f)orge a JWT? ").lower()

    if choice == 'd':
        token = input("Paste JWT: ").strip()
        decode_jwt(token)

    elif choice == 'f':
        header = json.loads(input("Enter header JSON: "))
        payload = json.loads(input("Enter payload JSON: "))
        secret = input("Enter shared secret (HMAC key): ").strip()
        forge_jwt(header, payload, secret)

    else:
        print("Invalid choice.")