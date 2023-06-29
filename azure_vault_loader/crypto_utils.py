import base64
import json

from cryptography.fernet import Fernet

def decrypt_service_principals(obfuscation_key, encrypted_principals):
    # Ensure the obfuscation key is 32 bytes long
    padded_key = (obfuscation_key[:32] + (32 * '0'))[:32]
    encoded_key = base64.urlsafe_b64encode(padded_key.encode())

    # Create a Fernet cipher
    fernet = Fernet(encoded_key)

    # Decode and decrypt the service principals
    decrypted_service_principals = fernet.decrypt(encrypted_principals)
    return json.loads(decrypted_service_principals.decode())

def obfuscate_service_principals(obfuscation_key,principals):
    # Encode the key, ensure it's 32 bytes long
    padded_key = (args.key[:32] + (32 * '0'))[:32]
    encoded_key = base64.urlsafe_b64encode(padded_key.encode())

    # Obfuscate service principals
    fernet = Fernet(encoded_key)
    return fernet.encrypt(json.dumps(service_principals).encode())