import argparse

from cryptography.fernet import Fernet
import argparse
import json
import base64

def main():
    parser = argparse.ArgumentParser(description='Load secrets from Azure Key Vault into environment variables.')
    parser.add_argument('-k', '--key', help='The Azure service principals', required=True)
    parser.add_argument('-j', '--json', help='The JSON file containing secrets to load', required=True)
    parser.add_argument('-c', '--command', nargs='+', help='The command to run after loading secrets', required=True)
    parser.add_argument('-u', '--url', help='The URL of your Azure Key Vault', required=True)
    args = parser.parse_args()

    print(f'Key: {args.key}')
    print(f'JSON: {args.json}')
    print(f'Command: {args.command}')

    # TODO: Add your logic here

    # Create a secret client using the service principals
    credential = ClientSecretCredential(key_data['tenantId'], key_data['clientId'], key_data['clientSecret'])
    secret_client = SecretClient(vault_url=key_data['vaultUrl'], credential=credential)

    # Load the secret-envvar mapping from the json file
    with open(args.json, 'r') as json_file:
        secret_mapping = json.load(json_file)

    # Fetch each secret and set it as an environment variable
    for secret_name, envvar_name in secret_mapping.items():
        secret = secret_client.get_secret(secret_name)
        os.environ[envvar_name] = secret.value

    # Run the command with the loaded environment variables
    subprocess.run(args.command)



def obfuscate_service_principals():
    parser = argparse.ArgumentParser(description='Obfuscate Azure service principals.')
    parser.add_argument('-j', '--json', help='The JSON file containing service principals to obfuscate', required=True)
    parser.add_argument('-o', '--output', help='The output file for the obfuscated service principals', required=True)
    parser.add_argument('-k', '--key', help='The key for obfuscation', required=True)
    args = parser.parse_args()

    # Load service principals from JSON file
    with open(args.json, 'r') as f:
        service_principals = json.load(f)

    # Encode the key, ensure it's 32 bytes long
    padded_key = (args.key[:32] + (32 * '0'))[:32]
    encoded_key = base64.urlsafe_b64encode(padded_key.encode())

    # Obfuscate service principals
    fernet = Fernet(encoded_key)
    obfuscated_service_principals = fernet.encrypt(json.dumps(service_principals).encode())

    # Write obfuscated service principals to output file
    with open(args.output, 'wb') as f:
        f.write(obfuscated_service_principals)

    print(f'Service principals obfuscated and written to: {args.output}')
