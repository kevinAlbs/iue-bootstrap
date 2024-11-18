import os

from pymongo import MongoClient
from pymongo.encryption import ClientEncryption


def main():
    # Use a named KMS provider:
    kms_providers = {"local:my_local_provider": {"key": os.urandom(96)}}
    client = MongoClient()

    client_encryption = ClientEncryption(
        kms_providers=kms_providers,
        key_vault_namespace="keyvault.datakeys",
        key_vault_client=client,
        codec_options=client.codec_options
    )

    # Create a new data key for the encryptedField.
    data_key_id = client_encryption.create_data_key("local:my_local_provider")
    print (f"created data key with id: {data_key_id}")

    # Cleanup resources.
    client_encryption.close()
    client.close()


if __name__ == "__main__":
    main()
