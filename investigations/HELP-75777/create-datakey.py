import os

from pymongo import MongoClient
from pymongo.encryption import ClientEncryption

def main():
    certpath = os.environ["CERTPATH"]
    kms_providers = {"kmip": {"endpoint": "localhost:5698"}}
    client = MongoClient()

    client_encryption = ClientEncryption(
        kms_providers=kms_providers,
        kms_tls_options={
            "kmip": {
                "tlsCertificateKeyFile": certpath + "/client.pem",
                "tlsCAFile": certpath + "/ca.pem"
            }
        },
        key_vault_namespace="keyvault.datakeys",
        key_vault_client=client,
        codec_options=client.codec_options
    )

    # Create a new data key for the encryptedField.
    data_key_id = client_encryption.create_data_key("kmip", {
        "delegated": True,
        "keyId": "11" # Refers to a symmetric key in KMIP
    })
    print (f"created data key with id: {data_key_id}")

    # Cleanup resources.
    client_encryption.close()
    client.close()


if __name__ == "__main__":
    main()
