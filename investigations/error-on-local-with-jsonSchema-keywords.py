"""
If a local schema is configured with JSON schema keywords, an error is returned by query analysis
"""

import os
from pymongo import MongoClient
from pymongo.encryption import AutoEncryptionOpts


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"
    key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

    # Set up the key vault (key_vault_namespace) for this example.
    client = MongoClient()
    key_vault = client[key_vault_db_name][key_vault_coll_name]

    key_vault.drop()


    opts = AutoEncryptionOpts(
        kms_providers,
        key_vault.full_name,
        key_vault_client=client,
        schema_map={
            "db.coll": { "required": ["foo"] }
        }
    )

    client = MongoClient(auto_encryption_opts=opts)
    client.drop_database("db")
    client["db"]["coll"].insert_one({}) # Exception: JSON schema keyword 'required' is only allowed with a remote schema


    client.close()
    client.close()


if __name__ == "__main__":
    main()
