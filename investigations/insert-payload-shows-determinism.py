# Run with: uv run insert-payload-shows-determinism.py
#
# /// script
# dependencies = [
#   "pymongo[encryption]",
# ]
# ///

import os
from pymongo import MongoClient
from pymongo.encryption import (
    Algorithm,
    ClientEncryption
)
import bson


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"
    key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

    client = MongoClient()
    key_vault = client[key_vault_db_name][key_vault_coll_name]
    key_vault.drop()

    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )

    # Create a new data key for the encryptedField.
    key_id = client_encryption.create_data_key("local")

    # Create encrypted payloads:
    payload1 = client_encryption.encrypt("a", contention_factor=100, algorithm=Algorithm.INDEXED, key_id=key_id)
    l1 = bson.decode(payload1[1:])["l"]

    payload2 = client_encryption.encrypt("a", contention_factor=100, algorithm=Algorithm.INDEXED, key_id=key_id)
    l2 = bson.decode(payload2[1:])["l"]

    payload3 = client_encryption.encrypt("b", contention_factor=100, algorithm=Algorithm.INDEXED, key_id=key_id)
    l3 = bson.decode(payload3[1:])["l"]

    assert l1 == l2 # ServerDerivedFromDataToken is deterministic for the same value and key.
    assert l1 != l3 # Sanity-check: different values produce different ServerDerivedFromDataTokens.


    # Cleanup resources.
    client_encryption.close()
    client.close()


if __name__ == "__main__":
    main()
