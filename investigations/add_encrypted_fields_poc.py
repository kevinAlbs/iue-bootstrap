"""
This is a sketch of an API for add_encrypted_fields for WRITING-29014.
"""

from pymongo import MongoClient
from pymongo.encryption import ClientEncryption

def with_helper (ce : ClientEncryption, client : MongoClient, kms_providers: dict):
    """
    Add two encrypted fields with a proposed `add_encrypted_fields` helper.
    """
    ef = {
        "fields": [
            {
                "keyId": None,  # Specify `None` (BSON null) to have driver create key.
                "path": "secret",
                "bsonType": "string"
            },
            {
                "keyId": None,  # Specify `None` (BSON null) to have driver create key.
                "path": "queryableSecret",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }
    ef = ce.add_encrypted_fields(
        client["db"]["coll"],
        encrypted_fields=ef,
        kms_provider="local",
    )
    # `add_encrypted_fields` returns input with newly created key IDs:
    assert ef["fields"][0]["keyId"] is not None
    assert ef["fields"][1]["keyId"] is not None

def without_helper (ce : ClientEncryption, client : MongoClient, kms_providers: dict):
    """
    Create a QE collection with two encrypted fields without using create_encrypted_collection.
    """
    keyid1 = ce.create_data_key ("local")
    keyid2 = ce.create_data_key ("local")
    ef = {
        "fields": [
            {
                "keyId": keyid1,
                "path": "secret",
                "bsonType": "string"
            },
            {
                "keyId": keyid2,
                "path": "queryableSecret",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }

    client["db"].command({
        "collMod": "coll",
        "addEncryptedFields": ef
    })
