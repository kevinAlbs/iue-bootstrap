"""
Test behavior of CSFLE schemas.

To run:
    Start mongocryptd and mongod.
    python -m pip install 'pymongo[encryption]'
    python test-jsonSchemas.py
"""

import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import Algorithm, ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
from bson import Binary

import unittest


class TestCSFLESchema(unittest.TestCase):
    def setUp(self):
        self.client = MongoClient()
        self.client["keyvault"]["datakeys"].drop()

        self.kms_providers = {"local": {"key": os.urandom(96)}}
        client_encryption = ClientEncryption(
            self.kms_providers,
            "keyvault.datakeys",
            self.client,
            CodecOptions(),
        )

        self.keyid = client_encryption.create_data_key("local")
    
    def test_pattern_properties(self):
        """
        Q: Can “properties” and “patternProperties” be used together?
        A: Yes.
        """
        schema = {
            "patternProperties": {
                "^encrypted": {
                    "encrypt": {
                        "keyId": [self.keyid],
                        "bsonType": "string",
                        "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                    }
                }
            },
            "properties": {
                "csfle": {
                    "encrypt": {
                        "keyId": [self.keyid],
                        "bsonType": "string",
                        "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                    }
                }
            },
            "bsonType": "object"
        }

        self.client["db"]["coll"].drop()
        # Create collection with remote schema to reject plaintext for encrypted fields server-side.
        self.client["db"].create_collection(
            "coll", validator={"$jsonSchema": schema}
        )

        encrypted_client = MongoClient(
            auto_encryption_opts=AutoEncryptionOpts(
                kms_providers=self.kms_providers,
                key_vault_namespace="keyvault.datakeys",
                mongocryptd_bypass_spawn=True,
                schema_map={
                    "db.coll": schema
                }
            )
        )
        encrypted_client["db"]["coll"].insert_one({"csfle": "foo", "encrypted_string": "bar"})
        # Find document with unencrypted client. Expect data is encrypted.
        got = self.client["db"]["coll"].find_one()
        self.assertEqual(type(got["csfle"]), Binary) # Encrypted.
        self.assertEqual(type(got["encrypted_string"]), Binary) # Encrypted.
        encrypted_client.close()

    def test_encrypteMetadata_subdocument(self):
        """
        Q: Is it possible to use “encryptMetadata” in a subdocument?
        A: Yes.
        """
        schema = {
            "properties": {
                "subdoc": {
                    "bsonType": "object",
                    "encryptMetadata": {
                        "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                        "keyId": [self.keyid]
                    },
                    "properties": {
                        "csfle": {
                            "encrypt": {
                                "bsonType": "string",
                            }
                        }
                    }
                    
                }
            },
            "bsonType": "object"
        }

        self.client["db"]["coll"].drop()
        # Create collection with remote schema to reject plaintext for encrypted fields server-side.
        self.client["db"].create_collection(
            "coll", validator={"$jsonSchema": schema}
        )

        encrypted_client = MongoClient(
            auto_encryption_opts=AutoEncryptionOpts(
                kms_providers=self.kms_providers,
                key_vault_namespace="keyvault.datakeys",
                mongocryptd_bypass_spawn=True,
                schema_map={
                    "db.coll": schema
                }
            )
        )
        encrypted_client["db"]["coll"].insert_one({"subdoc": { "csfle": "foo" }})
        # Find document with unencrypted client. Expect data is encrypted.
        got = self.client["db"]["coll"].find_one()
        self.assertEqual(type(got["subdoc"]["csfle"]), Binary) # Encrypted.
        encrypted_client.close()

    def test_encrypteMetadata_subdocument_patternProperties(self):
        """
        Q: Is it possible to use “encryptMetadata” in a subdocument via patternProperties?
        A: Yes.
        """
        schema = {
            "properties": {
                "subdoc": {
                    "bsonType": "object",
                    "encryptMetadata": {
                        "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                        "keyId": [self.keyid]
                    },
                    "patternProperties": {
                        "^csfle": {
                            "encrypt": {
                                "bsonType": "string",
                            }
                        }
                    }
                    
                }
            },
            "bsonType": "object"
        }

        self.client["db"]["coll"].drop()
        # Create collection with remote schema to reject plaintext for encrypted fields server-side.
        self.client["db"].create_collection(
            "coll", validator={"$jsonSchema": schema}
        )

        encrypted_client = MongoClient(
            auto_encryption_opts=AutoEncryptionOpts(
                kms_providers=self.kms_providers,
                key_vault_namespace="keyvault.datakeys",
                mongocryptd_bypass_spawn=True,
                schema_map={
                    "db.coll": schema
                }
            )
        )
        encrypted_client["db"]["coll"].insert_one({"subdoc": { "csfle": "foo" }})
        # Find document with unencrypted client. Expect data is encrypted.
        got = self.client["db"]["coll"].find_one()
        self.assertEqual(type(got["subdoc"]["csfle"]), Binary) # Encrypted.
        encrypted_client.close()

    def tearDown(self):
        self.client.close()


unittest.main()
