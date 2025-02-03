"""
Test unexpected interactions with the 'create' command and validators.

These may be a low impact issues. I expect a misconfiguration would be found quickly.
"""

from pymongo import MongoClient
import bson.binary
import uuid
import unittest

class TestCreateCmdsToMongocryptd(unittest.TestCase):
    def setUp(self):
        self.client = MongoClient("localhost:27020")
        keyid = bson.binary.Binary.from_uuid(uuid.uuid4())
        self.keyid = keyid
        self.json_schema = {
            "properties": {
                "csfleEncrypted": {
                    "encrypt": {
                        "bsonType": "string",
                        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                        "keyId": [keyid],
                    }
                }
            },
            "bsonType": "object",
        }

        self.encrypted_fields = {
            "fields": [{"keyId": keyid, "path": "qeEncrypted", "bsonType": "string"}],
        }
        return super().setUp()

    def tearDown(self):
        self.client.close()
        return super().tearDown()

    def testEncryptedFieldsArg (self):
        # Q: Is libmongocrypt expected to append encryptedFields argument as encryptionInformation?
        # A:
        cmd = {
            "create": "coll",
            "encryptedFields": self.encrypted_fields,
            "validator": {
                "qeEncrypted": "foo"
            },
            "jsonSchema": {},
            "isRemoteSchema": False
        }
        self.client["db"].command(cmd) # Unexpected: no error.

    def testEncryptedFieldsFromLocal (self):
        cmd = {
            "create": "coll",
            "encryptedFields": self.encrypted_fields,
            "validator": {
                "qeEncrypted": "foo"
            },
            "encryptionInformation": {
                "type": 1,
                "schema": {
                    "db.coll": self.encrypted_fields
                }
            }
        }
        with self.assertRaises(Exception) as eo:
            # Expected: Raises error.
            self.client["db"].command(cmd)
        self.assertIn ("Can only execute encrypted equality queries with an encrypted equality index", str(eo.exception))

    def testJSONSchemaWithUnrelatedValidator (self):
        # Q: Is mongocryptd expected to error for validators that do not refer to encrypted fields?
        # A:
        cmd = {
            "create": "coll",
            "validator": {
                "$jsonSchema": self.json_schema,
                "unrelated": "foo"
            },
            "jsonSchema": self.json_schema,
            "isRemoteSchema": False
        }
        with self.assertRaises(Exception) as eo:
            # Unexpected: Raises error.
            self.client["db"].command(cmd)
        self.assertIn ("Invalid match expression operator on encrypted field", str(eo.exception))

    def testJSONSchemaWithUnrelatedValidatorNoArg (self):
        cmd = {
            "create": "coll",
            "validator": {
                "unrelated": "foo"
            },
            "jsonSchema": self.json_schema,
            "isRemoteSchema": False
        }
        self.client["db"].command(cmd) # Expected: No error.

    def testJSONSchemaWithRelatedValidatorNoArg (self):
        cmd = {
            "create": "coll",
            "validator": {
                "csfleEncrypted": "foo"
            },
            "jsonSchema": self.json_schema,
            "isRemoteSchema": False
        }
        with self.assertRaises(Exception) as eo:
            # Expected: Raises error.
            self.client["db"].command(cmd)
        self.assertIn ("Comparison to encrypted fields not supported in collection validator", str(eo.exception))


    def testBoth (self):
        cmd = {
            "create": "coll",
            "validator": {
                "$jsonSchema": self.json_schema
            },
            "encryptionInformation": {
                "type": 1,
                "schema": {
                    "db.coll": { "fields": [{"keyId": self.keyid, "path": "csfleEncrypted", "bsonType": "string"}] }
                }
            }
        }
        with self.assertRaises(Exception) as eo:
            # Expected: Raises error.
            self.client["db"].command(cmd)
        self.assertIn ("Invalid match expression operator on encrypted field", str(eo.exception))

    def testIsRemoteSchema (self):
        cmd = {
            "find": "foo",
            "filter": {},
            "jsonSchema": {
                "properties": {
                    "csfleEncrypted": {
                        "encrypt": {
                            "bsonType": "string",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                            "keyId": [self.keyid],
                        }
                    },
                },
                "bsonType": "object",
                "required": ["foo", "bar"],
            },
            "isRemoteSchema": False
        }
        with self.assertRaises(Exception) as eo:
            # Expected: Raises error.
            self.client["db"].command(cmd)
        self.assertIn ("JSON schema keyword 'required' is only allowed with a remote schema", str(eo.exception))
        
        cmd["isRemoteSchema"] = True
        self.client["db"].command(cmd) # No error.
        


if __name__ == "__main__":
    unittest.main()
