"""
Test commands to mongocryptd. To run, start mongocryptd.
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
