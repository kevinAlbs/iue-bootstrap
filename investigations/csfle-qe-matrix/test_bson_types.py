# Run with: uv
#
# /// script
# dependencies = [
#   "pymongo[encryption]",
# ]
# ///

import os
from datetime import datetime
from unittest import TestCase

from bson import Decimal128, Int64, Timestamp
from bson.binary import Binary
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts


class TestBsonTypes(TestCase):
    def setUp(self):
        # Setup code for the test case
        local_master_key = os.urandom(96)
        self.kms_providers = {"local": {"key": local_master_key}}
        self.client = MongoClient()
        self.key_vault_namespace = "keyvault.datakeys"
        self.client_encryption = ClientEncryption(
            self.kms_providers, self.key_vault_namespace, self.client, CodecOptions()
        )
        self.client["keyvault"]["datakeys"].drop()
        self.key_id = self.client_encryption.create_data_key("local")

        opts = AutoEncryptionOpts(
                    self.kms_providers,
                    self.key_vault_namespace,
                    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
                )
        self.encrypted_client = MongoClient(auto_encryption_opts=opts)

    def tearDown(self):
        self.encrypted_client.close()
        self.client_encryption.close()
        self.client.close()

    def create_collection(self, json_schema=None, encrypted_fields=None):
        db = self.client["db"]
        db.drop_collection("coll")
        validator = {}
        if json_schema:
            validator["$jsonSchema"] = json_schema
        db.create_collection("coll", validator=validator, encryptedFields=encrypted_fields)

    def assertValueEqual(self, got, expected):
        # Binary with subtype 0 round-trips as plain `bytes`, and Binary.__eq__
        # returns False when compared to non-Binary. Compare the raw bytes.
        if isinstance(got, bytes) and isinstance(expected, bytes):
            self.assertEqual(bytes(got), bytes(expected))
        else:
            self.assertEqual(got, expected)

    def assertFailsWithCode(self, code):
        """Assert the block raises an error reporting `code`.

        The code may be on the exception itself (server errors) or embedded in
        the message of a libmongocrypt/crypt_shared error.
        """
        outer = self

        class _Ctx:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                outer.assertIsNotNone(exc, f"expected an error with code {code}")
                if getattr(exc, "code", None) != code:
                    outer.assertIn(f"code {code}", str(exc))
                return True

        return _Ctx()

    def check_csfle(self, bson_type, value, algorithm, query):
        self.create_collection(json_schema={
            "bsonType": "object",
            "properties": {
                "secret": {
                    "encrypt": {
                        "bsonType": bson_type,
                        "algorithm": algorithm,
                        "keyId": [self.key_id],
                    }
                }
            },
        })

        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "secret": value})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["secret"], Binary)
        self.assertEqual(raw["secret"].subtype, 6)

        if query:
            got = coll.find_one({"secret": value})
            self.assertIsNotNone(got)
            self.assertValueEqual(got["secret"], value)

    def check_qe(self, bson_type, value, query):
        field = {
            "path": "secret",
            "bsonType": bson_type,
            "keyId": self.key_id,
        }
        if query:
            field["queries"] = [{"queryType": "equality"}]
        self.create_collection(encrypted_fields={"fields": [field]})

        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "secret": value})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["secret"], Binary)
        self.assertEqual(raw["secret"].subtype, 6)

        if query:
            got = coll.find_one({"secret": value})
            self.assertIsNotNone(got)
            self.assertValueEqual(got["secret"], value)

    def test_csfle_auto_string_none(self):
        self.create_collection(json_schema={
            "bsonType": "object",
            "properties": {
                "secret": {
                    "encrypt": {
                        "bsonType": "string",
                        # "none" means "random" for CSFLE since it does not support queries.
                        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                        "keyId": [self.key_id],
                    }
                }
            },
        })
    
        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "secret": "foo"})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["secret"], Binary)
        self.assertEqual(raw["secret"].subtype, 6)

    def test_csfle_auto_string_equality(self):
        self.create_collection(json_schema={
            "bsonType": "object",
            "properties": {
                "secret": {
                    "encrypt": {
                        "bsonType": "string",
                        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                        "keyId": [self.key_id],
                    }
                }
            },
        })
    
        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "secret": "foo"})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["secret"], Binary)
        self.assertEqual(raw["secret"].subtype, 6)

        # Expect equality query supported:
        got = coll.find_one({"secret": "foo"})
        self.assertIsNotNone(got)
        self.assertEqual(got["secret"], "foo")

    def test_qe_auto_string_none(self):
        self.create_collection(encrypted_fields={
             "fields": [
                {
                    "path": "secret",
                    "bsonType": "string",
                    "keyId": self.key_id,
                },
            ],
        })
    
        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "secret": "foo"})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["secret"], Binary)
        self.assertEqual(raw["secret"].subtype, 6)

    def test_qe_auto_string_equality(self):
        self.create_collection(encrypted_fields={
             "fields": [
                {
                    "path": "secret",
                    "bsonType": "string",
                    "keyId": self.key_id,
                    "queries": [{ "queryType": "equality" }]
                },
            ],
        })
    
        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "secret": "foo"})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["secret"], Binary)
        self.assertEqual(raw["secret"].subtype, 6)

        # Expect equality query supported:
        got = coll.find_one({"secret": "foo"})
        self.assertIsNotNone(got)
        self.assertEqual(got["secret"], "foo")

    def test_csfle_auto_nested_object(self):
        # "obj.secret" is a string nested in an object.
        self.create_collection(json_schema={
            "bsonType": "object",
            "properties": {
                "obj": {
                    "bsonType": "object",
                    "properties": {
                        "secret": {
                            "encrypt": {
                                "bsonType": "string",
                                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                "keyId": [self.key_id],
                            }
                        }
                    },
                }
            },
        })

        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "obj": {"secret": "foo"}})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["obj"]["secret"], Binary)
        self.assertEqual(raw["obj"]["secret"].subtype, 6)

        # Expect equality query supported:
        got = coll.find_one({"obj.secret": "foo"})
        self.assertIsNotNone(got)
        self.assertEqual(got["obj"]["secret"], "foo")

    def test_qe_auto_nested_object(self):
        self.create_collection(encrypted_fields={
            "fields": [
                {
                    "path": "obj.secret",
                    "bsonType": "string",
                    "keyId": self.key_id,
                    "queries": [{"queryType": "equality"}],
                },
            ],
        })

        coll = self.encrypted_client["db"]["coll"]
        coll.insert_one({"_id": 0, "obj": {"secret": "foo"}})

        # Expect encrypted:
        raw = self.client["db"]["coll"].find_one({"_id": 0})
        self.assertIsInstance(raw["obj"]["secret"], Binary)
        self.assertEqual(raw["obj"]["secret"].subtype, 6)

        # Expect equality query supported:
        got = coll.find_one({"obj.secret": "foo"})
        self.assertIsNotNone(got)
        self.assertEqual(got["obj"]["secret"], "foo")

    def test_csfle_auto_nested_array(self):
        # "arr.secret" is a string nested in an object inside an array.
        self.create_collection(json_schema={
            "bsonType": "object",
            "properties": {
                "arr": {
                    "bsonType": "array",
                    "items": {
                        "bsonType": "object",
                        "properties": {
                            "secret": {
                                "encrypt": {
                                    "bsonType": "string",
                                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                    "keyId": [self.key_id],
                                }
                            }
                        },
                    },
                }
            },
        })

        coll = self.encrypted_client["db"]["coll"]
        # Expect unsupported: 'encrypt' is not permitted under 'items'.
        with self.assertFailsWithCode(51077):
            coll.insert_one({"_id": 0, "arr": [{"secret": "foo"}]})

    def test_qe_auto_nested_array(self):
        self.create_collection(encrypted_fields={
            "fields": [
                {
                    "path": "arr.secret",
                    "bsonType": "string",
                    "keyId": self.key_id,
                    "queries": [{"queryType": "equality"}],
                },
            ],
        })

        coll = self.encrypted_client["db"]["coll"]
        # The encryptedFields config is accepted, but an array at 'arr' is not.
        with self.assertFailsWithCode(31006):
            coll.insert_one({"_id": 0, "arr": [{"secret": "foo"}]})


# BSON types under test, with a representative Python value.
BSON_TYPES = {
    "string": "foo",
    "double": 1.5,
    "object": {"a": 1},
    "array": [1, 2],
    "binData": Binary(b"abc", 0),
    "bool": True,
    "date": datetime(2026, 1, 1),
    "int": 1,
    "long": Int64(1),
    "decimal": Decimal128("1.5"),
    # Not Timestamp(0, 0): the server replaces a zero timestamp on insert, so
    # crypt_shared refuses to encrypt it (code 51129).
    "timestamp": Timestamp(1, 1),
}


# Types the deterministic CSFLE algorithm refuses to encrypt.
# crypt_shared: "Cannot encrypt element of type: X"
CSFLE_DETERMINISTIC_UNSUPPORTED = {"double", "object", "array", "bool", "decimal"}
CSFLE_UNSUPPORTED_CODE = 31122

# Types QE cannot equality-index.
# server: "Type 'X' is not a supported equality indexed type"
QE_EQUALITY_UNSUPPORTED = {"double", "object", "array", "decimal"}
QE_EQUALITY_UNSUPPORTED_CODE = 6338405


def _add_tests():
    for bson_type, value in BSON_TYPES.items():
        if bson_type == "string":
            continue  # Already written by hand above.

        def csfle_none(self, bson_type=bson_type, value=value):
            self.check_csfle(
                bson_type, value, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", query=False
            )

        def csfle_equality(self, bson_type=bson_type, value=value):
            if bson_type in CSFLE_DETERMINISTIC_UNSUPPORTED:
                with self.assertFailsWithCode(CSFLE_UNSUPPORTED_CODE):
                    self.check_csfle(
                        bson_type, value, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", query=True
                    )
                return
            self.check_csfle(
                bson_type, value, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", query=True
            )

        def qe_none(self, bson_type=bson_type, value=value):
            self.check_qe(bson_type, value, query=False)

        def qe_equality(self, bson_type=bson_type, value=value):
            if bson_type in QE_EQUALITY_UNSUPPORTED:
                with self.assertFailsWithCode(QE_EQUALITY_UNSUPPORTED_CODE):
                    self.check_qe(bson_type, value, query=True)
                return
            self.check_qe(bson_type, value, query=True)

        for label, fn in [
            ("csfle_auto_{}_none", csfle_none),
            ("csfle_auto_{}_equality", csfle_equality),
            ("qe_auto_{}_none", qe_none),
            ("qe_auto_{}_equality", qe_equality),
        ]:
            name = "test_" + label.format(bson_type)
            fn.__name__ = name
            setattr(TestBsonTypes, name, fn)


_add_tests()


if __name__ == "__main__":
    import unittest

    unittest.main()

