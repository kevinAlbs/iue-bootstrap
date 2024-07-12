import unittest
import markup

import bson
import bson.binary
from bson import json_util

json_options = json_util.JSONOptions(
    json_mode=json_util.JSONMode.CANONICAL,
    uuid_representation=bson.binary.UuidRepresentation.STANDARD)

in_json_str = """
{
    "find": "test",
    "filter": {
        "value": 123456
    },
    "encryptionInformation": {
        "type": 1,
        "schema": {
            "db.test": {
                "escCollection": "esc",
                "eccCollection": "ecc",
                "ecocCollection": "ecoc",
                "fields": [
                    {
                        "keyId": {
                            "$binary": {
                                "base64": "EjRWeBI0mHYSNBI0VniQEg==",
                                "subType": "04"
                            }
                        },
                        "path": "value",
                        "bsonType": "int",
                        "queries": {
                            "queryType": "equality",
                            "contention": {
                                "$numberLong": "0"
                            }
                        }
                    }
                ]
            }
        }
    },
    "$db": "db"
}
"""

expect_json_str = """
{
    "hasEncryptionPlaceholders": true,
    "schemaRequiresEncryption": true,
    "result": {
        "find": "test",
        "filter": {
            "value": {
                "$eq": {
                    "$binary": {
                        "base64": "A1gAAAAQdAACAAAAEGEAAgAAAAVraQAQAAAABBI0VngSNJh2EjQSNFZ4kBIFa3UAEAAAAAQSNFZ4EjSYdhI0EjRWeJASEHYAQOIBABJjbQAAAAAAAAAAAAA=",
                        "subType": "06"
                    }
                }
            }
        },
        "encryptionInformation": {
            "type": {
                "$numberInt": "1"
            },
            "schema": {
                "db.test": {
                    "escCollection": "esc",
                    "eccCollection": "ecc",
                    "ecocCollection": "ecoc",
                    "fields": [
                        {
                            "keyId": {
                                "$binary": {
                                    "base64": "EjRWeBI0mHYSNBI0VniQEg==",
                                    "subType": "04"
                                }
                            },
                            "path": "value",
                            "bsonType": "int",
                            "queries": {
                                "queryType": "equality",
                                "contention": {
                                    "$numberLong": "0"
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
}
"""

import os

class TestMarkup (unittest.TestCase):
    def test_markup_cmd(self):
        if "CRYPT_SHARED_PATH" not in os.environ:
            raise Exception("CRYPT_SHARED_PATH environment variable must be set")
        libpath = os.environ["CRYPT_SHARED_PATH"]
        json_options = json_util.JSONOptions(
            json_mode=json_util.JSONMode.CANONICAL,
            uuid_representation=bson.binary.UuidRepresentation.STANDARD)
        cmd_json = in_json_str
        cmd_dict = json_util.loads(cmd_json, json_options=json_options)
        codec_options = bson.CodecOptions(uuid_representation=bson.binary.UuidRepresentation.STANDARD)
        cmd_bson = bson.encode(cmd_dict, codec_options=codec_options)
        got = markup.markup_cmd (libpath, cmd_bson)
        self.assertEqual (got, expect_json_str.strip())

    def test_get_version(self):
        if "CRYPT_SHARED_PATH" not in os.environ:
            raise Exception("CRYPT_SHARED_PATH environment variable must be set")
        libpath = os.environ["CRYPT_SHARED_PATH"]
        got : str = markup.get_version (libpath)
        self.assertEqual (got.find("mongo_crypt_v1"), 0)

if __name__ == "__main__":
    unittest.main()
