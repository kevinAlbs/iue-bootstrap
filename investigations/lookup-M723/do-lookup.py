"""
What happens when auto encryption uses $lookup? Test server 8.0 prior to any changes for MONGOCRYPT-723.

To run:
- run `mongocryptd`.
- set the `CRYPT_SHARED_PATH` environment variable.

"""

import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import Algorithm, ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.errors import EncryptionError

import unittest


class TestLookup(unittest.TestCase):
    def setUp(self):
        keyvault_client = MongoClient()
        keyvault_client["keyvault"]["datakeys"].drop()

        kms_providers = {"local": {"key": os.urandom(96)}}
        client_encryption = ClientEncryption(
            kms_providers,
            "keyvault.datakeys",
            keyvault_client,
            CodecOptions(),
        )

        keyid = client_encryption.create_data_key("local")

        # Create collection with CSFLE schema:
        schema = {
            "properties": {
                "csfle": {
                    "encrypt": {
                        "keyId": [keyid],
                        "bsonType": "string",
                        "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                    }
                }
            },
            "bsonType": "object",
        }

        keyvault_client["db"]["csfle"].drop()
        keyvault_client["db"]["csfle2"].drop()
        keyvault_client["db"].create_collection("csfle", validator={"$jsonSchema": schema})
        keyvault_client["db"].create_collection("csfle2", validator={"$jsonSchema": schema})

        # Create collection with QE schema:
        encrypted_fields = {
            "fields": [
                {
                    "keyId": keyid,
                    "path": "qe",
                    "bsonType": "string",
                    "queries": {"queryType": "equality", "contention": 0},
                }
            ]
        }

        keyvault_client["db"]["qe"].drop(encrypted_fields=encrypted_fields)
        keyvault_client["db"]["qe2"].drop(encrypted_fields=encrypted_fields)
        keyvault_client["db"].create_collection("qe", encryptedFields=encrypted_fields)
        keyvault_client["db"].create_collection("qe2", encryptedFields=encrypted_fields)
        keyvault_client.close()

        encrypted_client = MongoClient(auto_encryption_opts=AutoEncryptionOpts(
            kms_providers=kms_providers,
            key_vault_namespace="keyvault.datakeys",
            mongocryptd_bypass_spawn=True,
        ))
        encrypted_client["db"]["csfle"].insert_one(
            {"csfle": "csfle_encrypted", "joinme": 1}
        )
        encrypted_client["db"]["csfle2"].insert_one(
            {"csfle": "csfle_encrypted2", "joinme": 1}
        )
        encrypted_client["db"]["qe"].insert_one({"qe": "qe_encrypted", "joinme": 1})
        encrypted_client["db"]["qe2"].insert_one({"qe": "qe_encrypted2", "joinme": 1})
        encrypted_client["db"]["unencrypted"].insert_one(
            {
                "unencrypted": "unencrypted",
                "joinme": 1,
            }
        )
        encrypted_client["db"]["unencrypted2"].insert_one(
            {
                "unencrypted": "unencrypted2",
                "joinme": 1,
            }
        )

        self.encrypted_client_mongocryptd = encrypted_client

        self.encrypted_client_crypt_shared = MongoClient(
            auto_encryption_opts=AutoEncryptionOpts(
                kms_providers=kms_providers,
                key_vault_namespace="keyvault.datakeys",
                crypt_shared_lib_path=os.environ["CRYPT_SHARED_PATH"],
                crypt_shared_lib_required=True,
            )
        )

    def tearDown(self):
        self.encrypted_client_mongocryptd.close()
        self.encrypted_client_crypt_shared.close()

    def test_csfle_unencrypted(self):
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["csfle"].aggregate([
                { "$lookup": { "from": "unencrypted", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["csfle"].aggregate([
                { "$lookup": { "from": "unencrypted", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

    def test_qe_unencrypted(self):
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["qe"].aggregate([
                { "$lookup": { "from": "unencrypted", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["qe"].aggregate([
                { "$lookup": { "from": "unencrypted", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

    def test_unencrypted_csfle(self):
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "csfle", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "csfle", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))
        
    def test_unencrypted_qe(self):
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "qe", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "qe", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

    def test_csfle_csfle(self):
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["csfle"].aggregate([
                { "$lookup": { "from": "csfle2", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["csfle"].aggregate([
                { "$lookup": { "from": "csfle2", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

    def test_qe_qe(self):
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["qe"].aggregate([
                { "$lookup": { "from": "qe2", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["qe"].aggregate([
                { "$lookup": { "from": "qe2", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

    def test_unencrypted_unencrypted(self):
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "unencrypted2", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "unencrypted2", "localField": "joinme", "foreignField": "joinme", "as": "matched" } }
            ])
        self.assertIn("Pipeline over an encrypted collection cannot reference additional collections", str(exc.exception))

    def test_csfle_self(self):
        # Error occurs with a $match:
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["csfle"].aggregate([
                { "$lookup": { "from": "csfle", "localField": "joinme", "foreignField": "joinme", "as": "matched" } },
                { "$match": { "matched.csfle": "csfle_encrypted"}}
            ])
        self.assertIn("Cannot get metadata for path whose encryption properties are not known until runtime", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["csfle"].aggregate([
                { "$lookup": { "from": "csfle", "localField": "joinme", "foreignField": "joinme", "as": "matched" } },
                { "$match": { "matched.csfle": "csfle_encrypted"}}
            ])
        self.assertIn("Cannot get metadata for path whose encryption properties are not known until runtime", str(exc.exception))

    def test_qe_self(self):
        # Error occurs with a $match:
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["qe"].aggregate([
                { "$lookup": { "from": "qe", "localField": "joinme", "foreignField": "joinme", "as": "matched" } },
                { "$match": { "matched.qe": "qe_encrypted"}}
            ])
        self.assertIn("Cannot get metadata for path whose encryption properties are not known until runtime", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["qe"].aggregate([
                { "$lookup": { "from": "qe", "localField": "joinme", "foreignField": "joinme", "as": "matched" } },
                { "$match": { "matched.qe": "qe_encrypted"}}
            ])
        self.assertIn("Cannot get metadata for path whose encryption properties are not known until runtime", str(exc.exception))

    def test_unencrypted_self(self):
        # Error occurs with a $match:
        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_mongocryptd["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "unencrypted", "localField": "joinme", "foreignField": "joinme", "as": "matched" } },
                { "$match": { "matched.unencrypted": "unencrypted"}}
            ])
        self.assertIn("Cannot get metadata for path whose encryption properties are not known until runtime", str(exc.exception))

        with self.assertRaises(expected_exception=EncryptionError) as exc:
            self.encrypted_client_crypt_shared["db"]["unencrypted"].aggregate([
                { "$lookup": { "from": "unencrypted", "localField": "joinme", "foreignField": "joinme", "as": "matched" } },
                { "$match": { "matched.unencrypted": "unencrypted"}}
            ])
        self.assertIn("Cannot get metadata for path whose encryption properties are not known until runtime", str(exc.exception))
        

unittest.main()
