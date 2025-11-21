"""
Prerequisites:
- Start mongod 7.0+ (supports $median)
- Start mongocryptd < 7.0 (does not support $median)

Expected error: Invalid $project :: caused by :: Unknown expression $median
"""

from pymongo import MongoClient
from pymongo.encryption import EncryptionError
from pymongo.encryption_options import AutoEncryptionOpts

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers={"local": {"key": b"A" * 96}},
    key_vault_namespace="keyvault.datakeys",
    mongocryptd_bypass_spawn=True # Expect already running
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
client.db.coll.insert_one({"_id": 1, "x": [1,2,3]})

# Print version of mongocryptd
mongocryptd_version = MongoClient("mongodb://localhost:27020").db.command({"buildInfo": True})["version"]
print("Detected mongocryptd version: " + mongocryptd_version)

pipeline = [{"$project": {"med": {"$median": { "input": "$x", "method": "approximate" }}}}]
try:
    client.db.coll.aggregate(pipeline).next()
    print ("Did not get expected error. Test with mongocryptd < 7.0 to reproduce error")
except EncryptionError as e:
    expect = "Invalid $project :: caused by :: Unknown expression $median"
    assert expect in str(e)
    print ("Got expected error: " + expect)
