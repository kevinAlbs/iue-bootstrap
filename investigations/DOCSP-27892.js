// To run: 
//   Install mongosh from: https://www.mongodb.com/try/download/shell (not homebrew) for IUE support.
//   mongosh DOCSP-27892.js

// Create a local master key:
const TEST_LOCAL_KEY = require("crypto").randomBytes(96).toString("base64");

// Clear data:
{
    const client = Mongo("mongodb://localhost:27017");
    client.getDB("db").dropDatabase();
}

let keyId = null;
let encryptedClient = null;
let encryptedColl = null;
let clientEncryption = null;
// Create a client for QE without auto encryption.
{
    const autoEncryptionOpts = {
        "keyVaultNamespace": "db.keyvault",
        "kmsProviders": {
            "local": {
                "key": BinData(0, TEST_LOCAL_KEY)
            }
        },
        "bypassQueryAnalysis": true // Do not use mongocryptd/crypt_shared. Disables auto encryption.
    }

    encryptedClient = Mongo(
        "mongodb://localhost:27017/",
        autoEncryptionOpts
    );

    let keyvault = encryptedClient.getKeyVault();
    keyId = keyvault.createDataKey("local");

    const createCollectionOptions = {
        encryptedFields: {
            fields: [
                {
                    path: "secret",
                    bsonType: "int",
                    keyId: keyId,
                    queries: { queryType: "range", min: 0, max: 200, contention: 8 },
                },
            ],
        },
    };

    let db = encryptedClient.getDB("db")
    db.createCollection("coll", createCollectionOptions);
    clientEncryption = encryptedClient.getClientEncryption();
    encryptedColl = db.getCollection("coll");
}

// Explicit encrypt an insert:
{
    let payload = clientEncryption.encrypt(keyId, 123, { algorithm: "range", rangeOptions: { min: 0, max: 200 }, contentionFactor: 8 });
    encryptedClient.getDB("db").getCollection("coll").insertOne({ "secret": payload });
}

// Explicit encrypt a find.
{
    let expr = clientEncryption.encryptExpression(keyId,
        { $and: [{ secretField: { $gt: 122 } }, { secretField: { $lt: 124 } }] },
        { algorithm: "range", queryType: "range", rangeOptions: { min: 0, max: 200 }, contentionFactor: 8 });
    let got = encryptedColl.findOne(expr);
    console.log("with explicit encryption, got: ", got)
}

