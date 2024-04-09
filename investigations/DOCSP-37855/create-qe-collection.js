// Run with `mongosh --nodb create-qe-collection.sh`

const TEST_LOCAL_KEY = require("crypto").randomBytes(96).toString("base64")

var autoEncryptionOpts = {
    "keyVaultNamespace": "encryption.__dataKeys",
    "kmsProviders": {
        "local": {
            "key": BinData(0, TEST_LOCAL_KEY)
        }
    }
}

let encryptedClient = Mongo(
    "mongodb://localhost:27017/",
    autoEncryptionOpts
);


encryptedClient.getDB("enc").dropDatabase();

const createCollectionOptions = {
    encryptedFields: {
        fields: [
            {
                path: "secretField",
                bsonType: "string",
                queries: { queryType: "equality" },
            },
        ],
    },
};


clientEncryption = encryptedClient.getClientEncryption();

var result = clientEncryption.createEncryptedCollection(
    "enc",
    "users",
    {
        provider: "local",
        createCollectionOptions: createCollectionOptions,
        masterKey: {} // masterKey is optional when provider is local
    }
)

assert("keyId" in result.encryptedFields["fields"][0])
