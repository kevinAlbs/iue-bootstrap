// Based off of: https://github.com/mongodb-university/docs-in-use-encryption-examples/blob/f1c08526bed63bfbcf0100aeac812d37f527bd92/csfle/node/local/reader/make_data_key.js
const mongodb = require("mongodb");
const { MongoClient, ClientEncryption } = mongodb;

const kmsProviders = {
    local: {
        key: "Mng0NCt4ZHVUYUJCa1kxNkVyNUR1QURhZ2h2UzR2d2RrZzh0cFBwM3R6NmdWMDFBMUN3YkQ5aXRRMkhGRGdQV09wOGVNYUMxT2k3NjZKelhaQmRCZGJkTXVyZG9uSjFk",
    },
};

async function main() {
    const uri = "mongodb://localhost:27017";
    const keyVaultNamespace = "keyvault.datakeys";
    const client = new MongoClient(uri);
    await client.connect();
    const encryption = new ClientEncryption(client, {
        keyVaultNamespace,
        kmsProviders,
    });
    const key = await encryption.createDataKey("local");
    console.log("DataKeyId [base64]: ", key.toString("base64"));
    await client.close();
}
main();
