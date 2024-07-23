// Show the default "range" crypto parameters applied in mongod.
// Run with `mongosh mongod-range-defaults.js`
db.foo.drop()
db.runCommand({
    create: "foo",
    encryptedFields: {
        "fields": [
            {
                "keyId": UUID(),
                "path": "encryptedInt",
                "bsonType": "int",
                "queries": {
                    "queryType": "range"
                }
            }
        ]

    }
})
const collInfo = db.getCollectionInfos({ name: "foo" })
print(collInfo[0]["options"]["encryptedFields"]["fields"][0]["queries"])
// Prints: { queryType: 'range', contention: Long('8') }
