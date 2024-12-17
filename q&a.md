# Q7: What types are supported for QE?

A: See https://github.com/10gen/mongo/blob/488dc7f55c7512da8f2befbd13f5a7f23c404c39/src/mongo/crypto/encryption_fields_util.h#L44-L170

# Q6: What is this error: `BSON field 'root.sp'`
    Upgrade to MongoDB server 8.0.

# Q4: Can `collMod` be used to change a `$jsonSchema` with CSFLE encrypted fields?

Yes. mongocryptd rejects a `collMod` command where the `jsonSchema` does not match the `validator.$jsonSchema`. However, MONGOCRYPT-463 changes libmongocrypt to prefer the `jsonSchema` from the `collMod` command.

# Q3: Does QE support multi writes?

Yes, in a limited capacity. 

For `insert`, `update`, and `delete` commands, see [investigations/multiwrite](./investigations/multiwrite/):
- Multi-statement inserts are OK.
- Multi-statement updates and deletes results in the errors: `Only single document deletes are permitted` and `Only single document updates are permitted`.
- Single-statement delete with multi-document statement is OK.
- Single-statement update with multi-document statement results in the error: `Multi-document updates are not allowed with Queryable Encryption`.

The `bulkWrite` command has similar limitations. Multi-statement single-document updates or deletes are not supported. `bulkWrite` errors in mongocryptd, and `update` / `delete` errors in `mongod`. See: [investigations/M588](./investigations/M588).


# Q2: What fields does Query Analysis include in response?
Is `$db` included in response? `$readPreference`? `apiVersion`?
Does the behavior differ between crypt_shared and mongocryptd?
Relevant:
- https://jira.mongodb.org/browse/SERVER-40354 mongocryptd should echo back all fields in command, and none that aren't
- https://jira.mongodb.org/browse/SERVER-69564 Query analysis omits version API fields with "explain"
A: (Open)

# Q1: What is the differences between Queryable Encryption (QE) and Client-Side Field Level Encryption (CSFLE)?
A:
Both features CSFLE and QE are nested under "In Use Encryption". Refer: DRIVERS-2454.

CSFLE consists of these algorithms:
- "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
- "AEAD_AES_256_CBC_HMAC_SHA_512-Random"

QE consists of these algorithms:
- "Indexed"
- "Unindexed"
- "RangePreview"

CSFLE is a near 100% client-side feature. The only support from the server is support of the `encrypt` and `encryptMetadata` in the JSON schema: https://www.mongodb.com/docs/manual/core/csfle/fundamentals/create-schema/. If a JSON schema is optionally configured on the server, the server rejects plaintext values for encrypted fields.

QE is closer to 50% client-side 50% server-side feature. Enabling QE requires additional server-side data structures:
1. Two metadata collections:
    - `enxcol_.<collectionName>.esc`, referred to as ESC
    - `enxcol_.<collectionName>.ecoc`, referred to as ECOC
2. A field in every document in the encrypted collection called `__safeContent__`.

The client must append a field `encryptionInformation` to every command that requires server processing for Queryable Encryption. This is done by libmongocrypt in drivers.
