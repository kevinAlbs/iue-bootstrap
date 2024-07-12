# dump_payload

Dump In-Use Encryption payloads to text.

In-Use Encryption consists of Client-Side Field Level Encryption and Queryable Encryption.
In-Use Encryption makes use of the BSON binary subtype 6 in its protocol.

# Example Usage

```
$ dump_payload.py ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA
blob_subtype: 0 (FLE1EncryptionPlaceholder)
a (algorithm): 1 (Deterministic)
ki (keyId): b'aaaaaaaaaaaaaaaa' 
v (value): 457-55-5462
```

# More information

The server representation of FLE fields is available here:
https://github.com/mongodb/mongo/blob/4fc261005c7726a1b99025d60e6ded3f1ba299ca/src/mongo/crypto/fle_field_schema.idl

The Subtype 6 specification describes some of the payload types:
https://github.com/mongodb/specifications/blob/master/source/client-side-encryption/subtype6.rst
