This directory contains `run_cmd.py` to send a command to `mongocryptd`, and sample commands in `tests`.

## Multiple single-document updates

`bulkWrite` with one single-document update is OK. Running `cat ./tests/bulkWrite-one-update.json  | python run_cmd.py --port 27020` results in replacing the `encrypt` field with an encryption placeholder (BSON binary subtype 6).

`bulkWrite` with two single-document updates is an error. Running `cat ./tests/bulkWrite-two-updates.json  | python run_cmd.py --port 27020` results in the error `Only insert is supported in BulkWrite with multiple operations and Queryable Encryption.`

`update` with two single-document updates is OK. Running `cat ./tests/update-two-updates.json | python run_cmd.py --port 27020 --db db` results in replacing both `encrypt` fields with an encryption placeholder (BSON binary subtype 6).
Though mongocryptd does not error on two single-document updates, mongod does: https://github.com/10gen/mongo/blob/3477a0bc3a282b365196ee6f4dd40c0e59141422/src/mongo/db/fle_crud.cpp#L639


