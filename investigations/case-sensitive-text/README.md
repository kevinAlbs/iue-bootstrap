Try to find a case-insensitive text payload with explicit encryption:

To run:
```bash
$ export CRYPT_SHARED_PATH=/Users/kevin.albertson/bin/mongodl/crypt_shared/latest-build/lib/mongo_crypt_v1.dylib
$ uv run insert-find.py
Using key with _id: 0b93282ad2604b12a152c5f513fecc6b
Inserting auto-encrypted 'foo' with 'substringPreview' ...
Inserting auto-encrypted 'foo' with 'substringPreview' ... done
Finding 'foo' with '$encStrNormalizedEq' ...
Finding 'foo' with '$encStrNormalizedEq' ... found
Finding 'FOO' with '$encStrNormalizedEq' ...
Finding 'FOO' with '$encStrNormalizedEq' ... NOT FOUND!
```
