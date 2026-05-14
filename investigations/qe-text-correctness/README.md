Correctness tests for QE text search with explicit encryption.

Covers:
- All four query operators: `$encStrStartsWith`, `$encStrEndsWith`, `$encStrContains`, `$encStrNormalizedEq`
- All four `caseSensitive` × `diacriticSensitive` permutations
- Mixed auto/explicit encryption (DRIVERS-3470 regression)

## Prerequisites

- MongoDB 8.2 enterprise running with replica set (`./start-server.sh` then `mongosh --port 27777 --eval "rs.initiate()"` once)
- libmongocrypt 1.18.1 built at `~/code/c-bootstrap/install/libmongocrypt-1.18.1/`
- `crypt_shared` latest-build at `~/bin/mongodl/crypt_shared/latest-build/`

## To run

```bash
./run.sh
```

## DRIVERS-3470

libmongocrypt < 1.18.1 had `caseSensitive` and `diacriticSensitive` swapped for
explicit encryption. `test-auto-explicit-mix.py` Scenario C directly reproduces
the bug (auto-insert + explicit-find with `caseSensitive=False, diacriticSensitive=True`).

## Observed behavior: $encStrNormalizedEq on substringPreview

`$encStrNormalizedEq` on a `substringPreview` index matches any stored substring
token, not just the whole-value equality token. Searching for "foo" finds a document
containing "FooBarBaz" because "foo" is a stored 3-char substring. This may be a
server bug — the name implies whole-value equality. See the comment in
`test-operators.py` for details.
