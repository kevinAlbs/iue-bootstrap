# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A personal testbed for experimenting with MongoDB In-Use Encryption (IUE), which encompasses two features:

- **CSFLE (Client-Side Field Level Encryption)**: ~100% client-side. Algorithms: `AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic` and `-Random`. Server optionally enforces a JSON schema to reject unencrypted values.
- **QE (Queryable Encryption)**: ~50% client-side. Algorithms: `Indexed`, `Unindexed`, `RangePreview`. Requires server-side metadata collections (`enxcol_.<coll>.esc`, `enxcol_.<coll>.ecoc`) and a `__safeContent__` field in each document.

## Running Scripts

Most investigation scripts use `uv`:
```bash
uv run <script>.py
```

Key environment variables (set via `KEVINALBS/set-crypt_shared-path.sh`):
```bash
export CRYPT_SHARED_PATH="$HOME/bin/mongodl/crypt_shared/8.0.0/lib/mongo_crypt_v1.dylib"
# Optionally override libmongocrypt:
export PYMONGOCRYPT_LIB=/path/to/libmongocrypt.dylib
```

`mongocryptd` (for query analysis without crypt_shared) runs on port 27020. Start it via `KEVINALBS/start-mongocryptd.sh`.

## Tools

### `tools/generate-markings/`
Sends commands to `mongocryptd` and returns the marked-up result with encryption placeholders. Test cases are YAML files in `tests/`.
```bash
cat tests/find.json | python run_cmd.py --port 27020 --db db
```

### `tools/markup/`
Tests the `crypt_shared` shared library directly (via cffi) without a running mongocryptd. Requires `pip install cffi`.
```bash
python markup.py --version --libpath $CRYPT_SHARED_PATH
cat input.json | python markup.py --libpath $CRYPT_SHARED_PATH
```

### `tools/dump_payload/`
Decodes BSON binary subtype 6 payloads used in the IUE wire protocol.
```bash
python dump_payload.py <base64-payload>
```
Relevant spec: [subtype6.rst](https://github.com/mongodb/specifications/blob/master/source/client-side-encryption/subtype6.rst)

## Architecture

The IUE stack has three query analysis components (interchangeable for different testing scenarios):
1. **mongocryptd** — standalone daemon, enterprise-licensed
2. **crypt_shared** — shared library loaded in-process, enterprise-licensed
3. **libmongocrypt** — Apache-licensed library used by all drivers; wraps the above

`driver-quickstarts/` has minimal end-to-end Python examples for auto-encryption (`autoencrypt.py`) and explicit encryption (`explicitencrypt.py`) that show the full pymongo API surface.

`investigations/` contains ~48 directories, each scoped to a ticket, feature, or question (named after JIRA IDs like `DOCSP-37855`, `HELP-75777`, or descriptively like `multiwrite`, `case-sensitive-text`). Each typically has a `run.sh` and one or more Python scripts.

## Key References

- Driver spec: https://github.com/mongodb/specifications/tree/master/source/client-side-encryption/client-side-encryption.md
- libmongocrypt: https://github.com/mongodb/libmongocrypt
- Public docs: https://www.mongodb.com/docs/manual/core/security-in-use-encryption/
- Q&A on IUE behavior edge cases: [qanda.md](qanda.md)
