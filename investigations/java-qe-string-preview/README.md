Java QE String preview example.

## Prerequisites

- A `mongod` >=8.2 and <9.0 running on `mongodb://localhost:27017` (enterprise, for QE).
- Java 17+ and Gradle (see repo root for install notes).

## Run

```bash
gradle run
```

The `crypt_shared` library is not required because `bypassQueryAnalysis(true)`
is set: the driver never performs query analysis, so no `mongocryptd` or
`crypt_shared` is needed. Encrypted payloads are produced explicitly via
`ClientEncryption.encrypt(...)`.
