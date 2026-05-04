# Use server >= 8.2 and < 9.0 for prefixPreview.

# This was used to override libmongocrypt to use a determinstic IV:
# export MONGOCRYPT_DETERMINISTIC_RANDOM=ON
# export PYMONGOCRYPT_LIB=/Users/kevin.albertson/code/tasks/libmongocrypt-explicit-vs-auto-text/cmake-build/libmongocrypt.dylib

export CRYPT_SHARED_PATH=/Users/kevin.albertson/bin/mongodl/crypt_shared/latest-build/lib/mongo_crypt_v1.dylib
uv run do-test.py
