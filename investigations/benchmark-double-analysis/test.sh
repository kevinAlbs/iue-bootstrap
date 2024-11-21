export CRYPT_SHARED_PATH=~/bin/mongodl/crypt_shared/8.0.0/lib/mongo_crypt_v1.dylib
export PYMONGOCRYPT_LIB=/Users/kevin.albertson/code/tasks/libmongocrypt-WRITING-8867/cmake-build/libmongocrypt.dylib
echo "Testing with PYMONGOCRYPT_LIB=$PYMONGOCRYPT_LIB and CRYPT_SHARED_PATH=$CRYPT_SHARED_PATH"
python benchmark.py
