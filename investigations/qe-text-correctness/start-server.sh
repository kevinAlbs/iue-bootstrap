#!/bin/bash
mkdir -p "$(dirname "$0")/.menv-8.2"
/Users/kevin.albertson/bin/mongodl/archive/8.2.4/mongodb-macos-aarch64-enterprise--8.2.4/bin/mongod \
  --dbpath "$(dirname "$0")/.menv-8.2" \
  --replSet rs0 \
  --setParameter enableTestCommands=1
