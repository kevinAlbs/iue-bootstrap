#!/usr/bin/env python3
"""
run_cmd reads extended canonical JSON and runs it as a command.
"""
from pymongo import MongoClient
import pymongo.errors
import sys
from bson import json_util
import bson
import argparse

json_opts = json_util.JSONOptions(
    json_mode=json_util.JSONMode.CANONICAL, uuid_representation=bson.UuidRepresentation.STANDARD)

codec_opts = bson.CodecOptions(
    uuid_representation=bson.UuidRepresentation.STANDARD)


def run_cmd(uri, cmd, db, quiet, server_error_ok):
    global json_opts, codec_opts
    ok = False

    client = MongoClient(uri)
    try:
        reply = client[db].command(cmd, codec_options=codec_opts)
        if not quiet:
            print(json_util.dumps(reply, indent=4, json_options=json_opts))
        ok = True
    except pymongo.errors.OperationFailure as of:
        if server_error_ok:
            ok = True
            if not quiet:
                print(json_util.dumps(of.details, indent=4, json_options=json_opts))
        else:
            print(json_util.dumps(of.details, indent=4, json_options=json_opts))
    client.close()
    return ok


def main():
    parser = argparse.ArgumentParser(
        description="Run a command from canonical JSON. Reads from stdin.")
    parser.add_argument("--db", default="admin",
                        help="Database to run command")
    parser.add_argument("--port", default="27017",
                        help="Port to server process")
    parser.add_argument("--uri", help="URI to MongoDB cluster")
    parser.add_argument("--quiet", action="store_true",
                        help="Do not output on success")
    parser.add_argument("--server_error_ok", action="store_true",
                        help="Consider an error reply from server a success")
    args = parser.parse_args()

    uri = args.uri
    if uri == None:
        uri = "mongodb://localhost:{}/?serverSelectionTimeoutMS=1000".format(
            args.port)

    cmd = json_util.loads(sys.stdin.read(), json_options=json_opts)
    if not run_cmd(uri, cmd, args.db, args.quiet, args.server_error_ok):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
