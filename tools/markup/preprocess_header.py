#!/usr/bin/env python3
"""
Preprocess the header from the crypt_shared library.
The output of this script is intended to be copied into markup.py.
Example:
preprocess_header.py \
    /home/kevin/bin/mongo_crypt_shared_v1-linux-x86_64-enterprise-ubuntu1804-6.0/include/mongo_crypt/v1/mongo_crypt/mongo_crypt.h \
    | xsel --clipboard
"""

import argparse
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("header_file")
args = parser.parse_args()

with open(args.header_file, "r") as file:
    ifcount = 0
    for line in file:
        line = line[0:-1]  # Strip newline.
        if line == "#ifndef MONGO_CRYPT_SUPPORT_H" or line == "#endif  // MONGO_CRYPT_SUPPORT_H":
            # Ignore the macro line, but do not ignore the nested block.
            continue
        if re.match("^#if", line):
            ifcount += 1
            continue
        if re.match("^#end", line):
            ifcount -= 1
            continue
        if ifcount > 0:
            # Ignore blocks nested in #if or #ifdef.
            continue
        if re.match("^#", line):
            continue

        line = re.sub(r"MONGO_CRYPT_API ", "", line)
        line = re.sub(r"MONGO_API_CALL( ?)", "", line)
        print(line)
