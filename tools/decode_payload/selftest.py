# /// script
# dependencies = [
#   "pymongo",
# ]
# ///

import unittest
import base64

import bson
import decode_payload
import os
from pathlib import Path

class TestDecode (unittest.TestCase):
    def __init__(self, methodName='runTest'):
        unittest.TestCase.__init__(self, methodName)
        if os.environ.get("REGENERATE_GOLDEN_FILES", None) == "1":
            self.regenGolden = True

    def test_decode(self):
        if "REGENERATE_GOLDEN_FILES" in os.environ:
            print("Regenerating golden files")
        for test_path in Path("selftest_data").glob("*.b64"):
            file_name = test_path.stem
            test_b64 = test_path.read_text()
            test_data = base64.b64decode(test_b64)
            got_dict = decode_payload.decode_payload(test_data)
            got_json = bson.json_util.dumps(got_dict, indent=2)
            if "REGENERATE_GOLDEN_FILES" in os.environ:
                Path(f"selftest_data/{file_name}.golden").write_text(got_json)
            else:
                expect = Path(f"selftest_data/{file_name}.golden").read_text()
                self.maxDiff = None # To print big string
                self.assertEqual(got_json, expect, msg=f"Failed to match: {file_name}")

if __name__ == "__main__":
    unittest.main()
