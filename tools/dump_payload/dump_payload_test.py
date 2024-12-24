import unittest
import base64
import dump_payload
from io import StringIO
import os
import sys


class TestDump (unittest.TestCase):
    def __init__(self, methodName='runTest'):
        unittest.TestCase.__init__(self, methodName)
        if os.environ.get("REGENERATE_GOLDEN_FILES", None) == "1":
            self.regenGolden = True

    def test_dump(self):
        testcases = [
            {"filename": "payload0"},
            {"filename": "payload1"},
            {"filename": "payload2"},
            {"filename": "payload3"},
            {"filename": "payload4"},
            {"filename": "payload5"},
            {"filename": "payload6"},
            {"filename": "payload7"},
            {"filename": "payload9"},
            {"filename": "payload4", "dumpivs": True},
            {"filename": "payload12"},
            {"filename": "payload14"},
        ]
        if "REGENERATE_GOLDEN_FILES" in os.environ:
            print("Regenerating golden files")
        for test in testcases:
            filename = test["filename"]
            with open(f"testdata/{filename}.b64", "r") as file:
                contents = file.read()
            # Capture stdout.
            capture = StringIO()
            old_stdout = sys.stdout
            sys.stdout = capture
            suffix = ""
            dumpivs = False
            if "dumpivs" in test and test["dumpivs"]:
                suffix += "_ivs"
                dumpivs = True
            dump_payload.dump_payload(contents, dumpivs=dumpivs)
            got = capture.getvalue()
            # Restore stdout
            sys.stdout = old_stdout
            if "REGENERATE_GOLDEN_FILES" in os.environ:
                with open(f"testdata/{filename}{suffix}.golden", "w") as file:
                    file.write(got)
            else:
                with open(f"testdata/{filename}{suffix}.golden", "r") as file:
                    golden = file.read()
                    self.assertEqual(
                        got, golden, msg=f"Failed to match: {filename}")

    def test_dumpivs_not_supported(self):
        with open(f"testdata/payload9.b64", "r") as file:
            contents = file.read()
        with self.assertRaises(RuntimeError) as e:
            # Capture stdout.
            capture = StringIO()
            old_stdout = sys.stdout
            sys.stdout = capture
            dump_payload.dump_payload(contents, dumpivs=True)
            # Restore stdout
            sys.stdout = old_stdout
        expect = "--dumpivs specified, but not supported for payload type"
        got = str(e.exception)
        self.assertTrue(
            expect in got, "expected exception to contain '{}', but got '{}'".format(expect, got))


if __name__ == "__main__":
    unittest.main()
