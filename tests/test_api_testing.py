import importlib.metadata
import unittest

from whitehat.api_testing import test_owned_api as run_owned


def installed():
    try:
        return importlib.metadata.version("schemathesis") == "4.27.1"
    except importlib.metadata.PackageNotFoundError:
        return False


class StatefulApiTests(unittest.TestCase):
    @unittest.skipUnless(installed(), "install the api-test extra")
    def test_actual_engine_and_deterministic_lifecycle_twins(self):
        for broken in (False, True):
            with self.subTest(broken=broken):
                result = run_owned(broken)
                self.assertTrue(result["provenance"]["generated"]["complete"])
                self.assertGreater(
                    result["provenance"]["generated"]["testCases"]["generated"], 0
                )
                last = result["provenance"]["lifecycle"]["provenance"]["evaluations"][
                    -1
                ]
                self.assertEqual(
                    last["outcome"], "mismatch" if broken else "consistent"
                )
                self.assertFalse(any(result["claims"].values()))
                self.assertTrue(result["effects"]["fixtureDisposed"])
                self.assertFalse(result["effects"]["externalTargetRequests"])


if __name__ == "__main__":
    unittest.main()
