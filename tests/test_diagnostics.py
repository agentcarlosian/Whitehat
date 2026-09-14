import unittest

from whitehat.diagnostics import doctor_result


class DoctorTests(unittest.TestCase):
    def test_doctor_reports_only_implemented_capabilities(self) -> None:
        result = doctor_result()
        self.assertTrue(result["ok"])
        self.assertTrue(result["capabilities"]["localDependencyComparison"])
        self.assertTrue(result["capabilities"]["localDirectoryDiff"])
        self.assertTrue(result["capabilities"]["localFileInventory"])
        self.assertTrue(result["capabilities"]["localResultStorage"])
        self.assertTrue(result["capabilities"]["localReviewNotes"])
        self.assertTrue(result["capabilities"]["localSyntheticExecution"])
        self.assertTrue(result["capabilities"]["networkSessionValidation"])
        self.assertTrue(result["capabilities"]["releaseAudit"])
        self.assertTrue(result["capabilities"]["ruffScannerAdapter"])
        self.assertTrue(result["capabilities"]["network"])
        self.assertTrue(result["capabilities"]["loopbackNetworkExecution"])
        self.assertFalse(result["capabilities"]["externalNetwork"])
        self.assertFalse(result["capabilities"]["credentials"])
        self.assertFalse(result["capabilities"]["externalContact"])
        self.assertFalse(result["capabilities"]["submission"])


if __name__ == "__main__":
    unittest.main()
