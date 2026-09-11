import unittest

from whitehat.diagnostics import doctor_result


class DoctorTests(unittest.TestCase):
    def test_doctor_reports_only_implemented_capabilities(self) -> None:
        result = doctor_result()
        self.assertTrue(result["ok"])
        self.assertTrue(result["capabilities"]["localDirectoryDiff"])
        self.assertFalse(result["capabilities"]["network"])
        self.assertFalse(result["capabilities"]["credentials"])
        self.assertFalse(result["capabilities"]["externalContact"])
        self.assertFalse(result["capabilities"]["submission"])


if __name__ == "__main__":
    unittest.main()
