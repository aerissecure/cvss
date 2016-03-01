#/usr/bin/python
"""
Tests cvss2 module.
"""

import unittest
from decimal import Decimal as D
from cvss2 import nvd_severity, valid_vector, BaseVector, from_base_metrics

class TestCVSS2(unittest.TestCase):

    def test_nvd_severity(self):
        """Tests severity value cut-offs"""
        self.assertEqual(nvd_severity('1.0'), 'Low')
        self.assertEqual(nvd_severity('3.9'), 'Low')
        self.assertEqual(nvd_severity('4.0'), 'Medium')
        self.assertEqual(nvd_severity('6.9'), 'Medium')
        self.assertEqual(nvd_severity('7.0'), 'High')
        self.assertEqual(nvd_severity('10.0'), 'High')

    def test_valid_vector(self):
        # Valid vector
        actual = valid_vector('AV:N/AC:L/Au:N/C:N/I:N/A:P')
        expected = True
        self.assertEqual(actual,expected)
        # Invalid vector - missing metric
        actual = valid_vector('AV:N/AC:L/Au:N/C:N/I:N/')
        expected = False
        self.assertEqual(actual,expected)
        # Invalid vector - invalid metric
        actual = valid_vector('AV:N/AC:L/Au:N/C:N/I:N/A:H')
        expected = False
        self.assertEqual(actual,expected)

    def test_severity(self):
        actual = BaseVector('AV:N/AC:L/Au:N/C:N/I:N/A:P').severity
        expected = 'Medium'
        self.assertEqual(actual,expected)
        actual = BaseVector('AV:N/AC:L/Au:N/C:P/I:P/A:P').severity
        expected = 'High'
        self.assertEqual(actual,expected)
        actual = BaseVector('AV:L/AC:H/Au:S/C:P/I:P/A:N').severity
        expected = 'Low'
        self.assertEqual(actual,expected)

    def test_base_score(self):
        actual = BaseVector('AV:N/AC:L/Au:N/C:N/I:N/A:P').base_score
        expected = D('5.0')
        self.assertEqual(actual,expected)
        actual = BaseVector('AV:N/AC:L/Au:N/C:P/I:P/A:P').base_score
        expected = D('7.5')
        self.assertEqual(actual,expected)
        actual = BaseVector('AV:L/AC:H/Au:S/C:P/I:P/A:N').base_score
        expected = D('2.4')
        self.assertEqual(actual,expected)

    def test_from_base_metrics(self):
        expected = BaseVector('AV:N/AC:L/Au:N/C:N/I:P/A:C')
        actual = from_base_metrics('n', 'l', 'n', 'n', 'p', 'c')
        self.assertEqual(actual,expected)


if __name__ == '__main__':
    unittest.main()