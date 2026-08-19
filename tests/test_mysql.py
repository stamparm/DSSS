#!/usr/bin/env python3

"""
The same scanner, pointed at a *real* MySQL (5.5, in a container) instead of the
sqlite3 fixture.  MySQL is what the payload matrix inside dsss.py is aimed at, and
it is the one DBMS that disagrees with sqlite3 on the things that matter:

* `--` only starts a comment when whitespace follows it, so `-- -` works while the
  inline comment flavour `--/**/-` does not (`#` covers that case instead, and `#`
  is a comment in MySQL only);
* its error messages are what half of DBMS_ERRORS was written against.

Skipped unless docker and the image are already available locally; nothing is
downloaded and nothing outside 127.0.0.1 is contacted.
"""

import unittest

from test_dsss import scan

import dsss
import fixture

AVAILABLE = fixture.mysql_available()


@unittest.skipUnless(AVAILABLE, "docker image %s or pymysql not available" % fixture.MySQL.IMAGE)
class TestRealMySQL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = fixture.mysql_server()
        cls.server.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__()

    def setUp(self):
        dsss.TIMEOUT = 10
        dsss.init_options()
        self.server.state["randint"] = dsss.RANDINT
        del self.server.requests[:]

    def scan(self, target, data=None):
        return scan(self.server, target, data)

    def test_error_message_is_recognised_as_mysql(self):
        """The genuine 1064 message, echoed the way mysql_error() gets echoed."""

        result, output = self.scan("/error-verbatim?id=1")
        self.assertTrue(result, output)
        self.assertIn("error SQLi vulnerable (MySQL)", output)

    def test_blind_numeric_parameter(self):
        result, output = self.scan("/blind?id=1")
        self.assertTrue(result, output)
        self.assertIn("blind SQLi vulnerable", output)

    def test_blind_single_quoted_parameter(self):
        """Needs one of the comment suffixes to swallow the trailing quote."""

        result, output = self.scan("/blind-quoted?name=alice")
        self.assertTrue(result, output)

    def test_blind_single_quoted_parameter_behind_a_space_filter(self):
        """Only the inline comment payloads survive a filter that rejects whitespace,
        and on MySQL only the `#` suffix survives being inline commented."""

        result, output = self.scan("/blind-quoted-no-spaces?name=alice")
        self.assertTrue(result, output)
        self.assertNotIn("%20", output.split("e.g.: ")[-1])

    def test_post_parameter(self):
        result, output = self.scan("/blind", data="id=1")
        self.assertTrue(result, output)

    def test_parameterised_query_is_not_flagged(self):
        result, output = self.scan("/safe?id=1")
        self.assertFalse(result, output)

    def test_dbms_error_pages_are_not_needed_for_the_verdict(self):
        """A target that swallows its errors is still found through the booleans."""

        result, output = self.scan("/blind?id=2")
        self.assertTrue(result, output)


if __name__ == "__main__":
    unittest.main()
