#!/usr/bin/env python3

"""
Two sweeps that are deliberately broad rather than deep:

* every fixture endpoint is scanned and its verdict compared against the truth
  known from the fixture's own source (no endpoint may silently flip verdict);
* the interesting endpoints are scanned again for a range of RANDINT values,
  because that random integer ends up inside payloads *and* inside the regular
  expression that strips reflected payloads.
"""

import unittest

from test_dsss import Base

import dsss

# (target, data) -> the scanner must report something
VULNERABLE = (
    ("/error?id=1", None),
    ("/error-mysql?id=1", None),
    ("/error-python-sqlite?id=1", None),
    ("/error-python-postgres?id=1", None),
    ("/blind?id=1", None),
    ("/blind?id=1", "id=2"),
    ("/blind", "id=1"),
    ("/blind space?id=1", None),
    ("/blind-quoted?name=alice", None),
    ("/blind-code?id=1", None),
    ("/blind-empty?id=1", None),
    ("/blind-title?id=1", None),
    ("/blind-title-attribute?id=1", None),
    ("/blind-big?id=1", None),
    ("/blind-wordy?id=1", None),
    ("/blind-brand?id=1", None),
    ("/blind-dashed?user-id=1", None),
    ("/blind-dashed?filter[id]=1", None),
    ("/blind-pair", "id=1&subid=1"),
    ("/duplicated?page=1&id=1&sort=name&id=1", None),
    ("/gzipped?id=1", None),
    ("/huge?id=1", None),
    ("/session?id=1", None),
    ("/first-visit?id=1", None),
)

# (target, data) -> the scanner must keep quiet
NOT_VULNERABLE = (
    ("/safe?id=1", None),
    ("/reflecting?id=1", None),
    ("/dynamic?id=1", None),
    ("/signature-waf?id=1", None),
    ("/error500?id=1", None),
    ("/static?id=1", None),
    ("/static", None),
    ("/blind?_token=1", None),
    ("/blind", "_token=1"),
)

RANDINTS = (1, 2, 9, 10, 42, 99, 100, 128, 199, 254, 255)

INTERESTING = ("/blind?id=1", "/blind-wordy?id=1", "/blind-brand?id=1", "/blind-big?id=1", "/blind-title?id=1", "/error?id=1")


class TestMatrix(Base):
    def test_vulnerable_endpoints(self):
        for target, data in VULNERABLE:
            with self.subTest(target=target, data=data):
                result, output = self.scan(target, data)
                self.assertTrue(result, "nothing reported for %s (%s)\n%s" % (target, data, output))

    def test_not_vulnerable_endpoints(self):
        for target, data in NOT_VULNERABLE:
            with self.subTest(target=target, data=data):
                self.server.state["every"] = 3
                result, output = self.scan(target, data)
                self.assertFalse(result, "false positive for %s (%s)\n%s" % (target, data, output))

    def test_request_count_stays_bounded(self):
        """4 prefixes * 2 tests * 4 suffixes * 2 comment styles, two requests each,
        plus the original and the poisoned one: 130 for a parameter that is not
        vulnerable, and no more than that."""

        self.scan("/safe?id=1")
        self.assertLessEqual(len(self.server.requests), 130)


class TestRandintRobustness(Base):
    def setUp(self):
        Base.setUp(self)
        self.addCleanup(setattr, dsss, "RANDINT", dsss.RANDINT)

    def test_verdicts_do_not_depend_on_the_random_integer(self):
        for randint in RANDINTS:
            dsss.RANDINT = self.server.state["randint"] = randint
            for target in INTERESTING:
                with self.subTest(randint=randint, target=target):
                    result, output = self.scan(target)
                    self.assertTrue(result, "nothing reported for %s with RANDINT=%d\n%s" % (target, randint, output))

    def test_no_false_positives_for_any_random_integer(self):
        for randint in RANDINTS:
            dsss.RANDINT = self.server.state["randint"] = randint
            for target in ("/safe?id=1", "/reflecting?id=1", "/dynamic?id=1"):
                with self.subTest(randint=randint, target=target):
                    result, output = self.scan(target)
                    self.assertFalse(result, "false positive for %s with RANDINT=%d\n%s" % (target, randint, output))


if __name__ == "__main__":
    unittest.main()
