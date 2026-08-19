#!/usr/bin/env python3

"""
Regression tests for dsss.py.

Everything runs against local fixtures (see fixture.py) - no third party target
is ever contacted.  Run with:

    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.environ.get("DSSS_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))    # DSSS_DIR lets mutations.py point the whole suite at a patched copy

import dsss
import fixture

EXPECTED_HELP = """Usage: dsss.py [options]

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.php?id=1")
  --data=DATA        POST data (e.g. "query=test")
  --cookie=COOKIE    HTTP Cookie header value
  --user-agent=UA    HTTP User-Agent header value
  --referer=REFERER  HTTP Referer header value
  --proxy=PROXY      HTTP proxy address (e.g. "http://127.0.0.1:8080")
"""

DSSS = os.path.join(sys.path[0], "dsss.py")


def scan(server, target, data=None):
    """Runs a scan against a local fixture, returning (result, printed output)."""

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = dsss.scan_page(server.url(target) if target.startswith("/") else target, data)
    return result, buffer.getvalue()


class Base(unittest.TestCase):
    routes = None

    def setUp(self):
        dsss.TIMEOUT = 10
        dsss.init_options()
        self.server = fixture.server(self.routes)
        self.server.__enter__()
        self.server.state["randint"] = dsss.RANDINT
        self.addCleanup(self.server.__exit__)

    def scan(self, path, data=None):
        return scan(self.server, path, data)

    def assertVulnerable(self, path, data=None, kind="blind"):
        result, output = self.scan(path, data)
        self.assertTrue(result, "no vulnerability reported for %s (%s)\n%s" % (path, data, output))
        self.assertIn("%s SQLi vulnerable" % kind, output, output)
        return output

    def assertNotVulnerable(self, path, data=None):
        result, output = self.scan(path, data)
        self.assertFalse(result, "false positive for %s (%s)\n%s" % (path, data, output))
        return output


class TestErrorBased(Base):
    def test_sqlite_error_is_detected(self):
        output = self.assertVulnerable("/error?id=1", kind="error")
        self.assertIn("(SQLite)", output)

    def test_mysql_error_is_detected(self):
        output = self.assertVulnerable("/error-mysql?id=1", kind="error")
        self.assertIn("(MySQL)", output)

    def test_parameterised_query_is_not_flagged(self):
        self.assertNotVulnerable("/safe?id=1")

    def test_reflected_value_is_not_flagged(self):
        self.assertNotVulnerable("/reflecting?id=1")


class TestBlind(Base):
    def test_unquoted_numeric_parameter(self):
        self.assertVulnerable("/blind?id=1")

    def test_single_quoted_string_parameter(self):
        self.assertVulnerable("/blind-quoted?name=alice")

    def test_boolean_leaked_through_http_code(self):
        self.assertVulnerable("/blind-code?id=1")

    def test_boolean_leaked_through_title(self):
        self.assertVulnerable("/blind-title?id=1")

    def test_post_parameter(self):
        self.assertVulnerable("/blind", data="id=1")

    def test_second_of_several_parameters(self):
        output = self.assertVulnerable("/blind?page=2&id=1")
        self.assertIn("scanning GET parameter 'page'", output)
        self.assertIn("scanning GET parameter 'id'", output)

    def test_internal_server_errors_are_not_flagged(self):
        self.assertNotVulnerable("/error500?id=1")

    def test_static_page_without_parameters(self):
        result, output = self.scan("/static")
        self.assertFalse(result)
        self.assertIn("no usable GET/POST parameters found", output)

    def test_empty_parameter_value_is_filled_in(self):
        output = self.assertVulnerable("/blind?id=")
        self.assertIn("scanning GET parameter 'id'", output)


class TestHeaders(Base):
    def test_custom_headers_are_sent(self):
        dsss.init_options(cookie="a=b", ua="my-agent", referer="http://ref.local/")
        self.scan("/static?id=1")
        headers = self.server.requests[0][3]
        self.assertEqual(headers.get("Cookie"), "a=b")
        self.assertEqual(headers.get("User-Agent"), "my-agent")
        self.assertEqual(headers.get("Referer"), "http://ref.local/")

    def test_default_user_agent_is_the_scanner_name(self):
        self.scan("/static?id=1")
        self.assertEqual(self.server.requests[0][3].get("User-Agent"), dsss.NAME)


class TestCommandLine(unittest.TestCase):
    def run_cli(self, *args):
        process = subprocess.run([sys.executable, DSSS] + list(args), capture_output=True, text=True, timeout=120)
        return process.returncode, process.stdout + process.stderr

    def test_help_is_printed_without_arguments(self):
        code, output = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("--url", output)

    def test_command_line_interface_is_unchanged(self):
        """The published interface, verbatim: options, order, metavars and help texts."""

        code, output = self.run_cli("--help")
        self.assertEqual(code, 0)
        self.assertIn(EXPECTED_HELP, output.replace("\r\n", "\n"))

    def test_version(self):
        code, output = self.run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn(dsss.VERSION, output)

    def test_every_option_at_once(self):
        """The whole command line, end to end, against a local target."""

        with fixture.server() as server:
            code, output = self.run_cli("-u", server.url("/blind?id=1"), "--data", "x=1", "--cookie", "a=b",
                                       "--user-agent", "ua/1.0", "--referer", "http://ref.local/")
            self.assertEqual(code, 0)
            self.assertIn("blind SQLi vulnerable", output)
            self.assertIn("possible vulnerabilities found", output)
            self.assertIn("scanning POST parameter 'x'", output)
            method, path, body, headers = server.requests[0]
            self.assertEqual(method, "POST")
            self.assertEqual((headers.get("Cookie"), headers.get("User-Agent"), headers.get("Referer")), ("a=b", "ua/1.0", "http://ref.local/"))

    def test_scan_without_scheme(self):
        with fixture.server() as server:
            code, output = self.run_cli("-u", "%s/blind?id=1" % server.base.split("//")[1])
            self.assertIn("blind SQLi vulnerable", output)
            self.assertIn("possible vulnerabilities found", output)


if __name__ == "__main__":
    unittest.main()
