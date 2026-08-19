#!/usr/bin/env python3

"""
One test per correctness defect found in dsss.py.  Every one of them failed
before the corresponding fix landed - that is the whole point of the file.

All targets are local fixtures (see fixture.py); nothing here touches the
Internet.  Run with:

    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import socket
import subprocess
import sys
import time
import unittest
import urllib.request

from test_dsss import Base, DSSS, scan

import dsss
import fixture


class TestReflectionFilter(Base):
    """`_retrieve_content` blanks out anything that looks like a reflected payload.

    Without word boundaries that filter also eats legitimate page content that
    merely sits next to the words "and"/"or" and a number containing the random
    integer, which silently equalises the true and the false answer.
    """

    def test_content_next_to_a_standalone_and(self):
        self.assertVulnerable("/blind-wordy?id=1")

    def test_content_next_to_a_word_containing_and(self):
        self.assertVulnerable("/blind-brand?id=1")

    def test_reflected_payload_is_still_neutralised(self):
        self.assertNotVulnerable("/reflecting?id=1")

    def test_filter_does_not_blow_up_on_larger_pages(self):
        """The filter used to be super quadratic: 30kB of text took over 2 minutes."""

        url = self.server.url("/huge?id=1")
        started = time.time()
        content = dsss._retrieve_content(url)
        elapsed = time.time() - started
        self.assertGreater(len(content[dsss.HTML]), 10000)
        self.assertLess(elapsed, 2.0, "retrieving a %d byte page took %.1fs" % (len(content[dsss.HTML]), elapsed))


class TestComparison(Base):
    def test_big_page_with_a_tiny_conditional_difference(self):
        """A byte identical true answer is the strongest signal there is; it used to be
        thrown away because the fuzzy ratio of the false answer stayed above the
        threshold on a large page."""

        self.assertVulnerable("/blind-big?id=1")

    def test_title_tag_with_attributes(self):
        """<title id="..."> was not recognised as a title at all."""

        self.assertVulnerable("/blind-title-attribute?id=1")

    def test_inverted_boolean_answers_are_not_a_finding(self):
        """A WAF that blocks the *true* payload (the classic `1=1` signature) makes the
        false answer the one that matches the original.  That is not an injection."""

        self.assertNotVulnerable("/signature-waf?id=1")

    def test_page_with_per_request_content_is_not_a_finding(self):
        self.assertNotVulnerable("/dynamic?id=1")

    def test_empty_answer_is_still_comparable_by_status_code(self):
        """An empty body is not by itself suspicious: dropping every such answer would
        throw away a perfectly good status code oracle."""

        self.assertVulnerable("/blind-empty?id=1")

    def test_blocked_answers_are_not_a_finding(self):
        """Answers recognised as a firewall block have their content dropped; comparing
        such an empty answer against the original used to yield a finding."""

        self.server.state["every"] = 3
        self.assertNotVulnerable("/waf?id=1")


class TestParameters(Base):
    def test_parameter_name_with_a_dash(self):
        self.assertVulnerable("/blind-dashed?user-id=1")

    def test_parameter_name_with_a_dot(self):
        self.assertVulnerable("/blind-dashed?user.id=1")

    def test_parameter_name_with_brackets(self):
        self.assertVulnerable("/blind-dashed?filter[id]=1")

    def test_injection_does_not_poison_a_second_parameter(self):
        """`id=1` is a substring of `subid=1`: injecting by string replacement hits
        both parameters at once, and the target then only answers with error pages."""

        output = self.assertVulnerable("/blind-pair", data="id=1&subid=1")
        self.assertIn("scanning POST parameter 'id'", output)

    def test_poisoning_a_second_parameter_also_hides_error_messages(self):
        """Same defect seen from the error based side: the poisoned second parameter
        makes the target answer 400 before it ever talks to its database."""

        output = self.assertVulnerable("/error-pair", data="id=1&subid=1", kind="error")
        self.assertIn("(SQLite)", output)


class TestApi(Base):
    def test_parameter_name_is_not_polluted_by_separators(self):
        """`[^_]` happily matched the separator itself, so `?&id=1` was reported as a
        parameter literally named `&id`."""

        output = self.assertVulnerable("/blind?&id=1")
        self.assertIn("parameter 'id'", output)
        self.assertNotIn("'&id'", output)

    def test_hash_in_post_data(self):
        """There is no fragment in a request body, so `#` is an ordinary character;
        cutting the value there injected into the middle of somebody else's value."""

        output = self.assertVulnerable("/blind", data="color=#fff&id=1")
        self.assertIn("scanning POST parameter 'color'", output)

    def test_scan_page_without_a_url(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(dsss.scan_page(None))
            self.assertFalse(dsss.scan_page(None, None))

    def test_basic_auth_credentials_in_the_url(self):
        """`http://user:pass@host/` is how everybody writes down a target behind Basic
        auth; urllib passes the credentials straight into the host name and fails."""

        target = "http://user:pass@127.0.0.1:%d/auth?id=1" % self.server.server_address[1]
        result, output = self.scan(target)
        self.assertTrue(result, output)
        self.assertTrue(any(_[3].get("Authorization") for _ in self.server.requests))


class TestTransport(Base):
    def test_compression_is_ruled_out(self):
        """urllib never decompresses, so an answer that arrives gzipped is unreadable
        garbage.  http.client asks for `identity` on our behalf - keep it that way."""

        output = self.assertVulnerable("/gzipped?id=1", kind="error")
        self.assertIn("(SQLite)", output)
        self.assertTrue(all(_[3].get("Accept-Encoding") == "identity" for _ in self.server.requests), "compression was not ruled out")

    def test_unreachable_target_is_reported(self):
        """Instead of hammering a dead target with every payload and then claiming
        that no vulnerability was found, say that the target could not be read."""

        result, output = self.scan("http://%s/blind?id=1" % fixture.closed_port())
        self.assertFalse(result)
        self.assertIn("unable to retrieve", output)

    def test_unresponsive_target_gives_up_early(self):
        """A target that never answers used to cost one full timeout per payload."""

        dsss.TIMEOUT = 1
        started = time.time()
        result, output = self.scan("/hang?id=1")
        elapsed = time.time() - started
        self.assertFalse(result)
        self.assertIn("unable to retrieve", output)
        self.assertLess(elapsed, 15.0, "gave up only after %.1fs" % elapsed)

    def test_exception_without_arguments(self):
        """`str(ex.args[-1])` raised IndexError for exceptions carrying no arguments."""

        original = urllib.request.urlopen
        urllib.request.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(Exception())
        try:
            content = dsss._retrieve_content("http://127.0.0.1:1/x?id=1")
        finally:
            urllib.request.urlopen = original
        self.assertEqual(content[dsss.HTML], "")
        self.assertIsNone(content[dsss.HTTPCODE])


class TestErrorSignatures(Base):
    """Framework debug pages leak DB-API exceptions that no signature covered."""

    def test_python_sqlite_traceback(self):
        output = self.assertVulnerable("/error-python-sqlite?id=1", kind="error")
        self.assertIn("(SQLite)", output)

    def test_python_postgres_traceback(self):
        output = self.assertVulnerable("/error-python-postgres?id=1", kind="error")
        self.assertIn("(PostgreSQL)", output)


class TestUrls(Base):
    def test_space_in_the_url_path(self):
        """Only spaces *after* the question mark were escaped, so a path holding one
        made http.client reject every single request."""

        self.assertVulnerable("/blind space?id=1")


class TestEncoding(Base):
    def test_non_ascii_in_the_url(self):
        """A single non ASCII character used to make http.client reject every request,
        so not one of them ever reached the target."""

        output = self.assertVulnerable("/blind?zoo=caf\u00e9&id=1")
        self.assertIn("scanning GET parameter 'id'", output)

    def test_host_name_is_left_alone(self):
        """Percent-encoding the whole URL would break an internationalised host name:
        http.client punycodes the host itself, but only if it can still see it."""

        captured, original = [], urllib.request.Request
        urllib.request.Request = lambda url, *args, **kwargs: (captured.append(url), original(url, *args, **kwargs))[1]
        urlopen, urllib.request.urlopen = urllib.request.urlopen, lambda *args, **kwargs: (_ for _ in ()).throw(Exception("offline"))
        try:
            dsss._retrieve_content("http://m\u00fcnchen.test/p\u00e4th?q=\u00fc&id=1")
        finally:
            urllib.request.Request, urllib.request.urlopen = original, urlopen
        self.assertEqual(captured[0], "http://m\u00fcnchen.test/p%C3%A4th?q=%C3%BC&id=1")

    def test_fragment_is_not_part_of_the_target(self):
        """A fragment never reaches the server, so appending the payload behind it
        means testing the untouched original over and over again."""

        self.assertVulnerable("/blind?id=1#section-2")

    def test_unescaped_characters_in_the_url(self):
        self.assertVulnerable("/blind?q=a<b|c&id=1")


class TestSession(Base):
    def test_first_answer_is_not_the_yardstick(self):
        """The first request is the one that bootstraps the session, so its answer can
        differ from every later one; it must not become the baseline."""

        self.assertVulnerable("/first-visit?id=1")

    def test_cookie_set_by_the_target_is_sent_back(self):
        """Targets that hand out a session cookie on the first hit answered every
        later request with their "please enable cookies" page."""

        self.assertVulnerable("/session?id=1")


class TestTargets(unittest.TestCase):
    def setUp(self):
        dsss.TIMEOUT = 10
        dsss.init_options()

    def test_https_target_with_a_self_signed_certificate(self):
        """Test targets rarely have a certificate a CA would vouch for; refusing to
        talk to them means refusing to scan them."""

        with fixture.server(tls=True) as server:
            result, output = scan(server, "/blind?id=1")
        self.assertTrue(result, output)

    def test_ipv6_target(self):
        with fixture.server(family=socket.AF_INET6) as server:
            result, output = scan(server, "/blind?id=1")
        self.assertTrue(result, output)


class TestProxy(unittest.TestCase):
    def tearDown(self):
        dsss.init_options()

    def test_https_targets_go_through_the_proxy_too(self):
        """Only the `http` scheme was mapped, so every https target quietly bypassed
        the proxy the user asked for."""

        dsss.init_options(proxy="http://127.0.0.1:1")
        handlers = [_ for _ in urllib.request._opener.handlers if isinstance(_, urllib.request.ProxyHandler)]
        self.assertTrue(handlers)
        self.assertEqual(set(handlers[0].proxies), set(("http", "https")))

    def test_requests_really_are_proxied(self):
        with fixture.server() as server:
            with fixture.Proxy("127.0.0.1:%d" % server.server_address[1]) as proxy:
                dsss.init_options(proxy=proxy.address)
                self.assertTrue(scan(server, "/blind?id=1")[0])
                self.assertTrue(proxy.seen)
                self.assertTrue(all(_[1].startswith("http://") for _ in proxy.seen))


class TestCommandLineTargets(unittest.TestCase):
    def tearDown(self):
        dsss.init_options()

    def run_cli(self, *args):
        process = subprocess.run([sys.executable, DSSS] + list(args), capture_output=True, text=True, timeout=180)
        return process.returncode, process.stdout + process.stderr

    def test_host_name_starting_with_http(self):
        """`url.startswith("http")` is true for a host like `http2.example.com`, so no
        scheme was prepended and every single request failed."""

        with fixture.server() as server:
            with fixture.Proxy("127.0.0.1:%d" % server.server_address[1]) as proxy:
                code, output = self.run_cli("-u", "http2.example.test/blind?id=1", "--proxy", proxy.address)
                self.assertIn("blind SQLi vulnerable", output)


if __name__ == "__main__":
    unittest.main()
