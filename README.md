Damn Small SQLi Scanner [![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-Public_domain-red.svg)](https://wiki.creativecommons.org/wiki/Public_domain)
=========

**Damn Small SQLi Scanner** (DSSS) is a fully functional [SQL injection](https://en.wikipedia.org/wiki/SQL_injection) vulnerability scanner (supporting GET and POST parameters) written in under 100 lines of code.

![Vulnerable](http://i.imgur.com/7mXeXjF.png)

As of optional settings it supports HTTP proxy together with HTTP header values `User-Agent`, `Referer` and `Cookie`.

Sample runs
----

```
$ python3 dsss.py -h
Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code) #v0.4b
 by: Miroslav Stampar (@stamparm)

Usage: dsss.py [options]

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.php?id=1")
  --data=DATA        POST data (e.g. "query=test")
  --cookie=COOKIE    HTTP Cookie header value
  --user-agent=UA    HTTP User-Agent header value
  --referer=REFERER  HTTP Referer header value
  --proxy=PROXY      HTTP proxy address (e.g. "http://127.0.0.1:8080")
```

```
$ python3 dsss.py -u "http://testphp.vulnweb.com/artists.php?artist=1"
Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code) #v0.4b
 by: Miroslav Stampar (@stamparm)

* scanning GET parameter 'artist'
 (i) GET parameter 'artist' appears to be error SQLi vulnerable (MySQL)
 (i) GET parameter 'artist' appears to be blind SQLi vulnerable (e.g.: 'http://t
estphp.vulnweb.com/artists.php?artist=1%20AND%2061%3D61')

scan results: possible vulnerabilities found
```

Requirements
----

[Python](http://www.python.org/download/) version **3.x** is required for running this program.

Tests
----

The test suite lives in `tests/` and needs nothing besides the standard library (plus
`openssl` for the TLS fixture). It never touches the Internet: `tests/fixture.py` starts
local HTTP servers backed by a real `sqlite3` database whose queries are built by string
interpolation, so the injections the scanner finds there are genuine ones. The endpoints
differ in how they *present* the result - DBMS error message, HTTP status code, `<title>`,
page size, a firewall block page, a session cookie, a self signed certificate - which is
exactly what a scanner has to key off.

```
$ python3 -m unittest discover -s tests -v
...
Ran 68 tests in 57.241s

OK
```

`tests/test_dsss.py` covers the documented behaviour (including the command line
interface verbatim), `tests/test_regressions.py` holds one test per fixed defect,
and `tests/test_matrix.py` sweeps every endpoint plus a range of `RANDINT` values.
`tests/test_mysql.py` repeats the interesting cases against a real MySQL in a
container - MySQL is the DBMS the payload matrix is aimed at, and the only one where
`#` is a comment while `--` needs trailing whitespace - and skips itself when docker
or the image is not already there.

To check that the suite really does pin those fixes, `tests/mutations.py` puts each
piece of pre-fix code back into a private copy of `dsss.py` and insists that the suite
notices:

```
$ python3 tests/mutations.py
running 24 mutations against the suite

ok   reflection filter: no word boundaries                          FAILED (failures=1) -> test_content_next_to_a_standalone_and
ok   title tag: no attributes allowed                               FAILED (failures=1) -> test_title_tag_with_attributes
...
24/24 mutations caught
```
