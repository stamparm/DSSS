#!/usr/bin/env python3

"""
Deterministic, fully offline fixtures for exercising dsss.py.

The heart of it is a *real* SQL injection: every ``/sqli/*`` endpoint builds its
query by string interpolation and hands it to a real sqlite3 database, so the
"vulnerable" behaviour is genuine rather than mocked.  Endpoints differ only in
how they *present* the result (error message, HTTP code, title, page size, ...)
which is exactly what the scanner has to key off.

Nothing here talks to the network beyond 127.0.0.1.
"""

import atexit
import base64
import gzip
import http.server
import os
import re
import socket
import sqlite3
import shutil
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

USERS = ((1, "alice", "admin"), (2, "bob", "user"))

# Error templates lifted (shortened) from real world applications, chosen so that
# they match the DBMS_ERRORS regular expressions inside dsss.py.
SQLITE_ERROR = "<b>Warning</b>:  SQLite3::query(): Unable to prepare statement: 1, %s in <b>/var/www/html/index.php</b> on line <b>12</b>"
PYTHON_SQLITE_ERROR = "<title>OperationalError</title><h1>sqlite3.OperationalError</h1><div>sqlite3.OperationalError: %s</div><div>Traceback (most recent call last): File \"/app/views.py\", line 20, in search</div>"
PYTHON_POSTGRES_ERROR = "<title>ProgrammingError</title><h1>psycopg2.errors.SyntaxError</h1><div>psycopg2.errors.SyntaxError: syntax error at or near \"AND\"</div><div>LINE 1: %s</div>"
MYSQL_ERROR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%s' at line 1"
BLOCKED_PAGE = "<html><head><title>Forbidden</title></head><body>Your IP has been blocked by our firewall.</body></html>"

FILLER = " ".join("Nam quis nulla lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor." for _ in range(20))


def page(title, body, filler=""):
    return "<html><head><title>%s</title></head><body>%s%s</body></html>" % (title, filler, body)


class Database(object):
    """Throwaway on-disk sqlite3 database (on-disk so any thread can open it)."""

    def __init__(self):
        handle, self.path = tempfile.mkstemp(prefix="dsss-fixture-", suffix=".sqlite")
        os.close(handle)
        connection = sqlite3.connect(self.path)
        connection.execute("CREATE TABLE users (id INTEGER, name TEXT, role TEXT)")
        connection.executemany("INSERT INTO users VALUES (?, ?, ?)", USERS)
        connection.commit()
        connection.close()

    def query(self, sql):
        """Runs `sql` verbatim.  Returns (rows, error message or None)."""

        connection = sqlite3.connect(self.path)
        try:
            return connection.execute(sql).fetchall(), None
        except sqlite3.Error as ex:
            return [], str(ex)
        finally:
            connection.close()

    def parameterised(self, sql, params):
        connection = sqlite3.connect(self.path)
        try:
            return connection.execute(sql, params).fetchall()
        finally:
            connection.close()

    def remove(self):
        if os.path.exists(self.path):
            os.remove(self.path)


class MySQL(object):
    """The same interface as `Database`, but backed by a real MySQL in a container.

    Worth the trouble because MySQL is the DBMS the payload matrix is really aimed
    at: its `-- ` comment needs trailing whitespace, `#` is a comment while it is
    not one anywhere else, and its error messages are what DBMS_ERRORS was written
    for.  sqlite3 agrees with none of that.
    """

    IMAGE = "cytopia/mysql-5.5"

    def __init__(self):
        self.container = subprocess.check_output(("docker", "run", "-d", "--rm", "-e", "MYSQL_ALLOW_EMPTY_PASSWORD=yes", "-e", "MYSQL_ROOT_PASSWORD=", "-P", self.IMAGE), stderr=subprocess.STDOUT).decode().strip()
        for attempt in range(120):                                      # the port mapping and then the server itself both need a moment
            try:
                self.port = int(re.search(r":(\d+)", subprocess.check_output(("docker", "port", self.container, "3306/tcp"), stderr=subprocess.DEVNULL).decode()).group(1))
                self.connection = __import__("pymysql").connect(host="127.0.0.1", port=self.port, user="root", password="", autocommit=True)
                break
            except Exception:
                threading.Event().wait(0.5)
        else:
            raise RuntimeError("MySQL in %s never came up" % self.container)
        self.lock = threading.Lock()
        cursor = self.connection.cursor()
        cursor.execute("CREATE DATABASE app")
        cursor.execute("USE app")
        cursor.execute("CREATE TABLE users (id INT, name VARCHAR(32), role VARCHAR(32))")
        cursor.executemany("INSERT INTO users VALUES (%s, %s, %s)", USERS)

    def query(self, sql):
        with self.lock:                                                 # one shared connection, and the fixture server is threaded
            cursor = self.connection.cursor()
            try:
                cursor.execute(sql)
                return cursor.fetchall(), None
            except Exception as ex:
                return [], "%s" % (ex.args[-1] if ex.args else ex)

    def parameterised(self, sql, params):
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute(sql.replace('?', "%s"), params)
            return cursor.fetchall()

    def remove(self):
        subprocess.call(("docker", "rm", "-f", self.container), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def mysql_available():
    try:
        __import__("pymysql")
        return bool(subprocess.check_output(("docker", "images", "-q", MySQL.IMAGE), stderr=subprocess.DEVNULL).strip())
    except Exception:
        return False


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    # ------------------------------------------------------------------ plumbing

    def _params(self):
        parsed = urllib.parse.urlsplit(self.path)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if self.command == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            self.body = self.rfile.read(length).decode("utf8", "ignore")
            pairs += urllib.parse.parse_qsl(self.body, keep_blank_values=True)
        else:
            self.body = ""
        params = {}
        for name, value in pairs:                                       # first occurrence wins, like PHP's $_GET does *not*, but like most frameworks do
            params.setdefault(name, value)
        return urllib.parse.unquote(parsed.path), params

    def _respond(self, code, body, gzipped=False, headers=()):
        payload = body.encode("utf8")
        if gzipped:
            payload = gzip.compress(payload)
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if gzipped:
            self.send_header("Content-Encoding", "gzip")
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.handle_request()

    do_POST = do_GET

    def handle_request(self):
        path, params = self._params()
        server = self.server
        server.requests.append((self.command, self.path, self.body, dict(self.headers)))
        handler = server.routes.get(path)
        if handler is None:
            self._respond(404, page("Not Found", "no such route"))
        else:
            handler(self, params)


def certificate():
    """Self signed certificate for 127.0.0.1, generated once per interpreter."""

    if not globals().get("_certificate"):
        directory = tempfile.mkdtemp(prefix="dsss-fixture-tls-")
        atexit.register(shutil.rmtree, directory, True)
        globals()["_certificate"] = os.path.join(directory, "cert.pem")
        subprocess.check_output(("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", _certificate,
                                 "-out", _certificate, "-days", "1", "-subj", "/CN=127.0.0.1"), stderr=subprocess.STDOUT)
    return _certificate


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, routes, database=None, family=socket.AF_INET, tls=False):
        self.address_family, self.scheme = family, "https" if tls else "http"
        http.server.ThreadingHTTPServer.__init__(self, ("::1" if family == socket.AF_INET6 else "127.0.0.1", 0), Handler)
        self.routes, self.database, self.requests, self.state = routes, database, [], {}
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate())
            self.socket = context.wrap_socket(self.socket, server_side=True)

    @property
    def base(self):
        host = "[::1]" if self.address_family == socket.AF_INET6 else "127.0.0.1"
        return "%s://%s:%d" % (self.scheme, host, self.server_address[1])

    def url(self, path):
        return "%s%s" % (self.base, path)

    def bump(self, key):
        self.state[key] = self.state.get(key, 0) + 1
        return self.state[key]

    def __enter__(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *args):
        self.shutdown()
        self.server_close()
        if self.database:
            self.database.remove()


# --------------------------------------------------------------------- endpoints
#
# Every endpoint below receives the parsed parameters and answers with a page.
# The ones named *sqli* are genuinely injectable through sqlite3.


def _lookup(handler, params, column="id", table="users"):
    value = params.get(column, "1")
    return handler.server.database.query("SELECT name FROM %s WHERE %s = %s" % (table, column, value))


def error_based(handler, params):
    """Leaks the DBMS error message into the page (HTTP 200), like a stock PHP app."""

    rows, error = _lookup(handler, params)
    if error:
        handler._respond(200, page("Error", SQLITE_ERROR % error))
    else:
        handler._respond(200, page("User", rows[0][0] if rows else "not found"))


def error_based_mysql(handler, params):
    rows, error = _lookup(handler, params)
    if error:
        handler._respond(200, page("Error", MYSQL_ERROR % error))
    else:
        handler._respond(200, page("User", rows[0][0] if rows else "not found"))


def error_based_python_sqlite(handler, params):
    """A framework debug page (Flask/Django style) leaking a DB-API exception."""

    rows, error = _lookup(handler, params)
    if error:
        handler._respond(500, "<html><head>%s</head><body>debug</body></html>" % (PYTHON_SQLITE_ERROR % error))
    else:
        handler._respond(200, page("User", rows[0][0] if rows else "not found"))


def error_based_python_postgres(handler, params):
    rows, error = _lookup(handler, params)
    if error:
        handler._respond(500, "<html><head>%s</head><body>debug</body></html>" % (PYTHON_POSTGRES_ERROR % error))
    else:
        handler._respond(200, page("User", rows[0][0] if rows else "not found"))


def error_verbatim(handler, params):
    """Echoes the DBMS error message as it comes, the way mysql_error() gets echoed."""

    rows, error = _lookup(handler, params)
    handler._respond(200, page("Error" if error else "User", error or (rows[0][0] if rows else "not found")))


def blind_quoted_no_spaces(handler, params):
    """Single quoted and behind a filter that rejects whitespace in values, so only
    the inline comment flavour of the payloads can get through."""

    value = params.get("name", "alice")
    if " " in value:
        handler._respond(403, page("Blocked", "<h1>request blocked</h1>"))
    else:
        rows, _ = handler.server.database.query("SELECT role FROM users WHERE name = '%s'" % value)
        handler._respond(200, page("Users", "<h1>%s</h1>" % (rows[0][0] if rows else "no such user")))


def blind(handler, params):
    """Swallows errors: only the presence of a row leaks the boolean."""

    rows, _ = _lookup(handler, params)
    handler._respond(200, page("Users", "<h1>%s</h1>" % (rows[0][0] if rows else "no such user")))


def first_visit(handler, params):
    """Vulnerable, but the very first (cookie-less) hit gets a different page.

    Now that cookies are kept, that page must not be the one everything else is
    compared against, or the comparison is off by one banner for the whole scan.
    """

    if "session=" not in (handler.headers.get("Cookie") or ""):
        handler._respond(200, page("Welcome", "<h1>welcome, this is your first visit</h1>", FILLER), headers=(("Set-Cookie", "session=deadbeef; Path=/"),))
    else:
        blind(handler, params)


def basic_auth(handler, params):
    """Requires HTTP Basic credentials; vulnerable once authenticated."""

    if handler.headers.get("Authorization") != "Basic %s" % base64.b64encode(b"user:pass").decode():
        handler._respond(401, page("Unauthorized", "<h1>authentication required</h1>"), headers=(("WWW-Authenticate", "Basic realm=\"dsss\""),))
    else:
        blind(handler, params)


def session(handler, params):
    """Vulnerable, but bootstraps a session first: without a cookie it only ever
    redirects to itself, which is an endless loop for a client that drops cookies."""

    if "session=" not in (handler.headers.get("Cookie") or ""):
        handler._respond(302, page("Redirect", "<h1>redirecting</h1>"), headers=(("Location", handler.path), ("Set-Cookie", "session=deadbeef; Path=/")))
    else:
        blind(handler, params)


def blind_quoted(handler, params):
    """Same, but the value is single quoted, so a comment suffix is required."""

    value = params.get("name", "alice")
    rows, _ = handler.server.database.query("SELECT role FROM users WHERE name = '%s'" % value)
    handler._respond(200, page("Users", "<h1>%s</h1>" % (rows[0][0] if rows else "no such user")))


def blind_code(handler, params):
    """Leaks the boolean through the HTTP status code only."""

    rows, _ = _lookup(handler, params)
    body = page("Users", "<h1>result</h1>")
    handler._respond(200 if rows else 404, body)


def blind_empty(handler, params):
    """Leaks the boolean as content plus 200 versus an empty 404 - no content at all
    to compare, but the status code alone is a perfectly good oracle."""

    rows, _ = _lookup(handler, params)
    if rows:
        handler._respond(200, page("Users", "<h1>%s</h1>" % rows[0][0]))
    else:
        handler._respond(404, "")


def blind_title(handler, params):
    """Leaks the boolean through the <title> only (body is byte identical)."""

    rows, _ = _lookup(handler, params)
    handler._respond(200, page("Found" if rows else "Missing", "<h1>result</h1>", FILLER))


def blind_title_attribute(handler, params):
    """Leaks the boolean through a <title> that carries attributes.

    The body also holds a per request counter, so that byte for byte comparison of
    the whole page cannot be used as a shortcut: only the title is a usable signal.
    """

    rows, _ = _lookup(handler, params)
    body = "<html><head><title id=\"pageTitle\" lang=\"en\">%s</title></head><body>%s<h1>result</h1><!-- request %d --></body></html>"
    handler._respond(200, body % ("Found" if rows else "Missing", FILLER, handler.server.bump("title")))


def blind_big(handler, params):
    """A big page with a tiny conditional difference (fuzzy ratio stays > threshold)."""

    rows, _ = _lookup(handler, params)
    handler._respond(200, page("Users", "<span>%s</span>" % ("yes" if rows else "no"), FILLER * 3))


def blind_wordy(handler, params):
    """Conditional text sitting next to the words 'and'/'or' and a longer number.

    dsss.py blanks out anything that looks like a reflected payload.  The number
    used in the payloads is a substring of the number below and the text contains
    a standalone 'and', so a filter without word boundaries eats this legitimate
    (and differing) content, equalising both answers.
    """

    rows, _ = _lookup(handler, params)
    randint = handler.server.state.get("randint", 61)
    handler._respond(200, page("Users", "<p>Sales and %d0 models available: %s</p>" % (randint, "in stock" if rows else "sorry, nothing matched that query")))


def blind_brand(handler, params):
    """Conditional text next to a word *containing* 'and' plus a standalone number."""

    rows, _ = _lookup(handler, params)
    randint = handler.server.state.get("randint", 61)
    handler._respond(200, page("Users", "<p>Brand %d: %s</p>" % (randint, "in stock" if rows else "sorry, nothing matched that query")))


def blind_dashed(handler, params):
    """Vulnerable, but the parameter name is not a plain identifier."""

    value = params.get("user-id") or params.get("user.id") or params.get("filter[id]") or "1"
    rows, _ = handler.server.database.query("SELECT name FROM users WHERE id = %s" % value)
    handler._respond(200, page("Users", "<h1>%s</h1>" % (rows[0][0] if rows else "no such user")))


def signature_waf(handler, params):
    """Emulates a CRS-style rule that blocks self referencing comparisons (1=1).

    The block page deliberately looks nothing like an IP ban, so dsss.py cannot
    recognise it; the *true* payload is the one that gets blocked, which inverts
    the usual response pattern.  The backend itself is parameterised (not vulnerable).
    """

    value = params.get("id", "1")
    if re.search(r"(?i)\b(\w+)\s*(?:=|<=|>=|<|>)\s*\1\b", value):
        handler._respond(200, page("Rejected", "<h1>Request rejected by security policy</h1>"))
    else:
        safe(handler, params)


def dynamic(handler, params):
    """Not vulnerable, but no two answers are ever byte identical."""

    handler._respond(200, page("Home", "<h1>welcome</h1><!-- request %d -->" % handler.server.bump("dynamic"), FILLER))


def blind_pair(handler, params):
    """Vulnerable through `id`, but `subid` has to stay a valid number.

    `id=1` is a substring of `subid=1`, so a scanner that injects by plain string
    replacement poisons both parameters at once and only ever sees an error page.
    """

    try:
        int(params.get("subid", "1"))
    except ValueError:
        handler._respond(400, page("Bad Request", "<h1>subid must be a number</h1>"))
        return
    rows, _ = _lookup(handler, params)
    handler._respond(200, page("Users", "<h1>%s</h1>" % (rows[0][0] if rows else "no such user")))


def error_pair(handler, params):
    """Leaks the DBMS error through `id`, but `subid` has to stay a valid number.

    Poisoning both parameters at once (which plain string replacement does, since
    `id=1` is a substring of `subid=1`) never even reaches the database.
    """

    try:
        int(params.get("subid", "1"))
    except ValueError:
        handler._respond(400, page("Bad Request", "<h1>subid must be a number</h1>"))
        return
    error_based(handler, params)


def huge(handler, params):
    """A big page, to keep an eye on the scanner's own processing cost."""

    rows, _ = _lookup(handler, params)
    handler._respond(200, page("Users", "<span>%s</span>" % ("yes" if rows else "no"), FILLER * 8))


def reflecting(handler, params):
    """*Not* injectable, but echoes the raw parameter value back into the page."""

    value = params.get("id", "1")
    handler._respond(200, page("Search", "<p>No results for <em>%s</em></p>" % value, FILLER))


def safe(handler, params):
    """Parameterised query: no injection whatsoever."""

    rows = handler.server.database.parameterised("SELECT name FROM users WHERE id = ?", (params.get("id", "1"),))
    handler._respond(200, page("User", rows[0][0] if rows else "not found", FILLER))


def gzipped(handler, params):
    """Leaks the DBMS error, but gzips the answer even though nobody asked for it.

    urllib never decompresses, so neither the error message nor the <title> of such
    an answer can be read unless the request rules compression out.
    """

    rows, error = _lookup(handler, params)
    body = page("Error", SQLITE_ERROR % error) if error else page("User", rows[0][0] if rows else "not found")
    handler._respond(200, body, gzipped="identity" not in (handler.headers.get("Accept-Encoding") or ""))


def duplicated(handler, params):
    """Vulnerable, and the interesting parameter is present twice (first wins)."""

    return blind(handler, params)


def internal_error(handler, params):
    """Answers 500 to anything that smells like an injection."""

    value = params.get("id", "1")
    if re.search(r"(?i)\b(and|or|union|select)\b|['\")(]", value):
        handler._respond(500, page("Error", "Internal Server Error"))
    else:
        handler._respond(200, page("User", "alice"))


def blocking_waf(handler, params):
    """A rate limiting WAF: every `every`-th request is answered with a block page."""

    count = handler.server.bump("waf")
    if count % handler.server.state.get("every", 3) == 0:
        handler._respond(200, BLOCKED_PAGE)
    else:
        handler._respond(200, page("Home", "<h1>welcome</h1>", FILLER))


def static(handler, params):
    handler._respond(200, page("Static", "<h1>nothing to see</h1>"))


def hanging(handler, params):
    threading.Event().wait(30)


ROUTES = {
    "/error": error_based,
    "/error-mysql": error_based_mysql,
    "/error-verbatim": error_verbatim,
    "/blind-quoted-no-spaces": blind_quoted_no_spaces,
    "/error-python-sqlite": error_based_python_sqlite,
    "/error-python-postgres": error_based_python_postgres,
    "/blind space": blind,
    "/session": session,
    "/auth": basic_auth,
    "/first-visit": first_visit,
    "/blind": blind,
    "/blind-quoted": blind_quoted,
    "/blind-code": blind_code,
    "/blind-empty": blind_empty,
    "/blind-title": blind_title,
    "/blind-title-attribute": blind_title_attribute,
    "/blind-big": blind_big,
    "/blind-wordy": blind_wordy,
    "/blind-brand": blind_brand,
    "/blind-dashed": blind_dashed,
    "/signature-waf": signature_waf,
    "/dynamic": dynamic,
    "/blind-pair": blind_pair,
    "/error-pair": error_pair,
    "/huge": huge,
    "/reflecting": reflecting,
    "/safe": safe,
    "/gzipped": gzipped,
    "/duplicated": duplicated,
    "/error500": internal_error,
    "/waf": blocking_waf,
    "/static": static,
    "/hang": hanging,
}


def server(routes=None, **kwargs):
    return Server(routes or dict(ROUTES), Database(), **kwargs)


def mysql_server(routes=None, **kwargs):
    return Server(routes or dict(ROUTES), MySQL(), **kwargs)


# ------------------------------------------------------------------------ proxy


# A private, proxy-less opener: dsss.py installs a *global* opener pointing at
# this very proxy, which would otherwise make the proxy forward to itself.
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.seen.append((self.command, self.path))
        target = urllib.parse.urlsplit(self.path)
        forwarded = urllib.parse.urlunsplit(("http", self.server.upstream, target.path, target.query, ""))
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        try:
            response = DIRECT.open(urllib.request.Request(forwarded, body), timeout=10)
            code, payload = response.code, response.read()
        except urllib.error.HTTPError as ex:
            code, payload = ex.code, ex.read()
        self.send_response(code)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_POST = do_GET


class Proxy(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, upstream):
        http.server.ThreadingHTTPServer.__init__(self, ("127.0.0.1", 0), ProxyHandler)
        self.upstream, self.seen = upstream, []

    @property
    def address(self):
        return "http://127.0.0.1:%d" % self.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *args):
        self.shutdown()
        self.server_close()


def closed_port():
    """Returns an address nothing listens on (bind, read the port, release it)."""

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return "127.0.0.1:%d" % port
