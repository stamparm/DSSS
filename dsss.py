#!/usr/bin/env python
import difflib, httplib, itertools, optparse, random, re, urllib, urllib2, urlparse

NAME, VERSION, AUTHOR, LICENSE = "Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code)", "0.2p", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

PREFIXES = (" ", ") ", "' ", "') ", "%%' ", "%%') ")                    # prefix values used for building testing blind payloads
SUFFIXES = ("", "-- -", "#", "%%00", "%%16")                            # suffix values used for building testing blind payloads
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')                            # characters used for SQL tampering/poisoning of parameter values
BOOLEAN_TESTS = ("AND %d=%d", "OR (%d>%d)")                             # boolean tests used for building testing blind payloads
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                 # optional HTTP header names
GET, POST = "GET", "POST"                                               # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = xrange(4)                                 # enumerator-like values used for marking content type
FUZZY_THRESHOLD = 0.95                                                  # ratio value in range (0,1) used for distinguishing True from False responses
TIMEOUT = 30                                                            # connection timeout in seconds

DBMS_ERRORS = {                                                         # regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*")
}

_headers = {}                                                           # used for storing dictionary with optional header values

def _retrieve_content(url, data=None):
    retval = {HTTPCODE: httplib.OK}
    try:
        req = urllib2.Request("".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in xrange(len(url))), data, _headers)
        retval[HTML] = urllib2.urlopen(req, timeout=TIMEOUT).read()
    except Exception, ex:
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", "")
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval

def scan_page(url, data=None):
    retval, usable = False, False
    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
            original, current = None, url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>\w+)=)(?P<value>[^&]+)", current):
                vulnerable, usable = False, True
                print "* scanning %s parameter '%s'" % (phase, match.group("parameter"))
                tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))))
                content = _retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if not vulnerable and re.search(regex, content[HTML], re.I):
                        print " (i) %s parameter '%s' appears to be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms)
                        retval = vulnerable = True
                vulnerable = False
                original = original or (_retrieve_content(current, data) if phase is GET else _retrieve_content(url, current))
                randint = random.randint(1, 255)
                for prefix, boolean, suffix in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES):
                    if not vulnerable:
                        template = "%s%s%s" % (prefix, boolean, suffix)
                        payloads = dict((_, current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote(template % (randint if _ else randint + 1, randint), safe='%')))) for _ in (True, False))
                        contents = dict((_, _retrieve_content(payloads[_], data) if phase is GET else _retrieve_content(url, payloads[_])) for _ in (False, True))
                        if all(_[HTTPCODE] for _ in (original, contents[True], contents[False])) and (any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE))):
                            vulnerable = True
                        else:
                            ratios = dict((_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio()) for _ in (True, False))
                            vulnerable = all(ratios.values()) and min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10
                        if vulnerable:
                            print " (i) %s parameter '%s' appears to be blind SQLi vulnerable (e.g.: '%s')" % (phase, match.group("parameter"), payloads[True])
                            retval = True
        if not usable:
            print " (x) no usable GET/POST parameters found"
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})) if proxy else None)

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
        print "\nscan results: %s vulnerabilities found" % ("possible" if result else "no")
    else:
        parser.print_help()
