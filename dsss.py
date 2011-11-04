#!/usr/bin/env python

import difflib, httplib, itertools, optparse, random, re, urllib2, urlparse

NAME    = "Damn Small SQLi Scanner (DSSS) < 100 LOC (Lines of Code)"
VERSION = "0.1j"
AUTHOR  = "Miroslav Stampar (http://unconciousmind.blogspot.com | @stamparm)"
LICENSE = "Public domain (FREE)"

INVALID_SQL_CHAR_POOL = ['(', ')', '\'', '"']   # characters used for SQL poisoning of parameter values
PREFIXES = [" ", ") ", "' ", "') "]             # prefix values used for building testing blind payloads
SUFFIXES = ["", "-- ", "#"]                     # suffix values used for building testing blind payloads
BOOLEAN_TESTS = ["AND %d=%d", "OR NOT (%d=%d)"] # boolean tests used for building testing blind payloads
TEXT, HTTPCODE, TITLE, HTML = range(4)          # enumerator-like values used for marking content type
MIN_BOOL_VAL, MAX_BOOL_VAL = 100, 255           # minimum and maximum random range values used in boolean tests
FUZZY_THRESHOLD = 0.95                          # ratio value in range (0,1) used for distinguishing True from False responses

DBMS_ERRORS = {
    "MySQL": [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."],\
    "PostgreSQL": [r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."],\
    "Microsoft SQL Server": [r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."],\
    "Microsoft Access": [r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"],\
    "Oracle": [r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"],\
    "IBM DB2": [r"CLI Driver.*DB2", r"DB2 SQL error", r"db2_connect\(", r"db2_exec\(", r"db2_execute\(", r"db2_fetch_"],\
    "Informix": [r"Exception.*Informix"],\
    "Firebird": [r"Dynamic SQL Error", r"Warning.*ibase_.*"],\
    "SQLite": [r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::"],\
    "SAP MaxDB": [r"SQL error.*POS([0-9]+).*", r"Warning.*maxdb.*"],\
    "Sybase": [r"Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"],\
    "Ingres": [r"Warning.*ingres_", r"Ingres SQLSTATE", r"Ingres\W.*Driver"]
}

def retrieve_content(url, data=None):
    retval = {HTTPCODE: httplib.OK}
    try:
        retval[HTML] = urllib2.urlopen("".join([url[i].replace(' ', '%20') if i > url.find('?') else url[i] for i in xrange(len(url))]), data).read() # replacing ' ' with %20 is a quick/dirty fix for urllib2
    except Exception, ex:
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML], re.I | re.S)
    return retval

def shallow_crawl(url, data=None):
    print "* crawling for links at the given target url"
    retval = set([url])
    for match in re.finditer(r"href\s*=\s*\"(?P<href>[^\"]+)\"", retrieve_content(url, data)[HTML], re.I):
        link = urlparse.urljoin(url, match.group("href"))
        if reduce(lambda x, y: x == y, map(lambda x: urlparse.urlparse(x).netloc.split(':')[0], [url, link])):
            retval.add(link)
    return retval

def scan_page(url, data=None):
    retval = False
    try:
        for link in shallow_crawl(url):
            print "* scanning: %s%s" % (link, " (no GET parameters)" if '?' not in link else "")
            for match in re.finditer(r"[?&;]((?P<parameter>\w+)=[^&;]+)|[^/](/\d+)(?=(/|\Z))", link):
                vulnerable = False
                tampered = link.replace(match.group(0), "%s%s" % (match.group(0), "".join(random.sample(INVALID_SQL_CHAR_POOL, len(INVALID_SQL_CHAR_POOL)))))
                content = retrieve_content(tampered, data)
                for dbms in DBMS_ERRORS:
                    for regex in DBMS_ERRORS[dbms]:
                        if not vulnerable and re.search(regex, content[HTML], re.I):
                            print " (o) %s could be error SQLi vulnerable! (%s error message)" % ("parameter '%s'" % match.group("parameter") if match.groupdict().get("parameter") else "url", dbms)
                            retval = vulnerable = True
                vulnerable = False
                original = retrieve_content(link, data)
                left, right = random.sample(xrange(MIN_BOOL_VAL, MAX_BOOL_VAL + 1), 2)
                for prefix, boolean, suffix in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES):
                    if not vulnerable:
                        template = "%s%s%s" % (prefix, boolean, suffix)
                        payloads = dict([(x, link.replace(match.group(0), "%s%s" % (match.group(0), (template % (left, left if x else right))))) for x in (True, False)])
                        contents = dict([(x, retrieve_content(payloads[x], data)) for x in (True, False)])
                        if any(map(lambda x: original[x] == contents[True][x] != contents[False][x], [HTTPCODE, TITLE])) or len(original[TEXT]) == len(contents[True][TEXT]) != len(contents[False][TEXT]):
                            vulnerable = True
                        else:
                            ratios = dict([(x, difflib.SequenceMatcher(None, original[TEXT], contents[x][TEXT]).quick_ratio()) for x in (True, False)])
                            vulnerable = ratios[True] > FUZZY_THRESHOLD and ratios[False] < FUZZY_THRESHOLD
                        if vulnerable:
                            print " (i) %s appears to be blind SQLi vulnerable! (\"%s\")" % ("parameter '%s'" % match.group("parameter") if match.groupdict().get("parameter") else "url", payloads[True])
                            retval = True
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.htm?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"PHPSESSID=9ac32950af67ec5b21d17...\")")
    options, _ = parser.parse_args()
    if options.url:
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
        print "\nscan results: %s vulnerabilities found" % ("possible" if result else "no")
    else:
        parser.print_help()
