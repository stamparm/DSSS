#!/usr/bin/env python3

"""
Proof that the test suite actually pins every fix.

For each fix applied to dsss.py this script puts the *old, broken* code back into
a private copy, runs the suite against that copy and insists that it fails.  A
mutation that survives means the fix is not covered by any test.

The runs stop at the first failure, and the MySQL suite is left out of them (it is
about the DBMS, not about these fixes, and 24 containers at once is nobody's idea
of a good time).

    python3 tests/mutations.py            # all mutations
    python3 tests/mutations.py title      # only mutations whose name matches
"""

import concurrent.futures
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "dsss.py")

# (name, current code, code as it was before the fix)
MUTATIONS = (
    ("reflection filter: no word boundaries",
     r'r"(?i)\b(AND|OR)\b[^<>]{0,32}\b%d\b[^<>]{0,32}"',
     r'r"(?i)[^>]*(AND|OR)[^<]*%d[^<]*"'),

    ("title tag: no attributes allowed",
     r'r"<title[^>]*>(?P<result>[^<]+)</title>"',
     r'r"<title>(?P<result>[^<]+)</title>"'),

    ("comparison: whole page not used as a signal",
     "for _ in (HTTPCODE, TITLE, HTML)):",
     "for _ in (HTTPCODE, TITLE)):"),

    ("comparison: direction of the fuzzy ratios ignored",
     "vulnerable = ratios[True] > FUZZY_THRESHOLD > ratios[False] and ratios[True] - ratios[False] > FUZZY_THRESHOLD / 10",
     "vulnerable = all(ratios.values()) and min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10"),

    ("blocked answers: kept as comparable content",
     'if re.search(BLOCKED_IP_REGEX, retval[HTML]): retval[HTTPCODE], retval[HTML] = None, ""',
     'retval[HTML] = "" if re.search(BLOCKED_IP_REGEX, retval[HTML]) else retval[HTML]'),

    ("unreachable target: no early give up",
     'if not original[HTTPCODE]: print(" (x) unable to retrieve the original content"); break',
     'pass'),

    ("exception without arguments: back to args[-1]",
     'retval[HTML] = ex.read() if hasattr(ex, "read") else b""',
     'retval[HTML] = ex.read() if hasattr(ex, "read") else str(ex.args[-1])'),

    ("injection: back to plain string replacement",
     '''tampered = "%s%s%s" % (current[:match.end()], urllib.parse.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)))), current[match.end():])''',
     '''tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))))'''),

    ("payloads: back to plain string replacement",
     '''payloads = dict((_, "%s%s%s" % (current[:match.end()], urllib.parse.quote(template % (RANDINT if _ else RANDINT + 1, RANDINT), safe='%'), current[match.end():])) for _ in (True, False))''',
     '''payloads = dict((_, current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote(template % (RANDINT if _ else RANDINT + 1, RANDINT), safe='%')))) for _ in (True, False))'''),

    ("parameters: only plain identifiers, value cut at #",
     r'r"((\A|[?&])(?P<parameter>[^\W_][\w.\-\[\]]*)=)(?P<value>[^&]+)"',
     r'r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)"'),

    ("parameters: separator may start a name",
     r'(?P<parameter>[^\W_][\w.\-\[\]]*)',
     r'(?P<parameter>[^_][\w.\-\[\]]*)'),

    ("url: only spaces after the question mark escaped",
     """urllib.parse.urlunsplit(parsed._replace(netloc=parsed.netloc.rpartition('@')[2], path=urllib.parse.quote(parsed.path, safe=SAFE), query=urllib.parse.quote(parsed.query, safe=SAFE)))""",
     """"".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in range(len(url)))"""),

    ("url: whole target percent-encoded, host included",
     """urllib.parse.urlunsplit(parsed._replace(netloc=parsed.netloc.rpartition('@')[2], path=urllib.parse.quote(parsed.path, safe=SAFE), query=urllib.parse.quote(parsed.query, safe=SAFE)))""",
     """urllib.parse.quote(url, safe=SAFE)"""),

    ("url: credentials left in the host name",
     """{AUTH: "Basic %s" % base64.b64encode(urllib.parse.unquote(parsed.netloc.rpartition('@')[0]).encode("utf8")).decode()} if '@' in parsed.netloc else {}""",
     """{}"""),

    ("url: fragment kept",
     """re.sub(r"=(&|\\Z)", r"=1\\g<1>", url.split('#')[0]) if url else url""",
     """re.sub(r"=(&|\\Z)", r"=1\\g<1>", url) if url else url"""),

    ("main: scheme guessed by startswith(\"http\")",
     'options.url if "://" in options.url else "http://%s" % options.url',
     'options.url if options.url.startswith("http") else "http://%s" % options.url'),

    ("proxy: http scheme only, no cookies, verified certificates",
     """urllib.request.build_opener(*([urllib.request.ProxyHandler(dict((_, proxy) for _ in ("http", "https")))] if proxy else []), urllib.request.HTTPSHandler(context=ssl._create_unverified_context()), urllib.request.HTTPCookieProcessor())""",
     """urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None"""),

    ("proxy: https targets bypass it",
     """dict((_, proxy) for _ in ("http", "https"))""",
     """{'http': proxy}"""),

    ("session: cookies dropped",
     """, urllib.request.HTTPCookieProcessor()""",
     """"""),

    ("tls: certificates must be signed by a known CA",
     """urllib.request.HTTPSHandler(context=ssl._create_unverified_context()), """,
     """"""),

    ("order: the session establishing answer becomes the baseline",
     '''tampered = "%s%s%s" % (current[:match.end()], urllib.parse.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)))), current[match.end():])
                content = _retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)                        # this one goes first, so that the original is not the odd (e.g. session establishing) request out
                original = original or (_retrieve_content(current, data) if phase is GET else _retrieve_content(url, current))
                if not original[HTTPCODE]: print(" (x) unable to retrieve the original content"); break''',
     '''original = original or (_retrieve_content(current, data) if phase is GET else _retrieve_content(url, current))
                if not original[HTTPCODE]: print(" (x) unable to retrieve the original content"); break
                tampered = "%s%s%s" % (current[:match.end()], urllib.parse.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)))), current[match.end():])
                content = _retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)'''),

    ("errors: no signature for Python DB-API tracebacks",
     r', r"\bpsycopg2?\.[\w.]*Error\b"',
     ''),

    ("errors: no signature for sqlite3 tracebacks",
     r', r"\bsqlite3\.\w*Error\b"',
     ''),

    ("api: no url is a crash again",
     '(url or "") if phase is GET else (data or "")',
     'url if phase is GET else (data or "")'),
)


def run(mutation):
    name, current, previous = mutation
    source = open(SOURCE).read()
    if source.count(current) != 1:
        return name, None, "the code to mutate appears %d times" % source.count(current)
    directory = tempfile.mkdtemp(prefix="dsss-mutation-")
    with open(os.path.join(directory, "dsss.py"), "w") as handle:
        handle.write(source.replace(current, previous))
    environment = dict(os.environ, DSSS_DIR=directory, PYTHONDONTWRITEBYTECODE="1")
    try:
        process = subprocess.run([sys.executable, "-m", "unittest", "-f", "-v", "test_regressions", "test_dsss", "test_matrix"],
                                 cwd=os.path.join(ROOT, "tests"), env=environment, capture_output=True, text=True, timeout=1800)
        output = process.stdout + process.stderr
    except subprocess.TimeoutExpired:
        return name, True, "suite timed out (which counts as noticing)"
    caught = re.findall(r"^(?:FAIL|ERROR): (\S+)", output, re.M)
    summary = re.search(r"^(FAILED \(.*\)|OK)$", output, re.M)
    return name, bool(caught), "%s -> %s" % (summary.group(1) if summary else "?", ", ".join(sorted(set(caught))[:3]) or "nothing")


def main():
    wanted = [_ for _ in MUTATIONS if not sys.argv[1:] or any(re.search(_[0], argument, re.I) or re.search(argument, _[0], re.I) for argument in sys.argv[1:])]
    print("running %d mutations against the suite\n" % len(wanted))
    survivors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for name, caught, detail in pool.map(run, wanted):
            print("%-4s %-62s %s" % ("ok" if caught else "MISS", name, detail))
            if not caught:
                survivors.append(name)
    print("\n%d/%d mutations caught" % (len(wanted) - len(survivors), len(wanted)))
    for name in survivors:
        print(" (x) not covered by any test: %s" % name)
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
