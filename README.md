Damn Small SQLi Scanner [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-Public_domain-red.svg)](https://wiki.creativecommons.org/wiki/Public_domain)
=========

**Damn Small SQLi Scanner** (DSSS) is a fully functional [SQL injection](https://en.wikipedia.org/wiki/SQL_injection) vulnerability scanner (supporting GET and POST parameters) written in under 100 lines of code.

![Vulnerable](http://i.imgur.com/7mXeXjF.png)

As of optional settings it supports HTTP proxy together with HTTP header values `User-Agent`, `Referer` and `Cookie`.

Sample runs
----

```
$ python dsss.py -h
Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code) #v0.2o
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
$ python dsss.py -u "http://testphp.vulnweb.com/artists.php?artist=1"
Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code) #v0.2o
 by: Miroslav Stampar (@stamparm)

* scanning GET parameter 'artist'
 (i) GET parameter 'artist' could be error SQLi vulnerable (MySQL)
 (i) GET parameter 'artist' appears to be blind SQLi vulnerable (e.g.: 'http://t
estphp.vulnweb.com/artists.php?artist=1%20AND%2061%3E60')

scan results: possible vulnerabilities found
```

Requirements
----

[Python](http://www.python.org/download/) version **2.6.x** or **2.7.x** is required for running this program.
