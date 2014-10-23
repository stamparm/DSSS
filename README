Damn Small SQLi Scanner (DSSS) has been made as a PoC where I wanted to show that commercial (SQLi) scanners can be beaten under 100 lines of code.

It supports GET and POST parameters, blind/error SQLi tests and advanced comparison of different response attributes to distinguish blind responses. If you are satisfied with your commercial tool scanning results then I believe that you could even be more satisfied with this one.

As of optional settings it supports HTTP proxy together with HTTP header values "User-Agent", "Referer" and "Cookie".

```
$ python dsss.py -u "http://testphp.vulnweb.com/artists.php?artist=1"
Damn Small SQLi Scanner (DSSS) < 100 LOC (Lines of Code) #v0.2c
 by: Miroslav Stampar (http://unconciousmind.blogspot.com | @stamparm)

* scanning GET parameter 'artist'
 (i) GET parameter 'artist' could be error SQLi vulnerable (MySQL)
 (i) GET parameter 'artist' appears to be blind SQLi vulnerable

scan results: possible vulnerabilities found
```

p.s. Python v2.6 or v2.7 is required for running this program
