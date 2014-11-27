3Scan - fast HTTP/SOCKS4/SOCKS5 detector

Compile under *nix:
	gcc -o3scan 3scan.c

Compile under Windows:
	gcc -o3scan 3scan.c -lws2_32
	or
	cl 3scan.c ws2_32.lib

Usage: 3scan.exe ip[/srcip] portlist option webhost url [keyword] [timeout]
	ip - IP address to test
	srcip - source IP address to use
	portlist - comma delimited list of ports. May contain additional tests:
	 s - Socks 4/5 test for this port
	 p - HTTP/CONNECT proxy test for this port
	 f - FTP proxy test for this port
	 t - TELNET proxy test for this port
	option:
	 p - scan for HTTP proxy on all ports
	 c - scan for CONNECT proxy on all ports
	 f - scan for FTP proxy on all ports
	 t - scan for TELNET proxy on all ports
	 4 - scan for Socks v4 proxy on all ports
	 5 - scan for Socks v5 proxy on all ports
	 w - scan for WINPROXY
	 v - be verbose
	 V - be Very Verbose
	 s - be silent (exit code is non-zero if proxy detected)
	 S - check SMTP instead of HTTP
	webhost - IP address for testing web server to try access via proxy
	url - URL to request on testing Web server
	 We will try to access http://webhosturl via proxy
	keyword - keyword to look for in requested page. If keyword not found
	 proxy will not be reported
	timeout - timeout in milliseconds
example: C:\Users\v.dubrovin\Documents\GitHub\3scan\3scan.exe localhost 1080s,3128p,8080p 4v www.myserver.com /test.html
will test all 3 ports for Socks 4, additionally 3128 and 8080 will be tested
for HTTP proxy, 1080 for both Socks 4 and 5, tests will be verbose.
http://www.myserver.com/test.html should exist.

(c) 2002 by 3APA3A, http://www.security.nnov.ru
