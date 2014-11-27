/*
	3Scan - fast HTTP/SOCKS4/SOCKS5 proxy detector.

	You can do anything you want with this software.
	(c) 2002 by 3APA3A.
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#include <winsock.h>
#define NIL ((DWORD)0l)
#define RETURNTYPE DWORD WINAPI
#define SHUT_RDWR SD_BOTH
#else
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <syslog.h>
#define NIL ((void *)0l)
#define RETURNTYPE void *
#endif

#ifdef __CYGWIN__
#include <windows.h>
#define daemonize() FreeConsole()
#define SLEEPTIME 1000
#undef _WIN32
#elif _WIN32
#ifdef errno
#undef errno
#endif
#define errno WSAGetLastError()
#define EAGAIN WSAEWOULDBLOCK
#define SLEEPTIME 1
#define close closesocket
#define usleep Sleep
#define pthread_self GetCurrentThreadId
#define getpid GetCurrentProcessId
#define pthread_t DWORD
#define daemonize() FreeConsole()
#else
#include <pthread.h>
#define daemonize() daemon(0,0)
#define SLEEPTIME 1000
#endif

int verbose = 1;
int result = 0;
int threadcount = 0;
int to = 25000;

int sockgetchar(int sock, int timeosec, int timeousec){
 unsigned char buf;
 int res;
 fd_set fds;
 struct timeval tv = {timeosec,timeousec};

 FD_ZERO(&fds);
 FD_SET(sock, &fds);
 if ((res = select (sock+1, &fds, NULL, NULL, &tv))!=1) {
	return EOF;
 }
 if ((res = recv(sock, &buf, 1, 0))!=1) {
	return EOF;
 }

/*
fprintf(stderr, " -%d- ", (int)buf);
fflush(stderr);
*/
 return((int)buf);
}

int sockgetline(int sock, char * buf, int bufsize, int delim, int timeout){
 int c;
 int i=0, tos, tou;

 if(!bufsize) return 0;
 c = sockgetchar(sock, timeout, 0);
 if (c == EOF) {
	return 0;
 }
 buf[i++] = c;
 tos = (timeout>>4);
 tou = ((timeout * 1000) >> 4)%1000;
 while(i < bufsize && (c = sockgetchar(sock, tos, tou)) != EOF) {
	buf[i++] = c;
	if(delim != EOF && c == delim) break;
 }
 return i;
}

#define PROXY 1
#define SOCKS4 2
#define SOCKS5 4
#define CONNECT 8
#define WINPROXY 16
#define FTP 32
#define TELNET 64

struct clientparam {
	struct sockaddr_in sins;
	struct sockaddr_in sinc;
	char * webhost;
	struct in_addr webip;
	char * url;
	char *keyword;
	int dosmtp;
};

char * dosmtp(struct clientparam* param, int sock, char * module){
	char buf[1024];
	int res;

	if((res = sockgetline(sock,buf,1020,'\r',(1 + (to>>10)))) < 3) {
		return "something, not SMTP server (reply is too short)";
	}
	buf[res] = 0;
	if(verbose > 2)fprintf(stderr, "%s received: %s\n", module, buf);
	if(buf[0] != '2' || buf[1] != '2' || buf[2] != '0') {
		return "bad SMTP response";
	}
	if(param->keyword) {
		if(!strstr(buf, param->keyword)) return "No keyword found in server response";
	}
	return NULL;
}

char * dohttp(struct clientparam* param, int sock, char * module){
	char buf[1024];
	int res;

	if (*module == 'H') sprintf(buf, "GET http://%.100s%s%.500s HTTP/1.0\r\nHost: %s\r\n%s\r\n\r\n", param->webhost, param->dosmtp? ":25" : "", param->url, param->webhost, param->dosmtp? "quit" : "Pragma: no-cache");
	else sprintf(buf, "GET %.500s HTTP/1.0\r\nHost: %s\r\n%s\r\n\r\n", param->url, param->webhost, param->dosmtp? "quit" : "Pragma: no-cache");
	if(verbose > 2)fprintf(stderr, "%s sending:\n%s", module, buf);
	if(send(sock, buf, strlen(buf), 0) != strlen(buf)) {
		return "data not accepted";
	};
	if(param->dosmtp) {
		return dosmtp(param, sock, module);
	}
	if((sockgetline(sock,buf,12,'\r',(1 + (to>>10)))) < 12) {
		return "something, not HTTP server (reply is too short)";
	}
	buf[12] = 0;
	if(verbose > 2)fprintf(stderr, "%s received: %s\n", module, buf);
	if(buf[9] != '2') {
		return "failed to retrieve requested URL";
	}
	if(param->keyword) {
		while((res = sockgetline(sock,buf,1023,'\n',(1 + (to>>10)))) > 0){
			buf[res] = 0;
			if(strstr(buf, param->keyword)) break;
		}
		if(res <= 0) {
			return "No keyword found in server response";
		}
	}
	return NULL;
}

RETURNTYPE doproxy(void * data){
	int sock = -1;
	char * string = "";

	if ((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		string = "error";
		goto CLEANRET1;
	}
	if (bind(sock, (struct sockaddr *)&((struct clientparam*)data)->sinc,sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		string = "error";
		goto CLEANRET1;
	}
	if(verbose > 2)fprintf(stderr, "Http connecting %s:%hu\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	if(connect(sock,(struct sockaddr *)&((struct clientparam*)data)->sins,sizeof(struct sockaddr_in))) {
		string = "closed";
		goto CLEANRET1;
	}
	string = dohttp((struct clientparam*) data, sock, "HTTP");
	if (string) goto CLEANRET1;
	string = "works OK for us";
	if (verbose == 1) fprintf(stderr, "%s:%hu/HTTP\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	result |= PROXY;
CLEANRET1:
	if (verbose > 1) fprintf(stderr, "%s:%hu/HTTP %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	if(sock != -1){
		shutdown(sock, SHUT_RDWR);
		close(sock);
	}
	threadcount--;
	return NIL;
}

RETURNTYPE dosocks4(void *data){
	int sock = -1;
	char buf[1024];
	char request[] = {4, 1, 0, 80};
	char * string = "";
	int res;

	if(((struct clientparam*)data)->dosmtp) request[3] = 25;
	if ((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		string = "error";
		goto CLEANRET2;
	}
	if (bind(sock, (struct sockaddr *)&((struct clientparam*)data)->sinc,sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		string = "error";
		goto CLEANRET2;
	}
	if(verbose > 2)fprintf(stderr, "SOCKS4 connecting %s:%hu\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	if(connect(sock,(struct sockaddr *)&((struct clientparam*)data)->sins,sizeof(struct sockaddr_in))) {
		string = "closed";
		goto CLEANRET2;
	}

	send(sock, request, sizeof(request), 0);
	send(sock, (void *)&((struct clientparam*)data)->webip.s_addr, 4, 0);
	send(sock, "3APA3A", 7, 0);
	if((res = sockgetline(sock,buf,8,EOF,(1 + (to>>10)))) < 8){
		string = "something, not socks4 (reply is too short)";
		goto CLEANRET2;
	}
	if(buf[1] != 90) {
		string = "failed to establish connection";
		goto CLEANRET2;
	}
	string = ((struct clientparam*)data)->dosmtp?
		dosmtp((struct clientparam*) data, sock, "SOCKS4"):
		dohttp((struct clientparam*) data, sock, "SOCKS4");
	if (string) goto CLEANRET2;
	string = "works OK for us";
	if (verbose == 1)fprintf(stderr, "%s:%hu/SOCKS4\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	result |= SOCKS4;
CLEANRET2:
	if (verbose > 1)fprintf(stderr, "%s:%hu/SOCKS4 %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	if(sock != -1) close(sock);
	threadcount--;
	return NIL;
}

RETURNTYPE dosocks5(void * data){
	int sock = -1;
	char buf[1024];
	char request[] = {5, 1, 0};
	char request2[] = {5, 1, 0, 1};
	struct linger lg;
	char * string = "";

	lg.l_onoff = 1;
	lg.l_linger = 10;
	if ((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		string = "error";
		goto CLEANRET3;
	}
	if (bind(sock, (struct sockaddr *)&((struct clientparam*)data)->sinc,sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		string = "error";
		goto CLEANRET3;
	}
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
	setsockopt(sock, SOL_SOCKET, SO_OOBINLINE, NULL, 0);
	if(verbose > 2)fprintf(stderr, "Socks5 connecting %s:%hu\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	if(connect(sock,(struct sockaddr *)&((struct clientparam*)data)->sins,sizeof(struct sockaddr_in))) {
		string = "closed";
		goto CLEANRET3;
	}

	send(sock, request, sizeof(request), 0);
	if((sockgetline(sock,buf,2,EOF,(1 + (to>>10)))) < 2){
		string = "something, not socks5 (reply is too short)";
		goto CLEANRET3;
	}
	if(buf[0] != 5) {
		string = "something, not socks5 (version doesn't match)";
		goto CLEANRET3;
	}
	if(buf[1] != 0) {
		string = "authentication required";
		goto CLEANRET3;
	}
	send(sock, request2, sizeof(request2), 0);
	send(sock, (void *)&(((struct clientparam*)data)->webip.s_addr), 4, 0);
	send(sock, ((struct clientparam*)data)->dosmtp? "\0\31" : "\0\120", 2, 0);
	if((sockgetline(sock,buf,10,EOF,(1 + (to>>10)))) < 10){
		string = "something, not socks5 (reply is too short)";
		goto CLEANRET3;
	}
	if(buf[0] != 5) {
		string = "something, not socks5 (version doesn't match)";
		goto CLEANRET3;
	}
	if(buf[1] != 0) {
		string = "failed to establish connection";
		goto CLEANRET3;
	}
	string = ((struct clientparam*)data)->dosmtp?
		dosmtp((struct clientparam*) data, sock, "SOCKS5"):
		dohttp((struct clientparam*) data, sock, "SOCKS5");
	if (string) goto CLEANRET3;
	string = "works OK for us";
	if (verbose == 1)fprintf(stderr, "%s:%hu/SOCKS5\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	result |= SOCKS5;
CLEANRET3:
	if (verbose > 1)fprintf(stderr, "%s:%hu/SOCKS5 %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	if(sock != -1)close(sock);
	threadcount--;
	return NIL;
}



RETURNTYPE doconnect(void * data){
	int sock = -1;
	char buf[1024];
	char * string = "";
	int res;

	if ((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		string = "error";
		goto CLEANRET4;
	}
	if (bind(sock, (struct sockaddr *)&((struct clientparam*)data)->sinc,sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		string = "error";
		goto CLEANRET4;
	}
	if(verbose > 2)fprintf(stderr, "Http CONNECT connecting %s:%hu\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	if(connect(sock,(struct sockaddr *)&((struct clientparam*)data)->sins,sizeof(struct sockaddr_in))) {
		string = "closed";
		goto CLEANRET4;
	}


	sprintf(buf, "CONNECT %.100s:%d HTTP/1.0\r\n\r\n", ((struct clientparam*)data)->webhost, ((struct clientparam*)data)->dosmtp? 25:80);
	if(verbose > 2)fprintf(stderr, "Http CONNECT sending:\n%s", buf);
	if(send(sock, buf, strlen(buf), 0) != strlen(buf)) {
		string = "data not accepted";
		goto CLEANRET4;
	};
	if((sockgetline(sock,buf,12,'\r',(1 + (to>>10)))) < 12) {
		string = "something, not http proxy (reply is too short)";
		goto CLEANRET4;
	}
	buf[12] = 0;
	if(verbose > 2)fprintf(stderr, "Http CONNECT received: %s\n", buf);
	if(buf[9] != '2') {
		string = "failed to retrieve requested URL";
		goto CLEANRET4;
	}
	while((res = sockgetline(sock,buf,1023,'\n',(1 + (to>>10)))) > 2){
		buf[res] = 0;
		if(verbose > 2)fprintf(stderr, "Http CONNECT received: %s\n", buf);
	};

	string = ((struct clientparam*)data)->dosmtp?
		dosmtp((struct clientparam*) data, sock, "CONNECT"):
		dohttp((struct clientparam*) data, sock, "CONNECT");
	if (string) goto CLEANRET4;
	string = "works OK for us";
	if (verbose == 1) fprintf(stderr, "%s:%hu/CONNECT\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	result |= CONNECT;
CLEANRET4:
	if (verbose > 1) fprintf(stderr, "%s:%hu/CONNECT %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	if(sock != -1)close(sock);
	threadcount--;
	return NIL;
}

RETURNTYPE dotrojan(void * data){
	int sock = -1;
	char buf[1024];
	char * string = "";
	char sig[] = {0x01, 0x0D, 0x00, 0x01};
	int i;

	if ((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		string = "error";
		goto CLEANRET5;
	}
	if (bind(sock, (struct sockaddr *)&((struct clientparam*)data)->sinc,sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		string = "error";
		goto CLEANRET5;
	}
	if(verbose > 2)fprintf(stderr, "WINPROXY connecting %s:%hu\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	if(connect(sock,(struct sockaddr *)&((struct clientparam*)data)->sins,sizeof(struct sockaddr_in))) {
		string = "closed";
		goto CLEANRET5;
	}

	if(sockgetline(sock,buf,5,EOF,(1 + (to>>10))) < 5 || sockgetline(sock,buf+5,10,0,(1 + (to>>10))) < 5) {
		string = "something, not WINPROXY (reply is too short)";
		goto CLEANRET5;
	}
	buf[15] = 0;
	if(verbose > 2)fprintf(stderr, "WINPROXY received: [0x%02x0x%02x0x%02x0x%02x0x%02x]%s\n", (unsigned)buf[0], (unsigned)buf[1], (unsigned)buf[2], (unsigned)buf[3], (unsigned)buf[4], buf+5);
	if(memcmp(buf+1, sig, 4)) {
		string = "something, not WINPROXY (signature doesn't match)";
		goto CLEANRET5;
	}
	for (i = 5; buf[i]; i++) {
		if(buf[i] < '0' || buf[i] > '9') {
			string = "something, not WINPROXY (no numbers)";
			goto CLEANRET5;
		}
	}
	string = "works OK for us";
	if (verbose == 1) fprintf(stderr, "%s:%hu/WINPROXY\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	result |= WINPROXY;
CLEANRET5:
	if (verbose > 1) fprintf(stderr, "%s:%hu/WINPROXY %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	if(sock != -1)close(sock);
	threadcount--;
	return NIL;
}


RETURNTYPE doftp(void *data){
	int sock = -1;
	char buf[1024];
	char * string = "";
	int res;

	if(!((struct clientparam*)data)->dosmtp) return NIL;
	if ((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		string = "error";
		goto CLEANRET6;
	}
	if (bind(sock, (struct sockaddr *)&((struct clientparam*)data)->sinc,sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		string = "error";
		goto CLEANRET6;
	}
	if(verbose > 2)fprintf(stderr, "FTP connecting %s:%hu\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	if(connect(sock,(struct sockaddr *)&((struct clientparam*)data)->sins,sizeof(struct sockaddr_in))) {
		string = "closed";
		goto CLEANRET6;
	}
	res = sockgetline(sock,buf,1023,'\n',(1 + (to>>10)));
	buf[res] = 0;
	if(verbose > 2)fprintf(stderr, "FTP received: %s", buf);
	if(res < 4) {
		string = "something, not FTP proxy (no banner)";
		goto CLEANRET6;
	}
	if(buf[0] != '2' || buf[1] != '2' || buf[2] != '0'){
		string = "something, not FTP proxy (wrong banner)";
		goto CLEANRET6;
	}
	sprintf(buf, "USER zaraza@%.100s:%d\r\n", ((struct clientparam*)data)->webhost, 25);
	if(verbose > 2)fprintf(stderr, "FTP sending:%s", buf);
	if(send(sock, buf, strlen(buf), 0) != strlen(buf)) {
		string = "data not accepted";
		goto CLEANRET6;
	};
	res = sockgetline(sock,buf,1023,'\n',(1 + (to>>10)));
	buf[res] = 0;
	if(verbose > 2)fprintf(stderr, "FTP received: %s", buf);
	if(res < 4 || buf[0] < '0' || buf[1] < '0' || buf[2] < '0' || buf[0] > '9' || buf[1] > '9' || buf[2] > '9') {
		string = "something, not FTP proxy (no banner)";
		goto CLEANRET6;
	}
	string = dosmtp((struct clientparam*) data, sock, "FTP");
	if (string) goto CLEANRET6;
	string = "works OK for us";

	if (verbose == 1) fprintf(stderr, "%s:%hu/FTP %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	result |= FTP;
	
CLEANRET6:
	if (verbose > 1) fprintf(stderr, "%s:%hu/FTP %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	if(sock != -1)close(sock);
	threadcount--;
	return NIL;
}

RETURNTYPE dotelnet(void *data){
	int sock = -1;
	char buf[1024];
	char * string = "";
	int res;

	if ((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		string = "error";
		goto CLEANRET7;
	}
	if (bind(sock, (struct sockaddr *)&((struct clientparam*)data)->sinc,sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		string = "error";
		goto CLEANRET7;
	}
	if(verbose > 2)fprintf(stderr, "TELNET connecting %s:%hu\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port));
	if(connect(sock,(struct sockaddr *)&((struct clientparam*)data)->sins,sizeof(struct sockaddr_in))) {
		string = "closed";
		goto CLEANRET7;
	}
	res = sockgetline(sock,buf,1023,'\n',(1 + (to>>10)));
	buf[res] = 0;
	if(verbose > 2)fprintf(stderr, "FTP received: %s", buf);
	if(res < 2) {
		string = "something, not TELNET proxy (no banner)";
		goto CLEANRET7;
	}
	if(strstr(buf, "poon")) {
		sprintf(buf, "%.100s %d\r\n", ((struct clientparam*)data)->webhost, ((struct clientparam*)data)->dosmtp? 25:80);
	}
	else if(strstr(buf, "gw") || strstr(buf, "telnet")) {
		sprintf(buf, "telnet %.100s %d\r\n", ((struct clientparam*)data)->webhost, ((struct clientparam*)data)->dosmtp? 25:80);
	}
	else if(strstr(buf, "CCP")) {
		sprintf(buf, "open %.100s %d\r\n", ((struct clientparam*)data)->webhost, ((struct clientparam*)data)->dosmtp? 25:80);
	}
	else {
		sprintf(buf, "%.100s:%d\r\n", ((struct clientparam*)data)->webhost, ((struct clientparam*)data)->dosmtp? 25:80);
	}
	string = ((struct clientparam*)data)->dosmtp?
		dosmtp((struct clientparam*) data, sock, "CONNECT"):
		dohttp((struct clientparam*) data, sock, "CONNECT");
	if (string) goto CLEANRET7;
	string = "works OK for us";

	if (verbose == 1) fprintf(stderr, "%s:%hu/FTP %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	result |= FTP;
	
CLEANRET7:
	if (verbose > 1) fprintf(stderr, "%s:%hu/FTP %s\n", inet_ntoa(((struct clientparam*)data)->sins.sin_addr), ntohs(((struct clientparam*)data)->sins.sin_port), string);
	if(sock != -1)close(sock);
	threadcount--;
	return NIL;
}


int main(int argc, char* argv[]){
	int test, deftest = 0;
	struct in_addr ia;
	struct in_addr ias;
	struct clientparam *newparam;
	pthread_t thread;
	char * portlist;
	struct hostent* hp;
	int smtp = 0;
	char *s;

#ifdef _WIN32
 WSADATA wd;
 WSAStartup(MAKEWORD( 1, 1 ), &wd);
#endif

	if(argc < 6) {
		fprintf(stderr, "3Scan - fast HTTP/SOCKS4/SOCKS5 detector\n"
				"Usage: %s ip[/srcip] portlist option webhost url [keyword] [timeout]\n"
				"\tip - IP address to test\n"
				"\tsrcip - source IP address to\n"
				"\tportlist - comma delimited list of ports. May contain additional tests:\n"
				"\t s - Socks 4/5 test for this port\n"
				"\t p - HTTP/CONNECT proxy test for this port\n"
				"\t f - FTP proxy test for this port\n"
				"\t t - TELNET proxy test for this port\n"
				"\toption:\n"
				"\t p - scan for HTTP proxy on all ports\n"
				"\t c - scan for CONNECT proxy on all ports\n"
				"\t f - scan for FTP proxy on all ports\n"
				"\t t - scan for TELNET proxy on all ports\n"
				"\t 4 - scan for Socks v4 proxy on all ports\n"
				"\t 5 - scan for Socks v5 proxy on all ports\n"
				"\t w - scan for WINPROXY\n"
				"\t v - be verbose\n"
				"\t V - be Very Verbose\n"
				"\t s - be silent (exit code is non-zero if proxy detected)\n"
				"\t S - check SMTP instead of HTTP\n"
				"\twebhost - IP address for testing web server to try access via proxy\n"
				"\turl - URL to request on testing Web server\n"
				"\t We will try to access http://webhosturl via proxy\n"
				"\tkeyword - keyword to look for in requested page. If keyword not found\n"
				"\t proxy will not be reported\n"
				"\ttimeout - timeout in milliseconds\n"
				"example: %s localhost 1080s,3128p,8080p 4v www.myserver.com /test.html\n"
				"will test all 3 ports for Socks 4, additionally 3128 and 8080 will be tested\n"
				"for HTTP proxy, 1080 for both Socks 4 and 5, tests will be verbose.\n"
				"http://www.myserver.com/test.html should exist.\n"
				"\n(c) 2002 by 3APA3A, http://www.security.nnov.ru\n"
			,argc?argv[0]:"?",argc?argv[0]:"?");
		return 100;
	}
	if(argc > 7) to = atoi(argv[7]);
	if(strchr(argv[3], 'p')) deftest |= PROXY;
	if(strchr(argv[3], 'w')) deftest |= WINPROXY;
	if(strchr(argv[3], 'f')) deftest |= FTP;
	if(strchr(argv[3], 't')) deftest |= FTP;
	if(strchr(argv[3], 'c')) deftest |= CONNECT;
	if(strchr(argv[3], '4')) deftest |= SOCKS4;
	if(strchr(argv[3], '5')) deftest |= SOCKS5;
	if(strchr(argv[3], 'v')) verbose = 2;
	if(strchr(argv[3], 'V')) verbose = 3;
	if(strchr(argv[3], 's')) verbose = 0;
	if(strchr(argv[3], 'S')) smtp = 1;
	ias.s_addr = 0;
	if((s = strchr(argv[1], '/'))) {
		*s = 0;
	}

	hp = gethostbyname(argv[1]);
	if (!hp) {
		perror("gethostbyname()");
		return 102;
	}
	ia.s_addr = *(unsigned long *)hp->h_addr;

	for (portlist = strtok(argv[2], ","); portlist || (deftest & WINPROXY); portlist = strtok(NULL, ",")) {
		newparam = malloc(sizeof(struct clientparam));

		if(!newparam) {
			fprintf(stderr, "Memory allocation failed");
			return 0;
		}
		memset(newparam, 0, sizeof(struct clientparam));
		if(s){
			hp = gethostbyname(s+1); 
			newparam->sinc.sin_addr.s_addr = *(unsigned long *)hp->h_addr;
		}
		test = deftest;
		newparam->sins.sin_addr.s_addr = ia.s_addr;
		newparam->sins.sin_family = AF_INET;
		newparam->sinc.sin_family = AF_INET;
		newparam->webhost = argv[4];
		newparam->url = argv[5];
		newparam->keyword = (argc > 6)?argv[6] : 0;
		newparam->dosmtp = smtp;
		hp = gethostbyname(argv[4]);
		if (!hp) {
			perror("gethostbyname() error resolving target");
			return 0;
		}
		newparam->webip.s_addr = *(unsigned long *)hp->h_addr;
		if(!portlist) {
			newparam->sins.sin_port = htons(608);
			threadcount++;
#ifdef _WIN32
			CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, dotrojan, (void *) newparam, (DWORD)0, &thread);
#else
			pthread_create(&thread, NULL, dotrojan, (void *)newparam);
#endif
			break;
		}
		if(strchr(portlist, 'p')) test |= (CONNECT | PROXY);
		if(strchr(portlist, 's')) test |= (SOCKS4|SOCKS5);
		if(strchr(portlist, 'f')) test |= FTP;
		if(strchr(portlist, 't')) test |= TELNET;
		newparam->sins.sin_port = htons(atoi(portlist));
		if (test & PROXY) {
			threadcount++;
#ifdef _WIN32
			CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, doproxy, (void *) newparam, (DWORD)0, &thread);
#else
			pthread_create(&thread, NULL, doproxy, (void *)newparam);
#endif
		}
		if (test & CONNECT) {
			threadcount++;
#ifdef _WIN32
			CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, doconnect, (void *) newparam, (DWORD)0, &thread);
#else
			pthread_create(&thread, NULL, doconnect, (void *)newparam);
#endif
		}
		if (test & SOCKS4) {
			threadcount++;
#ifdef _WIN32
			CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, dosocks4, (void *) newparam, (DWORD)0, &thread);
#else
			pthread_create(&thread, NULL, dosocks4, (void *)newparam);
#endif  
		}
		if (test & SOCKS5) {
			threadcount++;
#ifdef _WIN32
			CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, dosocks5, (void *) newparam, (DWORD)0, &thread);
#else
			pthread_create(&thread, NULL, dosocks5, (void *)newparam);
#endif
		}
		if (test & FTP) {
			threadcount++;
#ifdef _WIN32
			CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, doftp, (void *) newparam, (DWORD)0, &thread);
#else
			pthread_create(&thread, NULL, doftp, (void *)newparam);
#endif
		}
		if (test & TELNET) {
			threadcount++;
#ifdef _WIN32
			CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, dotelnet, (void *) newparam, (DWORD)0, &thread);
#else
			pthread_create(&thread, NULL, dotelnet, (void *)newparam);
#endif
		}
	}
	for ( ; to > 0; to-=16){
		if(!threadcount)break;
		usleep((SLEEPTIME<<4));
	}
	return result;
}

