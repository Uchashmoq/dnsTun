#ifndef DNS_NET_H
#define DNS_NET_H
#include <string>
#include <vector>
#include "../src/lib/Bytes.hpp"
#ifdef WIN32

#include <wspiapi.h>
#include<iphlpapi.h>
#include <winsock2.h>
#include "../src/lib/Bytes.hpp"
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#endif
#define NO_TIMEOUT 0
#define SET_ZERO(o) memset(&o,0,sizeof(o))
typedef sockaddr_in SA_IN;
typedef sockaddr SA;
extern const SA_IN ADDR_ZERO;
std::string getLastErrorMessage();
SA_IN inetAddr(const char* addrStr,unsigned short port);
std::string sockaddr_inStr(const SA_IN& addr);
std::vector<Bytes> cstrToDomain(const char* str);
int setSocketTimeout(int sockfd, int seconds);
int closeSocket(int sockfd);
int isTimeOut();
bool operator==(const SA_IN& addr1,const SA_IN& addr2);
bool operator!=(const SA_IN& addr1,const SA_IN& addr2);
#endif
