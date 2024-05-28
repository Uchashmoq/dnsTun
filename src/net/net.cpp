#include "net.h"
#include <cstring>
#include "../lib/strings.h"

SA_IN inetAddr(const char *addrStr, unsigned short port) {
    SA_IN addr;
    memset(&addr,0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(addrStr== nullptr || strcmp(addrStr,"0.0.0.0")==0){
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    else if (inet_pton(AF_INET, addrStr, &(addr.sin_addr))!=1 ){
        perror("inet_pton");
    }
    addr.sin_port = htons(port);
    return addr;
}

const SA_IN ADDR_ZERO = inetAddr("0.0.0.0", 0);

std::string sockaddr_inStr(const SA_IN &addr) {
    std::string addrStr = inet_ntoa(addr.sin_addr);
    auto port = ntohs(addr.sin_port);
    return addrStr+":"+ std::to_string(port);
}


std::string getLastErrorMessage() {
#ifdef WIN32
    char errorMessage[2048];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, WSAGetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  errorMessage, sizeof(errorMessage), NULL);
    return errorMessage;
#else
    return strerror(errno);
#endif
}

int closeSocket(int sockfd) {
#ifdef WIN32
    return closesocket(sockfd);
#else
    return close(sockfd);
#endif
}

std::vector<Bytes> cstrToDomain(const char *str) {
    const std::vector<std::string> &strs = splitString(str, '.');
    std::vector<Bytes> v;
    for(const auto& s : strs){
        v.emplace_back(s);
    }
    return move(v);
}

int setSocketTimeout(int sockfd, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
}

int isTimeOut() {
#ifdef WIN32
    return WSAGetLastError() == WSAETIMEDOUT;
#else
    return errno == EWOULDBLOCK || errno == EAGAIN;
#endif

}

bool operator==(const SA_IN& addr1,const SA_IN& addr2){
    return addr1.sin_addr.s_addr == addr2.sin_addr.s_addr && addr1.sin_port==addr2.sin_port && addr1.sin_family==addr2.sin_family;
}
bool operator!=(const SA_IN& addr1,const SA_IN& addr2){
    return !(addr1==addr2);
}

