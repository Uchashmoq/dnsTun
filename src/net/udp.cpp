#include "udp.h"
#include <iostream>
#include <cstring>

#ifdef WIN32
static int initWSA(){
    static int shouldWsa=1;
    if(shouldWsa){
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr<<"WSAStartup failed. Error Code : %d"<<WSAGetLastError()<<std::endl;
            return -1;
        }
        atexit([](){WSACleanup();});
        shouldWsa=0;
    }
}
#endif

int udpSocket(const SA_IN *pAddr){
#ifdef WIN32
    if(initWSA()<0){
        return -1;
    }
#endif
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) <0) {
        std::cerr<<"Could not create socket"<<std::endl;
        return -1;
    }
    if(pAddr!= nullptr){
        if (bind(sockfd, (SA *)pAddr, sizeof(SA_IN)) < 0) {
            std::cerr<<"Bind failed :"<< getLastErrorMessage() <<std::endl;
            return -1;
        }
    }
    return sockfd;
}

int dialUdp(const SA_IN &remoteAddr, const SA_IN *pLocalAddr) {
#ifdef WIN32
    if(initWSA()<0){
        return -1;
    }
#endif
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) <0) {
        std::cerr<<"Could not create socket"<<std::endl;
        return -1;
    }
    if(pLocalAddr!= nullptr){
        if (bind(sockfd, (SA *)pLocalAddr, sizeof(SA_IN)) < 0) {
            std::cerr<<"Bind failed :"<< getLastErrorMessage() <<std::endl;
            return -1;
        }
    }
    if(connect(sockfd,(SA*)&remoteAddr, sizeof(remoteAddr))<0){
        std::cerr<<"Connect failed :"<< getLastErrorMessage() <<std::endl;
        return -1;
    }
    return sockfd;
}



ssize_t recvfromUdp(int sockfd, void* dst, size_t size, SA_IN* addr){
    socklen_t len = sizeof(SA_IN);
    return recvfrom(sockfd,(char*)dst,size,0,(SA*)addr,&len);
}

ssize_t sendtoUdp(int sockfd, const void *src, size_t size, const SA_IN &addr) {
    return sendto(sockfd,(char*)src,size,0,(SA*)&addr,sizeof(addr));
}

ssize_t sendUdp(int sockfd, const void *src, size_t size) {
    return send(sockfd,(char*)src,size,0);
}

ssize_t recvUdp(int sockfd, void *dst, size_t size,int timeout) {
    if(timeout>0){
        if (setSocketTimeout(sockfd, timeout)<0){
            return -1;
        }
    }
    auto n = recv(sockfd,(char*)dst,size,0);
    if(n<0){
        return -1;
    }
    if(timeout>0){
        if (setSocketTimeout(sockfd, NO_TIMEOUT)<0){
            return -1;
        }
    }
    return n;
}






