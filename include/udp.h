#ifndef DNS_UDP_H
#define DNS_UDP_H
#include "net.h"
#include <cstdlib>
struct UdpPacket {
    Bytes data;
    SA_IN remoteAddr;
    UdpPacket(const void* pData,size_t size,const SA_IN& remoteAddr_) : data(Bytes(pData,size)) , remoteAddr(remoteAddr_){}
};
int dialUdp(const SA_IN& remoteAddr,const SA_IN* localAddr);
int udpSocket(const SA_IN *pAddr= nullptr);
ssize_t recvfromUdp(int sockfd, void* dst, size_t size, SA_IN* addr);
ssize_t sendtoUdp(int sockfd, const void* src, size_t size, const SA_IN& addr);
ssize_t sendUdp(int sockfd,const void* src,size_t size);
ssize_t recvUdp(int sockfd,void* dst,size_t size,int timeout=0);
#endif //DNS_UDP_H
