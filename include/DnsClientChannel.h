#ifndef DNSTUN_DNSCLIENTCHANNEL_H
#define DNSTUN_DNSCLIENTCHANNEL_H
#include "BlockingQueue.hpp"
#include "net.h"
#include "Packet.h"
#include "DnsServerChannel.h"
#include <atomic>
#include <thread>
#define DEFAULT_ACK_TIMEOUT 1
#define DEFAULT_POLL_TIMEOUT 1

enum dns_client_channel_err_t{
    DCCE_NULL,
    DCCE_AUTHENTICATE_ERR,
    DCCE_NETWORK_ERR
};

class DnsClientChannel {
    int sockfd;
    SA_IN remoteAddr;
    SA_IN localAddr;
    std::vector<Bytes> myDomain;
    std::string userId;
    BlockingQueue<AggregatedPacket> uploadBuffer;
    BlockingQueue<Packet> ackBuffer;
    BlockingQueue<Packet> downloadBuffer;
    BlockingQueue<AggregatedPacket> inboundBuffer;
    std::atomic<bool> running;
    std::atomic<int> err;
    uint16_t channelGroupId;

    std::thread uploadThread;
    std::thread dispatchThread;
    std::thread downloadThread;
    int authenticate(int timeout=NO_TIMEOUT);
    void uploading();
    void dispatching();
    void downloading();
    int sendDnsQuery(const Dns& dns);
    int recvPacketResp(Packet &packet, Dns &dnsResp, int timeout=NO_TIMEOUT);
    int sendGroup(const PacketGroup& group);

public:
    std::string name;
    int ackTimeout;
    int pollTimeout;
    DnsClientChannel(const SA_IN& remoteAddr_,SA_IN& localAddr_,const char* myDomain_,const std::string& userId_):
            remoteAddr(remoteAddr_),localAddr(localAddr_),myDomain(cstrToDomain(myDomain_)),userId(userId_),ackTimeout(DEFAULT_ACK_TIMEOUT),pollTimeout(DEFAULT_POLL_TIMEOUT),channelGroupId(0){running.store(false),err.store(DCCE_NULL);}
    DnsClientChannel(const SA_IN& remoteAddr_,const char* myDomain_,const std::string& userId_):
            remoteAddr(remoteAddr_),localAddr(ADDR_ZERO),myDomain(cstrToDomain(myDomain_)),userId(userId_),ackTimeout(DEFAULT_ACK_TIMEOUT),pollTimeout(DEFAULT_POLL_TIMEOUT),channelGroupId(0){running.store(false),err.store(DCCE_NULL);}
    ~DnsClientChannel();
    int open(int timeout=NO_TIMEOUT);
    void close();
    ssize_t write(const void* buf, size_t len);
    ssize_t read(void *dst, int timeout=0);
    ssize_t read(Bytes& dst,int timeout=0);
    ssize_t write(const Bytes& src);

};


#endif //DNSTUN_DNSCLIENTCHANNEL_H
