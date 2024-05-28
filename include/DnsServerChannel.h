#ifndef DNSTUN_DNSSERVERCHANNEL_H
#define DNSTUN_DNSSERVERCHANNEL_H
#include "BlockingQueue.hpp"
#include "net.h"
#include "Packet.h"
#include <atomic>
#include <thread>
#include <map>

enum dns_server_channel_err_t{
    DSCE_NULL,
    DSCE_NETWORK_ERR,
};

struct User{
    std::string id;
};
using UserWhiteList = std::map<std::string,User>;




class DnsServerChannel;
class ConnectionManager;

#define MAX_RESPONSE_DATA_LEN 85
class ClientConnection{
    friend class DnsServerChannel;
    int sockfd;
    session_id_t sessionId;
    std::atomic<int>* err;
    std::weak_ptr<ConnectionManager> manager;
    std::atomic<bool> running;
    BlockingQueue<AggregatedPacket> inboundBuffer;
    BlockingQueue<Packet> uploadBuffer;
    BlockingQueue<AggregatedPacket> downloadBuffer;
    BlockingQueue<Packet> pollBuffer;
    std::thread uploadThread;
    std::thread downloadThread;
    group_id_t connGroupId;
    void stop();
    void uploading();
    void downloading();
    int sendPacketResp(const Packet& packet);
    int sendGroup(AggregatedPacket &aggregatedPacket);
public:
    const User user;
    std::string name;
    void close();
    void open();
    ClientConnection(int sockfd_,session_id_t sessionId_,const User& user_,const std::shared_ptr<ConnectionManager>& manager_,std::atomic<int>* err_):
    sockfd(sockfd_), sessionId(sessionId_),user(user_),manager(manager_),err(err_),connGroupId(0){
        running.store(false);
    }
    ~ClientConnection();
    ssize_t read(void *dst, int timeout=0);
    ssize_t write(const void* src,size_t len);
    ssize_t read(Bytes& dst,int timeout=0);
    ssize_t write(const Bytes& src);
};

using ClientConnectionPtr = std::shared_ptr<ClientConnection>;
class ConnectionManager{
    std::mutex lock;
    std::map<session_id_t,ClientConnectionPtr> conns;
    BlockingQueue<std::weak_ptr<ClientConnection>> acceptBuffer;
public:
    session_id_t sessionIdGen();
    bool exist(session_id_t id);
    void remove(session_id_t id);
    void add(session_id_t id, const ClientConnectionPtr &ptr);
    ClientConnectionPtr accept();
    ClientConnectionPtr get(session_id_t id);
    ~ConnectionManager();
};

class DnsServerChannel {
    int sockfd;
    UserWhiteList whiteList;
    std::shared_ptr<ConnectionManager> manager;
    SA_IN localAddr;
    std::vector<Bytes> myDomain;
    std::atomic<bool> running;
    std::atomic<int> err;

    std::thread dispatchThread;
    int recvPacketQuery(Packet &packet, Dns &dns);
    int sendPacketResp(const Packet &packet, const SA_IN &addr);
    void dispatching();
    void authenticate(const Packet &packet);
public:
    DnsServerChannel(SA_IN& localAddr_,const char*myDomain_,const UserWhiteList& whiteList_):
            localAddr(localAddr_),whiteList(whiteList_),myDomain(cstrToDomain(myDomain_)){
        running.store(false),err.store(DSCE_NULL);
        manager= std::make_shared<ConnectionManager>();
    }
    int open();
    void close();
    ClientConnectionPtr accept();


};


#endif
