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

enum client_connection_err_t{
    CCE_NULL,
    CCE_IDLE
};

struct User{
    std::string id;
};
using UserWhiteList = std::map<std::string,User>;

class DnsServerChannel;
class ConnectionManager;

#define MAX_RESPONSE_DATA_LEN 85
#define DEFAULT_CLIENT_IDLE_TIMEOUT 5
class ClientConnection{
    friend class DnsServerChannel;
    int sockfd;
    session_id_t sessionId;
    std::atomic<int>* err;
    std::atomic<int> connErr;
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
    int idleTimeout;
    void close();
    void open();
    ClientConnection(int sockfd_,session_id_t sessionId_,const User& user_,const std::shared_ptr<ConnectionManager>& manager_,std::atomic<int>* err_):
    sockfd(sockfd_), sessionId(sessionId_),user(user_),manager(manager_),err(err_),connGroupId(0),idleTimeout(DEFAULT_CLIENT_IDLE_TIMEOUT){
        connErr.store(CCE_NULL);
        running.store(false);
    }
    ~ClientConnection();
    bool noConnErr();
    ssize_t read(void *dst, int timeout=0);
    ssize_t write(const void* src,size_t len);
    ssize_t read(Bytes& dst,int timeout=0);
    ssize_t write(const Bytes& src);
    void handleIdle();
    void closeBuffer();
};

using ClientConnectionPtr = std::shared_ptr<ClientConnection>;
class ConnectionManager{
    std::mutex lock;
    std::map<session_id_t,ClientConnectionPtr> conns;
    BlockingQueue<std::weak_ptr<ClientConnection>> acceptBuffer;
public:
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
    bool authenticateUserId(const std::string &userId);
    int sendPacketResp(const Packet &packet);
public:
    DnsServerChannel(SA_IN& localAddr_,const char*myDomain_,const UserWhiteList& whiteList_ = UserWhiteList()):
            localAddr(localAddr_),myDomain(cstrToDomain(myDomain_)),whiteList(whiteList_){
        running.store(false),err.store(DSCE_NULL);
        manager= std::make_shared<ConnectionManager>();
    }
    int open();
    void close();
    ClientConnectionPtr accept();


};


#endif
