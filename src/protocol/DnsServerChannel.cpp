#include "DnsServerChannel.h"
#include "Log.h"
#include "udp.h"
#include <functional>
#include "packetProcess.h"
using namespace std;
int DnsServerChannel::recvPacketQuery(Packet &packet, Dns &dns) {
    if(!running.load() || err.load() == DSCE_NETWORK_ERR) return -1;
    char buf[6*1024];
    SA_IN source;
    auto n= recvfromUdp(sockfd,buf, sizeof(buf), &source);
    if ( n<0 ){
        if(running.load()) Log::printf(LOG_ERROR,getLastErrorMessage().c_str());
        err.store(DSCE_NETWORK_ERR);
        return -1;
    }
    if (Dns::resolve(dns, buf, n)<0){
        return -1;
    }
    if(Packet::dnsQueryToPacket(packet,dns,myDomain)<0){
        return -1;
    }
    dns.source=source;
    packet.source=source;
    return 1;
}


void DnsServerChannel::dispatching() {
    while(running.load()){
        Packet packet;
        Dns dns;
        if (recvPacketQuery(packet, dns) < 0){
            if(err.load()==DSCE_NETWORK_ERR) break;
            else continue;
        }
        if(packet.type==PACKET_AUTHENTICATE){
            authenticate(packet);
        }else {
            session_id_t sessionId =packet.sessionId;
            if(manager->exist(sessionId)) {
                auto connPtr = manager->get(sessionId);
                if(connPtr->running.load()){
                    switch (packet.type) {
                        case PACKET_POLL:
                            connPtr->pollBuffer.push(std::move(packet));
                            break;
                        case PACKET_UPLOAD:
                        case PACKET_GROUP_END:
                            connPtr->uploadBuffer.push(std::move(packet));
                            break;
                        default:
                            Log::printf(LOG_ERROR, "packet with unexpected type : %s", packet.toString().c_str());
                    }
                }
            }
        }
    }
}

static bool authenticateUser(const UserWhiteList& whiteList,const string& userId){
    if(whiteList.empty()) return true;
    return whiteList.count(userId)>0;
}

void DnsServerChannel::authenticate(const Packet &packet) {
    string userId = packet.data;
    bool permit= false;
    bool exist = manager->exist(packet.sessionId);
    auto sessionId=packet.sessionId;
    if(exist){
        auto conn = manager->get(sessionId);
        permit = conn->user.id == userId;
    }else{
        permit = authenticateUser(whiteList,userId);
    }

    if(permit){
        auto newSessionId = manager->sessionIdGen();
        if(!exist){
            User newUser = {userId};
            auto connPtr = make_shared<ClientConnection>(sockfd,newSessionId,newUser,manager,&err);
            connPtr->open();
            manager->add(newSessionId,connPtr);
        }
        auto success = packet.getResponsePacket(PACKET_AUTHENTICATION_SUCCESS);
        success.sessionId = exist ? sessionId : newSessionId;
        if (sendPacketResp(success, packet.source)<0) return;
    }else{
        auto failure = packet.getResponsePacket(PACKET_AUTHENTICATION_FAILURE);
        sendPacketResp(failure,packet.source);
    }
}

int DnsServerChannel::sendPacketResp(const Packet &packet, const SA_IN &addr) {
    if(err.load()==DSCE_NETWORK_ERR ) return -1;
    char buf[4096];
    Dns dns;
    Packet::packetToDnsResp(dns,packet.dnsTransactionId,packet);
    ssize_t n = Dns::bytes(dns, buf, sizeof(buf));
    if (sendtoUdp(sockfd,buf,n,addr)<0){
        if(running.load()) Log::printf(LOG_ERROR,getLastErrorMessage().c_str());
        err.store(DSCE_NETWORK_ERR);
        return -1;
    }
    return 1;
}

ClientConnectionPtr DnsServerChannel::accept() {
    return manager->accept();
}

int DnsServerChannel::open() {
    if(running.load())  return -1;
    sockfd= udpSocket(&localAddr);
    if(sockfd<0){
        Log::printf(LOG_ERROR,"%s",getLastErrorMessage().c_str());
        return -1;
    }
    dispatchThread=std::thread(std::bind(&DnsServerChannel::dispatching,this));
    running.store(true);
    Log::printf(LOG_INFO,"DnsServerChannel opened at %s",sockaddr_inStr(localAddr).c_str());
    return 1;
}

void DnsServerChannel::close() {
    if(running.load()){
        running.store(false);
        dispatchThread.join();
    }
}


session_id_t getsessionId(const SA_IN &addr) {
    const static auto ipSize = sizeof(addr.sin_addr.s_addr);
    session_id_t id=0;
    id |= addr.sin_addr.s_addr;
    id <<= ipSize;
    id |= addr.sin_port;
    return id;
}

void ConnectionManager::add(session_id_t id, const ClientConnectionPtr &ptr) {
    lock.lock();
    conns.insert(make_pair(id , ptr));
    lock.unlock();
    acceptBuffer.push(ptr);
}

void ConnectionManager::remove(session_id_t id) {
    lock_guard<mutex> guard(lock);
    conns.erase(id);
}

bool ConnectionManager::exist(session_id_t id) {
    lock_guard<mutex> guard(lock);
    return conns.count(id);
}

ClientConnectionPtr ConnectionManager::get(session_id_t id) {
    lock_guard<mutex> guard(lock);
    return conns[id];
}

ClientConnectionPtr ConnectionManager::accept() {
    weak_ptr<ClientConnection> ptr;
    if(acceptBuffer.pop(ptr)!=POP_SUCCESSFULLY) return nullptr;
    return ptr.lock();
}

ConnectionManager::~ConnectionManager() {
    acceptBuffer.unblock();
}

session_id_t ConnectionManager::sessionIdGen() {
    session_id_t id;
    do{
        id=rand();
    } while (exist(id) || id==0);
    return id;
}


void ClientConnection::close() {
    auto ptr = manager.lock();
    if(ptr){
        if(ptr->exist(sessionId)){
            ptr->remove(sessionId);
            Log::printf(LOG_TRACE,"ClientConnection '%s' closed",name.c_str());
        }else{
            Log::printf(LOG_WARN,"failed to remove ClientConnection from ConnectionManager : invalid sessionId : %u",sessionId);
        }
    }
}

void ClientConnection::stop() {
    if(running.load()){
        running.store(false);
        downloadBuffer.unblock();
        uploadBuffer.unblock();
        pollBuffer.unblock();
        downloadThread.join();
        uploadThread.join();
        Log::printf(LOG_TRACE,"ClientConnection '%s' stopped",name.c_str());
    }
}

ClientConnection::~ClientConnection() {
    stop();
    Log::printf(LOG_TRACE,"ClientConnection '%s' destroyed",name.c_str());
}


void ClientConnection::uploading() {
    vector<Packet> packets;
    group_id_t groupId=0,dataId=DATA_SEG_START;

    while (running.load()){
        Packet packetUpload;
        if (uploadBuffer.pop(packetUpload)==POP_INVALID) break;
        if(!verifyPacket(packetUpload,groupId,dataId)) continue;

        auto packetAck = packetUpload.getResponsePacket(PACKET_ACK);
        if(packetUpload.dataId==DATA_SEG_START){
            newPacketGroup(groupId, dataId, packetUpload, packets);
        }else if(packetUpload.type==PACKET_GROUP_END){
            exportPackets(inboundBuffer,packets,groupId,dataId);
            groupId++;
        }else{
            packetGroupAdd(groupId, dataId, packetUpload, packets);
        }
        sendPacketResp(packetAck);
    }
}

void ClientConnection::downloading() {
    while (running.load()){
        Packet packetPoll;
        if(pollBuffer.pop(packetPoll)==POP_INVALID) break;

        if(downloadBuffer.size()==0){
            auto packetResp = packetPoll.getResponsePacket(PACKET_DOWNLOAD_NOTHING);
            if (sendPacketResp(packetResp)<0) break;
        }else {
            AggregatedPacket aggregatedPacket;
            if (downloadBuffer.pop(aggregatedPacket) == POP_INVALID) break;
            if (sendGroup(aggregatedPacket) < 0) break;
            connGroupId++;
        }
    }
}

int ClientConnection::sendPacketResp(const Packet &packet) {
    if(err->load()==DSCE_NETWORK_ERR ) return -1;
    char buf[4096];
    Dns dns;
    Packet::packetToDnsResp(dns,packet.dnsTransactionId,packet);
    ssize_t n = Dns::bytes(dns, buf, sizeof(buf));
    if (sendtoUdp(sockfd,buf,n,packet.source)<0){
        if(running.load()) Log::printf(LOG_ERROR,getLastErrorMessage().c_str());
        err->store(DSCE_NETWORK_ERR);
        return -1;
    }
    return 1;
}


static size_t readAggregatedPacket(BytesReader& br,Packet& packet){
    if(br.readableBytes()==0) {
        packet.type=PACKET_GROUP_END;
        return 0;
    }
    packet.data =  br.readBytes(MAX_RESPONSE_DATA_LEN);
    return packet.data.size;
}

int ClientConnection::sendGroup(AggregatedPacket &aggregatedPacket) {
    BytesReader br(aggregatedPacket.data);
    group_id_t groupId = connGroupId , dataId = DATA_SEG_START;
    vector<Packet> temp;
    while (running.load()){
        Packet packetPoll;
        if(pollBuffer.pop(packetPoll)==POP_INVALID) return -1;

        auto packetDownload = packetPoll.getResponsePacket(PACKET_DOWNLOAD,groupId,dataId);
        if(packetPoll.dataId==dataId){
            if(readAggregatedPacket(br,packetDownload)>0){
                if(sendPacketResp(packetDownload)<0) return -1;
            }else{
                if(sendPacketResp(packetDownload)<0) return -1;
                else return 1;
            }
            temp.push_back(std::move(packetDownload));
            dataId++;
        }else if(packetPoll.dataId<dataId){
            if(sendPacketResp(temp[packetPoll.dataId])<0) return -1;
        }else{
            Log::printf(LOG_WARN,"advanced data id in packetPoll : %u",packetPoll.dataId);
            return 2;
        }
    }
    return -1;
}

void ClientConnection::open() {
    if(err->load()==DSCE_NULL && !running.load()) {
        running.store(true);
        uploadThread=thread(std::bind(&ClientConnection::uploading,this));
        downloadThread=thread(std::thread(&ClientConnection::downloading , this));
        name=std::to_string(sessionId)+"@"+user.id;
        Log::printf(LOG_TRACE,"ClientConnection '%s' opened",name.c_str());
    }
}

ssize_t ClientConnection::read(void *dst, int timeout) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed ClientConnection");
        return -1;
    }
    int e=err->load();
    if(e==DSCE_NETWORK_ERR){
        return -1;
    }
    AggregatedPacket packet;
    if (inboundBuffer.pop(packet,timeout)==POP_SUCCESSFULLY){
        memcpy(dst,packet.data.data,packet.data.size);
        return packet.data.size;
    }
    return -1;
}

ssize_t ClientConnection::write(const void *src, size_t len) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed DnsClientChannel");
        return -1;
    }
    int e=err->load();
    if(e==DSCE_NETWORK_ERR){
        return -1;
    }
    AggregatedPacket aggregatedPacket={Bytes(src,len)};
    downloadBuffer.push(std::move(aggregatedPacket));
    return len;
}

ssize_t ClientConnection::read(Bytes &dst, int timeout) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed ClientConnection");
        return -1;
    }
    int e=err->load();
    if(e==DSCE_NETWORK_ERR){
        return -1;
    }
    AggregatedPacket packet;
    if (inboundBuffer.pop(packet,timeout)==POP_SUCCESSFULLY){
        dst=std::move(packet.data);
        return dst.size;
    }
    return -1;
}

ssize_t ClientConnection::write(const Bytes &src) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed DnsClientChannel");
        return -1;
    }
    int e=err->load();
    if(e==DSCE_NETWORK_ERR){
        return -1;
    }
    AggregatedPacket aggregatedPacket={src};
    downloadBuffer.push(std::move(aggregatedPacket));
    return src.size;
}
