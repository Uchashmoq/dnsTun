#include "DnsServerChannel.h"
#include "Log.h"
#include "udp.h"
#include <functional>
#include "packetProcess.h"
using namespace std;



namespace ucsmq{

    static string lookupPreviousPacket(const std::list<std::pair<group_id_t,std::vector<Packet>>>& groups){
        stringstream ss;
        for(const auto& pa : groups){
            const auto& v =pa.second;
            ss<<pa.first<<" : {"<< v.front().dataId << " ~ "<<v.back().dataId <<"}"<<endl;
        }
        return ss.str();
    }

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
                continue;
            }
            session_id_t sessionId =packet.sessionId;
            if(!manager->exist(sessionId)) {
                auto packetErr = packet.getResponsePacket(PACKET_SESSION_NOT_FOUND);
                sendPacketResp(packetErr);
                continue;
            }

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
                        auto packetErr = packet.getResponsePacket(PACKET_INVALID_TYPE);
                        sendPacketResp(packetErr);
                        Log::printf(LOG_ERROR, "packet with unexpected type : %s", packet.toString().c_str());
                }
            }else{
                auto packetErr = packet.getResponsePacket(PACKET_SESSION_CLOSED);
                sendPacketResp(packetErr);
            }
        }
    }


    void DnsServerChannel::authenticate(const Packet &packet) {
        string userId = packet.data;
        auto sessionId = packet.sessionId;
        if(manager->exist(sessionId)){
            auto failure = packet.getResponsePacket(PACKET_AUTHENTICATION_FAILURE);
            Log::printf(LOG_DEBUG,"replicated authentication packet , session id : %u,user id : %s",sessionId,userId.c_str());
            if (sendPacketResp(failure)<0) return;
        }
        if(!authenticateUserId(userId)){
            auto failure = packet.getResponsePacket(PACKET_AUTHENTICATION_FAILURE);
            Log::printf(LOG_INFO,"authentication  failure session id : %u,user id : %s",sessionId,userId.c_str());
            if (sendPacketResp(failure)<0) return;
        }

        User newUser = {userId};
        auto connPtr = make_shared<ClientConnection>(sockfd,sessionId,newUser,manager,&err);
        connPtr->open();
        manager->add(sessionId,connPtr);
        auto success = packet.getResponsePacket(PACKET_AUTHENTICATION_SUCCESS);
        success.sessionId=sessionId;
        if (sendPacketResp(success)<0) return;
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

    bool DnsServerChannel::authenticateUserId(const string &userId) {
        if(whiteList.empty()) return true;
        return whiteList.count(userId)>0;
    }

    int DnsServerChannel::sendPacketResp(const Packet &packet) {
        return sendPacketResp(packet,packet.source);
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
            closeBuffer();
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
            if(!verifyPacket(packetUpload,groupId,dataId)) {
                auto packetDiscard = packetUpload.getResponsePacket(PACKET_DISCARD);
                sendPacketResp(packetDiscard);
                continue;
            }
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
            auto result = pollBuffer.pop(packetPoll,idleTimeout);
            if(result==POP_INVALID) break;
            if(result==POP_TIMEOUT) {
                handleIdle();
                break;
            }

            if(packetPoll.groupId!=connGroupId){
                if(downloadPreviousPacket(packetPoll)<0) break;
                continue;
            }

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
        if(!noConnErr()) return -1;
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

    int ClientConnection::sendGroup(const AggregatedPacket &aggregatedPacket) {
        BytesReader br(aggregatedPacket.data);
        data_id_t dataId = DATA_SEG_START;
        vector<Packet> temp;
        while (running.load()){
            Packet packetPoll;
            auto result=pollBuffer.pop(packetPoll,idleTimeout);
            if(result==POP_INVALID) return -1;
            if(result==POP_TIMEOUT){
                handleIdle();
                return -1;
            }
            printf("poll %u,%u , conn %u,%u\n",packetPoll.groupId,packetPoll.dataId,connGroupId,dataId);
            if(packetPoll.groupId!=connGroupId){
                if(downloadPreviousPacket(packetPoll)<0) return -1;
                continue;
            }

            if(packetPoll.dataId==dataId){
                auto packetDownload = packetPoll.getResponsePacket(PACKET_DOWNLOAD);
                auto n =  readAggregatedPacket(br,packetDownload);
                printf("down %u,%u,%s,n=%zu\n",packetDownload.groupId,packetDownload.dataId, packetTypeName(packetDownload.type),n);
                if(sendPacketResp(packetDownload)<0) return -1;
                if(temp.empty() || temp.back().dataId!= packetDownload.dataId){
                    temp.push_back(std::move(packetDownload));
                }
                dataId++;
                if(n==0) {
                    addDownloadedPackets(connGroupId,temp);
                    return 1;
                }
            }else if(packetPoll.dataId<dataId){
                printf("down1 %u,%u\n",connGroupId,packetPoll.dataId);
                if(sendPacketResp(temp[packetPoll.dataId])<0) return -1;
            }else{
                Log::printf(LOG_WARN,"advanced data id in packetPoll : %u",packetPoll.dataId);
                if(sendPacketResp(packetPoll.getResponsePacket(PACKET_DISCARD))<0) return -1;
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

        if(!noConnErr()){
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

        if(!noConnErr()){
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
        if(!noConnErr()){
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

        if(!noConnErr()){
            return -1;
        }
        AggregatedPacket aggregatedPacket={src};
        downloadBuffer.push(std::move(aggregatedPacket));
        return src.size;
    }

    void ClientConnection::handleIdle() {
        Log::printf(LOG_INFO,"ClientConnection '%s' is idle",name.c_str());
        connErr.store(CCE_IDLE);
        closeBuffer();
        close();
    }

    void ClientConnection::closeBuffer() {
        downloadBuffer.unblock();
        uploadBuffer.unblock();
        pollBuffer.unblock();
        inboundBuffer.unblock();
    }

    bool ClientConnection::noConnErr() {
        return !(err->load()==DSCE_NETWORK_ERR || connErr.load()==CCE_IDLE);
    }

    void ClientConnection::addDownloadedPackets(group_id_t groupId, vector <Packet> &packets) {
        if (downloadedPackets.size()>=downloadedPacketsStorageLimit){
            downloadedPackets.pop_front();
        }
        downloadedPackets.push_back(make_pair(groupId,std::move(packets)));
    }


    int ClientConnection::downloadPreviousPacket(const Packet &packetPoll) {
        auto packetResp = packetPoll.getResponsePacket(PACKET_DISCARD);
        for(const auto& pa : downloadedPackets){
            if(pa.first==packetPoll.groupId){
                for(const auto& packet : pa.second){
                    if(packet.dataId==packetPoll.dataId){
                         packetResp.data=packet.data;
                         packetResp.type=packet.type;
                    }
                }
            }
        }
        if(packetResp.type==PACKET_DISCARD){
            Log::printf(LOG_WARN,"can not find previous packet , group id : %u,data id : %u , current group id %u:\n previous packets storage : \n %s",packetPoll.groupId,packetPoll.dataId,connGroupId,
                        lookupPreviousPacket(downloadedPackets).c_str());
        }else{
            Log::printf(LOG_DEBUG,"send previous packet , group id : %u,data id : %u ",packetPoll.groupId,packetPoll.dataId);
        }
        return sendPacketResp(packetResp);
    }
}
