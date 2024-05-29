#include "DnsClientChannel.h"
#include <functional>
#include "Log.h"
#include "udp.h"
#include "packetProcess.h"
using namespace std;



int DnsClientChannel::open(int timeout) {
    if(running.load()) return -1;
    if((sockfd= dialUdp(remoteAddr,&localAddr))<0){
        Log::printf(LOG_ERROR,"failed to open ClientDnsChannel : %s",getLastErrorMessage().c_str());
        err.store(DCCE_AUTHENTICATE_ERR);
        return -1;
    }
    if(authenticate(timeout)<0){
        return -1;
    }
    running.store(true);
    name=std::to_string(sessionId)+"@"+userId;
    uploadThread=thread(std::bind(&DnsClientChannel::uploading, this));
    dispatchThread=thread(std::bind(&DnsClientChannel::dispatching, this));
    downloadThread=thread(std::bind(&DnsClientChannel::downloading, this ));
    Log::printf(LOG_TRACE,"DnsClientChannel '%s' connected to %s",name.c_str(), sockaddr_inStr(remoteAddr).c_str());
    return 1;
}

int DnsClientChannel::authenticate(int timeout) {
    Dns dns,dnsResp;
    Packet packet,packetResp;
    packet.sessionId=rand();
    if (Packet::authentication(dns, packet, userId.c_str(), myDomain) < 0){
        Log::printf(LOG_ERROR,"user id is too long");
        return -1;
    }
    if(sendDnsQuery(dns)<0){
        return -1;
    }
    if(recvPacketResp(packetResp, dnsResp, timeout) < 0){
        return -1;
    }
    if(packetResp.type != PACKET_AUTHENTICATION_SUCCESS){
        Log::printf(LOG_ERROR,"authentication failure");
        return -1;
    }
    sessionId=packetResp.sessionId;
    name=std::to_string(sessionId)+"@"+userId;
    return 1;
}

void DnsClientChannel::uploading() {
    while (running.load()){
        AggregatedPacket aggregatedPacket;
        auto result=uploadBuffer.pop(aggregatedPacket);
        if(result==POP_INVALID || !noConnErr()) break;
        auto group = disaggregateToQueryPacketGroup(aggregatedPacket, sessionId, channelGroupId, randRecordType(),
                                                    PACKET_UPLOAD, myDomain);
        if (sendGroup(group)<0) break;
        channelGroupId++;
    }
}
void DnsClientChannel::dispatching() {
    while(running.load()){
        Packet packet;
        Dns dns;
        if (recvPacketResp(packet, dns)<0){
            if(!noConnErr()) break;
            else continue;
        }
        switch (packet.type) {
            case PACKET_ACK:
                ackBuffer.push(std::move(packet));
                break;
            case PACKET_DOWNLOAD:
            case PACKET_GROUP_END:
            case PACKET_DOWNLOAD_NOTHING:
                downloadBuffer.push(std::move(packet));
                break;
            case PACKET_DISCARD:
                Log::printf(LOG_TRACE,"packet discard ,group id :%u,data id :%u",packet.groupId,packet.dataId);
                break;
            case PACKET_SESSION_NOT_FOUND:
            case PACKET_SESSION_CLOSED:
                err.store(DCCE_PEER_CLOSED);
                closeBuffers();
                break;
            default:
                Log::printf(LOG_ERROR,"packet with unexpected type : %s",packet.toString().c_str());
        }
    }
}


void DnsClientChannel::downloading() {
    group_id_t groupId=0, dataId=DATA_SEG_START;
    vector<Packet> packets;
    while (running.load()){
        DNS_POLL:
        Dns dnsPoll; Packet packetPoll;
        Packet::poll(dnsPoll, packetPoll, myDomain, sessionId, groupId, dataId);
        if (sendDnsQuery(dnsPoll)<0){
            break;
        }

        Packet packetDown;
        auto result = downloadBuffer.pop(packetDown,pollTimeout);
        if(result==POP_INVALID || !noConnErr()) break;
        if(result==POP_TIMEOUT || packetDown.type == PACKET_DOWNLOAD_NOTHING){
            goto DNS_POLL;
        }

        if(packetDown.dataId==DATA_SEG_START){
            newPacketGroup(groupId, dataId, packetDown, packets);
        }else if(packetDown.type==PACKET_GROUP_END){
            exportPackets(inboundBuffer,packets,groupId,dataId);
            groupId++;
        }else{
            packetGroupAdd(groupId, dataId, packetDown, packets);
        }
    }
}


int DnsClientChannel::sendGroup(const PacketGroup &group) {
    vector<Packet> responses;
    for(const auto& seg : group.segments) {
        DNS_SEND:
        if (sendDnsQuery(seg.dns) < 0) {
            Log::printf(LOG_ERROR,"%s : %s" ,__FUNCTION__ ,getLastErrorMessage().c_str());
            return -1;
        }
        PACKET_RECV:
        Packet packetAck;
        auto result = ackBuffer.pop(packetAck,ackTimeout);
        if(result==POP_INVALID || !noConnErr()) return -1;
        if(result==POP_TIMEOUT) goto DNS_SEND;
        if(!verifyPacket(packetAck,group.groupId,seg.packet.dataId)){
            goto PACKET_RECV;
        }
    }
    return 1;
}

int DnsClientChannel::sendDnsQuery(const Dns &dns) {
    if(!noConnErr()) return -1;
    char buf[4096];
    ssize_t n = Dns::bytes(dns, buf, sizeof(buf));
    if (sendUdp(sockfd, buf, n)<0){
        if(running.load()) Log::printf(LOG_DEBUG,getLastErrorMessage().c_str());
        err.store(DCCE_NETWORK_ERR);
        return -1;
    }
    return 1;
}

int DnsClientChannel::recvPacketResp(Packet &packet, Dns &dnsResp, int timeout) {
    if(!noConnErr()) return -1;
    char buf[4*1024];
    auto n=recvUdp(sockfd,buf,sizeof (buf),timeout);
    if ( n<0 ){
        if( running.load()) Log::printf(LOG_DEBUG,getLastErrorMessage().c_str());
        err.store(DCCE_NETWORK_ERR);
        return -1;
    }
    if (Dns::resolve(dnsResp, buf, n)<0){
        return -1;
    }
    if(Packet::dnsRespToPacket(packet,dnsResp)<0){
        return -1;
    }
    return 1;
}


ssize_t DnsClientChannel::write(const void *buf, size_t len) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed DnsClientChannel");
        return -1;
    }
    int e=err.load();
    if(!noConnErr() || e==DCCE_AUTHENTICATE_ERR){
        return -1;
    }
    AggregatedPacket aggregatedPacket={Bytes(buf,len)};
    uploadBuffer.push(std::move(aggregatedPacket));
    return len;
}

ssize_t DnsClientChannel::read(void *dst, int timeout) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed DnsClientChannel");
        return -1;
    }
    int e=err.load();
    if(!noConnErr()|| e==DCCE_AUTHENTICATE_ERR){
        return -1;
    }
    AggregatedPacket packet;
    if (inboundBuffer.pop(packet, timeout)==POP_SUCCESSFULLY){
        memcpy(dst,packet.data.data,packet.data.size);
        return packet.data.size;
    }else{
        return -1;
    }
}

void DnsClientChannel::close() {
    if(running.load()){
        running.store(false);
        closeBuffers();
        closeSocket(sockfd);
        dispatchThread.join();
        uploadThread.join();
        downloadThread.join();
        Log::printf(LOG_TRACE,"DnsClientChannel '%s' closed",name.c_str());
    }
}

DnsClientChannel::~DnsClientChannel() {
    close();
    Log::printf(LOG_TRACE,"DnsClientChannel '%s' destroyed",name.c_str());
}

ssize_t DnsClientChannel::write(const Bytes &src) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed DnsClientChannel");
        return -1;
    }
    int e=err.load();
    if(e==DCCE_NETWORK_ERR || e==DCCE_AUTHENTICATE_ERR){
        return -1;
    }
    AggregatedPacket aggregatedPacket={src};
    uploadBuffer.push(std::move(aggregatedPacket));
    return src.size;
}

ssize_t DnsClientChannel::read(Bytes &dst, int timeout) {
    if(!running.load()){
        Log::printf(LOG_ERROR,"writing data to a closed DnsClientChannel");
        return -1;
    }
    int e=err.load();
    if(e==DCCE_NETWORK_ERR || e==DCCE_AUTHENTICATE_ERR){
        return -1;
    }
    AggregatedPacket packet;
    if (inboundBuffer.pop(packet, timeout)==POP_SUCCESSFULLY){
        dst=std::move(packet.data);
        return dst.size;
    }else{
        return -1;
    }
}

void DnsClientChannel::closeBuffers() {
    uploadBuffer.unblock();
    downloadBuffer.unblock();
    inboundBuffer.unblock();
}

bool DnsClientChannel::noConnErr() {
    auto e = err.load();
    return !(e==DCCE_NETWORK_ERR || e==DCCE_PEER_CLOSED);
}



