#ifndef DNS_PACKET_H
#define DNS_PACKET_H
#include "net.h"
#include <stdint.h>
#include <list>
#include "../src/lib/Bytes.hpp"
#include "../src/protocol/Dns.h"
#include <cstring>

enum packet_t {
    PACKET_PING=1,
    PACKET_UPLOAD,
    PACKET_AUTHENTICATE,
    PACKET_ACK,
    PACKET_DOWNLOAD,
    PACKET_RESPONSE_ADDITIONAL,
    PACKET_POLL,
    PACKET_AUTHENTICATION_SUCCESS,
    PACKET_AUTHENTICATION_FAILURE,
    PACKET_GROUP_END,
    PACKET_DOWNLOAD_NOTHING
};

#define DATA_SEG_START 0

using session_id_t = uint16_t;
using group_id_t = uint16_t;
using data_id_t = uint16_t;
using packet_type_t=uint8_t;

struct Packet {
    Packet():dnsTransactionId(0),sessionId(0),groupId(0),dataId(0),type(0),qr(0), source(ADDR_ZERO),dnsQueryType(TXT){}
    uint16_t dnsTransactionId;
    record_t dnsQueryType;
    session_id_t sessionId;
    group_id_t groupId;
    data_id_t dataId;
    packet_type_t type;
    uint8_t qr;
    SA_IN source;
    std::vector<Query> originalQueries;
    Bytes data;
    static int dnsRespToPacket(Packet& packet,const Dns& dns);
    static int packetToDnsResp(Dns& dns,uint16_t transactionId ,const Packet& packet);
    static int dnsQueryToPacket(Packet& packet,const Dns& dns, const std::vector<Bytes>& myDomain);
    static int packetToDnsQuery(Dns &dns, uint16_t transactionId,const Packet &packet , const std::vector<Bytes>& myDomain);
    static size_t
    dataToSingleQuery(Dns &dns, Packet &packet, BytesReader &br, uint16_t dnsTransactionId, record_t dnsQueryType,
                      session_id_t sessionId, group_id_t groupId, data_id_t dataId, packet_type_t type,
                      const std::vector<Bytes> &myDomain);
    std::string toString() const;
    static int authentication(Dns &dns, Packet &packet, const char *userId, const std::vector<Bytes> &myDomain);
    static void
    poll(Dns &dns, Packet &packet, const std::vector<Bytes> &myDomain, session_id_t sessionId, group_id_t groupId = 0,
         data_id_t dataId = 0);
    Packet getResponsePacket(packet_t type, group_id_t groupId, data_id_t dataId) const ;
    Packet getResponsePacket(packet_t type) const ;
private:
    static const size_t BUF_SIZE;

};

struct AggregatedPacket{
    Bytes data;
};

struct DataSegment{
    Dns dns;
    Packet packet;
    DataSegment(Dns&& dns_,Packet&& packet_) : dns(dns_) , packet(packet_){}
    DataSegment()=default;
};

struct PacketGroup {
    std::vector<DataSegment> segments;
    group_id_t groupId;
    PacketGroup(group_id_t groupId_=0){groupId=groupId_;}
};


PacketGroup
disaggregateToQueryPacketGroup(const AggregatedPacket &aggregatedPacket, session_id_t sessionId, group_id_t groupId,
                               record_t recordType, uint8_t packetType, const std::vector<Bytes> &myDomain);

record_t randRecordType();
#endif
