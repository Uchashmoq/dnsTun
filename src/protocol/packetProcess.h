#ifndef DNSTUN_PACKETPROCESS_H
#define DNSTUN_PACKETPROCESS_H
#include "Log.h"
#include "udp.h"
#include "Packet.h"
#include <vector>
#include "BlockingQueue.hpp"
namespace ucsmq{
    AggregatedPacket aggregatePackets(const std::vector<Packet>& packets);
    void newPacketGroup(uint16_t& groupId, uint16_t& dataId, Packet& packetDown, std::vector<Packet>& packets);
    bool verifyPacket(const Packet& packetResp , group_id_t groupId ,data_id_t dataId);
    int packetGroupAdd(uint16_t& groupId, uint16_t& dataId, Packet& packetDown, std:: vector<Packet>& packets);
    void exportPackets(BlockingQueue<AggregatedPacket>& buffer,std::vector<Packet>& packets,uint16_t& groupId, uint16_t& dataId);
}

#endif //DNSTUN_PACKETPROCESS_H
