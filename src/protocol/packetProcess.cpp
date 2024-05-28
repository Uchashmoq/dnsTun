#include "packetProcess.h"
AggregatedPacket aggregatePackets(const std::vector<Packet>& packets){
    AggregatedPacket aggregatedPacket;
    for(const auto & packet : packets){
        aggregatedPacket.data+=packet.data;
    }
    return std::move(aggregatedPacket);
}


void newPacketGroup(uint16_t& groupId, uint16_t& dataId, Packet& packetDown, std::vector<Packet>& packets){
    if(packets.empty()){
        groupId=packetDown.groupId;
        dataId++;
        packets.push_back(std::move(packetDown));
    }
}

bool verifyPacket(const Packet& packetResp , uint16_t groupId ,uint16_t dataId){
    if(packetResp.groupId!=groupId){
        Log::printf(LOG_ERROR, "unexpected group id ,got %u,expected %u",packetResp.groupId,groupId);
        return false;
    }
    if(packetResp.dataId!=dataId){
        Log::printf(LOG_DEBUG,"received packet ,data id : %u ",packetResp.dataId);
        return false;
    }
    return true;
}

int packetGroupAdd(uint16_t& groupId, uint16_t& dataId, Packet& packetDown, std:: vector<Packet>& packets){
    if(verifyPacket(packetDown,groupId,dataId)){
        packets.push_back(std::move(packetDown));
        dataId++;
        return 1;
    }
    return -1;
}

void exportPackets(BlockingQueue<AggregatedPacket>& buffer,std::vector<Packet>& packets,uint16_t& groupId, uint16_t& dataId){
    buffer.push(aggregatePackets(packets));
    packets.clear();
    dataId=DATA_SEG_START;
}

