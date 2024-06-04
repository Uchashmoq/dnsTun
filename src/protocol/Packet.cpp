#include "Packet.h"
#include "../lib/base36.h"
#include <algorithm>
#include "Log.h"
#include <cmath>
#include <cstdlib>
#define MAX_UNENCODED_DATA_LEN_OF_LABEL (MAX_LABEL_LEN/2 -3)
#define MAX_ANSWER 5

using namespace std;
namespace ucsmq{
    const size_t Packet::BUF_SIZE=1024*16;
    const uint32_t maxTTL=300;
    const ::uint32_t  minTTL=20;

    struct Payload_{
        uint8_t* hpDecoded;
        size_t len;
        Payload_(): hpDecoded(nullptr), len(0){}
        bool operator<(const Payload_& other ) const{
            return hpDecoded[0]<other.hpDecoded[0];
        }
        void destroy(){delete[] hpDecoded , len=0;}
    };

    static int randRange(int min,int max){
        return min + rand()%(max-min);
    }

    static bool getPayloadFromLabeledData(Payload_& pld , const vector<Bytes>& data, size_t maxLen){
        uint8_t *tmp = new uint8_t[maxLen];
        BytesWriter bw(tmp,maxLen);
        for(auto& b : data){
            bw.writeBytes(b);
        }
        uint8_t* decoded = new uint8_t [maxLen/2+16];
        auto n = base36decode(decoded,tmp,bw.writen());
        delete[] tmp;
        if(n<0){
            delete[] decoded;
            decoded= nullptr;
            Log::printf(LOG_DEBUG,"fail to base36 decode from data");
            return false;
        }
        pld.hpDecoded=decoded;
        pld.len=(size_t)n;
        return true;
    }

    static void clearPayloads(vector<Payload_>& payloads){
        for(auto& p : payloads){
            p.destroy();
        }
    }

    static size_t splicePayloads(uint8_t* buf,size_t len,const vector<Payload_>& payloads){

        BytesWriter bw(buf,len);
        for(auto& pld : payloads){
            if(pld.len>0){
                bw.writeBytes(pld.hpDecoded+1,pld.len-1);
            }
        }
        return bw.writen();
    }

    static size_t splicePayloads(BytesWriter& bw,const vector<Payload_>& payloads){
        auto n0=bw.writen();
        for(auto& pld : payloads){
            if(pld.len>0){
                bw.writeBytes(pld.hpDecoded+1,pld.len-1);
            }
        }
        return bw.writen()-n0;
    }

    static ssize_t getPayloadFromAnswers(BytesWriter &bw, const vector<Answer> &answers) {
        vector<Payload_> payloads;
        ssize_t n=-1;
        for(const auto& ans : answers){
            if(USE_LABEL(ans.ansType)){
                Payload_ payload;
                if(getPayloadFromLabeledData(payload,ans.data,bw.writableBytes())){
                    payloads.push_back(payload);
                }else{
                    goto clear;
                }
            }
        }
        sort(payloads.begin(),payloads.end());
        n=splicePayloads(bw,payloads);
        clear:
        clearPayloads(payloads);
        return n;
    }
    static ssize_t getPayloadFromAdditional(BytesWriter& bw,const vector<Additional>& additional){
        vector<Payload_> payloads;
        ssize_t n=-1;
        for(const auto& add : additional){
            if(USE_LABEL(add.addType)){
                Payload_ payloadInName;
                if(getPayloadFromLabeledData(payloadInName,add.name,bw.writableBytes())){
                    payloads.push_back(payloadInName);
                }else{
                    goto clear;
                }
                Payload_ payloadInData;
                if(getPayloadFromLabeledData(payloadInData,add.data,bw.writableBytes())){
                    payloads.push_back(payloadInData);
                }else{
                    goto clear;
                }
            }
        }
        sort(payloads.begin(),payloads.end());
        n=splicePayloads(bw,payloads);
        clear:
        clearPayloads(payloads);
        return n;
    }

    static void writePacketHead(BytesWriter& bw,const Packet& packet){
        bw.writeNum(packet.sessionId);
        bw.writeNum(packet.groupId);
        bw.writeNum(packet.dataId);
        bw.writeNum(packet.type);
    }

    static int readPacketHead(Packet& packet,BytesReader& br){
        if(br.readableBytes()<sizeof(session_id_t)){
            Log::printf(LOG_DEBUG,"readPacketHead: payload session id missing");
            return -1;
        }
        packet.sessionId=br.readNum<session_id_t>();

        if(br.readableBytes()<sizeof(group_id_t)){
            Log::printf(LOG_DEBUG,"readPacketHead: payload group id missing");
            return -1;
        }
        packet.groupId=br.readNum<group_id_t>();

        if(br.readableBytes()<sizeof(data_id_t)){
            Log::printf(LOG_DEBUG,"readPacketHead: payload data id missing");
            return -1;
        }
        packet.dataId=br.readNum<data_id_t>();

        if(br.readableBytes()<sizeof(packet_type_t)){
            Log::printf(LOG_DEBUG,"readPacketHead: payload type missing");
            return -1;
        }
        packet.type=br.readNum<packet_type_t>();
        return 0;
    }

    int Packet::dnsRespToPacket(Packet &packet, const Dns &dns) {
        int qr , rCode;
        dns.getFlags(&qr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,&rCode);
        if(rCode!=NO_ERR) {
            Log::printf(LOG_DEBUG,"dns has error:\n%s",dns.toString().c_str());
            return -1;
        }
        if(qr!=DNS_RESP) {
            Log::printf(LOG_DEBUG,"in function dnsRespToPacket , qr is not a dns response:\n%s",dns.toString().c_str());
            return -1;
        }
        packet.qr=qr;
        packet.dnsTransactionId=dns.transactionId;
        uint8_t payload[BUF_SIZE];
        BytesWriter bw(payload, sizeof(payload));
        auto payloadLen  = getPayloadFromAnswers(bw,dns.answers);
        if (payloadLen<0) return -1;

        BytesReader br(payload,payloadLen);
        if(readPacketHead(packet,br)<0){
            return -1;
        }
        packet.data=br.readBytes(br.readableBytes());
        return 0;
    }

    static size_t domainLen(const vector<Bytes>& domain){
        size_t n=0;
        for(auto& b : domain){
            n+=b.size+1;
        }
        return n;
    }

    static uint8_t randLabelSize(){
        const uint8_t base = 5;
        return (uint8_t)(base+1+abs(rand()) % (MAX_UNENCODED_DATA_LEN_OF_LABEL-base));
    }

    record_t randRecordType(){
#if 1
        const static record_t t[]={TXT};
        const static auto n = sizeof(t)/sizeof(t[0]);
         return  t[::rand()%n];
#else
        return TXT;
#endif
    }

    static Query writeToQuery(Readable& br ,record_t qType,const vector<Bytes>& domain,uint8_t cnt){
        uint8_t encodedPayload[1024], payload[512] , n =0,dlen = domainLen(domain) ,len ;
        Query q;
        q.queryType=qType;
        BytesWriter bw(payload,sizeof(payload));
        bw.writeNum(cnt);
        while(br.readableBytes()>0){
            len = randLabelSize();
            if(len*2+n+dlen>=MAX_TOTAL_DOMAIN_LEN) break;
            copy(bw,br,len);
            auto encodedN = base36encode(encodedPayload,payload,bw.writen());
            q.question.emplace_back(encodedPayload,encodedN);
            n+=encodedN;
            bw.jmp();
        }
        if(q.question.empty()){
            Log::printf(LOG_WARN, "write empty data to a query");
        }
        for(auto& b : domain){
            q.question.push_back(b);
        }
        return move(q);
    }

    static size_t writeToLabeledData(BytesReader& br,uint8_t cnt, vector<Bytes>& dst,size_t maxLen,bool append0){
        uint8_t encodedPayload[1024],payload[512],len,n=0;
        BytesWriter bw(payload,sizeof(payload));
        bw.writeNum(cnt);
        while(br.readableBytes()>0){
            len = randLabelSize();
            if(len*2+n>=maxLen) break;
            copy(bw,br,len);
            auto encodedN = base36encode(encodedPayload,payload,bw.writen());
            dst.emplace_back(encodedPayload,encodedN);
            n+=encodedN+1;
            bw.jmp();
        }
        if(append0&&n>0) n++;
        return n;
    }


    int Packet::packetToDnsQuery(Dns &dns, uint16_t transactionId,const Packet &packet , const vector<Bytes>& domain) {
        uint8_t unencoded[BUF_SIZE];
        dns.transactionId=transactionId;
        BytesWriter bw(unencoded, sizeof(unencoded));
        writePacketHead(bw,packet);
        bw.writeBytes(packet.data);
        dns.setFlag(QR_MASK,DNS_QUERY);
        dns.setFlag(RD_MASK,1);
        BytesReader br(unencoded,bw.writen());
        while(br.readableBytes()>0){
            dns.queries.push_back(writeToQuery(br,packet.dnsQueryType,domain,(uint8_t)(++dns.questions)));
        }
        return 0;
    }

    static uint32_t randTTL() {
        return randRange(minTTL,maxTTL);
    }

    static Answer writeToAnswer(BytesReader& br, const Query& originalQuery, uint8_t cnt){
        Answer a;
        a.ansType=originalQuery.queryType;
        a.ansClass=originalQuery.queryClass;
        a.ttl=randTTL();
        a.name=originalQuery.question;
        a.dataLen= writeToLabeledData(br,cnt,a.data,MAX_TOTAL_DOMAIN_LEN, DATA_SHOULD_APPEND0(a.ansType));

        return move(a);
    }

    static record_t randAdditionalType(){
        record_t t[]={NS,CNAME,TXT,PTR};
        return t[randRange(0,4)];
    }
#if 0
    static Additional writeToAdditional(BytesReader& br,uint8_t cnt){
    Additional a;
    a.addType=randAdditionalType();
    writeToLabeledData(br,cnt,a.name,MAX_TOTAL_DOMAIN_LEN, true);
    a.dataLen=writeToLabeledData(br,cnt+1,a.data,MAX_TOTAL_DOMAIN_LEN, DATA_SHOULD_APPEND0(a.addType));
    return move(a);
}
#endif
    int Packet::packetToDnsResp(Dns &dns,uint16_t transactionId ,const Packet &packet) {
        dns.transactionId=transactionId;
        dns.questions=packet.originalQueries.size();
        if(dns.questions==0){
            Log::printf(LOG_WARN,"dns response without original questions");
        }
        dns.queries=packet.originalQueries;
        dns.setFlag(QR_MASK,DNS_RESP);

        uint8_t unencoded[BUF_SIZE];
        BytesWriter bw(unencoded, sizeof(unencoded));
        writePacketHead(bw,packet);
        bw.writeBytes(packet.data);
        BytesReader br(unencoded,bw.writen());

        for(size_t i=0;i< br.readableBytes()>0 ;i++){
            if(i>=UINT8_MAX-1) Log::printf(LOG_WARN,"in packetToDnsResp, ansCnt exceeds range of uint8_t");
            dns.answers.push_back(writeToAnswer(br, packet.originalQueries.front(),i+1));
        }
        dns.answerRRs=dns.answers.size();

        return 0;
    }

    static bool cmpMyDomain(const vector<Bytes>& names,const vector<Bytes> &myDomain){
        size_t n1=names.size() , n2=myDomain.size();
        for(size_t i =0;i<n2;i++){
            if(names[n1-1-i] != myDomain[n2-1-i]) return false;
        }
        return true;
    }
    static int getPayloadFromQuery(Payload_& payload, const vector<Bytes>& names, const vector<Bytes> &myDomain){
        if(names.size()<=myDomain.size()) {
            Log::printf(LOG_DEBUG,"getPayloadFromQuery: query domain length exception in request");
            return -1;
        }
        if(!cmpMyDomain(names,myDomain)){
            Log::printf(LOG_WARN,"getPayloadFromQuery: parent domain error in query");
        }
        size_t endPos = names.size()-myDomain.size()  , dlen= domainLen(names);
        uint8_t * tmp=new uint8_t[dlen];
        BytesWriter bw(tmp,dlen);
        for(size_t i=0;i<endPos;i++){
            bw.writeBytes(names[i]);
        }
        uint8_t *decodedPayload=new uint8_t[dlen/2+16];
        auto decodeN = base36decode(decodedPayload, tmp, bw.writen());
        delete[] tmp;
        if(decodeN<0){
            delete[] decodedPayload;
            Log::printf(LOG_DEBUG,"getPayloadFromQuery: base36 decoding error");
            return -1;
        }
        payload.len=decodeN;
        payload.hpDecoded=decodedPayload;
        return 0;
    }

    static ssize_t getValuableQueryPayload(uint8_t* out,size_t size,const Dns& dns,const vector<Bytes> &myDomain){
        vector<Payload_> queryPayloads;
        ssize_t resultSize=0;

        for(auto& q : dns.queries){
            Payload_ payload;
            if(getPayloadFromQuery(payload,q.question,myDomain)<0){
                resultSize=-1;
                goto clear;
            }
            queryPayloads.push_back(payload);
        }
        sort(queryPayloads.begin(),queryPayloads.end());
        resultSize+= splicePayloads(out,size,queryPayloads);

        clear:
        clearPayloads(queryPayloads);
        return resultSize;
    }

    int Packet::dnsQueryToPacket(Packet &packet, const Dns &dns, const vector<Bytes> &myDomain) {
        int qr , rCode;
        dns.getFlags(&qr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,&rCode);
        if(rCode!=NO_ERR) {
            Log::printf(LOG_DEBUG,"dns has error");
            return -1;
        }
        if(qr!=DNS_QUERY) {
            Log::printf(LOG_DEBUG,"in function dnsRespToPacket , qr is not a dns response:\n%s",dns.toString().c_str());
            return -1;
        }
        packet.dnsTransactionId=dns.transactionId;
        packet.originalQueries=dns.queries;
        packet.qr=qr;
        uint8_t payload[BUF_SIZE];
        auto payloadLen  = getValuableQueryPayload(payload,sizeof(payload),dns,myDomain);
        if (payloadLen<0) return -1;

        BytesReader br(payload,payloadLen);
        readPacketHead(packet,br);
        packet.data=br.readBytes(br.readableBytes());
        return 0;
    }

    std::string Packet::toString() const {
        stringstream ss;
        ss<<"sessionId: "<<sessionId<<endl;
        ss<<"groupId: "<<groupId<<endl;
        ss<<"dataId: "<<dataId<<endl;
        ss<<"type: "<<(int)type<<endl;
        if(originalQueries.size()>0){
            cout<<"original queries from "<<sockaddr_inStr(source)<<": "<<endl;
            for(const auto & q : originalQueries){
                cout<<q.toString()<<endl;
            }
        }
        ss<<"data: "<<data.hexStr()<<endl;
        return ss.str();
    }

    size_t
    Packet::dataToSingleQuery(Dns &dns, Packet &packet, BytesReader &br, uint16_t dnsTransactionId, record_t dnsQueryType,
                              session_id_t sessionId, group_id_t groupId, data_id_t dataId, packet_type_t type,
                              const vector<Bytes> &myDomain) {
        dns.transactionId=dnsTransactionId;
        dns.setFlag(QR_MASK,DNS_QUERY);
        dns.setFlag(RD_MASK,1);

        packet.dnsTransactionId=dnsTransactionId;
        packet.sessionId=sessionId;
        packet.groupId=groupId;
        packet.dataId=dataId;
        packet.type=type;
        packet.dnsQueryType=dnsQueryType;

        uint8_t head[256];
        BytesWriter bw(head, sizeof(head));
        writePacketHead(bw,packet);
        BytesReader headBr(head,bw.writen());
        BytesReader packetBr=br;
        size_t n0=br.readn();
        MultiBytesReader mbr ={&headBr,&br};
        dns.queries.push_back(writeToQuery(mbr,dnsQueryType,myDomain,1));
        dns.questions=1;
        size_t d = br.readn()-n0;
        packet.data = Bytes(d);
        BytesWriter packetBw(packet.data);
        copy(packetBw,packetBr,d);
        return d;
    }

    int Packet::authentication(Dns &dns, Packet &packet, const char *userId, const vector<Bytes> &myDomain) {
        BytesReader br(userId);
        Packet::dataToSingleQuery(dns, packet, br, ::rand(), randRecordType(), packet.sessionId, 0, 0, PACKET_AUTHENTICATE, myDomain);
        return br.readableBytes()==0 ? 1 : -1;
    }

    void
    Packet::poll(Dns &dns, Packet &packet, const std::vector<Bytes> &myDomain, session_id_t sessionId, group_id_t groupId,
                 data_id_t dataId) {
        packet.sessionId=sessionId;
        packet.groupId=groupId;
        packet.dataId=dataId;
        packet.type=PACKET_POLL;
        packet.data=std::to_string((short)rand());
        Packet::packetToDnsQuery(dns,::rand(),packet,myDomain);
    }

    Packet Packet::getResponsePacket(packet_t type, group_id_t groupId, data_id_t dataId) const {
        Packet packet;
        packet.source=source;
        packet.type=type;
        packet.groupId=groupId;
        packet.dataId=dataId;
        packet.dnsTransactionId=dnsTransactionId;
        packet.originalQueries=originalQueries;
        return std::move(packet);
    }

    Packet Packet::getResponsePacket(packet_t type) const {
        return getResponsePacket(type,groupId,dataId);
    }



    PacketGroup
    disaggregateToQueryPacketGroup(const AggregatedPacket &aggregatedPacket, session_id_t sessionId, group_id_t groupId,
                                   record_t recordType, uint8_t packetType, const std::vector<Bytes> &myDomain) {
        PacketGroup group;
        BytesReader br (aggregatedPacket.data);
        uint16_t  dataId = DATA_SEG_START;
        while (br.readableBytes()>0 && dataId<UINT8_MAX){
            Dns dns;Packet packet;
            Packet::dataToSingleQuery(
                    dns, packet, br,
                    rand(), recordType, sessionId, groupId, dataId++, packetType,
                    myDomain
            );
            group.segments.emplace_back(std::move(dns),std::move(packet));
        }
        Dns endDns;Packet endPacket;
        endPacket.sessionId=sessionId;
        endPacket.dataId=dataId;
        endPacket.groupId=groupId;
        endPacket.dnsQueryType=recordType;
        endPacket.type=PACKET_GROUP_END;
        Packet::packetToDnsQuery(endDns,rand(),endPacket,myDomain);
        group.segments.emplace_back(std::move(endDns),std::move(endPacket));
        group.groupId=groupId;
        return std::move(group);
    }
}


