#include "Dns.h"
#include "Log.h"
#include <unordered_map>
#include <iostream>
using namespace std;
namespace ucsmq{
    /*
 * for example 'C0 0C is a domain pointer'
 * In DNS domain compression, C0 0C (hexadecimal notation) represents a specific pointer used for compression. Let's break down its meaning:
 *
 *  Understanding the format:
 *
 *  A pointer in DNS compression is a single byte value.
 *  The two most significant bits (leftmost) indicate whether it's a pointer (11 for pointer, 00 for normal label).
 *  The remaining 6 bits (rightmost) represent the actual offset value.
 *  Decoding C0 0C:
 *
 *  Binary representation: 11000000 00001100
 *  The first two bits (11) confirm it's a pointer.
 *  The remaining 6 bits (00001100) translate to decimal 12.
 *  Interpretation:
 *
 *  Therefore, C0 0C signifies a pointer with an offset value of 12. This value points back to a previously encountered domain name segment within the current DNS message.
 * */
    static bool isDomainPointer(uint8_t * p , uint16_t * offset){
        uint16_t k= *(uint16_t*)p;
        reverseBytes(&k, sizeof(k));
        if( k >>14==3){
            if(offset!= nullptr) {
                *offset = k & 0x3fff;
            }
            return true;
        }else{
            return false;
        }
    }
    /*
     * read labeled data . The domain name, and the data will be in this form <len0> [b0] [b1] [b2]... <len1> [b0] [b1] [b2]...
     *
     * for example  '07  77 61 70 70 61 73 73      05  62 61 69 64 75    03  63 6f 6d' (wappass.baidu.com)
     *
     * labeledData : result, {77 61 70 70 61 73 73} , {62 61 69 64 75} , {63 6f 6d}
     *
     * p: the start of labeled data : 07
     *
     * start: The beginning of the dns request, when encountering dns domain compression, you need to use start+offset to locate the real domain name
     *
     * end: End of dns request to prevent illegal memory accesses
     *
     * expand:The total size of the data, in the above example, expand=18 . When encountering dns domain compression, expand will be the size of the original domain name
     * */
    static size_t readLabeledData(vector<Bytes>& labeledData, uint8_t* p, const void* start , uint8_t* end, size_t* expand){
        uint16_t offset,skip=0;
        uint8_t len;
        if(*p==0) return 1;
        if(end-p< sizeof(offset)) throw DNSResolutionException("resolve dns exception : locate domain pointer error");
        //判断是否是域名指针，如果是，获取偏移
        if(isDomainPointer(p,&offset)){
            readLabeledData(labeledData, (uint8_t *) start + offset, start, end, expand);
            return 2;
            //dns requests where the domain name ends with a domain pointer do not need the last character to be '\0'
        }
        uint8_t *p0=p;
        while (p<end && *p!=0){
            if(end-p< sizeof(len)+1) throw DNSResolutionException("resolve dns exception : read domain");
            if(isDomainPointer(p,&offset)){
                readLabeledData(labeledData, (uint8_t *) start + offset, start, end, expand);
                p+=2;
                skip=0;
                break;
            }else{
                len=*(uint8_t*)p;
                p++;
                if(expand!= nullptr) (*expand)++;
                if(end-p<len) throw DNSResolutionException("resolve dns exception : read domain");
                labeledData.emplace_back(p,len);
                p+=len;
                if(expand!= nullptr) *expand+=len;
                skip=1;
                //should skip '\0' in the end
            }
        }
        if(expand!= nullptr) *expand+=skip-((p==end)&skip);
        return p-p0+skip-((p==end)&skip);
    }

    static uint8_t * readField(void* dst,uint8_t* p ,size_t size ,uint8_t *end){
        if(end-p<size) throw DNSResolutionException("resolve dns exception : read field error");
        memcpy(dst,p,size);
        reverseBytes(dst,size);
        return p+size;
    }
    void Dns::getFlags(int *pQR, int *pOPCODE, int *pAA, int *pTC, int *pRD, int *pRA,int* pZ, int *pRCODE) const {
        uint16_t b=flags;
#define GET_ITEM(o)  if(p ## o!= nullptr) *p ## o = (b & o ## _MASK) >> o ## _SHIFT
        GET_ITEM(QR);
        GET_ITEM(OPCODE);
        GET_ITEM(AA);
        GET_ITEM(TC);
        GET_ITEM(RD);
        GET_ITEM(RA);
        GET_ITEM(Z);
        GET_ITEM(RCODE);
#undef GET_ITEM
    }
    string flagsStr(const Dns& d){
        int QR=0,OPCODE=0,AA=0,TC=0,RD=0,RA=0,RCODE=0;
        char buf[128];
        d.getFlags(&QR,&OPCODE,&AA,&TC,&RD,&RA, nullptr,&RCODE);
        sprintf(buf,"QR=%d,OPCODE=%d,AA=%d,TC=%d,RD=%d,RA=%d,RCODE=%d\n",
                QR,OPCODE,AA,TC,RD,RA,RCODE
        );
        return buf;
    }
    Dns& Dns::setFlag(int mask,int value){
#define GET_SHIFT(m) case m ## _MASK : \
    shift = m ## _SHIFT;break
        uint16_t shift;
        switch (mask) {
            GET_SHIFT(QR);
            GET_SHIFT(OPCODE);
            GET_SHIFT(AA);
            GET_SHIFT(TC);
            GET_SHIFT(RD);
            GET_SHIFT(RA);
            GET_SHIFT(Z);
            GET_SHIFT(RCODE);
            default:
                return *this;
        }
        flags |= (value<<shift) & mask;
        return *this;
    }
/*
 * Parses the dns data into a dns structure and returns a negative number if it fails.
 * */
    ssize_t Dns::resolve(Dns &dns, const void *buf, size_t size) {
        uint8_t * p=(uint8_t *)buf;//数据开头
        uint8_t * end = p+size;//数据末尾
        try{
            //读取整数字段,并将指针p后移
            p =  readField(&dns.transactionId , p , sizeof(transactionId) ,end);
            p =  readField(&dns.flags , p , sizeof(flags) ,end);
            p =  readField(&dns.questions , p , sizeof(questions) ,end);
            p =  readField(&dns.answerRRs , p , sizeof(answerRRs) ,end);
            p =  readField(&dns.authorityRRs , p , sizeof(authorityRRs) ,end);
            p =  readField(&dns.additionalRRs, p , sizeof(additionalRRs) ,end);

            for(uint16_t i=0;i<dns.questions;i++){
                Query q;
                //读取带标签的数据，并将p后移
                p+= readLabeledData(q.question, p, buf, end, nullptr);
                p = readField(&q.queryType,p, sizeof(q.queryType),end);
                p= readField(&q.queryClass,p, sizeof(q.queryClass),end);
                dns.queries.push_back(move(q));
            }
#define CHECK_DATA_LEN(len) do{if(end-p<len-1) throw DNSResolutionException("resolve dns exception : dataLen error :"+ to_string(len));}while(0)
            for(uint16_t i=0;i<dns.answerRRs;i++){
                Answer a;
                p+= readLabeledData(a.name, p, buf, end, nullptr);
                p= readField(&a.ansType,p, sizeof(a.ansType),end);
                p= readField(&a.ansClass,p, sizeof(a.ansClass),end);
                p = readField(&a.ttl,p, sizeof(a.ttl),end);
                p= readField(&a.dataLen,p, sizeof(a.dataLen),end);
                CHECK_DATA_LEN(a.dataLen);
                size_t expand=0;
                switch (a.ansType) {
                    case A:case AAAA:
                        if(end-p<a.dataLen) throw DNSResolutionException("data length exception :"+to_string(a.dataLen));
                        a.data.emplace_back(p,a.dataLen);
                        p+=a.dataLen;
                        break;
                    case NS: case CNAME: case TXT :case PTR:
                        p+= readLabeledData(a.data, p, buf, p + a.dataLen, &expand);
                        a.dataLen=expand;
                        break;
                    case MX:
                        a.data.emplace_back(p, sizeof(uint16_t));
                        p+= sizeof(uint16_t);
                        p+= readLabeledData(a.data, p, buf, p, &expand);
                        a.dataLen=expand;
                        break;
                    default:
                        if(end-p<a.dataLen) throw DNSResolutionException("data length exception :"+to_string(a.dataLen));
                        a.data.emplace_back(p,a.dataLen);
                        p+=a.dataLen;
                }
                dns.answers.push_back(move(a));
            }

            for(uint16_t i=0;i<dns.authorityRRs;i++){
                Nameserver ns;
                p+= readLabeledData(ns.name, p, buf, end, nullptr);
                p= readField(&ns.nsType,p, sizeof(ns.nsType),end);
                p= readField(&ns.nsClass, p,sizeof(ns.nsClass),end);
                p= readField(&ns.ttl,p, sizeof(ns.ttl),end);
                p= readField(&ns.dataLen,p, sizeof(ns.dataLen),end);
                CHECK_DATA_LEN(ns.dataLen);
                ns.data=Bytes(p,ns.dataLen);
                p+=ns.dataLen;
                dns.nameservers.push_back(move(ns));
            }
            for(uint16_t i=0;i<dns.additionalRRs;i++){
                Additional a;
                p+= readLabeledData(a.name, p, buf, end, nullptr);
                p= readField(&a.addType,p, sizeof(a.addType),end);
                p= readField(&a.addClass,p, sizeof(a.addClass),end);
                p = readField(&a.ttl,p, sizeof(a.ttl),end);
                p= readField(&a.dataLen,p, sizeof(a.dataLen),end);
                CHECK_DATA_LEN(a.dataLen);
                size_t expand=0;
                switch (a.addType) {
                    case A:case AAAA:
                        if(end-p<a.dataLen) throw DNSResolutionException("data length exception :"+to_string(a.dataLen));
                        a.data.emplace_back(p,a.dataLen);
                        p+=a.dataLen;
                        break;
                    case NS: case CNAME: case TXT: case PTR:
                        p+= readLabeledData(a.data, p, buf, p + a.dataLen, &expand);
                        a.dataLen=expand;
                        break;
                    case MX:
                        a.data.emplace_back(p, sizeof(uint16_t));
                        p+= sizeof(uint16_t);
                        p+= readLabeledData(a.data, p, buf, p, &expand);
                        a.dataLen=expand;
                        break;
                    default:
                        if(end-p<a.dataLen) throw DNSResolutionException("data length exception :"+to_string(a.dataLen));
                        a.data.emplace_back(p,a.dataLen);
                        p+=a.dataLen;
                }
                dns.additions.push_back(move(a));
            }
        }catch (DNSResolutionException& e){
            Log::printf(LOG_ERROR,"%s : %s",__FUNCTION__ ,e.what());
            return (uint8_t*)buf-p;
        }
        return p-(uint8_t*)buf;
    }

    using CompressMap = unordered_map<SimpleBytes,uint16_t ,SimpleBytes::HashCode,SimpleBytes::Equals>;

    void writeDomainPointer(BytesWriter& bw, uint16_t prevDomainOffset) {
        uint16_t pos=0xc000u;
        pos|=prevDomainOffset;
        bw.writeNum(pos);
    }

    bool compressDomain(uint8_t* start, size_t n, uint16_t offset, BytesWriter& bw, CompressMap& cmap){
        SimpleBytes domain(start,n);
        auto prevDomain = cmap.find(domain);
        if(prevDomain==cmap.end()) {
            cmap.insert(make_pair(domain,offset));
            return false;
        }
        auto prevDomainOffset = prevDomain->second;
        writeDomainPointer(bw.jmp(offset),prevDomainOffset);
        return true;
    }

    template<class IT>
    static size_t writeLabeledData(BytesWriter& bw,IT begin,IT end,bool append0,CompressMap& cmap){
        auto n0 = bw.writen();
        auto p0= bw.writep();
        for(auto it=begin;it!=end;++it ){
            if(it->size>MAX_LABEL_LEN) Log::printf(LOG_WARN,"length of label exceeds : %u",it->size);
            bw.writeNum((uint8_t)it->size);
            bw.writeBytes(*it);
        }
        if(append0) bw.writeNum((uint8_t)0);
        size_t n = bw.writen()-n0;
        if(compressDomain(p0,n,n0,bw,cmap)){
            return 2;
        }else{
            return n;
        }
    }

    ssize_t Dns::bytes(const Dns &dns, void *buf, size_t size) {
        CompressMap cmap;
        BytesWriter bw(buf,size);
        bw.writeNum(dns.transactionId);
        bw.writeNum(dns.flags);
        bw.writeNum(dns.questions);
        bw.writeNum(dns.answerRRs);
        bw.writeNum(dns.authorityRRs);
        bw.writeNum(dns.additionalRRs);

        for(auto& q : dns.queries){
            writeLabeledData(bw,q.question.begin(),q.question.end(), true,cmap);
            bw.writeNum(q.queryType);
            bw.writeNum(q.queryClass);
        }

        for(auto& ans : dns.answers){
            writeLabeledData(bw,ans.name.begin(),ans.name.end(), true,cmap);
            bw.writeNum(ans.ansType);
            bw.writeNum(ans.ansClass);
            bw.writeNum(ans.ttl);
            bw.writeNum(ans.dataLen);
            if(USE_LABEL(ans.ansType)){
                if(ans.ansType==MX){
                    bw.writeBytes(ans.data.front());
                }
                writeLabeledData(bw,ans.data.begin()+(ans.ansType==MX),ans.data.end(), DATA_SHOULD_APPEND0(ans.ansType),cmap);
            }else{
                bw.writeBytes(ans.data.front());
            }
        }

        for(auto& ns : dns.nameservers){
            writeLabeledData(bw,ns.name.begin(),ns.name.end(), true,cmap);
            bw.writeNum(ns.nsType);
            bw.writeNum(ns.nsClass);
            bw.writeNum(ns.ttl);
            bw.writeNum(ns.dataLen);
            bw.writeBytes(ns.data);
        }

        for(auto& add : dns.additions){
            writeLabeledData(bw,add.name.begin(),add.name.end(), true,cmap);
            bw.writeNum(add.addType);
            bw.writeNum(add.addClass);
            bw.writeNum(add.ttl);
            bw.writeNum(add.dataLen);

            if(USE_LABEL(add.addType)){
                if(add.addType==MX){
                    bw.writeBytes(add.data.front());
                }
                writeLabeledData(bw,add.data.begin()+(add.addType==MX)
                                 ,add.data.end(), DATA_SHOULD_APPEND0(add.addType),cmap);
            }else{
                bw.writeBytes(add.data.front());
            }
        }
        return bw.writen();
    }

    template<class IT>
    static string domainStr(IT begin,IT end){
        stringstream ss;
        int flag=0;
        for(auto it=begin;it!=end;++it){
            if(flag++) ss<<".";
            ss<<(string)*it;
        }
        return ss.str();
    }
    static string ipv4Str(void *p) {
        uint8_t * ip = (uint8_t*)p;
        return to_string(ip[0])+"."+to_string(ip[1])+"."+to_string(ip[2])+"."+to_string(ip[3]);
    }
    static string ipv6Str(void* p){
        uint16_t *ip=(uint16_t*)p;
        string ans = to_string(ip[0]);
        for(int i=1;i<8;i++){
            ans.append(":").append(to_string(ip[i]));
        }
        return ans;
    }
    string Query::toString() const {
        stringstream ss;
        ss<<"question: "<<domainStr(question.begin(),question.end())<<endl;
        ss<<"type: "<<queryType<<endl;
        ss<<"class: "<<queryClass<<endl;
        return ss.str();
    }

    string Answer::toString() const {
        stringstream ss;
        ss<<"name: "<<domainStr(name.begin(),name.end())<<endl;
        ss<<"type: "<<ansType<<endl;
        ss<<"class: "<<ansClass<<endl;
        ss<<"ttl: "<<ttl<<endl;
        ss<<"length: "<<dataLen<<endl;
        ss<<"data :";
        switch (ansType) {
            case A:
                ss<<ipv4Str(data[0].data)<<endl;
                break;
            case AAAA:
                ss<<ipv6Str(data[0].data)<<endl;
                break;
            case NS: case CNAME: case TXT:case PTR:
                ss<< domainStr(data.begin(),data.end())<<endl;
                break;
            case MX:
                ss<<"preference: "<<to_string(*(uint16_t*)data[0].data)<<endl;
                ss<<domainStr(data.begin()+1,data.end())<<endl;
                break;
            default:
                ss<<"other "<<endl;
        }
        return ss.str();
    }
    string Nameserver::toString() const{
        stringstream ss;
        ss<<"name: "<<domainStr(name.begin(),name.end())<<endl;
        ss<<"type: "<<nsType<<endl;
        ss<<"class: "<<nsClass<<endl;
        ss<<"ttl: "<<ttl<<endl;
        ss<<"length: "<<dataLen<<endl;
        ss<<"data :"<<data.hexStr()<<endl;
        return ss.str();
    }
    string Dns::toString() const {
        stringstream ss;
        char tmp[1024];
        sprintf(tmp,"transactionId: %u\nflags: %u (%s)\nquestions: %u\nansRRs: %u\nauthRRs: %u\naddRRs: %u\n"
                ,transactionId,flags, flagsStr(*this).c_str(),questions,answerRRs,authorityRRs,additionalRRs);
        ss<<tmp;
        int qn=1,an=1,aun=1,adn=1;
        for(auto& q : queries){
            ss<<"query :"<<qn++<<endl;
            ss<<q.toString()<<endl;
        }
        ss<<endl;
        for(auto& a : answers){
            ss<<"answer :"<<an++<<endl;
            ss<<a.toString()<<endl;
        }
        ss<<endl;
        for(auto& a : nameservers){
            ss<<"authoritative nameserver :"<<aun++<<endl;
            ss<<a.toString()<<endl;
        }
        ss<<endl;
        for(auto& a : additions){
            ss<<"addition: "<<adn++<<endl;
            ss<<a.toString()<<endl;
        }
        ss<<endl;
        return ss.str();
    }
    string Additional::toString() const {
        stringstream ss;
        ss<<"name: "<<domainStr(name.begin(),name.end())<<endl;
        ss<<"type: "<<addType<<endl;
        ss<<"class: "<<addClass<<endl;
        ss<<"ttl: "<<ttl<<endl;
        ss<<"length: "<<dataLen<<endl;
        ss<<"data :";
        switch (addType) {
            case A:
                ss<<ipv4Str(data[0].data)<<endl;
                break;
            case AAAA:
                ss<<ipv6Str(data[0].data)<<endl;
                break;
            case NS: case CNAME: case TXT: case PTR:
                ss<< domainStr(data.begin(),data.end())<<endl;
                break;
            case MX:
                ss<<"preference: "<<to_string(*(uint16_t*)data[0].data)<<endl;
                ss<<domainStr(data.begin()+1,data.end())<<endl;
                break;
            default:
                ss<<"other "<<endl;
        }
        return ss.str();
    }
}
