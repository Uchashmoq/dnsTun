#ifndef DNS_DNS_H
#define DNS_DNS_H
#include "../lib/Bytes.hpp"
#include "net.h"
#include <vector>
#include <memory>

#define QR_MASK     0x8000  // 查询/响应标志
#define OPCODE_MASK 0x7800  // 操作码
#define AA_MASK     0x0400  // 授权回答标志
#define TC_MASK     0x0200  // 截断标志
#define RD_MASK     0x0100  // 期望递归标志
#define RA_MASK     0x0080  // 可用递归标志
#define Z_MASK      0x0070  // 保留字段（必须为0）
#define RCODE_MASK  0x000F  // 响应码

#define QR_SHIFT     15
#define OPCODE_SHIFT 11
#define AA_SHIFT     10
#define TC_SHIFT     9
#define RD_SHIFT     8
#define RA_SHIFT     7
#define Z_SHIFT      4
#define RCODE_SHIFT  0

/*
0: No Error - The query was successful.
1: Format Error - The query was not formatted correctly.
2: Server Failure - The server encountered an internal error when processing the query.
3: Name Error - The domain name referenced in the query does not exist.
4: Not Implemented - The requested operation is not supported by the server.
5: Refused - The server refuses to process the query for some reason.
 * */
enum r_code_t {
    NO_ERR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
    NOT_IMPLEMENTED = 4,
    REFUSED = 5
};
enum record_t {
    A = 1,          // IPv4 地址查询
    AAAA = 28,      // IPv6 地址查询
    MX = 15,        // 邮件交换记录查询
    TXT = 16,       // 文本记录查询
    CNAME = 5,      // 别名记录查询
    NS = 2,         // 域名服务器记录查询
    PTR = 12,       // 指针记录查询
    SOA = 6,        // 起始授权机构记录查询
    SRV = 33,       // 服务记录查询
    NSEC=47,
    AXFR=252,   //传输整个区的请求
    ANY = 255       // 任意类型查询
};

#define DNS_QUERY 0
#define DNS_RESP 1

#define IS_IP(ty) (ty==A || ty==AAAA)
#define IS_SUPPORTED_RECORD(t) ( t==A||t==AAAA||t==NS||t==CNAME||t==TXT||t==PTR)
#define USE_LABEL(t) (t==NS||t==CNAME||t==TXT||t==PTR)
#define MAX_LABEL_LEN 60
#define MAX_TOTAL_DOMAIN_LEN 245
#define DATA_SHOULD_APPEND0(t) (!IS_IP(t) && t!=TXT)
class DNSResolutionException : public std::exception {
private:
    std::string message;
public:
    DNSResolutionException(const std::string& msg) : message(msg) {}
    virtual const char* what() const noexcept {
        return message.c_str();
    }
};

struct Query {
    std::vector<Bytes> question;
    uint16_t queryType;
    uint16_t queryClass;
    Query():queryType(ANY),queryClass(1){}
    std::string toString() const;
};
struct Answer {
    std::vector<Bytes> name;
    uint16_t ansType;
    uint16_t ansClass;
    uint32_t ttl;
    uint16_t dataLen;
    std::vector<Bytes> data;
    Answer() : ansType(ANY) , ansClass(1) ,dataLen (0){}
    std::string toString() const;
};
struct Nameserver {
    std::vector<Bytes> name;
    uint16_t nsType;
    uint16_t nsClass;
    uint32_t ttl;
    uint16_t dataLen;
    Bytes data;
    Nameserver() : nsType(ANY) , nsClass(1), ttl(0),dataLen(0){};
    std::string toString() const;
};
struct Additional{
    std::vector<Bytes> name;
    uint16_t addType;
    uint16_t addClass;
    uint32_t ttl;
    uint16_t dataLen;
    std::vector<Bytes> data;
    Additional() : addType(ANY) , addClass(1),ttl(0),dataLen(0){}
    std::string toString() const;
};
struct Dns {
    Dns() : transactionId(0),flags(0),questions(0),answerRRs(0),authorityRRs(0),additionalRRs(0), source(ADDR_ZERO){}
    //Convert binary data to dns structure
    static ssize_t resolve(Dns& dns,const void *buf, size_t size);
    //Convert dns structure to binary data
    static ssize_t bytes(const Dns& dns,void* buf,size_t size);
    void getFlags (int *pQR, int *pOPCODE, int *pAA, int *pTC, int *pRD, int *pRA,int* pZ, int *pRCODE) const ;
    Dns &setFlag(int flag, int value);
    //for debugging
    std::string toString() const;

    SA_IN source;
    uint16_t transactionId;
    uint16_t flags;
    uint16_t questions;
    uint16_t answerRRs;
    uint16_t authorityRRs;
    uint16_t additionalRRs;
    std::vector<Query> queries;
    std::vector<Answer> answers;
    //Do not focus on this field : nameservers
    std::vector<Nameserver> nameservers;
    std::vector<Additional> additions;

};
std::string flagsStr(const Dns& d);
#endif
