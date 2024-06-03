#ifndef DNSTUN_DISCARDCLIENT_H
#define DNSTUN_DISCARDCLIENT_H

#include <cassert>
#include "DnsClientChannel.h"
#include <functional>
#include <memory>
#include <iostream>
class DiscardClient{
    std::string myDomain;
    std::string userId;
    SA_IN serverAddr;
public:
    DiscardClient(const SA_IN& serverAddr_,const std::string& myDomain_,const std::string& userId_):
            serverAddr(serverAddr_),myDomain(myDomain_),userId(userId_){}
    void launch(std::istream* in=&std::cin){
        using namespace std;
        ucsmq::DnsClientChannel dcc(serverAddr,myDomain.c_str(),userId.c_str());
        assert(dcc.open()>0);
        while (true){
            Bytes recvBuf;
            if(dcc.read(recvBuf)<0) break;
            std::cout<<"from server "<<dcc.name<<" : "<<(std::string)recvBuf<<std::endl;
            if(recvBuf=="c.") break;
        }
        dcc.close();
    }
};



#endif //DNSTUN_DISCARDCLIENT_H
