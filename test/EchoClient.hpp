#ifndef DNSTUN_ECHOCLIENT_HPP
#define DNSTUN_ECHOCLIENT_HPP
#include <cassert>
#include "DnsClientChannel.h"
#include <functional>
#include <memory>
#include <iostream>
class EchoClient{
    std::string myDomain;
    std::string userId;
    SA_IN serverAddr;
public:
    EchoClient(const SA_IN& serverAddr_,const std::string& myDomain_,const std::string& userId_):
            serverAddr(serverAddr_),myDomain(myDomain_),userId(userId_){}
   void launch(std::istream* in=&std::cin){
       using namespace std;
        DnsClientChannel dcc(serverAddr,myDomain.c_str(),userId.c_str());
        assert(dcc.open()>0);
        while (true){
            string msg;
            getline(*in,msg);
            if(dcc.write(msg.c_str(),msg.size())<0) break;
            Bytes recvBuf;
            if(dcc.read(recvBuf)<0) break;
            std::cout<<"from server "<<dcc.name<<" : "<<(std::string)recvBuf<<std::endl;
            if(recvBuf=="c.") break;
        }
       dcc.close();
    }

};


#endif //DNSTUN_ECHOCLIENT_HPP
