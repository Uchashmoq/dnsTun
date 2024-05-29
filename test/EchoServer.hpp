#ifndef DNSTUN_ECHOSERVER_HPP
#define DNSTUN_ECHOSERVER_HPP
#include <cassert>
#include "DnsServerChannel.h"
#include <functional>
#include <memory>
#include <iostream>
class EchoServer{
    void serve(ClientConnectionPtr conn){
        while (true){
            Bytes bytes;
            assert(conn->read(bytes)>0);
            logLock.lock();
            std::cout<<"from ClientConnection "<<conn->name<<" : "<<(std::string)bytes<<std::endl;
            logLock.unlock();
            assert(conn->write(bytes)>0);
            if(bytes=="s." ){
                conn->close();
                break;
            }
        }
    }
public:
    SA_IN addr;
    UserWhiteList whiteList;
    std::string myDomain;
    static std::mutex logLock;
    EchoServer(const SA_IN& addr_,const std::string& myDomain_): addr(addr_),myDomain(myDomain_){}
    void launch(){
        DnsServerChannel dsc(addr,myDomain.c_str(),whiteList);
        assert(dsc.open()>0);
        while (true){
            auto conn = dsc.accept();
            assert(conn!= nullptr);
            std::thread s(std::bind(&EchoServer::serve,this,conn));
            s.detach();
        }
    }
};

std::mutex EchoServer::logLock;
#endif //DNSTUN_ECHOSERVER_HPP
