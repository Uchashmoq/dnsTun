#include <cassert>
#include "DnsClientChannel.h"
#include <functional>
#include <memory>
#include <iostream>
#include "DnsServerChannel.h"

using namespace ucsmq;
using namespace std;

const char* myDomain = "test.dnstun.com";
void client(){
    SA_IN dnsAddr = inetAddr("8.8.8.8",53);
    const char* userId = "testUser";
    DnsClientChannel dcc(dnsAddr,myDomain,userId);
    if(dcc.open(3000)<0){
        cerr<<"fail to connect to the server or timeout 3000s"<<endl;
        cerr<<getLastErrorMessage()<<endl;//path include/net.h
        exit(1);
    }
    const char* m1 = "hello server";
    dcc.write(m1,strlen(m1));
    Bytes resp;
    ssize_t n = dcc.read(resp);
    if(n < 0){
        cerr<<"fail to receive"<<endl;
    }else{
        cout<<(string)resp;
    }
    //optional, dcc will be closed after leaving its scope
    dcc.close();
}

void server(){
    SA_IN addr = inetAddr("47.118.113.44",53);
    //only "testUser" can connect
    UserWhiteList li = {"testUser",{"testUser"}};
    DnsServerChannel dsc(addr,myDomain,li);
    while(true){
        ClientConnectionPtr conn = dsc.accept();
        if(conn==nullptr) continue;
        
        auto f = [conn](){
        	Bytes m1;
            auto n  = conn->read(m1);
            if(n<0){
                cerr<<"fail to receive"<<endl;
            }else{
                cout << (string)m1;
            }
            const char* resp = "hello client";
            conn->write(resp,strlen(resp));
            //optional
            conn->close();
        };
        std::thread th(f);
        th.detach();
    }
    dsc.close();
}