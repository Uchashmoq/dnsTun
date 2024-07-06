#include <iostream>
#include <cassert>
#include "EchoClient.hpp"
#include "EchoServer.hpp"
#include "DiscardClient.h"
#include "TimeServer.hpp"

#define ALIYUN "tun.k72vb42ffx.xyz"

using namespace std;
using namespace ucsmq;

void testEcho1(){
    auto myDom=ALIYUN;
    auto addr= inetAddr("127.0.0.1",8964);
    auto userId = "test_user";
    thread s([&](){
        EchoServer server(addr,myDom);
        server.launch();
    });
    s.detach();
    EchoClient client(addr,myDom,userId);
    client.launch();
    this_thread::sleep_for(chrono::seconds(7));
}
#define GET_ARG(arg,i) if(argc>i) arg=args[i]

void testEchoServer(int argc,char** args){
    auto * serverIp="0.0.0.0",*myDom=ALIYUN,*port="5354";
    GET_ARG(serverIp,1);
    GET_ARG(port,2);
    GET_ARG(myDom,3);
    SA_IN serverAddr = inetAddr(serverIp, stoi(port));
    EchoServer server(serverAddr,myDom);
    server.launch();
}

static string chrpeat(char c,int n){
    string s;
    while(n-->0)s+=c;
    return move(s);
}

static void initSS(stringstream& ss,char c,int len,int line){
    for(int i=1;i<=line;i++){
        ss<<i<<" : "<<chrpeat(c,len)<<endl;
    }
}

void testEchoClient(){
    auto myDom=ALIYUN;
    //auto addr= inetAddr("192.168.88.128",5354);
    auto addr= inetAddr("114.114.114.114",53);
    auto userId = "test_user";
    EchoClient client(addr,myDom,userId);
#if 1
    stringstream ss;
    initSS(ss,'a',20000,5);
    client.launch(&ss);
#else
    client.launch();
#endif
}

void testDiscardClient(){
    auto myDom=ALIYUN;
    //auto addr= inetAddr("192.168.88.128",5354);
    auto addr= inetAddr("114.114.114.114",53);
    auto userId = "test_user";
    DiscardClient client(addr,myDom,userId);
    client.launch();
}

void testTimeServer(int argc,char** args){
    auto * serverIp="0.0.0.0",*myDom=ALIYUN,*port="5354";
    GET_ARG(serverIp,1);
    GET_ARG(port,2);
    GET_ARG(myDom,3);
    SA_IN serverAddr = inetAddr(serverIp, stoi(port));
    TimeServer server(serverAddr,myDom);
    server.launch();
}


int main(int argc,char** args){
    ::srand(::time(NULL));
    //testEcho1();
    //testEchoServer(argc,args);
    testEchoClient();
    //testDiscardClient();
   // testTimeServer(argc,args);
}