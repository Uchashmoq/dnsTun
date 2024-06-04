#include <iostream>
#include <cassert>
#include "EchoClient.hpp"
#include "EchoServer.hpp"
#include "DiscardClient.h"
#include "TimeServer.hpp"

using namespace std;
using namespace ucsmq;

void testEcho1(){
    auto myDom="tun.k72vb42ffx.xyz";
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
#define SET_ARG(arg,i) if(argc>i) arg=args[i]

void testEchoServer(int argc,char** args){
    auto * serverIp="0.0.0.0",*myDom="tun.k72vb42ffx.xyz",*port="53";
    SET_ARG(serverIp,1);
    SET_ARG(port,2);
    SET_ARG(myDom,3);
    SA_IN serverAddr = inetAddr(serverIp, stoi(port));
    EchoServer server(serverAddr,myDom);
    server.launch();
}
void testEchoClient(){
    auto myDom="tun.k72vb42ffx.xyz";
    //auto addr= inetAddr("192.168.88.128",5354);
    auto addr= inetAddr("114.114.114.114",53);
    auto userId = "test_user";
    EchoClient client(addr,myDom,userId);
    client.launch();
}

void testDiscardClient(){
    auto myDom="tun.k72vb42ffx.xyz";
    //auto addr= inetAddr("192.168.88.128",5354);
    auto addr= inetAddr("114.114.114.114",53);
    auto userId = "test_user";
    DiscardClient client(addr,myDom,userId);
    client.launch();
}

void testTimeServer(int argc,char** args){
    auto * serverIp="0.0.0.0",*myDom="tun.k72vb42ffx.xyz",*port="5354";
    SET_ARG(serverIp,1);
    SET_ARG(port,2);
    SET_ARG(myDom,3);
    SA_IN serverAddr = inetAddr(serverIp, stoi(port));
    TimeServer server(serverAddr,myDom);
    server.launch();
}


int main(int argc,char** args){
    ::srand(::time(NULL));
    //testEcho1();
    //testEchoServer(argc,args);
    //testEchoClient();
    testDiscardClient();
    //testTimeServer(argc,args);
}