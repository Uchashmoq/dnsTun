#include "Bytes.hpp"

void reverseBytes(void *buf,size_t len){
    char* p =(char*) buf;
    char tmp;
    for(size_t i=0;i<len/2;i++){
        tmp=p[i];
        p[i]=p[len-i-1];
        p[len-i-1]=tmp;
    }
}
size_t copy(Writeable &w, Readable &r, size_t n){
    if(n > w.writableBytes()) n=w.writableBytes();
    if(n > r.readableBytes()) n=r.readableBytes();
    if(n>0){
        uint8_t * tmp = new uint8_t [n];
        r.readBytes(tmp,n);
        w.writeBytes(tmp,n);
        delete[] tmp;
    }
    return n;
}
