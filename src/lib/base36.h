#ifndef DNS_BASE36_H
#define DNS_BASE36_H
#include <cstdlib>
#include <cstdint>
ssize_t base36encode(void *dst,const void *src,size_t size);
ssize_t base36decode(void *dst,const void *src,size_t size);
char itoc(int n);

#endif
