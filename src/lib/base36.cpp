#include "base36.h"
#define IS_DIGIT(c) ('0'<=c  &&  c<='9')
#define IS_ALPHA(c) ( 'A'<=c && c<='Z' || 'a'<=c && c<='z')
#define IS_UPPER(c) ('A'<=c && c<='Z')
#define IS_LOWER(c) ('a'<=c && c<='z')
#define TO_LOWER(c) (c+('a'-'A'))
#define TO_UPPER(c) (c-('a'-'A'))
#define IS_BASE36_CHAR(c) ( IS_DIGIT(c) || IS_ALPHA(c))
inline int charValue(char ch){
    if (IS_DIGIT(ch)) return ch-'0';
    if(IS_ALPHA(ch)){
        if(IS_UPPER(ch)) ch= (char )TO_LOWER(ch);
        return ch-'a'+10;
    }
    return -1;
}
char itoc(int n){
    if(n<10) return (char)('0'+n);
    return (char)('a'+n-10);
}
void randToUpper(char* p){
    if(IS_ALPHA(*p) && (rand()&1)) *p= TO_UPPER(*p);
}
void encodeByte(void *dst,uint8_t b){
    int v= b + (abs(rand())%5 )*(UINT8_MAX+1);
    char low,high,*p=(char *)dst;
    low= itoc(v%36);
    high= itoc(v/36%36);
    randToUpper(&low) , randToUpper(&high);
    p[0]=low,p[1]=high;
}
uint8_t decodeWord(void *src){
    char *p=(char *)src;
    char low=p[0] , high=p[1];
    int v = 36* charValue(high)+ charValue(low);
    return (uint8_t)(v%(UINT8_MAX+1));
}

ssize_t base36encode(void *dst,const void *src,size_t size){
    uint8_t *d=(uint8_t*)dst , *s=(uint8_t*)src;
    for(size_t i=0;i<size;++i){
        encodeByte(d,s[i]);
        d+=2;
    }
    return d-(uint8_t*)dst;
}
ssize_t base36decode(void *dst,const void *src,size_t size ){
    uint8_t *d=(uint8_t*)dst , *s=(uint8_t*)src;
    for(size_t i=0;i<size;i+=2){
        if(!IS_BASE36_CHAR(s[i]) || !IS_BASE36_CHAR(s[i+1])) return -i;
        *d = decodeWord(s+i);
        d++;
    }
    return d-(uint8_t*)dst;
}


