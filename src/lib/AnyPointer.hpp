#ifndef MYLIB_ANYPOINTER_HPP
#define MYLIB_ANYPOINTER_HPP
#include <typeinfo>
class AnyPointer {
    const std::type_info* pInfo;
    void *p;
public:
    template<class T>
    AnyPointer(T * pt) : p(pt),pInfo(&typeid(T)){}
    AnyPointer(std::nullptr_t null):p(null),pInfo(&typeid(null)){}
    bool operator==(const AnyPointer& a) const{
        return this == &a || pInfo==a.pInfo && p==a.p;
    }
    bool operator!=(const AnyPointer& a) const{
        return !(*this==a);
    }
    const std::type_info& type() const {return *pInfo;}
    template<class T>
    T* cast(){ return typeid(T)==*pInfo ? (T*)p : nullptr;}
};

#endif //MYLIB_ANYPOINTER_HPP
