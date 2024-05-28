#ifndef DNS_LOG_H
#define DNS_LOG_H
#include <iostream>
#include <cstdarg>
#include <vector>
#include <string>
#include <mutex>

enum log_level_t{
    LOG_TRACE=0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL,
    LOG_OFF
};
struct Log{
    Log()=delete;
    static std::string timeFormat;
    static log_level_t level;
    static std::vector<std::ostream*> outs;
    static void printf(log_level_t lv,const char* format, ...);
    static std::mutex lock;
};

#endif
