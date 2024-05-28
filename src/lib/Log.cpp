#include "Log.h"
#include <iomanip>
#include <ctime>
#include <cstdarg> 
using namespace std;
log_level_t Log::level=LOG_TRACE;
vector<ostream*> Log::outs={&cout};
string Log::timeFormat="[%Y-%m-%d %H:%M:%S]";
mutex Log::lock;
static const char *levelStr(log_level_t level) {
    switch (level) {
        case LOG_TRACE:
            return "TRACE";
        case LOG_DEBUG:
            return "DEBUG";
        case LOG_INFO:
            return "INFO";
        case LOG_WARN:
            return "WARN";
        case LOG_ERROR:
            return "ERROR";
        case LOG_FATAL:
            return "FATAL";
    }
    return "";
}

void Log::printf(log_level_t lv, const char *format, ...) {
    lock_guard<mutex> guard(lock);
    if(Log::level>lv) return;
    time_t currentTime = time(nullptr);
    tm localTime = *localtime(&currentTime);
    char tmp[1024*16],time[256];
    va_list args;
    va_start(args,format);
    for(auto* out : outs){
        *out<<levelStr(lv)<<": ";
        strftime(time, sizeof(time),timeFormat.c_str(),&localTime);
        *out << time << " ";
        std::vsprintf(tmp,format,args);
        *out<<tmp<<endl;
    }
    va_end(args);
    if(lv==LOG_FATAL) exit(1);
}
