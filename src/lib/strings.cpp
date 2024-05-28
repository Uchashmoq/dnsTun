#include "strings.h"
using namespace std;
vector<string> splitString(const string& s, char delimiter) {
    vector<string> tokens;
    size_t start = 0;
    size_t end = s.find(delimiter);
    while (end != string::npos) {
        tokens.push_back(s.substr(start, end - start));
        start = end + 1;
        end = s.find(delimiter, start);
    }
    tokens.push_back(s.substr(start));
    return tokens;
}