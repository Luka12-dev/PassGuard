#include <math.h>
#include <string.h>
#include <ctype.h>

double calc_entropy(const char* password) {
    if (!password) return 0.0;
    int len = (int)strlen(password);
    if (len == 0) return 0.0;
    int pool = 0;
    int hasLower = 0, hasUpper = 0, hasDigit = 0, hasSymbol = 0;
    for (int i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)password[i];
        if (c >= 'a' && c <= 'z') hasLower = 1;
        else if (c >= 'A' && c <= 'Z') hasUpper = 1;
        else if (c >= '0' && c <= '9') hasDigit = 1;
        else hasSymbol = 1;
    }
    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasDigit) pool += 10;
    if (hasSymbol) pool += 32; /* approximate symbol set */
    if (pool <= 0) pool = 1;
    double bits = len * (log((double)pool) / log(2.0));
    return bits;
}