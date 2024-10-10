#include <stdarg.h>

#include "../../include/util/log.h"

void log_message(const char* source, const char* color, const char* format, ...) {
    time_t now;
    time(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    va_list args;
    va_start(args, format);

    printf("%s[%s]%s %s%s%s ", LOG_COLOR_BLUE, timestamp, LOG_COLOR_RESET, color, source, LOG_COLOR_RESET);
    vprintf(format, args);
    printf("\n");

    va_end(args);
}