#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include "../../include/util/log.h"

void log_message(const char* source, const char* color, const char* format, ...) {
    time_t now;
    time(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    va_list args;
    va_start(args, format);

    char message[1024];
    vsnprintf(message, sizeof(message), format, args);

    fprintf(stderr, "%s[%s]%s %s%s%s %s", 
            LOG_COLOR_BLUE, timestamp, 
            LOG_COLOR_RESET, color, 
            source, LOG_COLOR_RESET, message);
    
    if (errno != 0) {
        fprintf(stderr, ": %s", strerror(errno));
        errno = 0; // Reset errno after use
    }
    
    fprintf(stderr, "\n");

    va_end(args);
}

void log_error(const char* source, const char* message) {
    log_message(source, LOG_COLOR_RED, "%s", message);
    perror("System Error");
}