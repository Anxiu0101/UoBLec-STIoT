#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

#define LOG_COLOR_RED     "\x1b[31m"
#define LOG_COLOR_GREEN   "\x1b[32m"
#define LOG_COLOR_YELLOW  "\x1b[33m"
#define LOG_COLOR_BLUE    "\x1b[34m"
#define LOG_COLOR_MAGENTA "\x1b[35m"
#define LOG_COLOR_CYAN    "\x1b[36m"
#define LOG_COLOR_RESET   "\x1b[0m"

// Log message
void log_message(const char* source, const char* color, const char* format, ...);

#define log_server(format, ...) log_message("server", LOG_COLOR_GREEN, format, ##__VA_ARGS__)
#define log_client(format, ...) log_message("client", LOG_COLOR_CYAN, format, ##__VA_ARGS__)

#endif // LOG_H