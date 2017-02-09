#ifndef _WHEELC_LOG_H_
#define _WHEELC_LOG_H_

#include <string.h>

static inline const char *filename_from_path(const char *path)
{
    const char *bname = strrchr(path, '/');
    return (bname != NULL) ? bname + 1 : path;
}

#define LOG_DEBUG(fmt, ...) \
    printf("[DEBUG %s:%d] " fmt "\n", filename_from_path(__FILE__), __LINE__, ## __VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    printf("[INFO  %s:%d] " fmt "\n", filename_from_path(__FILE__), __LINE__, ## __VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    printf("[WARN  %s:%d] " fmt "\n", filename_from_path(__FILE__), __LINE__, ## __VA_ARGS__)

#define LOG_ERR(fmt, ...) \
    printf("[ERROR %s:%d] " fmt "\n", filename_from_path(__FILE__), __LINE__, ## __VA_ARGS__)

#endif // _WHEELC_LOG_H_
