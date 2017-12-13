#ifndef __MN_GEN_H__
#define __MN_GEN_H__

#include <syslog.h>
#include <stddef.h>
#include <stdarg.h>

#include "daq_common.h"

#define STD_BUF  1024

#define MN_ERROR_DB     -1



extern int mn_config_flag;

static inline void LogMessage(const char *format, ...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);

    if ( mn_config_flag & DAQ_CFG_SYSLOG )
    {
        vsnprintf(buf, STD_BUF, format, ap);
        buf[STD_BUF] = '\0';
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }

    va_end(ap);
}

#endif  /*__MN_GEN_H__*/
