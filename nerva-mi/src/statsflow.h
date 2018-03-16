#ifndef __STATSFLOW_H__
#define __STATSFLOW_H__


#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <asm-generic/posix_types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <time.h>
#include <sys/un.h>
#include <sys/timerfd.h>
#include <signal.h>

#include "decode.h"


#define __USE_GNU
#include <sched.h>
#include <pthread.h>

#include <mn_sf_cfl.h>
#include <jhash.h>
#include <branch_prediction.h>
#include <mn_sf_sys_var.h>


void sf_PktInspcProc(Packet *p);
int sf_PktInspection(/*uint32_t ins_dev_idx, */uint64_t lcore);
int sf_PktInsCheckOp(void);

#endif	/*__STATSFLOW_H__*/
