#ifndef __MN_DAQ_H__
#define __MN_DAQ_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

#include <daq.h>


typedef struct {
    char** v;
    unsigned n;
} StringVector;


int mn_daq_Init(ApDpLoadInfo *dpl, char *lcore_mask, uint64_t ap_lcores, char *intf,
        char *ex_par, uint8_t log_dm);
/*int mn_daq_WasStarted (void);
int mn_daq_stop (void);*/
void mn_daq_start(void);
int mn_daq_multicast_msg(void *mdata, daq_sf_req_type req_type);
int mn_daq_get_mbuf(void *, uint8_t);
void mn_daq_breakloop_ext(void);

#endif /*__MN_DAQ_H__*/
