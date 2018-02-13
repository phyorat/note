#ifndef __STATSIFC_H__
#define __STATSIFC_H__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <ctype.h>

#include <daq_api.h>


#define M_USER_ENC_OS	0x8a
#define M_PASS_ENC_OS	0x6e

#define STATS_IF_MAX	8

#define     SQL_T_NAME_IF           "if_info"
#define     SQL_SELECT_IFINFO       "SELECT count(*) FROM "SQL_T_NAME_IF" WHERE (if_name='%s');"
#define     SQL_INSERT_IFINFO       "INSERT INTO "SQL_T_NAME_IF" (if_name,if_state,if_rxcnt,if_rxbyte,"\
                                        "if_txcnt,if_txbyte,if_rxbps,if_txbps,if_rxperc,if_txperc,if_linkspeed) "\
                                        "VALUES ('%s','%u','%lu','%lu','%lu','%lu','%lu','%lu','%f','%f','%u');"
#define     SQL_UPDATE_IFINFO       "UPDATE "SQL_T_NAME_IF" SET if_state='%u',if_rxcnt='%lu',if_rxbyte='%lu',"\
                                        "if_txcnt='%lu',if_txbyte='%lu',if_rxbps='%lu',if_txbps='%lu',"\
                                        "if_rxperc='%f',if_txperc='%f',if_linkspeed='%u' "\
                                        "WHERE (if_name='%s');"


typedef struct __portinfo
{
    char if_name[64];
    uint8_t cIfup;
    uint64_t uRxPrcnt;
    uint64_t uRxPrbyte;
    uint64_t uRxPrbps;
    uint64_t uTxPrcnt;
    uint64_t uTxPrbyte;
    uint64_t uTxPrbps;
    float uRxIfperc;
    float uTxIfperc;
}Ifaceinfo;


int stats_ifport_init(void);
int stats_ifport_scale(xstatsinfo *xtinfo, uint8_t pid);

#endif /* __STATSIFC_H__ */
