#ifndef __MN_SF_CFL_H__
#define __MN_SF_CFL_H__


#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <asm-generic/posix_types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <time.h>
#include <sys/un.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>

#define __USE_GNU
#include <sched.h>
#include <pthread.h>

#include <species.h>

#include "jhash.h"
#include "branch_prediction.h"


#ifdef BUILD_SP_SEALION

//Distributed
#define MAX_IPTET_HASHSZ                (0x20000)//4096
#define IPTET_HASHSZ_MASK               (MAX_IPTET_HASHSZ-1)
#define MAX_IPTET_NODE_SZ               (0x40000)//8192
//#define IPTET_PKTCNT_MASK             (MAX_IPTET_PKTCNT_SZ-1)

#define MAX_PROTOPORT_HASHSZ            (0x40000)
#define PROTOPORT_HASHSZ_MASK           (MAX_PROTOPORT_HASHSZ-1)
#define MAX_PROTOPORT_NODE_SZ           (0x80000)

#define MAX_SSNPROTO_HASHSZ             (0x20000)
#define SSNPROTO_HASHSZ_MASK            (MAX_SSNPROTO_HASHSZ-1)
#define MAX_SSNPROTO_NODE_SZ            (0x40000)//8192
#define SSNPROTO_NODE_SZ_MASK           (MAX_SSNPROTO_NODE_SZ-1)

//Confluence
#define MAX_IPTET_CONFLUENCE_HASHSZ                 (0x100000)
#define IPTET_CONFLUENCE_HASHSZ_MASK                (MAX_IPTET_CONFLUENCE_HASHSZ-1)
#define MAX_IPTET_CONFLUENCE_NODE_SZ                (0x800000)
#define IPTET_CONFLUENCE_NODE_SZ_MASK               (MAX_IPTET_CONFLUENCE_NODE_SZ-1)

#define MAX_PROTOPORT_CFL_HASHSZ            (0x100000)
#define PROTOPORT_CFL_HASHSZ_MASK           (MAX_PROTOPORT_CFL_HASHSZ-1)
#define MAX_PROTOPORT_CFL_NODE_SZ           (0x800000)

/*#define MAX_SSNPROTO_CFL_HASHSZ             (0x100000)
#define SSNPROTO_CFL_HASHSZ_MASK            (MAX_SSNPROTO_CFL_HASHSZ-1)
#define MAX_SSNPROTO_CONFLUENCE_NODE_SZ             (0x400000)*/
#define MAX_SSNPROTO_CFL_NODEPOOLS          (16)

#else
//Distributed
#define MAX_IPTET_HASHSZ				(0x20000)//4096
#define IPTET_HASHSZ_MASK				(MAX_IPTET_HASHSZ-1)
#define MAX_IPTET_NODE_SZ				(0x40000)//8192
//#define IPTET_PKTCNT_MASK             (MAX_IPTET_PKTCNT_SZ-1)

#define MAX_PROTOPORT_HASHSZ            (0x40000)
#define PROTOPORT_HASHSZ_MASK           (MAX_PROTOPORT_HASHSZ-1)
#define MAX_PROTOPORT_NODE_SZ           (0x100000)

#define MAX_SSNPROTO_HASHSZ             (0x20000)
#define SSNPROTO_HASHSZ_MASK            (MAX_SSNPROTO_HASHSZ-1)
#define MAX_SSNPROTO_NODE_SZ            (0x40000)//8192
#define SSNPROTO_NODE_SZ_MASK           (MAX_SSNPROTO_NODE_SZ-1)

//Confluence
#define MAX_IPTET_CONFLUENCE_HASHSZ					(0x100000)
#define IPTET_CONFLUENCE_HASHSZ_MASK				(MAX_IPTET_CONFLUENCE_HASHSZ-1)
#define MAX_IPTET_CONFLUENCE_NODE_SZ				(0x800000)
#define IPTET_CONFLUENCE_NODE_SZ_MASK               (MAX_IPTET_CONFLUENCE_NODE_SZ-1)

#define MAX_PROTOPORT_CFL_HASHSZ            (0x100000)
#define PROTOPORT_CFL_HASHSZ_MASK           (MAX_PROTOPORT_CFL_HASHSZ-1)
#define MAX_PROTOPORT_CFL_NODE_SZ           (0x800000)

/*#define MAX_SSNPROTO_CFL_HASHSZ             (0x100000)
#define SSNPROTO_CFL_HASHSZ_MASK            (MAX_SSNPROTO_CFL_HASHSZ-1)
#define MAX_SSNPROTO_CONFLUENCE_NODE_SZ             (0x400000)*/
#define MAX_SSNPROTO_CFL_NODEPOOLS          (16)
#endif

//STATSFLOW MBUF_RING
#define SUR_SF_MP_NUM_POOL_SIZE             2
#define SUR_SF_RING_MSG_TOLERATE            8
#define SUR_SF_RING_MSG_QUEUE_SIZE          SUR_SF_RING_MSG_TOLERATE

#define SUR_SF_MP_CFL_MASTER_NUM             1

//Define pkt small
#define NETFLOW_SMALL_PKT       62


#define SF_EP_MAX_EVENTS        8
//Pkt Inspection End

#define MAX_SEC_IPTET_DBREC_EXPIRE      604800//60×60×24×7, one week
#define MAX_SEC_SSN_NODE_TRACK_EXPIRE   604800//60×60×24×7, one week

//#define TCP_SSN_PKTGEN_DEBUG

#define SUR_SF_IPT_PP_SCALE_BASE_TIME       30      //20 seconds
#define SUR_SF_IPT_PP_SCALE_SUM_CNT         2       //60 seconds
#define SUR_SF_IPT_PP_SCALE_VAL_MIN         60      //aligned with above two MACRO
#define SUR_SF_IPT_PP_SCALE_VAL_HOUR        3600    //One Hour
#define SUR_SF_IPT_PP_SCALE_VAL_DAY         86400   //One Day

/*
 * Atomic Operation
 */
#define MPLOCKED        "lock ; "       /**< Insert MP lock prefix. */
typedef struct {
	volatile int32_t cnt; /**< An internal counter value. */
} sf_atomic32_t;

static inline int
sf_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	uint8_t res;

	asm volatile(
			MPLOCKED
			"cmpxchgl %[src], %[dst];"
			"sete %[res];"
			: [res] "=a" (res),     /* output */
			  [dst] "=m" (*dst)
			: [src] "r" (src),      /* input */
			  "a" (exp),
			  "m" (*dst)
			: "memory");            /* no-clobber list */
	return res;
}

static inline int sf_atomic32_test_and_set(sf_atomic32_t *v)
{
	return sf_atomic32_cmpset((volatile uint32_t *)&v->cnt, 0, 1);
}

static inline int sf_switch_test_and_set_on(sf_atomic32_t *v)
{
	return sf_atomic32_cmpset((volatile uint32_t *)&v->cnt, 0, 1);
}

static inline int sf_switch_test_and_set_done(sf_atomic32_t *v)
{
	return sf_atomic32_cmpset((volatile uint32_t *)&v->cnt, 1, 2);
}

static inline int sf_switch_test_and_set_off(sf_atomic32_t *v)
{
	return sf_atomic32_cmpset((volatile uint32_t *)&v->cnt, 2, 0);
}

/*
 * Business definition
 */
typedef enum
{
	FLOWSTA_NET_IP = 0,
/*	FLOWSTA_NET_IP_UP,
	FLOWSTA_NET_IP_DOWN,
	FLOWSTA_NET_IP_INTRA,
	FLOWSTA_NET_IP_EXTER,*/
	FLOWSTA_NET_ARP,
	//FLOWSTA_NET_SMALL,
	//FLOWSTA_NET_TCP_SYN,
	//FLOWSTA_NET_TCP_NOF,
	FLOWSTA_NET_COUNT
} netip_type;

typedef enum
{
	FLOWSTA_PROTO_TCP = 0,
	FLOWSTA_PROTO_UDP,
	FLOWSTA_PROTO_OTHER,    //Add protocol after this type
	FLOWSTA_PROTO_ICMP,
	/*Additional protocol stack data*/
/*	FLOWSTA_PROTO_TCP_UP,
	FLOWSTA_PROTO_TCP_DOWN,
	FLOWSTA_PROTO_UDP_UP,
	FLOWSTA_PROTO_UDP_DOWN,
	FLOWSTA_PROTO_ICMP_UP,
	FLOWSTA_PROTO_ICMP_DOWN,
	FLOWSTA_PROTO_OTHER_UP,
	FLOWSTA_PROTO_OTHER_DOWN,
	FLOWSTA_PROTO_MESS,*/
/*	FLOWSTA_PROTO_IGMP,
	FLOWSTA_PROTO_IGMP_UP,
	FLOWSTA_PROTO_IGMP_DOWN,
	FLOWSTA_PROTO_SCTP,
	FLOWSTA_PROTO_SCTP_UP,
	FLOWSTA_PROTO_SCTP_DOWN,*/
	FLOWSTA_PROTO_COUNT
} proto_type;

typedef struct __NetFlowProtoMap
{
    uint8_t proto_idx;
    uint8_t proto;
} NetFlowProtoMap;

enum {
    NF_PROTP_BS_TCP = (0x01<<FLOWSTA_PROTO_TCP),
    NF_PROTP_BS_UDP = (0x01<<FLOWSTA_PROTO_UDP),
    NF_PROTP_BS_OTHER = 0,
    NF_PROTP_BS_ICMP = 0,
};
typedef struct __NetFLowPortProtoMap
{
    uint16_t port;
    uint8_t pro_bitset;
    uint8_t pp_index;
    uint8_t fp_index;
    char pp_name[25];
    uint8_t pp_switch;
    uint8_t renew;
} NetFLowPortProtoMap;

#define NETFLOW_PORTPROTO_MAP_MAX       64
#define SF_MAX_PROT_PROTO_USER          (NETFLOW_PORTPROTO_MAP_MAX-1)  //last records is end flag

typedef struct __NetFlowPPmArray
{
    NetFLowPortProtoMap map_portproto[NETFLOW_PORTPROTO_MAP_MAX];
    NetFLowPortProtoMap map_portproto_user[NETFLOW_PORTPROTO_MAP_MAX];
} NetFlowPPmArray;

typedef struct __NetFlowProtoPortReflect
{
    uint8_t approto;
    uint8_t pro_bitset;
    uint64_t ports_sys;
    uint64_t ports_user;
} NetFlowProtoPortReflect;

typedef enum
{
    NF_APPRO_FTP_20 = 0,    /*0*/
    NF_APPRO_FTP_21,    /*1*/
    NF_APPRO_SSH,    /*2*/
    NF_APPRO_TELNET,    /*3*/
    NF_APPRO_SMTP,    /*4*/
    NF_APPRO_TIME,    /*5*/
    NF_APPRO_RLP,    /*6*/
    NF_APPRO_DNS,    /*7*/
    NF_APPRO_RAP,    /*8*/
    NF_APPRO_DHCP_67,    /*9*/
    NF_APPRO_DHCP_68,    /*10*/
    NF_APPRO_TFTP,    /*11*/
    NF_APPRO_GOTHER,    /*12*/
    NF_APPRO_FINGER,    /*13*/
    NF_APPRO_HTTP_80,    /*14*/
    NF_APPRO_POP2,    /*15*/
    NF_APPRO_POP3,    /*16*/
    NF_APPRO_SFTP,    /*17*/
    NF_APPRO_NNTP,    /*18*/
    NF_APPRO_NTP,    /*19*/
    NF_APPRO_NETBIOS_137,    /*20*/
    NF_APPRO_NETBIOS_138,    /*21*/
    NF_APPRO_NETBIOS_139,    /*22*/
    NF_APPRO_IMAP,    /*23*/
    NF_APPRO_SGMP,    /*24*/
    NF_APPRO_SQLSRV,    /*25*/
    NF_APPRO_SNMP,    /*26*/
    NF_APPRO_SNMPTRAP,    /*27*/
    NF_APPRO_BGP,    /*28*/
    NF_APPRO_QMTP,    /*29*/
    NF_APPRO_LDAP,      /*30*/
    NF_APPRO_HTTPS,    /*31*/
    NF_APPRO_SNPP,    /*32*/
    NF_APPRO_MICRODS,    /*33*/
    NF_APPRO_KPASSWD,    /*34*/
    NF_APPRO_SMTPS,    /*35*/
    NF_APPRO_WHO,    /*36*/
    NF_APPRO_RIP,    /*37*/
    NF_APPRO_RIPNG,    /*38*/
    NF_APPRO_RPC,    /*39*/
    NF_APPRO_UUCP,    /*40*/
    NF_APPRO_HTTPRPC,    /*41*/
    NF_APPRO_LDAP_SSL,  /*42*/
    NF_APPRO_FTP_SSL_989,   /*43*/
    NF_APPRO_FTP_SSL_990,   /*44*/
    NF_APPRO_TELNETSSL,    /*45*/
    NF_APPRO_MSSQLSRV,    /*46*/
    NF_APPRO_MSSQLMON,    /*47*/
    NF_APPRO_MYSQL,    /*48*/
    NF_APPRO_POSTRESQL,    /*49*/
    NF_APPRO_HTTP_8080,    /*50*/
    NF_APPRO_HTTP_8081,    /*51*/
//    NF_APPRO_QQ_36688,    /*52*/
    NF_APPRO_COUNT,
    NF_APPRO_UNKNOWN,    /*52*/
    NF_APPRO_NA_NET,
    NF_APPRO_NA_TRANS,
} app_proto_type;

typedef enum
{
    FLOWSTA_APPRO_RPC = 0,/*0*/
    FLOWSTA_APPRO_HTTP,/*1*/
    FLOWSTA_APPRO_FTP,/*2*/
    FLOWSTA_APPRO_IMAP,/*3*/
    FLOWSTA_APPRO_SNMP,/*4*/
    FLOWSTA_APPRO_TELNET,/*5*/
    FLOWSTA_APPRO_DNS,/*6*/
    FLOWSTA_APPRO_SMTP,/*7*/
    FLOWSTA_APPRO_RIP,/*8*/
    FLOWSTA_APPRO_RIPNG,/*9*/
    FLOWSTA_APPRO_TFTP,/*10*/
    FLOWSTA_APPRO_NNTP,/*11*/
    FLOWSTA_APPRO_NFS,/*12*/
    FLOWSTA_APPRO_NETBIOS,/*13*/
    FLOWSTA_APPRO_POP2,/*14*/
    FLOWSTA_APPRO_POP3,/*15*/
    FLOWSTA_APPRO_HTTPS,/*16*/
    FLOWSTA_APPRO_SSH,/*17*/
    FLOWSTA_APPRO_DHCP,/*18*/
    FLOWSTA_APPRO_MICRODS,/*19*/
    FLOWSTA_APPRO_MSSQL,/*20*/
    FLOWSTA_APPRO_MYSQL,/*21*/
//    FLOWSTA_APPRO_USER,/*22*/
    FLOWSTA_APPRO_UNKNOWN,/*22*/
    FLOWSTA_APPRO_COUNT
} flow_stats_proto_type;

typedef enum
{
	NF_NET,
	NF_IPTET,
	NF_PROTO,
	NF_APPRO,
	NF_PROSSN,
	NF_PROTP,
	NF_INS_TRACK,
} netflow_stack;

typedef enum
{
	NF_NODEIPT_IDLE = 0,
	NF_NODEIPT_RESERVED,
	NF_NODEIPT_NEW,
	NF_NODEIPT_NEW_PLUS,
	NF_NODEIPT_NEW_TOBE_CFM,
	//NF_NODEIPT_DBID_HALVE_MARK,
	NF_NODEIPT_UPD,
	NF_NODEIPT_UPD_PLUS,
	NF_NODEIPT_UPD_TOBE_CFM,
	NF_NODEIPT_SYNCED,
	NF_NODEIPT_NON,
} netflow_iptet_node_state;

typedef enum
{
    NF_IPTET_FLOW_DATA = 0x01,
    NF_IPTET_ALM_FLAG = 0x02,
    NF_IPTET_FLOW_DATA_QNC = 0x04,      //queried but not confirm
    NF_IPTET_ALM_FLAG_QNC = 0x08,      //queried but not confirm
} netflow_iptet_query_flag;

typedef enum
{
	SF_DPSTATE_NULL = 0,
	SF_DPSTATE_REQ_NEW,
	SF_DPSTATE_RECORDING,
	SF_DPSTATE_RECORD_STALL,
	SF_DPSTATE_INVALID,
} StatsFlowDPState;

/*######################################################################*/
//NOTE: Those ENUM need Align with python analyst(statsflow_analyst.py)
typedef enum
{
    SF_ALY_IP_TUPLE = 0,
    SF_ALY_PROTO_SESSION,
    SF_ALY_HB,
    SF_ALY_SSN_ALM_FLAG,
    SF_ALY_COUNT,
} StatsFlowAnalystType;

typedef enum
{
    SFALY_ALARM_SSN_UPDOWN_CNT = 0x01,
    SFALY_ALARM_SSN_UPDOWN_BSZ = 0x02,
    SFALY_ALARM_SSN_SML_PKT = 0x04,
    SFALY_ALARM_SSN_PSH = 0x08,
    SFALY_ALARM_IPTSSN_SYN = 0x10,
    SFALY_ALARM_IPT_EXPIRE = 0x20,
    SFALY_ALARM_SSN_LIVE_LONG = 0x40,
    SFALY_ALARM_SSN_CAP_HB = 0x80,
    SFALY_ALARM_MASK = 0xff
} sfaly_alarm_type;

/*#########################################
 * Keep Align With Definition in portrait
 */
typedef enum
{
    FLOW_ALG_CRITERIA_ANORMAL = 0,
    FLOW_ALG_CRITERIA_PORT_ANORMAL,
    FLOW_ALG_CRITERIA_STATS_TJ_HOST,
    FLOW_ALG_CRITERIA_STATS_TJ_COMM,
} flow_judge_criteria;

typedef enum
{
    FLOW_ALG_DYNAMIC_BASELINE = 0,
    FLOW_ALG_ABNORMAL_CHECK,
    FLOW_ALG_STATS_ANALYST,
    HTTP_ANOMALY_DETECTION,
    STATIC_MATCH_ALGORITHM,
    HEURISTICS_ALGORITHM,
    FREQUENCY_ANALYSIS_ALGORITHM,
} flow_algorithm;
/*
 * Keep Align With Definition in portrait
 * #########################################
 */


typedef enum
{
    PROSSN_IDLE = 0,
    PROSSN_DOING,
    PROSSN_END,
//    PROSSN_READY,
    PROSSN_FORCE_END,
    PROSSN_RENEW,
} ProtoSsnState;

typedef enum
{
    SF_STREAM_EXTER = 0,
    SF_STREAM_UP,
    SF_STREAM_DOWN,
    SF_STREAM_INTRA,
    SF_STREAM_DIRECTION_TYPES,
} StreamDirection;

typedef enum
{
    SF_SESSION_IN = 0,
    SF_SESSION_OUT,
} SessionDirection;

typedef enum
{
    SF_SESSION_ROLE_CLN = 0,
    SF_SESSION_ROLE_SRV,
    SF_SESSION_ROLE_CNT,
} SessionRole;

/*######################################################################*/

typedef enum
{
    SFALY_IPT_ACTIVE = 0x01,
    SFALY_IPT_INSPECT_PULSE = 0x02,
    SFALY_IPT_SEEMS_EXPIRE = 0x04,
} sfaly_iptet_stat;

typedef struct __NetFlowDBTblName
{
	netflow_stack nf_stack;
	char tbl_name[32];
} NetFlowDBTblName;

typedef struct __NetFlowItemToName
{
	netflow_stack nf_stack;
	uint32_t nf_type;
	char nf_name[16];
} NetFlowItemToName;

//Protocol Stack
typedef struct _ProtoStackStatsNodes
{
	uint32_t cnt[SF_STREAM_DIRECTION_TYPES];
	uint32_t bsize[SF_STREAM_DIRECTION_TYPES];
} ProtoStackStatsNodes;

typedef struct _ProtoStackStats
{
	netflow_stack nf_stack;
	uint32_t nf_type;
	uint8_t nd_new;
	uint8_t np_user;
	uint16_t nd_swt;     //node switch
	uint16_t port_idx;
	uint16_t port;
	uint32_t bps[SF_STREAM_DIRECTION_TYPES];
	uint64_t cnt[SF_STREAM_DIRECTION_TYPES];
	uint64_t bsize[SF_STREAM_DIRECTION_TYPES];
} ProtoStackStatsCflNodes;

#define NETFLOW_STACK_APP_STEP      (FLOWSTA_NET_COUNT+FLOWSTA_PROTO_COUNT)
#define NETFLOW_STACK_COUNT         (FLOWSTA_NET_COUNT+FLOWSTA_PROTO_COUNT+NF_APPRO_COUNT+(SF_MAX_PROT_PROTO_USER+1))

typedef struct __ProStackStatNodesTbl
{
	ProtoStackStatsNodes netsta[FLOWSTA_NET_COUNT];
	ProtoStackStatsNodes prosta[FLOWSTA_PROTO_COUNT];
	ProtoStackStatsNodes aprsta[/*FLOWSTA_APPRO_COUNT*/NF_APPRO_COUNT];
	ProtoStackStatsNodes aprsta_user[SF_MAX_PROT_PROTO_USER+1];
} ProStackStatNodesTbl;

typedef struct __ProStackConfluenceTbl
{
	ProtoStackStatsCflNodes netsta[FLOWSTA_NET_COUNT];
	ProtoStackStatsCflNodes prosta[FLOWSTA_PROTO_COUNT];
	ProtoStackStatsCflNodes aprsta[/*FLOWSTA_APPRO_COUNT*/NF_APPRO_COUNT];
	ProtoStackStatsCflNodes aprsta_user[SF_MAX_PROT_PROTO_USER+1];
} ProStackConfluenceTbl;

//Protocol session
/*typedef enum
{
	SSN_NODE_ADD,
	SSN_NODE_GET,
	SSN_NODE_END
} ProtoSsnOper;*/



typedef enum
{
    PORT_VEC_IN,
    PORT_VEC_OUT,
    PORT_VEC_INVALID,
} PortVection;

typedef enum
{
    CFL_IPTET_NODE_NONE = 0,
    CFL_IPTET_NODE_USED,
//    CFL_IPTET_NODE_EXPIRE,
} CflIPTetNodeState;

typedef struct _IPTet
{
    in_addr_t src;
    in_addr_t dst;
} IPTet;

typedef struct _TetRad
{
    in_addr_t cln_ip;
    in_addr_t ser_ip;
    uint16_t cln_p;
    uint16_t ser_p;
} TetRad;

typedef struct __PktQuinTuple
{
    union {
        TetRad tr;
        struct{
            in_addr_t cln_ip;
            in_addr_t ser_ip;
            uint16_t cln_p;
            uint16_t ser_p;
        };
    };
    uint8_t proto;
    uint8_t direction;  //1, Inside-Out; 2, Outside-In
    uint8_t pad[2];
} PktQuinTuple;

#define SSN_FSM_IDLE_ACCUM_MAX      4
typedef struct __SSNFsmNode
{
    uint8_t pad[14];
    volatile uint8_t db_sync:1,
                     db_ood:1,
                     idle_cum;
    volatile uint8_t stat;
} SSNFsmNode;


#define MAX_SSN_CHSUM_EQU_TRACK_PPL_SIZE    (256)         //same cksum packet saving
#define MAX_SSN_CHSUM_EQU_TRACK_PPL_MA      (MAX_SSN_CHSUM_EQU_TRACK_PPL_SIZE-1)
#define MAX_SSN_CHSUM_EQU_TRACK_PPL_NUM     (0x10000)     //buf count
/* Lets add some space for payload decoding and query esaping..*/
#define SSN_CHSUM_SQU_TRACK_BASE64_BUFLEN   ((MAX_SSN_CHSUM_EQU_TRACK_PPL_SIZE<<1) + 4096)

#define MAX_SSN_CHSUM_EQU_TRACK_CNT_MA      (63)
#define SSN_CHSUM_SP_HB_PCNT_THRESHOLD      (30)        // packet count threshold
#define SSN_CHSUM_SP_HB_PTS_RELATE_DIFF     (10)        // packet time-stamp relative difference, within 20 seconds

typedef enum
{
    SSN_CS_TRACK_NONE = 0,
    SSN_CS_TRACK_PRE_CAP,
    SSN_CS_TRACK_CAP,
    SSN_CS_TRACK_SYNC_DB,
} SSNCksumTrackStat;

typedef struct __SSNCksumTrack
{
    void *data_pl;
    uint32_t tv_stamp;
    uint16_t tv_int_min;
    uint16_t tv_int_max;
    uint16_t cksum;
    uint8_t data_len;       /*MAX_SSN_CHSUM_EQU_TRACK_PPL_SIZE*/
    uint8_t cnt_cs:6,       /*MAX_SSN_CHSUM_EQU_TRACK_CNT_MA*/
            cap:2;
} SSNCksumTrack;

typedef struct __SSNProtoStatsNode {
	struct __SSNProtoStatsNode *hnxt;
	struct __SSNProtoStatsNode *snxt;
	void *p_tnode;
	uint32_t tv_start;
	uint32_t tv_upd;
	//uint32_t tv_dur;
	//uint32_t ipt_id;
	SSNCksumTrack cs_trc[SF_SESSION_ROLE_CNT];
	uint32_t cnt_up;
	uint32_t cnt_down;
	uint32_t bsz_up;
	uint32_t bsz_down;
/*	uint32_t syn;
	uint32_t nof;*/
	uint32_t psh;
	uint32_t sml;
	union{
	    PktQuinTuple qt;
	    SSNFsmNode fsm;
	};
	uint64_t dbid;
} SSNProtoStatsNode;
/*
typedef struct __SSNProtoStatsCflList {
	struct __SSNProtoStatsCflList *nxt;
	uint32_t ipt_id;
	uint32_t cnt_up;
	uint32_t cnt_down;
	uint32_t bsz_up;
	uint32_t bsz_down;
	uint32_t syn;
	uint32_t nof;
} SSNProtoStatsCflNode;*/

//Protocol & Port(application layer protocol)
typedef struct __ProtoProtKeyDb {
    uint16_t port;
    uint16_t proto;
    uint32_t ipt_id;      //parent ip-tet dbid
} ProtoProtKeyDb;

typedef union {
    uint64_t keyID;
    ProtoProtKeyDb dk;
} ProtoProtKeyDbUnion;

typedef struct __ProtoProtNodeKeyDemo {
    IPTet tet;      //parent ip-tet
    uint8_t user_set:1,
            proto_idx:7;
    uint8_t port_vec:2,
            apport_idx:6;
    uint16_t port;
} ProtoProtNodeKeyDemo;

typedef struct __ProtoPortNode {
    struct __ProtoPortNode *hnxt;
    struct __ProtoPortNode *pnxt;
    union {
        uint8_t key;
        ProtoProtNodeKeyDemo nk;
    };
    uint32_t tv_upd;
    uint32_t cnt;
    uint32_t bsz;
} ProtoPortNode;

typedef enum
{
    SF_PROTP_SCALE_STAGE_META = 0,
    SF_PROTP_SCALE_STAGE_MIN,
    SF_PROTP_SCALE_STAGE_HOUR,
    SF_PROTP_SCALE_STAGE_DAY,
    SF_PROTP_SCALE_STAGE_MONTH,
    SF_PROTP_SCALE_STAGE_MAX,
    SF_PROTP_SCALE_STAGE_SAVE = (SF_PROTP_SCALE_STAGE_HOUR+1),
} sf_ProtoPort_Scale_Stage;

typedef struct __ProtoPortCflNode {
    struct __ProtoPortCflNode *hnxt;
    struct __ProtoPortCflNode *pnxt;
    union {
        uint8_t key;
        ProtoProtNodeKeyDemo nk;
    };
    uint32_t tv_upd;
    struct {
        uint32_t cnt;
        uint32_t bsz;
    } scl_st[SF_PROTP_SCALE_STAGE_SAVE];
} ProtoPortCflNode;

/**************************************************This two struct must be aligned at first part**/
//IP two-tuples
typedef struct __IPTetStatNode {
	struct __IPTetStatNode *nxt;
	ProtoPortNode *pp_node;
	IPTet tet;
	uint32_t cnt;
	uint32_t bsize;
	uint32_t syn;   //SYN pkt count
	uint32_t dns;   //DNS pkt count
	uint32_t tv_upd;
	uint8_t direction;  //1, Inside-Out; 2, Outside-In
	SSNProtoStatsNode *ssn_node;
} IPTetStatNode;

/*
 * Only TCP(0)/UDP(1) map ports, other protocol(max protocols:16) only one bit occupy
 * */
#define NF_IPTET_PFLAG_NUM          5
#define NF_IPTET_PFLAG_TYPE_CNT     (FLOWSTA_PROTO_OTHER)      //(TCP:UDP)
#define NF_IPTET_PFLAG_TYPE_CELL   (1)                         //(proto:proto_user)<<count
#define NF_IPTET_PFLAG_TYPE_MASK    (NF_IPTET_PFLAG_TYPE_CNT-1)

/*#define SF_CFL_GET_PPFLAG(proto, port)          (0x01<<( ((proto)<FLOWSTA_PROTO_OTHER) ? \
            ((nf_app_proto_t_bitset_map[(proto)])+(port)):\
            ((nf_app_proto_t_bitset_map[FLOWSTA_PROTO_OTHER])+((proto)-FLOWSTA_PROTO_OTHER)) ))*/

#define SF_CFL_SET_PPFLAG(pflag, user_set, proto, appro)      do { \
    if ( (proto)<NF_IPTET_PFLAG_TYPE_CNT )    \
        *((pflag)+(((user_set)<<1)+((proto)&NF_IPTET_PFLAG_TYPE_MASK))) |= (0x01L<<(appro)); \
    else    \
        *((pflag)+(NF_IPTET_PFLAG_TYPE_CELL<<NF_IPTET_PFLAG_TYPE_CNT)) |= (0x01L<<(proto)); \
    } while(0)

#define SF_CFL_GET_PPFLAG(tpflag, pflag, user_set, proto, appro)      do { \
    if ( (proto)<NF_IPTET_PFLAG_TYPE_CNT )    \
        tpflag = *((pflag)+(((user_set)<<1)+((proto)&NF_IPTET_PFLAG_TYPE_MASK))) & (0x01L<<(appro)); \
    else    \
        tpflag = *((pflag)+(NF_IPTET_PFLAG_TYPE_CELL<<NF_IPTET_PFLAG_TYPE_CNT)) & (0x01L<<(proto)); \
    } while(0)


typedef struct __IPTetCflPPFlag
{
    union {
        uint64_t flag[NF_IPTET_PFLAG_NUM];
        struct {
            uint64_t tcp;               //proto-port tcp flag---system_default
            uint64_t udp;               //proto-port udp flag---system_default
            uint64_t tcp_user;          //proto-port tcp flag---user_set
            uint64_t udp_user;          //proto-port udp flag---user_set
            uint64_t other;             //proto-other, not be aware of port
        };
    };
} IPTetCflPPFlag;

typedef struct __IPTetCflStatNode {
	struct __IPTetCflStatNode *nxt;
	ProtoPortCflNode *pp_node;
	IPTet tet;
	uint32_t cnt;
	uint32_t bsize;
	uint32_t syn;   //SYN pkt count
	uint32_t dns;   //DNS pkt count
	uint32_t tv_upd;
	uint8_t direction;  //1, Inside-Out; 2, Outside-In
	IPTetCflPPFlag ppflag;//SSNProtoStatsCflNode *ssn_node;//replace pointer "ssn_node"
	uint64_t dbid;
	uint32_t hsum;
	uint32_t almflag;
	volatile uint8_t expire;     //The only variable that other thread can modify without lock
	volatile uint8_t aly_stat;   //if sent to analyst after last update
	volatile uint8_t qry_flag;   //DB query data flag
	volatile uint8_t fsm;
} IPTetCflStatNode;
/****************************************************/

/*Distributed Statistic
 *
 */
typedef struct __IPTetStatNodeHaTbl {
	IPTetStatNode *hatbl[MAX_IPTET_HASHSZ];
} IPTetStatNodeHaTbl;

typedef struct __IPTetStatNodePool {
	uint32_t npidx;
	IPTetStatNode nodes[MAX_IPTET_NODE_SZ];
} IPTetStatNodePool;

typedef struct __ProtoPortNodeHaTbl {
    ProtoPortNode *hatbl[MAX_PROTOPORT_HASHSZ];
} ProtoPortNodeHaTbl;

typedef struct __ProtoPortNodePool {
    uint32_t npidx;
    ProtoPortNode nodes[MAX_PROTOPORT_NODE_SZ];
} ProtoPortNodePool;

typedef struct __SSNAlySockSend
{
    uint32_t type;
    uint32_t pad[1];
    uint64_t id_start;
    uint64_t id_end;
} SFAlySockSend;

typedef struct __SSNProtoNodeHaTbl {
    SSNProtoStatsNode *hatbl[MAX_SSNPROTO_HASHSZ];
} SSNProtoNodeHaTbl;

typedef struct __SSNProtoNodePool {
    uint32_t npidx;
    volatile uint32_t np_active;
    SSNProtoStatsNode nodes[MAX_SSNPROTO_NODE_SZ];
} SSNProtoNodePool;

typedef struct __StatsFlowNodeExp
{
    IPTetStatNode itnode;
    ProtoPortNode ppnode;
    PktQuinTuple pkt_qt;
} StatsFlowNodeExp;

typedef struct __StatsFlowDataPlane
{
    SSNProtoNodeHaTbl *p_hnode;
    SSNProtoNodePool *p_snode;
    IPTetStatNodeHaTbl h_tnode;//0x40000*8
    ProtoPortNodeHaTbl h_pnode;
    IPTetStatNodePool tnode;//0x100000*24 +4
    ProtoPortNodePool pnode;
    StatsFlowNodeExp nodes_exp;
} StatsFlowDataPlane;

typedef struct __StatsFlowDPSSN
{
    SSNProtoNodeHaTbl h_snode;
    SSNProtoNodePool snode;
} StatsFlowDPSSN;

/*NetFlow_Confluence
 *
 */
typedef struct __IPTetConfluenceNodeHaTbl {
	IPTetCflStatNode *hatbl[MAX_IPTET_CONFLUENCE_HASHSZ];
} IPTetConfluenceNodeHaTbl;

typedef struct __IPTetConfluenceNodePool {
	uint32_t npidx;
	uint32_t npcnt;
	IPTetCflStatNode nodes[MAX_IPTET_CONFLUENCE_NODE_SZ];
} IPTetConfluenceNodePool;

typedef struct __ProtoPortCflNodeHaTbl {
    ProtoPortCflNode *hatbl[MAX_PROTOPORT_CFL_HASHSZ];
} ProtoPortCflNodeHaTbl;

typedef struct __ProtoPortCflNodePool {
    uint32_t npidx;
    ProtoPortCflNode nodes[MAX_PROTOPORT_CFL_NODE_SZ];
} ProtoPortCflNodePool;
/*
typedef struct __SSNProtoCflNodeHaTbl {
    SSNProtoStatsCflNode *hatbl[MAX_SSNPROTO_CFL_HASHSZ];
} SSNProtoCflNodeHaTbl;

typedef struct __SSNProtoCflNodePool {
    uint32_t npidx;
    SSNProtoStatsCflNode nodes[MAX_SSNPROTO_CONFLUENCE_NODE_SZ];
} SSNProtoCflNodePool;
*/
typedef struct _StatsFlowConfluDataPlane
{
    SSNProtoNodeHaTbl *p_hnode[MAX_SSNPROTO_CFL_NODEPOOLS];
    SSNProtoNodePool *p_snode[MAX_SSNPROTO_CFL_NODEPOOLS];
    IPTetConfluenceNodeHaTbl h_tnode;//0x100000*8
    ProtoPortCflNodeHaTbl h_pnode;
    IPTetConfluenceNodePool tnode;//0x6000000*48 +4
    ProtoPortCflNodePool pnode;
    ProStackConfluenceTbl stack;//26*16
} StatsFlowConfluDataPlane;
//0x6000000⋅48+0x400000⋅16+0x100000⋅8+26⋅16
/*data-plane loader
 *
 */
typedef struct _CounterNetFlow
{
    int fd_timer_sf;
    int fd_timer_stack;
    int fd_epoll;
    volatile StatsFlowDPState dpState;
    sf_atomic32_t dpSwitch;
    uint64_t arp_count;
    StatsFlowDataPlane *psDPIntef;
    ProStackStatNodesTbl *psDpStack;
    StatsFlowDPSSN *psDPSsn;
    volatile StatsFlowDataPlane *psDPready;
    volatile ProStackStatNodesTbl *psStackReady;
} CounterNetFlow;

typedef enum {
    SF_GLOB_VAR_PP_SCALE_L0 = (0x01<<SF_PROTP_SCALE_STAGE_META),    //Stock Data
    SF_GLOB_VAR_PP_SCALE_L1 = (0x01<<SF_PROTP_SCALE_STAGE_MIN),
    SF_GLOB_VAR_PP_SCALE_L2 = (0x01<<SF_PROTP_SCALE_STAGE_HOUR),
    SF_GLOB_VAR_PP_SCALE_L3 = (0x01<<SF_PROTP_SCALE_STAGE_DAY),     // Note: L3 and L4 need assists of L2!
    SF_GLOB_VAR_PP_SCALE_L4 = (0x01<<SF_PROTP_SCALE_STAGE_MONTH),
    SF_GLOB_VAR_PP_SCALE_DEEP = 0x06,
    SF_GLOB_VAR_PP_SCALE_DEEP_ALL = 0x1E,
    SF_GLOB_VAR_PP_SCALE_DEEP_LIT = 0x0C,
    SF_GLOB_VAR_MAX = 0xff,
} StatsGlobalSetup;

typedef struct __StatsFlowGlobal
{
    uint32_t envset_scl_flag;
    volatile uint64_t cur_iptid;
    volatile uint64_t max_iptid;
    volatile uint64_t cur_ssnid;
    volatile uint64_t max_ssnid;
} StatsFlowGlobal;


/****************NF COMMON*************************************/
static inline int sf_memcmp(s1, s2, n)
    const void *s1, *s2;
    size_t n;
{
    if (n != 0) {
        register const unsigned char *p1 = s1, *p2 = s2;

        do {
            if (*p1++ != *p2++)
                return 1;//(*--p1 - *--p2);
        } while (--n != 0);
    }
    return (0);
}

/*
 * Function inline
 */
static inline ProtoPortCflNode * SfProtoPortGetCflNode(ProtoPortCflNodePool *nodepool)
{
    uint8_t i;
    ProtoPortCflNode *cNode;

    if ( nodepool->npidx >= MAX_PROTOPORT_CFL_NODE_SZ )
        return NULL;
    cNode = nodepool->nodes+nodepool->npidx;
    nodepool->npidx++;

    //pre-set cfl-node state
    for ( i=SF_PROTP_SCALE_STAGE_MIN; i<SF_PROTP_SCALE_STAGE_SAVE; i++ ) {
        cNode->scl_st[i].cnt = 0;
        cNode->scl_st[i].bsz = 0;
    }

    return cNode;
}

/*
 * Function inline
 */
static inline ProtoPortNode * SfProtoPortGetNode(ProtoPortNodePool *nodepool, uint8_t cfl_plane)
{
    ProtoPortNode *eNode;

    //Confluence Node
    if ( cfl_plane )
        return (ProtoPortNode*)SfProtoPortGetCflNode((ProtoPortCflNodePool*)nodepool);

    //Scale Node
    if ( nodepool->npidx >= MAX_PROTOPORT_NODE_SZ )
        return NULL;
    eNode = nodepool->nodes+nodepool->npidx;
    nodepool->npidx++;

    return eNode;
}

static inline void jHashProtoPortDupNode(ProtoPortNode *dst, const ProtoPortNode *src)
{
    dst->hnxt = NULL;
    dst->pnxt = NULL;
    dst->nk = src->nk;
    dst->tv_upd = src->tv_upd;
    dst->cnt = src->cnt;
    dst->bsz = src->bsz;
}

static inline void jIptetAppendPpNode(IPTetStatNode *ipt_node, ProtoPortNode *pp_node)
{
    if ( ipt_node->pp_node ) {
        pp_node->pnxt = ipt_node->pp_node;
        ipt_node->pp_node = pp_node;
    }
    else {
        pp_node->pnxt = NULL;
        ipt_node->pp_node = pp_node;
    }
}

static inline int JHashProPortAdd(ProtoPortNode **hamap, ProtoPortNodePool *nodepool,
        const ProtoPortNode *ppn, ProtoPortNode **ipt_target, IPTetStatNode *ipt_node, uint8_t cfl_plane)//, uint8_t db_data)
{
    uint32_t HashVal;
    ProtoPortNode **jHead;
    ProtoPortNode *iNode;
    ProtoPortNode *tNode;

    HashVal = jhash(&ppn->key, sizeof(ProtoProtNodeKeyDemo), 0);
    jHead = hamap + (HashVal&PROTOPORT_HASHSZ_MASK);
    tNode = *jHead;

    //New Node, Not In Hash List
    if ( NULL == tNode ) {
        if ( NULL == (iNode=SfProtoPortGetNode(nodepool, cfl_plane)) )
            return -1;
        jHashProtoPortDupNode(iNode, ppn);
        *jHead = iNode;
        jIptetAppendPpNode(ipt_node, iNode);
    }
    else {
        //Check Conflict List
        do {
            if ( !sf_memcmp(&tNode->nk, &ppn->nk, sizeof(ppn->nk)) ) {   // In Hash List
                if ( ppn->tv_upd > tNode->tv_upd )
                    tNode->tv_upd = ppn->tv_upd;
                tNode->cnt += ppn->cnt;
                tNode->bsz += ppn->bsz;
                if ( ipt_target )
                    *ipt_target = tNode;
                return 0;
            }

            if ( NULL == tNode->hnxt )
                break;
            tNode = tNode->hnxt;
        } while ( 1 );

        //Append to Conflict List
        if ( NULL == (iNode=SfProtoPortGetNode(nodepool, cfl_plane)) )
            return -1;
        jHashProtoPortDupNode(iNode, ppn);
        tNode->hnxt = iNode;
        jIptetAppendPpNode(ipt_node, iNode);
    }

    if ( ipt_target )
        *ipt_target = iNode;
    return 0;
}

/*static inline SSNProtoStatsCflNode * SfSSNProtoGetCflNode(SSNProtoCflNodePool *nodepool)
{
	SSNProtoStatsCflNode *eNode;

	//Scale Node
	if ( nodepool->npidx >= MAX_SSNPROTO_CONFLUENCE_NODE_SZ )
		return NULL;
	eNode = nodepool->nodes+nodepool->npidx;
	nodepool->npidx++;

	//pre-set node state
	eNode->cnt_up = 0;
	eNode->bsz_up = 0;
    eNode->cnt_down = 0;
    eNode->bsz_down = 0;

	return eNode;
}*/

static inline SSNProtoStatsNode * SfSSNProtoNodeGet(SSNProtoNodePool *nodepool, uint8_t cfl_plane)
{
    int i;
	SSNProtoStatsNode *eNode;

	//Confluence Node
/*	if ( cfl_plane )
		return (SSNProtoStatsNode*)SfSSNProtoGetCflNode((SSNProtoCflNodePool*)nodepool);
*/
	//Scale Node
	for ( i=0; i<MAX_SSNPROTO_NODE_SZ; i++ ) {
	    eNode = nodepool->nodes+nodepool->npidx;
	    nodepool->npidx = (nodepool->npidx+1)&SSNPROTO_NODE_SZ_MASK;
	    if ( PROSSN_IDLE == eNode->fsm.stat ) //Node valid (Not in use)
	        break;
	}

	if ( i >= MAX_SSNPROTO_NODE_SZ )
	    return NULL;

	nodepool->np_active++;
	return eNode;
}

static inline void jSSNProtoAppendNode(IPTetStatNode *ipt_node, SSNProtoStatsNode *pp_node)
{
    if ( NULL == ipt_node )
        return;

    if ( ipt_node->ssn_node ) {
        pp_node->snxt = ipt_node->ssn_node;
        ipt_node->ssn_node = pp_node;
    }
    else {
        pp_node->snxt = NULL;
        ipt_node->ssn_node = pp_node;
    }
}

static inline void jSSNProtoNodeQTDup(PktQuinTuple *qt_dst, PktQuinTuple *qt_src)
{
    qt_dst->cln_ip = qt_src->cln_ip;
    qt_dst->ser_ip = qt_src->ser_ip;
    qt_dst->cln_p = qt_src->cln_p;
    qt_dst->ser_p = qt_src->ser_p;
    qt_dst->proto = qt_src->proto;
}

static inline int jSSNProtoNodeQTCmp(PktQuinTuple *qt_dst, PktQuinTuple *qt_src)
{
    return ((qt_dst->cln_ip == qt_src->cln_ip)
            && (qt_dst->ser_ip == qt_src->ser_ip)
            && (qt_dst->cln_p == qt_src->cln_p)
            && (qt_dst->ser_p == qt_src->ser_p)
            && (qt_dst->proto == qt_src->proto));
}

static inline int SfSSNStatsNodeFind(SSNProtoStatsNode **hamap, SSNProtoNodePool *snodePool,
        PktQuinTuple *pkt_qt, SSNProtoStatsNode **target_node, IPTetStatNode *ipt_node,
        uint8_t getnew, uint8_t cfl_plane)
{
    uint32_t HashVal;
    SSNProtoStatsNode **jHead;
    SSNProtoStatsNode *iNode = NULL;
    SSNProtoStatsNode *tNode;

    HashVal = jhash(pkt_qt, sizeof(/*PktQuinTuple*/TetRad), 0);
    jHead = hamap + (HashVal&SSNPROTO_HASHSZ_MASK);
    tNode = *jHead;

    //New Node, Not In Hash List
    if ( NULL == tNode ) {
        if ( !getnew )
            return -1;
        if ( NULL == (iNode=SfSSNProtoNodeGet(snodePool, cfl_plane)) )
            return -1;
        //iNode->qt = *pkt_qt;
        jSSNProtoNodeQTDup(&iNode->qt, pkt_qt);
        *jHead = iNode;
        jSSNProtoAppendNode(ipt_node, iNode);
    }
    else {
        //Check Conflict List
        do {
            if ( jSSNProtoNodeQTCmp(&tNode->qt, pkt_qt) ) {   // In Hash List
                *target_node = tNode;
                return 0;
            }

            if ( NULL == tNode->hnxt )
                break;
            tNode = tNode->hnxt;
        } while ( 1 );

        //Not Found
        if ( !getnew )
            return -1;
        if ( NULL == (iNode=SfSSNProtoNodeGet(snodePool, cfl_plane)) )
            return -1;
        //iNode->qt = *pkt_qt;
        jSSNProtoNodeQTDup(&iNode->qt, pkt_qt);
        tNode->hnxt = iNode;
        jSSNProtoAppendNode(ipt_node, iNode);
    }

    *target_node = iNode;
    return 0;
}

static inline int SfSSNStatsNodeDel(SSNProtoStatsNode **hamap, SSNProtoNodePool *nodepool,
        SSNProtoStatsNode *targ_snode)
{
    uint32_t HashVal;
    SSNProtoStatsNode **jHead;
    SSNProtoStatsNode *tNode, *tNodePre;

    HashVal = jhash(&targ_snode->qt, sizeof(TetRad), 0);
    jHead = hamap + (HashVal&SSNPROTO_HASHSZ_MASK);
    tNode = *jHead;
    tNodePre = NULL;

    //New Node, Not In Hash List
    if ( NULL == tNode )
        return -1;

    //Check Conflict List
    do {
        //if ( jSSNProtoNodeQTCmp(&tNode->qt, &targ_snode->qt) ) {   // In Hash List
        if ( tNode == targ_snode ) {
            if ( NULL != tNodePre )
                tNodePre->hnxt = tNode->hnxt;
            else
                *jHead = tNode->hnxt;

            //clear node memory
            tNode->fsm.stat = PROSSN_RENEW;
            memset(tNode, 0, sizeof(SSNProtoStatsNode));
            tNode->fsm.stat = PROSSN_IDLE;
            nodepool->np_active--;
            return 0;
        }

        tNodePre = tNode;
    } while ( NULL != (tNode=tNode->hnxt) );

    return -1;
}

/*
static inline int SfSSNStatsNodeOper(IPTetStatNode *tnode, SSNProtoNodePool *snodePool,
        PktQuinTuple *pkt_qt, ProtoSsnOper ssnState, uint8_t cfl_plane)
{
    SSNProtoStatsNode *ssnNode;

	switch ( ssnState ) {
	case SSN_NODE_ADD:
		ssnNode = SfSSNProtoGetNode(snodePool, cfl_plane);
		if ( !ssnNode )
			return 1;

		ssnNode->state = 1;

    	if ( !tnode->ssn_node ) {
    		ssnNode->snxt = NULL;
    		tnode->ssn_node = ssnNode;
    	}
    	else {
    		ssnNode->snxt = tnode->ssn_node;
    		tnode->ssn_node = ssnNode;
    	}
		break;
	case SSN_NODE_GET:
	    break;
	case SSN_NODE_END:
		//if ( tnode->ssn_node && !cfl_plane ) {
			tnode->ssn_node->state = 0;
		//}
		break;
	default:
		break;
	}

	return 0;
}*/

static inline IPTetCflStatNode * SfIpTetGetCflNode(IPTetConfluenceNodePool *nodepool)
{
    int i;
    IPTetCflStatNode *eNode;

/*	if ( nodepool->npidx >= MAX_IPTET_CONFLUENCE_NODE_SZ )
		return NULL;

	eNode = nodepool->nodes+nodepool->npidx;
	nodepool->npidx++;*/

    for ( i=0; i<MAX_IPTET_CONFLUENCE_NODE_SZ; i++ ) {
        eNode = nodepool->nodes+nodepool->npidx;
        nodepool->npidx = (nodepool->npidx+1)&IPTET_CONFLUENCE_NODE_SZ_MASK;
        if ( NF_NODEIPT_IDLE == eNode->fsm ) { //Node valid (Not in use)
            eNode->fsm = NF_NODEIPT_RESERVED;
            nodepool->npcnt++;
            break;
        }
    }

    if ( i >= MAX_IPTET_CONFLUENCE_NODE_SZ )
        return NULL;

    return eNode;
}

static inline IPTetStatNode * SfIpTetGetNode(IPTetStatNodePool *nodepool, uint8_t cfl_plane)
{
	IPTetStatNode *eNode;

	//Confluence Node
	if ( cfl_plane )
		return (IPTetStatNode*)SfIpTetGetCflNode((IPTetConfluenceNodePool*)nodepool);

	//Scale Node
	if ( nodepool->npidx >= MAX_IPTET_NODE_SZ )
		return NULL;
	eNode = nodepool->nodes+nodepool->npidx;
	nodepool->npidx++;

	return eNode;
}

static inline void jHashIpTetDupNode(IPTetStatNode *dst, const IPTetStatNode *src,
		uint32_t hash_val, uint8_t cfl_plane, uint8_t db_data)
{
	uint8_t i;
	IPTetCflStatNode *iNodeCfl;

	dst->tet.src = src->tet.src;
	dst->tet.dst = src->tet.dst;
	dst->cnt = src->cnt;
	dst->bsize = src->bsize;
	dst->syn = src->syn;
	dst->dns = src->dns;
	dst->tv_upd = src->tv_upd;
	dst->direction = src->direction;
	dst->nxt = NULL;
	dst->pp_node = NULL;

	if ( cfl_plane ) {
		iNodeCfl = (IPTetCflStatNode*)dst;
		iNodeCfl->hsum = hash_val;
		if ( likely(!db_data) ) {
			iNodeCfl->fsm = NF_NODEIPT_NEW;
		}
		else {
		    iNodeCfl->fsm = NF_NODEIPT_SYNCED;
		    iNodeCfl->dbid = ((IPTetCflStatNode*)src)->dbid;
		    for ( i=0; i<NF_IPTET_PFLAG_NUM; i++ ) {
		        iNodeCfl->ppflag.flag[i] = ((IPTetCflStatNode*)src)->ppflag.flag[i];
		    }
		    iNodeCfl->almflag = ((IPTetCflStatNode*)src)->almflag;
		    iNodeCfl->aly_stat = ((IPTetCflStatNode*)src)->aly_stat;
		}
	}
}

static inline int JHashIpTetAdd(IPTetStatNode **hamap, IPTetStatNodePool *nodepool,
		const IPTetStatNode *ipt, IPTetStatNode **ipt_target, uint8_t cfl_plane, uint8_t db_data)
{
    uint32_t HashVal;
    IPTetStatNode **jHead;
    IPTetStatNode *iNode;
    IPTetStatNode *tNode;
    IPTetCflStatNode *iNodeCfl;

    HashVal = jhash(&(ipt->tet), sizeof(IPTet), 0);
    if ( cfl_plane )
    	jHead = hamap + (HashVal&IPTET_CONFLUENCE_HASHSZ_MASK);
    else
    	jHead = hamap + (HashVal&IPTET_HASHSZ_MASK);
    tNode = *jHead;

    //New Node, Not In Hash List
    if ( NULL == tNode ) {
    	if ( NULL == (iNode=SfIpTetGetNode(nodepool, cfl_plane)) )
    		return -1;
   		jHashIpTetDupNode(iNode, ipt, HashVal, cfl_plane, db_data);
    	*jHead = iNode;
    }
    else {
    	//Check Conflict List
    	do {
    		if ( tNode->tet.src == ipt->tet.src
    				&& tNode->tet.dst == ipt->tet.dst ) {	// In Hash List
    			tNode->cnt += ipt->cnt;
    			tNode->bsize += ipt->bsize;
    			tNode->syn += ipt->syn;
    			tNode->dns += ipt->dns;
    			if ( ipt->tv_upd > tNode->tv_upd )
    			    tNode->tv_upd = ipt->tv_upd;
    			tNode->direction = ipt->direction;
    			if ( cfl_plane ) {
    				iNodeCfl = (IPTetCflStatNode*)tNode;
    				if ( likely(!db_data) ) {
    					if ( NF_NODEIPT_SYNCED == iNodeCfl->fsm )
    						iNodeCfl->fsm = NF_NODEIPT_UPD;
    					else if ( NF_NODEIPT_NEW == iNodeCfl->fsm )
    						iNodeCfl->fsm = NF_NODEIPT_NEW_PLUS;
    					else if ( NF_NODEIPT_UPD == iNodeCfl->fsm )
    						iNodeCfl->fsm = NF_NODEIPT_UPD_PLUS;

    					iNodeCfl->qry_flag |= NF_IPTET_FLOW_DATA;
    				}
    				else
    					iNodeCfl->dbid = ((IPTetCflStatNode*)ipt)->dbid;
    			}

    			if ( ipt_target )
    				*ipt_target = tNode;
    			return 0;
    		}

    		if ( NULL == tNode->nxt )
    			break;
    		tNode = tNode->nxt;
    	} while ( 1 );

		//Append to Conflict List
    	if ( NULL == (iNode=SfIpTetGetNode(nodepool, cfl_plane)) )
    		return -1;
    	jHashIpTetDupNode(iNode, ipt, HashVal, cfl_plane, db_data);
    	tNode->nxt = iNode;
    }

    if ( ipt_target )
    	*ipt_target = iNode;
    return 0;
}

/*static inline int JHashIpTetCflSetExp(IPTetCflStatNode **hamap, IPTetConfluenceNodePool *nodepool,
        IPTet *tet, uint32_t targ_dbid)
{
    uint32_t HashVal;
    IPTetCflStatNode **jHead;
    IPTetCflStatNode *tNode;

    HashVal = jhash(tet, sizeof(IPTet), 0);
    jHead = hamap + (HashVal&IPTET_CONFLUENCE_HASHSZ_MASK);
    tNode = *jHead;

    //New Node, Not In Hash List
    if ( NULL == tNode )
        return -1;

    //Check Conflict List
    do {
        if ( tNode->dbid == targ_dbid ) {   // In Hash List
            tNode->expire = 1;
            return 0;
        }
    } while ( NULL != (tNode=tNode->nxt) );

    return -1;
}*/

static inline int JHashIpTetCflDel(IPTetCflStatNode **hamap, IPTetConfluenceNodePool *nodepool,
        IPTet *tet, uint64_t targ_dbid)
{
    uint32_t HashVal;
    IPTetCflStatNode **jHead;
    IPTetCflStatNode *tNode, *tNodePre;

    HashVal = jhash(tet, sizeof(IPTet), 0);
    jHead = hamap + (HashVal&IPTET_CONFLUENCE_HASHSZ_MASK);
    tNode = *jHead;
    tNodePre = NULL;

    //New Node, Not In Hash List
    if ( NULL == tNode )
        return -1;

    //Check Conflict List
    do {
        if ( tNode->dbid == targ_dbid ) {   // In Hash List
            if ( NULL != tNodePre )
                tNodePre->nxt = tNode->nxt;
            else
                *jHead = tNode->nxt;

            tNode->fsm = NF_NODEIPT_NON;
            memset(tNode, 0, sizeof(IPTetCflStatNode));
            tNode->fsm = NF_NODEIPT_IDLE;
            nodepool->npcnt--;
            return 0;
        }

        tNodePre = tNode;
    } while ( NULL != (tNode=tNode->nxt) );

    return -1;
}

static inline int JHashIpTetCflGetDbid(IPTetCflStatNode **hamap, const IPTet *iptet, uint64_t *ipt_dbid)
{
    uint32_t HashVal;
    IPTetCflStatNode **jHead;
    IPTetCflStatNode *tNode;

    HashVal = jhash(iptet, sizeof(IPTet), 0);
    jHead = hamap + (HashVal&IPTET_CONFLUENCE_HASHSZ_MASK);
    tNode = *jHead;

    //New Node, Not In Hash List
    if ( NULL == tNode )
        return -1;

    //Check Conflict List
    do {
        if ( tNode->tet.src == iptet->src
                && tNode->tet.dst == iptet->dst ) {   // In Hash List
            *ipt_dbid = tNode->dbid;
            return 0;
        }
    } while ( NULL != (tNode=tNode->nxt) );

    return -1;
}

int sf_CflInit(void *dp_cfl);
int sf_Confluence(void *dp_cfl, void *dp, uint8_t dp_type, uint8_t db_sync);
int sf_CflSsnInit(void);
int sf_CflSession(void *dp_cfl);
int sf_DBIns_Loop(void *dp_cfl);
//void sf_PktInspcProc(Packet *p);
//int sf_PktInspection(uint32_t ins_dev_idx, uint64_t lcore);
//void sf_PktInsCheckOp(void);

#endif	/*__MN_SF_CFL_H__*/
