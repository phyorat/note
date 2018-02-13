
#include "mn_sf_cfl.h"
#include "mn_sf_sys_var.h"




/*****Copy from rte_ring.h*****/
#define RING_F_SP_ENQ 0x0001 /**< The default enqueue is "single-producer". */
#define RING_F_SC_DEQ 0x0002 /**< The default dequeue is "single-consumer". */
/*****Copy from rte_ring.h end*****/

/* daq_dpdk_mbuf_ring collections ****************************/
daq_dpdk_mpool_collect mn_sf_daq_mbuf_coll [] =
{
        {MPOOL_STATSFLOW,    MR_ALL_QUEUES,    DAQ_DP_MP_SF_FLW,    SUR_SF_MP_NUM_POOL_SIZE,  sizeof(StatsFlowDataPlane), 0, 0, DAQ_DPDK_DP_SF_REIN, 0},
        {MPOOL_SF_STACK,     MR_ALL_QUEUES,    DAQ_DP_MP_SF_STK,    SUR_SF_MP_NUM_POOL_SIZE,  sizeof(ProStackStatNodesTbl), 0, 0, DAQ_DPDK_DP_SF_REIN, 0},
        {MPOOL_SF_SSN,       MR_ALL_QUEUES,    DAQ_DP_MP_SF_SSN,    SUR_SF_MP_SSN_MASTER_NUM, sizeof(StatsFlowDPSSN), 0, 0, DAQ_DPDK_DP_SF_REIN, 0},
        {MPOOL_SF_CFL_IPT_HA, MR_PRIMARY_NUMA_NODES,  DAQ_DP_MP_SFCFL_IPTHA,
                SUR_SF_MP_CFL_MASTER_NUM, sizeof(IPTetConfluenceNodeHaTbl)*MAX_IPTET_CONFLUENCE_HASHSZ, 0, 0, DAQ_DPDK_DP_SF, 0},
        {MPOOL_SF_CFL_IPTET, MR_PRIMARY_NUMA_NODES,  DAQ_DP_MP_SFCFL_IPT,
                SUR_SF_MP_CFL_MASTER_NUM, sizeof(IPTetCflStatNode)*MAX_IPTET_CONFLUENCE_NODE_SZ, 0, 0, DAQ_DPDK_DP_SF, 0},
        {MPOOL_SF_CFL_PP_HA, MR_PRIMARY_NUMA_NODES,  DAQ_DP_MP_SFCFL_PPHA,
                SUR_SF_MP_CFL_MASTER_NUM, sizeof(ProtoPortCflNodeHaTbl)*MAX_PROTOPORT_CFL_HASHSZ, 0, 0, DAQ_DPDK_DP_SF, 0},
        {MPOOL_SF_CFL_PROTP, MR_PRIMARY_NUMA_NODES,  DAQ_DP_MP_SFCFL_PP,
                SUR_SF_MP_CFL_MASTER_NUM, sizeof(ProtoPortCflNode)*MAX_PROTOPORT_CFL_NODE_SZ, 0, 0, DAQ_DPDK_DP_SF, 0},
        {MPOOL_SF_CFL,       MR_PRIMARY_ONLY,  DAQ_DP_MP_SF_CFL,    SUR_SF_MP_CFL_MASTER_NUM, sizeof(StatsFlowConfluDataPlane), 0, 0, DAQ_DPDK_DP_SF, 0},
        {MPOOL_SF_PPL,       MR_SINGLETON,     DAQ_DP_MP_SF_PPL,
                MAX_SSN_CHSUM_EQU_TRACK_PPL_NUM, MAX_SSN_CHSUM_EQU_TRACK_PPL_SIZE, 0, 0, DAQ_DPDK_DP_SF, 0},
//        {MPOOL_DETECT_MCH, MR_ALL_QUEUES,    "MPOOL_DTM__S%dP%dQ%d",1,0,0,0, DAQ_DPDK_SF_OTHER},
#ifdef BUILD_SP_DIGGER_MULTI_QUEUES
        {MPOOL_META,         MR_ALL_QUEUES,    DAQ_DP_MP_DG_MTA,    8*8192,    256, 0, 0, DAQ_DPDK_DP_DIGGER, 0},
        {MPOOL_META_PAYLOAD, MR_ALL_QUEUES,    DAQ_DP_MP_DG_MPL,    8*8192,    4096, 0, 0, DAQ_DPDK_DP_DIGGER, 0},
#else
        {MPOOL_META,         MR_SINGLETON,     DAQ_DP_MP_DG_MTA,    8*8192,    256, 0, 0, DAQ_DPDK_DP_DIGGER, 0},
        {MPOOL_META_PAYLOAD, MR_SINGLETON,     DAQ_DP_MP_DG_MPL,    8*8192,    4096, 0, 0, DAQ_DPDK_DP_DIGGER, 0},
#endif
        {MPOOL_DIGGER,       MR_SINGLETON,     DAQ_DP_MP_DG_INT,    16*8192,   4096, 0, 0, DAQ_DPDK_DP_DIGGER, 0},
        {MPOOL_PORT_BITMAP,  MR_ALL_QUEUES,    DAQ_DP_MP_SUR_PBM,   4,         sizeof(NetProtoPortIdBitmap), 0, 0, DAQ_DPDK_DP_SUR_REIN, 0},
        {MPOOL_MATCHED_PKT,  MR_ALL_QUEUES,    DAQ_DP_MP_SUR_MCP,   0x100000,  128, 0, 0, DAQ_DPDK_DP_DIGGER, 0},
        {MPOOL_GEO,          MR_SINGLETON,     DAQ_DP_MP_DG_GEO,    16*8192,   512, 0, 0, DAQ_DPDK_DP_DIGGER, 0},
        {MPOOL_AP_MSG,       MR_SINGLETON,     DAQ_DP_MP_MSG_AP,    64,        256, 16, 0, DAQ_DPDK_DP_AP, 0},
        {MPOOL_AP_SQ_OP,     MR_SINGLETON,     DAQ_DP_MP_EVN_PT,    8192,      SP_MPOOL_BUF_LEN, 0, 0, DAQ_DPDK_DP_SQ_REIN, 0},
};

daq_dpdk_ring_collect mn_sf_daq_ring_coll [] =
{
        {RING_STATSFLOW,     MR_ALL_QUEUES,    DAQ_DP_RING_SF_FLW,    SUR_SF_RING_MSG_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_DP_SF},
        {RING_SF_STACK,      MR_ALL_QUEUES,    DAQ_DP_RING_SF_STK,    SUR_SF_RING_MSG_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_DP_SF},
        //{RING_SF_ALY,        RING_ALL_QUEUES,  "RING_SF_ALY_S%dP%dQ%d", SUR_SF_RING_MSG_QUEUE_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_SF_OTHER},
#ifdef BUILD_SP_DIGGER_MULTI_QUEUES
        {RING_META,          MR_ALL_QUEUES,    DAQ_DP_RING_DG_MTA,    8*8192, 0, DAQ_DPDK_DP_DIGGER},
        {RING_META_PAYLOAD,  MR_ALL_QUEUES,    DAQ_DP_RING_DG_MPL,    8*8192, 0, DAQ_DPDK_DP_DIGGER},
#else
        {RING_META,          MR_SINGLETON,     DAQ_DP_RING_DG_MTA,    8*8192, 0, DAQ_DPDK_DP_DIGGER},
        {RING_META_PAYLOAD,  MR_SINGLETON,     DAQ_DP_RING_DG_MPL,    8*8192, 0, DAQ_DPDK_DP_DIGGER},
#endif
        {RING_DIGGER,        MR_SINGLETON,     DAQ_DP_RING_DG_INT,    16*8192, 0, DAQ_DPDK_DP_DIGGER},
        {RING_MSG_MASTER,    MR_SINGLETON,     DAQ_DP_RING_MASTER,    SUR_SF_RING_MSG_QUEUE_SIZE<<8, 0, DAQ_DPDK_DP_AP},
//        {RING_AP_MSG_DG,     MR_SINGLETON,     DAQ_DP_RING_MSG_DG,    SUR_SF_RING_MSG_QUEUE_SIZE, 0, DAQ_DPDK_DP_DIGGER},
        {RING_AP_MSG_SQ,     MR_SINGLETON,     DAQ_DP_RING_MSG_SQ,    SUR_SF_RING_MSG_QUEUE_SIZE, 0, DAQ_DPDK_DP_AP},
//        {RING_AP_MSG_PT,     MR_SINGLETON,     DAQ_DP_RING_MSG_PT,    SUR_SF_RING_MSG_QUEUE_SIZE, 0, DAQ_DPDK_DP_AP},
        {RING_AP_SQ_OP,      MR_SINGLETON,     DAQ_DP_RING_SQ_SND,    SP_RING_SND_CNT, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_DP_AP},
        {RING_AP_SQ_OP_RET,  MR_SINGLETON,     DAQ_DP_RING_SQ_RSV,    SP_RING_RET_CNT, RING_F_SP_ENQ | RING_F_SC_DEQ, DAQ_DPDK_DP_AP},
};

uint16_t mn_sf_daq_mbuf_get_count(void)
{
    return (sizeof(mn_sf_daq_mbuf_coll)/sizeof(daq_dpdk_mpool_collect));
}

uint16_t mn_sf_daq_ring_get_count(void)
{
    return (sizeof(mn_sf_daq_ring_coll)/sizeof(daq_dpdk_ring_collect));
}

NetFlowProtoMap map_netflow_proto[] =
{
        {FLOWSTA_PROTO_TCP,         IPPROTO_TCP},
        {FLOWSTA_PROTO_UDP,         IPPROTO_UDP},
        {FLOWSTA_PROTO_OTHER,       IPPROTO_IP},
        {FLOWSTA_PROTO_ICMP,        IPPROTO_ICMP},
};

NetFLowPortProtoMap map_netflow_portproto[NETFLOW_PORTPROTO_MAP_MAX] =
{
/*        {RPC_530_TCP_UDP,           {{FLOWSTA_APPRO_RPC,          FLOWSTA_APPRO_RPC}}},
        {RPC_593_TCP_UDP,           {{FLOWSTA_APPRO_RPC,          FLOWSTA_APPRO_RPC}}},
        {HTTP_80_TCP_UDP,           {{FLOWSTA_APPRO_HTTP,         FLOWSTA_APPRO_HTTP}}},
        {HTTP_8080_TCP,             {{FLOWSTA_APPRO_HTTP,         -1}}},
        {HTTP_8081_TCP,             {{FLOWSTA_APPRO_HTTP,         -1}}},
        {FTP_20_TCP_UDP,            {{FLOWSTA_APPRO_FTP,          FLOWSTA_APPRO_FTP}}},
        {FTP_21_TCP_UDP_SCTP,       {{FLOWSTA_APPRO_FTP,          FLOWSTA_APPRO_FTP}}},
        {IMAP_143_TCP,              {{FLOWSTA_APPRO_IMAP,         -1}}},
        {SNMP_161_UDP,              {{-1,                         FLOWSTA_APPRO_SNMP}}},
        {TELNET_23_TCP_UDP,         {{FLOWSTA_APPRO_TELNET,       FLOWSTA_APPRO_TELNET}}},
        {TELNET_992_TCP_UDP,        {{FLOWSTA_APPRO_TELNET,       FLOWSTA_APPRO_TELNET}}},
        {DNS_53_TCP_UDP,            {{FLOWSTA_APPRO_DNS,          FLOWSTA_APPRO_DNS}}},
        {SMTP_25_TCP_UDP,           {{FLOWSTA_APPRO_SMTP,         FLOWSTA_APPRO_SMTP}}},
        {RIP_520_UDP,               {{-1,                         FLOWSTA_APPRO_RIP}}},
        {RIPNG_521_UDP,             {{FLOWSTA_APPRO_RIPNG,        FLOWSTA_APPRO_RIPNG}}},
        {TFTP_69_TCP_UDP,           {{FLOWSTA_APPRO_TFTP,         FLOWSTA_APPRO_TFTP}}},
        {NNTP_119_TCP,              {{FLOWSTA_APPRO_NNTP,         -1}}},
        {NFS_1025_TCP,              {{FLOWSTA_APPRO_NFS,          -1}}},
        {NFS_1039_TCP_UDP,          {{FLOWSTA_APPRO_NFS,          FLOWSTA_APPRO_NFS}}},
        {NFS_1047_TCP_UDP,          {{FLOWSTA_APPRO_NFS,          FLOWSTA_APPRO_NFS}}},
        {NFS_1048_TCP_UDP,          {{FLOWSTA_APPRO_NFS,          FLOWSTA_APPRO_NFS}}},
        {NETBIOS_137_TCP_UDP,       {{FLOWSTA_APPRO_NETBIOS,      FLOWSTA_APPRO_NETBIOS}}},
        {NETBIOS_138_TCP_UDP,       {{FLOWSTA_APPRO_NETBIOS,      FLOWSTA_APPRO_NETBIOS}}},
        {NETBIOS_139_TCP_UDP,       {{FLOWSTA_APPRO_NETBIOS,      FLOWSTA_APPRO_NETBIOS}}},
        {POP2_109_TCP_UDP,          {{FLOWSTA_APPRO_POP2,         FLOWSTA_APPRO_POP2}}},
        {POP3_110_TCP_UDP,          {{FLOWSTA_APPRO_POP3,         FLOWSTA_APPRO_POP3}}},
        {0,                         {{-1,                         -1}}},     //End of records
*/

        {20,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_FTP_20,       FLOWSTA_APPRO_FTP,       "FTP Data", 1, 0},
        {21,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_FTP_21,       FLOWSTA_APPRO_FTP,       "FTP Control", 1, 0},
        {22,        NF_PROTP_BS_TCP,                        NF_APPRO_SSH,          FLOWSTA_APPRO_SSH,       "SSH", 1, 0},
        {23,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_TELNET,       FLOWSTA_APPRO_TELNET,    "Telnet", 1, 0},
        {25,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_SMTP,         FLOWSTA_APPRO_SMTP,      "SMTP", 1, 0},
        {37,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_TIME,         FLOWSTA_APPRO_UNKNOWN,   "Time", 1, 0},
        {39,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_RLP,          FLOWSTA_APPRO_UNKNOWN,   "RLP", 1, 0},
        {53,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_DNS,          FLOWSTA_APPRO_DNS,       "DNS", 1, 0},
        {56,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_RAP,          FLOWSTA_APPRO_UNKNOWN,   "RAP", 1, 0},
        {67,        NF_PROTP_BS_UDP,                        NF_APPRO_DHCP_67,      FLOWSTA_APPRO_DHCP,      "DHCP", 1, 0},
        {68,        NF_PROTP_BS_UDP,                        NF_APPRO_DHCP_68,      FLOWSTA_APPRO_DHCP,      "DHCP", 1, 0},
        {69,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_TFTP,         FLOWSTA_APPRO_TFTP,      "TFTP", 1, 0},
        {70,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_GOTHER,       FLOWSTA_APPRO_UNKNOWN,   "Gopher", 1, 0},
        {79,        NF_PROTP_BS_TCP,                        NF_APPRO_FINGER,       FLOWSTA_APPRO_UNKNOWN,   "Finger", 1, 0},
        {80,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_HTTP_80,      FLOWSTA_APPRO_HTTP,      "HTTP", 1, 0},
        {109,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_POP2,         FLOWSTA_APPRO_POP2,      "POP2", 1, 0},
        {110,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_POP3,         FLOWSTA_APPRO_POP3,      "POP3", 1, 0},
        {115,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_SFTP,         FLOWSTA_APPRO_UNKNOWN,   "SFTP", 1, 0},
        {119,       NF_PROTP_BS_TCP,                        NF_APPRO_NNTP,         FLOWSTA_APPRO_UNKNOWN,   "NNTP", 1, 0},
        {123,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_NTP,          FLOWSTA_APPRO_UNKNOWN,   "NTP", 1, 0},
        {137,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_NETBIOS_137,  FLOWSTA_APPRO_NETBIOS,   "NetBIOS Name Service", 1, 0},
        {138,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_NETBIOS_138,  FLOWSTA_APPRO_NETBIOS,   "NetBIOS Datagram Service", 1, 0},
        {139,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_NETBIOS_139,  FLOWSTA_APPRO_NETBIOS,   "NetBIOS Session Service", 1, 0},
        {143,       NF_PROTP_BS_TCP,                        NF_APPRO_IMAP,         FLOWSTA_APPRO_IMAP,      "IMAP", 1, 0},
        {153,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_SGMP,         FLOWSTA_APPRO_UNKNOWN,   "SGMP", 1, 0},
        {156,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_SQLSRV,       FLOWSTA_APPRO_UNKNOWN,   "SQL Service", 1, 0},
        {161,       NF_PROTP_BS_UDP,                        NF_APPRO_SNMP,         FLOWSTA_APPRO_SNMP,      "SNMP", 1, 0},
        {162,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_SNMPTRAP,     FLOWSTA_APPRO_UNKNOWN,   "SNMP Trap", 1, 0},
        {179,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_BGP,          FLOWSTA_APPRO_UNKNOWN,   "BGP", 1, 0},
        {209,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_QMTP,         FLOWSTA_APPRO_UNKNOWN,   "QMTP", 1, 0},
        {389,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_LDAP,         FLOWSTA_APPRO_UNKNOWN,   "LDAP", 1, 0},
        {443,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_HTTPS,        FLOWSTA_APPRO_HTTPS,     "HTTPS", 1, 0},
        {444,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_SNPP,         FLOWSTA_APPRO_UNKNOWN,   "SNPP", 1, 0},
        {445,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_MICRODS,      FLOWSTA_APPRO_MICRODS,   "Microsoft-DS", 1, 0},
        {464,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_KPASSWD,      FLOWSTA_APPRO_UNKNOWN,   "KPassWD", 1, 0},
        {465,       NF_PROTP_BS_TCP,                        NF_APPRO_SMTPS,        FLOWSTA_APPRO_UNKNOWN,   "SMTPS", 1, 0},
        {513,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_WHO,          FLOWSTA_APPRO_UNKNOWN,   "Who", 1, 0},
        {520,       NF_PROTP_BS_UDP,                        NF_APPRO_RIP,          FLOWSTA_APPRO_RIP,       "RIP", 1, 0},
        {521,       NF_PROTP_BS_UDP,                        NF_APPRO_RIPNG,        FLOWSTA_APPRO_UNKNOWN,   "RIPng", 1, 0},
        {530,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_RPC,          FLOWSTA_APPRO_RPC,       "RPC", 1, 0},
        {540,       NF_PROTP_BS_TCP,                        NF_APPRO_UUCP,         FLOWSTA_APPRO_UNKNOWN,   "UUCP", 1, 0},
        {593,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_HTTPRPC,      FLOWSTA_APPRO_UNKNOWN,   "HTTP-RPC", 1, 0},
        {636,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_LDAP_SSL,     FLOWSTA_APPRO_UNKNOWN,   "LDAPS", 1, 0},
        {989,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_FTP_SSL_989,  FLOWSTA_APPRO_UNKNOWN,   "FTPS", 1, 0},
        {990,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_FTP_SSL_990,  FLOWSTA_APPRO_UNKNOWN,   "FTPS", 1, 0},
        {992,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_TELNETSSL,    FLOWSTA_APPRO_UNKNOWN,   "TELNET-S", 1, 0},
        {1433,      NF_PROTP_BS_TCP,                        NF_APPRO_MSSQLSRV,     FLOWSTA_APPRO_MSSQL,     "MS SQL Server", 1, 0},
        {1434,      NF_PROTP_BS_UDP,                        NF_APPRO_MSSQLMON,     FLOWSTA_APPRO_UNKNOWN,   "MS SQL Monitor", 1, 0},
        {3306,      NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_MYSQL,        FLOWSTA_APPRO_MYSQL,     "MySQL", 1, 0},
        {5432,      NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_POSTRESQL,    FLOWSTA_APPRO_UNKNOWN,   "PostgreSQL", 1, 0},
        {8080,      NF_PROTP_BS_TCP,                        NF_APPRO_HTTP_8080,    FLOWSTA_APPRO_HTTP,      "HTTP", 1, 0},
        {8081,      NF_PROTP_BS_TCP,                        NF_APPRO_HTTP_8081,    FLOWSTA_APPRO_HTTP,      "HTTP", 1, 0},
//        {36688,     NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        NF_APPRO_QQ_36688,     FLOWSTA_APPRO_UNKNOWN,   "TX-Service", 1, 0},
        {0,         0,                                      NF_APPRO_UNKNOWN,      FLOWSTA_APPRO_UNKNOWN,   "Unknown", 0, 0},
};

//Should load from database at startup of system
NetFLowPortProtoMap map_netflow_portproto_user[NETFLOW_PORTPROTO_MAP_MAX] =
{
        {0, 0, NF_APPRO_UNKNOWN, FLOWSTA_APPRO_UNKNOWN, "Unknown", 0, 0}
};

NetFlowProtoPortReflect reflect_netflow_protoport_reflect[] =
{
        {FLOWSTA_APPRO_RPC,         NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_RPC),                                      0},
        {FLOWSTA_APPRO_HTTP,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,
                (0x01L<<NF_APPRO_HTTP_80)|(0x01L<<NF_APPRO_HTTP_8080)|(0x01L<<NF_APPRO_HTTP_8081),                                      0},
        {FLOWSTA_APPRO_FTP,         NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_FTP_20)|(0x01L<<NF_APPRO_FTP_21),          0},
        {FLOWSTA_APPRO_IMAP,        NF_PROTP_BS_TCP,                        (0x01L<<NF_APPRO_IMAP),                                     0},
        {FLOWSTA_APPRO_SNMP,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_SNMP),                                     0},
        {FLOWSTA_APPRO_TELNET,      NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_TELNET),                                   0},
        {FLOWSTA_APPRO_DNS,         NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_DNS),                                      0},
        {FLOWSTA_APPRO_SMTP,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_SMTP),                                     0},
        {FLOWSTA_APPRO_RIP,         NF_PROTP_BS_UDP,                        (0x01L<<NF_APPRO_RIP),                                      0},
        {FLOWSTA_APPRO_RIPNG,       0, 0, 0},
        {FLOWSTA_APPRO_TFTP,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_TFTP),                                     0},
        {FLOWSTA_APPRO_NNTP,        0, 0, 0},
        {FLOWSTA_APPRO_NFS,         0, 0, 0},
        {FLOWSTA_APPRO_NETBIOS,     NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,
                (0x01L<<NF_APPRO_NETBIOS_137)|(0x01L<<NF_APPRO_NETBIOS_138)|(0x01L<<NF_APPRO_NETBIOS_139),                              0},
        {FLOWSTA_APPRO_POP2,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_POP2),                                     0},
        {FLOWSTA_APPRO_POP3,        NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_POP3),                                     0},
        {FLOWSTA_APPRO_HTTPS,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_HTTPS),                                    0},
        {FLOWSTA_APPRO_SSH,         NF_PROTP_BS_TCP,                        (0x01L<<NF_APPRO_SSH),                                      0},
        {FLOWSTA_APPRO_DHCP,        NF_PROTP_BS_UDP,                        (0x01L<<NF_APPRO_DHCP_67)|(0x01L<<NF_APPRO_DHCP_68),        0},
        {FLOWSTA_APPRO_MICRODS,     NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_MICRODS),                                  0},
        {FLOWSTA_APPRO_MSSQL,       NF_PROTP_BS_TCP,                        (0x01L<<NF_APPRO_MSSQLSRV),                                 0},
        {FLOWSTA_APPRO_MYSQL,       NF_PROTP_BS_TCP|NF_PROTP_BS_UDP,        (0x01L<<NF_APPRO_MYSQL),                                    0},
        {FLOWSTA_APPRO_UNKNOWN,     0, 0, 0},
};

NetFlowItemToName map_netfow2dp[] =
{
    {NF_NET, FLOWSTA_NET_IP,            "ip"},
/*  {NF_NET, FLOWSTA_NET_IP_UP,         "ip[up]"},
    {NF_NET, FLOWSTA_NET_IP_DOWN,       "ip[down]"},
    {NF_NET, FLOWSTA_NET_IP_INTRA,      "ip[intra]"},
    {NF_NET, FLOWSTA_NET_IP_EXTER,      "ip[external]"},*/
    {NF_NET, FLOWSTA_NET_ARP,           "arp"},
    //{NF_NET, FLOWSTA_NET_SMALL,         "small_pkt"},
    //{NF_NET, FLOWSTA_NET_TCP_SYN,       "tcp_syn"},
    //{NF_NET, FLOWSTA_NET_TCP_NOF,       "tcp_noflag"},      //No Flag
    {NF_PROTO, FLOWSTA_PROTO_TCP,       "tcp"},
    {NF_PROTO, FLOWSTA_PROTO_UDP,       "udp"},
    {NF_PROTO, FLOWSTA_PROTO_OTHER,     "other"},
    {NF_PROTO, FLOWSTA_PROTO_ICMP,      "icmp"},
/*    {NF_PROTO, FLOWSTA_PROTO_TCP_UP,    "tcp[up]"},
    {NF_PROTO, FLOWSTA_PROTO_TCP_DOWN,  "tcp[down]"},
    {NF_PROTO, FLOWSTA_PROTO_UDP_UP,    "udp[up]"},
    {NF_PROTO, FLOWSTA_PROTO_UDP_DOWN,  "udp[down]"},
    {NF_PROTO, FLOWSTA_PROTO_ICMP_UP,   "icmp[up]"},
    {NF_PROTO, FLOWSTA_PROTO_ICMP_DOWN, "icmp[down]"},
    {NF_PROTO, FLOWSTA_PROTO_OTHER_UP,  "other[up]"},
    {NF_PROTO, FLOWSTA_PROTO_OTHER_DOWN,"other[down]"},
    {NF_PROTO, FLOWSTA_PROTO_MESS,      "mess_direction"},*/
    {NF_APPRO, FLOWSTA_APPRO_RPC,       "rpc"},
    {NF_APPRO, FLOWSTA_APPRO_HTTP,      "http"},
    {NF_APPRO, FLOWSTA_APPRO_FTP,       "ftp"},
    {NF_APPRO, FLOWSTA_APPRO_IMAP,      "imap"},
    {NF_APPRO, FLOWSTA_APPRO_SNMP,      "snmp"},
    {NF_APPRO, FLOWSTA_APPRO_TELNET,    "telnet"},
    {NF_APPRO, FLOWSTA_APPRO_DNS,       "dns"},
    {NF_APPRO, FLOWSTA_APPRO_SMTP,      "smtp"},
    {NF_APPRO, FLOWSTA_APPRO_RIP,       "rip"},
    {NF_APPRO, FLOWSTA_APPRO_RIPNG,     "ripng"},
    {NF_APPRO, FLOWSTA_APPRO_TFTP,      "tftp"},
    {NF_APPRO, FLOWSTA_APPRO_NNTP,      "nntp"},
    {NF_APPRO, FLOWSTA_APPRO_NFS,       "nfs"},
    {NF_APPRO, FLOWSTA_APPRO_NETBIOS,   "netbios"},
    {NF_APPRO, FLOWSTA_APPRO_POP2,      "pop2"},
    {NF_APPRO, FLOWSTA_APPRO_POP3,      "pop3"},
    {NF_APPRO, FLOWSTA_APPRO_HTTPS,     "https"},
    {NF_APPRO, FLOWSTA_APPRO_SSH,       "ssh"},
    {NF_APPRO, FLOWSTA_APPRO_DHCP,      "dhcp"},
    {NF_APPRO, FLOWSTA_APPRO_MICRODS,   "microsoft_ds"},
    {NF_APPRO, FLOWSTA_APPRO_MSSQL,     "mssql"},
    {NF_APPRO, FLOWSTA_APPRO_MYSQL,     "mysql"},
//    {NF_APPRO, FLOWSTA_APPRO_USER,      "user_set_ports"},
    {NF_APPRO, FLOWSTA_APPRO_UNKNOWN,   "ap_other"}
};

NetFlowDBTblName map_nf2dbtbl[] =
{
    {NF_NET, "nfnet_stats"},
    {NF_IPTET, "nfiptet_stats"},
    {NF_PROTO, "protocol_stats"},
    {NF_APPRO, "nfappro_stats"},
    {NF_PROSSN, "nfssn_stats"},
    {NF_PROTP, "nfprotp_stats"},
    {NF_INS_TRACK, "nf_ins_track"}
};

