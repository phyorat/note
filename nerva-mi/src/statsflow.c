


#include "statsflow.h"

#include "snort.h"
#include "sfdaq.h"
#include "session_api.h"
#include "session_common.h"
#include "stream_common.h"

static const char *server = "localhost";
static const char *database = "surveyor";
static const char *user = "root";
static const char *password = "13246";
static MYSQL *sf_mysql;
#if 0
static MYSQL *sfssn_mysql;
//static MYSQL *sfins_mysql;
static MYSQL *sfstack_mysql;

static const char *ipt_initfromdb = "select id,ip_src,ip_dst,tppflag,uppflag,tppflag_user,uppflag_user,pflag_other,almflag from %s";
static const char *ipt_insert = "insert into %s (ip_sum,ip_src,ip_dst,direction,tv_start,tv_upd,cnt,bsize,syn,dns,"
        "tppflag,uppflag,tppflag_user,uppflag_user,pflag_other,almflag) values(%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%u)";
static const char *ipt_update = "update %s set direction=%u,tv_upd=%u,cnt=cnt+%lu,bsize=bsize+%lu,syn=syn+%lu,dns=dns+%lu,"
        "tppflag=%lu,uppflag=%lu,tppflag_user=%lu,uppflag_user=%lu,pflag_other=%lu,almflag=%u where id=%lu";
static const char *ipt_upd_almflag = "update %s set almflag=%u where id=%lu";
//static const char *ipt_select = "select ip_src,ip_dst,tv_upd,cnt,syn from %s where id=%u";
static const char *ipt_delete = "delete from %s where id=%lu";
static const char *iptssn_insert = "insert into %s (ipt_id,proto,direction,port_src,port_dst,cnt_up,bsz_up,cnt_down,bsz_down,"
        "flg_psh,bsz_sml,tv_start,tv_upd,tv_dur,state) values(%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u)";
/*static const char *iptssn_update = "update %s set cnt_up=%u,bsz_up=%u,cnt_down=%u,bsz_down=%u,"
        "flg_psh=%u,bsz_sml=%u,tv_upd=%u,tv_dur=%u where id=%lu";*/
static const char *iptssn_update = "update %s set cnt_up=%u,bsz_up=%u,cnt_down=%u,bsz_down=%u,"
        "flg_psh=%u,bsz_sml=%u,tv_upd=%u,tv_dur=%u,state=%u where id=%lu";
static const char *protp_insert = "insert into %s (ipt_id,ip_src,ip_dst,tv_upd,proto,port,port_idx,user_set,cnt_vi,bsz_vi,cnt_vo,bsz_vo) "
        "values(%lu,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu)";
static const char *protp_set_pp_id = "SET @pp_id=LAST_INSERT_ID()";
static const char *protp_update = "update %s set tv_upd=%u,cnt_vi=cnt_vi+%lu,bsz_vi=bsz_vi+%lu,"
        "cnt_vo=cnt_vo+%lu,bsz_vo=bsz_vo+%lu,id=(select @pp_id := id) "
        "where ipt_id=%lu and proto=%u and port_idx=%u and user_set=%u ORDER BY id DESC LIMIT 1";
static const char *protp_scale_throw = "INSERT INTO %s (pp_id,scl_cmb,tv_upd,cnt_vi,bsz_vi,cnt_vo,bsz_vo,direc) "
        "SELECT @pp_id,%u,%u,%u,%u,%u,%u,%u ON DUPLICATE KEY UPDATE tv_upd=VALUES(tv_upd),cnt_vi=VALUES(cnt_vi),bsz_vi=VALUES(bsz_vi),"
        "cnt_vo=VALUES(cnt_vo),bsz_vo=VALUES(bsz_vo)";
static const char *protp_scale_add = "INSERT INTO %s (pp_id,scl_cmb,tv_upd,cnt_vi,bsz_vi,cnt_vo,bsz_vo,direc) "
        "SELECT @pp_id,%u,%u,%u,%u,%u,%u,%u ON DUPLICATE KEY UPDATE tv_upd=VALUES(tv_upd),cnt_vi=cnt_vi+VALUES(cnt_vi),bsz_vi=bsz_vi+VALUES(bsz_vi),"
        "cnt_vo=cnt_vo+VALUES(cnt_vo),bsz_vo=bsz_vo+VALUES(bsz_vo)";
static const char *scale_cmb_table_name [] = {
        "nfprotp_stats_scale_l1",
        "nfprotp_stats_scale_l2",
        "nfprotp_stats_scale_l3",
        "nfprotp_stats_scale_l4",
};
/*static const char *protp_scale_throw = "REPLACE INTO nfprotp_stats_scale (pp_id,scl_cmb,tv_upd,cnt_vi,bsz_vi,cnt_vo,bsz_vo) "
        "SELECT @pp_id,%u,%u,%u,%u,%u,%u";*/
static const char *protp_delete = "delete from %s where ipt_id=%lu";

static const char *stack_insert = "insert into %s (pid,name,port_idx,user,port,direction,cnt,bsz,bps) values(%u,'%s',%u,%u,%u,%u,%lu,%lu,%u)";
static const char *stack_update = "update %s set port=%u,cnt=%lu,bsz=%lu,bps=%u where pid=%u and direction=%u";
static const char *stack_select = "SELECT pid,direction,cnt,bsz FROM %s ORDER BY pid ASC";

static const char *iptssn_pkt_sample = "INSERT INTO nfssn_track_hbpkt (ssn_id,ipt_id,tv_stamp,pkt_sample) VALUES(%lu,%lu,%u,'";


static char sql_cfl[1024] = "";
static char sql_cfl_pp_scl[1024] = "";
static char sql_cfl_ssn[1024] = "";
//static char sql_cfl_dbins[1024] = "";
static char sql_cfl_stack[1024] = "";
#endif

static CounterNetFlow sfPktInspectCons;
static void *sfPortMapList[2] = {NULL};
static NetProtoPortIdBitmap *sfPortMapInstance[2] = {NULL};
static StatsFlowNodeExp *nodesElem = NULL;
//static StatsFlowGlobal sfGlobalInfo = {0,0,0,0,0};

//buffer for ssn-packet sample BASE64
//static char sanitize_buffer[SSN_CHSUM_SQU_TRACK_BASE64_BUFLEN];
//static char sql_cfl_ssn_ptrc[SSN_CHSUM_SQU_TRACK_BASE64_BUFLEN+1024] = "";

/*static uint8_t nf_app_proto_t_bitset_map[] =
{
        FLOWSTA_APPRO_COUNT*FLOWSTA_PROTO_TCP,
        FLOWSTA_APPRO_COUNT*FLOWSTA_PROTO_UDP,
        FLOWSTA_APPRO_COUNT*FLOWSTA_PROTO_OTHER,
};*/

#if 0
NetFlowProtoMap map_netflow_proto[] =
{
        {FLOWSTA_PROTO_TCP,         IPPROTO_TCP},
        {FLOWSTA_PROTO_UDP,         IPPROTO_UDP},
        {FLOWSTA_PROTO_OTHER,       IPPROTO_IP},
        {FLOWSTA_PROTO_ICMP,        IPPROTO_ICMP},
};

NetFLowPortProtoMap map_netflow_portproto[] =
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
NetFLowPortProtoMap map_netflow_portproto_user[SF_MAX_PROT_PROTO_USER+1] =
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
	{NF_NET, FLOWSTA_NET_IP,			"ip"},
/*	{NF_NET, FLOWSTA_NET_IP_UP,         "ip[up]"},
	{NF_NET, FLOWSTA_NET_IP_DOWN,		"ip[down]"},
	{NF_NET, FLOWSTA_NET_IP_INTRA,		"ip[intra]"},
	{NF_NET, FLOWSTA_NET_IP_EXTER,      "ip[external]"},*/
    {NF_NET, FLOWSTA_NET_ARP,			"arp"},
    //{NF_NET, FLOWSTA_NET_SMALL,         "small_pkt"},
    //{NF_NET, FLOWSTA_NET_TCP_SYN,       "tcp_syn"},
    //{NF_NET, FLOWSTA_NET_TCP_NOF,       "tcp_noflag"},      //No Flag
    {NF_PROTO, FLOWSTA_PROTO_TCP,		"tcp"},
    {NF_PROTO, FLOWSTA_PROTO_UDP,		"udp"},
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
    {NF_APPRO, FLOWSTA_APPRO_RPC,		"rpc"},
    {NF_APPRO, FLOWSTA_APPRO_HTTP,		"http"},
    {NF_APPRO, FLOWSTA_APPRO_FTP,		"ftp"},
    {NF_APPRO, FLOWSTA_APPRO_IMAP,		"imap"},
    {NF_APPRO, FLOWSTA_APPRO_SNMP,		"snmp"},
    {NF_APPRO, FLOWSTA_APPRO_TELNET,	"telnet"},
    {NF_APPRO, FLOWSTA_APPRO_DNS,		"dns"},
    {NF_APPRO, FLOWSTA_APPRO_SMTP,		"smtp"},
    {NF_APPRO, FLOWSTA_APPRO_RIP,		"rip"},
    {NF_APPRO, FLOWSTA_APPRO_RIPNG,		"ripng"},
    {NF_APPRO, FLOWSTA_APPRO_TFTP,		"tftp"},
    {NF_APPRO, FLOWSTA_APPRO_NNTP,		"nntp"},
    {NF_APPRO, FLOWSTA_APPRO_NFS,		"nfs"},
    {NF_APPRO, FLOWSTA_APPRO_NETBIOS,	"netbios"},
    {NF_APPRO, FLOWSTA_APPRO_POP2,		"pop2"},
    {NF_APPRO, FLOWSTA_APPRO_POP3,		"pop3"},
    {NF_APPRO, FLOWSTA_APPRO_HTTPS,		"https"},
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

char db_info[][16] =
{
	{"localhost"}, {"surveyor"}, {"root"}, {"13246"}
};
#endif

char *netflow_getnamebytype(netflow_stack nfstack, uint32_t nftype)
{
	int i;
	for(i=0; i<(FLOWSTA_NET_COUNT+FLOWSTA_PROTO_COUNT+FLOWSTA_APPRO_COUNT); i++) {
		if ( nfstack == map_netfow2dp[i].nf_stack
				&& nftype == map_netfow2dp[i].nf_type )
			return map_netfow2dp[i].nf_name;
	}

	return NULL;
}

int netflow_getproidbyname(char *name)
{
    int i;
    for(i=0; i<(FLOWSTA_NET_COUNT+FLOWSTA_PROTO_COUNT+FLOWSTA_APPRO_COUNT); i++) {
        if ( !strncmp(name, map_netfow2dp[i].nf_name, strlen(map_netfow2dp[i].nf_name)) )
            return i;
    }

    return -1;
}

static int MysqlConnect(MYSQL **sql_ins)
{
    *sql_ins = mysql_init(NULL);

    if(!mysql_real_connect(*sql_ins, server, user,
                password, database, 0, NULL, /*0*/CLIENT_INTERACTIVE)) {
        LogMessage("Failed to connect to database %s:%s@%s/%s: %s\n",
                user, password, server,
                database, mysql_error(*sql_ins));
        return 1;
    }

    mysql_autocommit(*sql_ins, 0);

    return 0;
}

static int MysqlSelectDbRes(MYSQL *sql_conn, char *sql_str, MYSQL_RES **mysql_res)
{
    int totalrows;

    if (mysql_query(sql_conn, sql_str) != 0) {
        LogMessage("Error (%s) executing query: %s\n", mysql_error(sql_conn), sql_str);
        return -1;
    }

    *mysql_res = mysql_store_result(sql_conn);
    totalrows = mysql_num_rows(*mysql_res);
    //numfields = mysql_num_fields(*mysql_res);

    return totalrows;
}

#if 0
static inline int MysqlTransBegin(MYSQL *sql_conn)
{
    if( 0 != mysql_query(sql_conn, "BEGIN;") ) {
        LogMessage("Error (%s) executing begin transaction\n", mysql_error(sql_conn));
        return -1;
    }

    return 0;
}

static inline int MysqlTransCommit(MYSQL *sql_conn)
{
    if( 0 != mysql_query(sql_conn, "COMMIT;") ) {
        LogMessage("Error (%s) executing commit transaction\n", mysql_error(sql_conn));
        return -1;
    }

    return 0;
}

static inline int MysqlTransRollback(MYSQL *sql_conn)
{
    if( 0 != mysql_query(sql_conn, "ROLLBACK;") ) {
        LogMessage("Error (%s) executing rollback transaction\n", mysql_error(sql_conn));
        return -1;
    }

    return 0;
}

static inline int MysqlQuery(MYSQL *sql_conn, const char *sql, unsigned int *row_id)
{
	int result;

    if( 0 != (result=mysql_query(sql_conn, sql)) ) {
        LogMessage("Error (%s) executing query: %s\n", mysql_error(sql_conn), sql);
        return -1;
    }

    if(row_id != NULL)
        *row_id = mysql_insert_id(sql_conn);
    return 0;
}

static inline int MysqlQueryUlid(MYSQL *sql_conn, const char *sql, unsigned long *row_id)
{
    int result;

    if( 0 != (result=mysql_query(sql_conn, sql)) ) {
        LogMessage("Error (%s) executing query: %s\n", mysql_error(sql_conn), sql);
        return -1;
    }

    if(row_id != NULL)
        *row_id = mysql_insert_id(sql_conn);
    return 0;
}
#endif


#define NET_PORT_BM_BIT_COUNT32(c, v)                   do {    \
                                                            v = v - ((v >> 1) & 0x55555555);  \
                                                            v = (v & 0x33333333) + ((v >> 2) & 0x33333333);   \
                                                            c += ((((v + (v >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24);   \
                                                        } while (0);

#define NET_PORT_BM_BIT_COUNT64(c, v)                   do {    \
                                                            uint32_t x, y;                      \
                                                            x = v&0xffffffff;                   \
                                                            y = v>>32;                          \
                                                            x = x - ((x >> 1) & 0x55555555);    \
                                                            y = y - ((y >> 1) & 0x55555555);    \
                                                            x = (x & 0x33333333) + ((x >> 2) & 0x33333333); \
                                                            y = (y & 0x33333333) + ((y >> 2) & 0x33333333); \
                                                            x = (x + (x >> 4)) & 0x0F0F0F0F;    \
                                                            y = (y + (y >> 4)) & 0x0F0F0F0F;    \
                                                            x = x + (x >> 8);                   \
                                                            y = y + (y >> 8);                   \
                                                            x = x + (x >> 16);                  \
                                                            y = y + (y >> 16);                  \
                                                            c += ((x+y) & 0x000000FF);          \
                                                        } while (0);

#define NET_PORT_BM_SET(bm, stc, port, mi, mi2)         do {    \
                                                            mi = (((port)>>6)&0xfc0)+(((port)>>6)&0x3f);    \
                                                            *((bm)+(mi)) |= (0x01L<<((port)&0x3f)); \
                                                            if (mi2 != mi) {                        \
                                                                *((stc)+(mi)) = *((stc)+(mi2));     \
                                                                while (++mi2 < mi) {                \
                                                                    *((stc)+(mi2)) = *((stc)+(mi)); \
                                                                }                                   \
                                                            }                                       \
                                                            *((stc)+(mi)) += 1;                     \
                                                        } while(0);

#define NET_PORT_BM_GET_BIT(bm, port, mi, tbm, bset)    do {    \
                                                            mi = (((port)>>6)&0xfc0)+(((port)>>6)&0x3f);    \
                                                            tbm = *((bm)+(mi));                 \
                                                            bset = tbm & (0x01L<<((port)&0x3f));   \
                                                        } while (0);

#define NET_PORT_BM_PP_IDX(stc, mi, tbm, bset, pi)      do {    \
                                                            if (mi)                                 \
                                                                pi = *((stc)+(mi-1));               \
                                                            else                                    \
                                                                pi = 0;                             \
                                                            tbm &= (bset-1);                        \
                                                            NET_PORT_BM_BIT_COUNT64(pi, tbm);       \
                                                        } while(0);

static int sf_NetProtoPort_BitMap(void)
{
    uint8_t pm_idx;
    uint16_t map_idx, map_idx2;
    DataplaneAddrs addr;
    NetFLowPortProtoMap *p_ppmap;

    addr.sock_id = -1;

    //Init Port-Bitmap
    if ( 0 != DAQ_APGetMBuf((void*)&addr, MPOOL_PORT_BITMAP) ) {
        LogMessage("%s: Can't get MBuf for net_port_bitmap.\n", __func__);
        return -1;
    }
    sfPortMapInstance[0] = (NetProtoPortIdBitmap*)addr.dp_main;

    if ( 0 != DAQ_APGetMBuf((void*)&addr, MPOOL_PORT_BITMAP) ) {
        LogMessage("%s: Can't get MBuf for net_port_user_bitmap.\n", __func__);
        DAQ_APPutMBuf(sfPortMapInstance[0], MPOOL_PORT_BITMAP);
        return -1;
    }
    sfPortMapInstance[1] = (NetProtoPortIdBitmap*)addr.dp_main;

    //0, User defined port; 1, System default
    for ( pm_idx=0; pm_idx<2; pm_idx++ ) {
        p_ppmap = (NetFLowPortProtoMap*)(sfPortMapList[pm_idx]);
        map_idx = 0;
        map_idx2 = 0;
        while ( p_ppmap->pp_switch ) {
            NET_PORT_BM_SET(sfPortMapInstance[pm_idx]->bm, sfPortMapInstance[pm_idx]->stc,
                    p_ppmap->port, map_idx, map_idx2);

//            LogMessage("%s: pm_idx %d, port %d\n", __func__, pm_idx, p_ppmap->port);
            p_ppmap++;
        }
    }

/*    LogMessage("%s: bm--0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx\n", __func__,
            port_bm[1]->bm[0], port_bm[1]->bm[1], port_bm[1]->bm[2], port_bm[1]->bm[3], port_bm[1]->bm[4],
            port_bm[1]->bm[5], port_bm[1]->bm[6], port_bm[1]->bm[7], port_bm[1]->bm[8], port_bm[1]->bm[9]);

    LogMessage("%s: stc--%d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n", __func__,
            port_bm[1]->stc[0], port_bm[1]->stc[1], port_bm[1]->stc[2], port_bm[1]->stc[3], port_bm[1]->stc[4],
            port_bm[1]->stc[5], port_bm[1]->stc[6], port_bm[1]->stc[7], port_bm[1]->stc[8], port_bm[1]->stc[9]);*/

    return 0;
}

static inline int sf_CheckSetProtoPort(Packet *p, ProtoProtNodeKeyDemo *pp_nk, uint8_t proto_bitset)
{
    uint8_t c_cnt, pm_idx, pp_idx;
    uint8_t port_vec;
    uint16_t port;
    uint16_t map_idx;
    uint64_t targ_bm, bitset;
//    void *pt_ppmap[2] = {map_netflow_portproto_user, map_netflow_portproto};
    NetFLowPortProtoMap *p_ppmap;

    if ( proto_bitset ) {       //TCP or UDP
        //0, User defined port; 1, System default
        for ( pm_idx=0; pm_idx<2; pm_idx++ ) {
            //destination port
            port = p->dp;
            port_vec = PORT_VEC_IN;
            c_cnt = 2;
            do {
/*                p_ppmap = (NetFLowPortProtoMap*)(sfPortMapList[pm_idx]);
                while ( p_ppmap->pp_switch ) {
                    if ( port != p_ppmap->port ) {
                        p_ppmap++;
                        continue;
                    }

                    if ( p_ppmap->pro_bitset & proto_bitset ) {*/

                NET_PORT_BM_GET_BIT(sfPortMapInstance[pm_idx]->bm, port, map_idx, targ_bm, bitset);
/*                LogMessage("%s: port[%d] %d, mi %d, tbm 0x%lx, bs 0x%lx\n", __func__,
                        c_cnt, port, map_idx, targ_bm, bitset);*/
                if ( bitset ) {
                    NET_PORT_BM_PP_IDX(sfPortMapInstance[pm_idx]->stc, map_idx, targ_bm, bitset, pp_idx);
                    p_ppmap = (NetFLowPortProtoMap*)sfPortMapList[pm_idx];
                    //LogMessage("%s: found, port %d, pp_idx %d\n", __func__, port, pp_idx);
                    if ( p_ppmap[pp_idx].pro_bitset & proto_bitset ) {
                        pp_nk->user_set = !pm_idx;      //first(pm_idx==0) for user_set
                        pp_nk->port_vec = port_vec;
                        pp_nk->apport_idx = p_ppmap[pp_idx].pp_index;
                        pp_nk->port = port;
                        return p_ppmap[pp_idx].fp_index;
                    }
                }
/*                    p_ppmap++;
                }*/

                //source port
                port = p->sp;
                port_vec = PORT_VEC_OUT;
            } while ( --c_cnt>0 );
        }
    }

    pp_nk->user_set = 0;
    pp_nk->port_vec = PORT_VEC_INVALID;
    pp_nk->apport_idx = NF_APPRO_UNKNOWN;
    pp_nk->port = 0;
    return FLOWSTA_APPRO_UNKNOWN;
}

static inline void sf_ProtoPortPrint(void)
{
    uint8_t pm_idx;
    NetFLowPortProtoMap *p_ppmap;

    if ( 1 ) {       //TCP or UDP
        //0, User defined port; 1, System default
        for ( pm_idx=0; pm_idx<2; pm_idx++ ) {
            //destination port
                p_ppmap = (NetFLowPortProtoMap*)(sfPortMapList[pm_idx]);
                while ( p_ppmap->pp_switch ) {
                    LogMessage("%s: pm_idx %d, port %d\n", __func__, pm_idx, p_ppmap->port);
                    p_ppmap++;
                }
        }
    }
}

#define SF_PROCSSN_INIT_NODE(tar_snode)            do {    \
    tar_snode->tv_upd = tar_snode->tv_start = p->pkth->ts.tv_sec;/*time(NULL);*/  \
    /*Identify direction*/      \
    if ( SF_STREAM_UP == stype ) {      \
        if ( nodesElem->pkt_qt.cln_ip == tnode->tet.src )      \
            tar_snode->qt.direction = SF_SESSION_OUT;       \
        else        \
            tar_snode->qt.direction = SF_SESSION_IN;        \
    }       \
    else {      \
        if ( nodesElem->pkt_qt.cln_ip == tnode->tet.dst )      \
            tar_snode->qt.direction = SF_SESSION_OUT;       \
        else        \
            tar_snode->qt.direction = SF_SESSION_IN;        \
    }       \
} while (0);

static inline void PktCnt_SsnTrackScs(SSNCksumTrack * p_track, uint16_t tu_sum, uint16_t t_intev)
{
    //track
    if ( (p_track->cksum != tu_sum || 0 == p_track->cnt_cs) ) {
        if ( SSN_CS_TRACK_CAP != p_track->cap ) {
            p_track->cap = SSN_CS_TRACK_PRE_CAP;
            p_track->cksum = tu_sum;
            p_track->cnt_cs = 1;
            p_track->tv_int_max = p_track->tv_int_min = 0;
        }
    }
    else {
        if ( 1 == p_track->cnt_cs )
            p_track->tv_int_max = p_track->tv_int_min = t_intev;
        else if ( t_intev > p_track->tv_int_max )
            p_track->tv_int_max = t_intev;
        else if ( t_intev < p_track->tv_int_min )
            p_track->tv_int_min = t_intev;

        if ( p_track->cnt_cs < MAX_SSN_CHSUM_EQU_TRACK_CNT_MA )
            p_track->cnt_cs ++;
    }
}

static inline void PktCnt_SsnInspcScs(SSNCksumTrack * p_track, SSNProtoStatsNode *t_snode, Packet *p, uint8_t role)
{
    int ret_m;
    DataplaneAddrs dpMbufs;

    dpMbufs.sock_id = -1;

    //inspection
    if ( ( SSN_CS_TRACK_PRE_CAP == p_track->cap )
            && (p_track->cnt_cs > SSN_CHSUM_SP_HB_PCNT_THRESHOLD)
            && ((p_track->tv_int_max-p_track->tv_int_min) < SSN_CHSUM_SP_HB_PTS_RELATE_DIFF) ) {
        ret_m = DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_SF_PPL);
        if ( !ret_m ) {
            p_track->data_len = ((p->pkth->caplen > MAX_SSN_CHSUM_EQU_TRACK_PPL_MA) ? MAX_SSN_CHSUM_EQU_TRACK_PPL_MA:(p->pkth->caplen));
            DAQ_RteMemcpy(dpMbufs.dp_main, (const void*)p->pkt, p_track->data_len);
            p_track->data_pl = dpMbufs.dp_main;
            p_track->tv_stamp = p->pkth->ts.tv_sec;
            p_track->cap = SSN_CS_TRACK_CAP;
            /*LogMessage("%s: detect same cksum pkt(role: %d), src_ip %x, dst_ip %x, port %d, sum %x, data_len %d\n", __func__,
                    role, t_snode->qt.cln_ip, t_snode->qt.ser_ip, t_snode->qt.ser_p, p_track->cksum,
                    p_track->data_len);*/
        }
    }
}

static inline int PktCnt_ProcSsn(StatsFlowDPSSN *sfdp, IPTetStatNode *tnode, Packet *p, StreamDirection stype)
{
    //ProtoSsnState ssn_state = PROSSN_NONE;
#ifndef TCP_SSN_PKTGEN_DEBUG
    uint32_t ssn_flags = 0;
    uint32_t ssn_state = 0;
#endif
    uint32_t tcp_flags = 0;
    uint16_t p_ck_sum = 0, tv_pgap;
    SessionControlBlock *ssnblk;
    SSNProtoStatsNode *tar_snode = NULL;

    if ( p->ssnptr ) {
        if ( p->tcph ) {
            tcp_flags = p->tcph->th_flags;
            p_ck_sum = p->tcph->th_sum;
        }
        else if ( p->udph ) {
            tcp_flags = 0;
            p_ck_sum = p->udph->uh_chk;
        }
        else {
            return 0;
        }

        ssnblk = (SessionControlBlock*)(p->ssnptr);

#ifndef TCP_SSN_PKTGEN_DEBUG
        ssn_flags = ssnblk->ha_state.session_flags;
        ssn_state = ssnblk->session_state;
/*        LogMessage("%s: ssn_flags %x, ssn_state %x, tcp_flags %x, %x.%x.%x.%x, %x.%x.%x.%x\n", __func__,
                ssn_flags, ssn_state, tcp_flags,
                ssnblk->client_ip.ia32[0], ssnblk->client_ip.ia32[1], ssnblk->client_ip.ia32[2], ssnblk->client_ip.ia32[3],
                ssnblk->server_ip.ia32[0], ssnblk->server_ip.ia32[1], ssnblk->server_ip.ia32[2], ssnblk->server_ip.ia32[3]);*/
#endif
        nodesElem->pkt_qt.cln_ip = ssnblk->client_ip.ia32[3];
        nodesElem->pkt_qt.ser_ip = ssnblk->server_ip.ia32[3];
        nodesElem->pkt_qt.cln_p = ntohs(ssnblk->client_port);
        nodesElem->pkt_qt.ser_p = ntohs(ssnblk->server_port);
        nodesElem->pkt_qt.proto = ssnblk->protocol;

        /***********FOR DEBUG, we need to find way identifying tcp session activity**************/
        //If we should stop this ssn recorder         /*(ssn_flags&SSNFLAG_CLIENT_FIN) && (ssn_flags&SSNFLAG_SERVER_FIN)*/
#ifdef TCP_SSN_PKTGEN_DEBUG
        if  ( TH_FIN & tcp_flags ) {
#else
        if  ( (ssn_state&STREAM_STATE_ESTABLISHED)
                && (ssn_flags&SSNFLAG_COUNTED_CLOSING) ) {
#endif
            //SfSSNStatsNodeOper(tnode, &sfdp->snode, SSN_NODE_END, 0);
            if ( 0 == SfSSNStatsNodeFind(sfdp->h_snode.hatbl, &sfdp->snode,
                    &nodesElem->pkt_qt, &tar_snode, tnode, 0, 0) ) {
                if ( PROSSN_DOING == tar_snode->fsm.stat ) {
                    //tar_snode->tv_dur = p->pkth->ts.tv_sec-tar_snode->tv_start;
                    tar_snode->fsm.stat = PROSSN_END;

                    /*LogMessage("%s: >>>>>^^^^^ session end(ssn_cnt: %d): src_ip %x, dst_ip %x, src_port %u, dst_port %u\n", __func__,
                            sfdp->snode.np_active, tnode->tet.src, tnode->tet.dst, p->sp, p->dp);*/
                }
            }
        }
        /***********FOR DEBUG, we need to find way identifying tcp session activity**************/
        //If we should start a new ssn recorder        /*else if ( (ssn_flags&SSNFLAG_SEEN_CLIENT) && (ssn_flags&SSNFLAG_SEEN_SERVER) ) {*/
            /*if ( 0 == SfSSNStatsNodeOper(tnode, &sfdp->snode, SSN_NODE_ADD, 0) )*/
#ifdef TCP_SSN_PKTGEN_DEBUG
        else if ( TH_SYN == tcp_flags ) {
#else
        else if ( (ssn_state&STREAM_STATE_ESTABLISHED)
                && (ssn_flags&SSNFLAG_COUNTED_ESTABLISH) ) {
#endif
            if ( 0 == SfSSNStatsNodeFind(sfdp->h_snode.hatbl, &sfdp->snode,
                    &nodesElem->pkt_qt, &tar_snode, tnode, 1, 0) ) {
                if ( PROSSN_IDLE == tar_snode->fsm.stat ) {
                    SF_PROCSSN_INIT_NODE(tar_snode);
                    /*LogMessage("%s: >>>>>,,,,, session start(ssn_cnt: %d): src_ip %x, dst_ip %x, src_port %u, dst_port %u\n", __func__,
                            sfdp->snode.np_active, tnode->tet.src, tnode->tet.dst, p->sp, p->dp);*/
                    tar_snode->fsm.stat = PROSSN_DOING;
                }
            }
        }
#ifdef TCP_SSN_PKTGEN_DEBUG
        else {
            SfSSNStatsNodeFind(sfdp->h_snode.hatbl, &sfdp->snode,
                    &nodesElem->pkt_qt, &tar_snode, tnode, 0, 0);
        }
#endif

        //if ( PROSSN_DOING == ssn_state ) {
        if ( NULL != tar_snode ) {
            if ( PROSSN_END < tar_snode->fsm.stat )
                return 0;

            if ( p->udph ) {
                LogMessage("%s: UDP sessoin...###\n", __func__);
            }

            if ( (SF_SESSION_OUT==tar_snode->qt.direction && SF_STREAM_UP==stype)
                    || (SF_SESSION_IN==tar_snode->qt.direction && SF_STREAM_DOWN==stype) ) {
                tar_snode->cnt_up++;
                tar_snode->bsz_up += p->pkth->pktlen;

                tv_pgap = p->pkth->ts.tv_sec - tar_snode->tv_upd;
                PktCnt_SsnTrackScs(&tar_snode->cs_trc[SF_SESSION_ROLE_CLN], p_ck_sum, tv_pgap);
                PktCnt_SsnInspcScs(&tar_snode->cs_trc[SF_SESSION_ROLE_CLN], tar_snode, p, SF_SESSION_ROLE_CLN);
            }
            else if ( (SF_SESSION_OUT==tar_snode->qt.direction && SF_STREAM_DOWN==stype)
                    || (SF_SESSION_IN==tar_snode->qt.direction && SF_STREAM_UP==stype) ) {
                tar_snode->cnt_down++;
                tar_snode->bsz_down += p->pkth->pktlen;

                tv_pgap = p->pkth->ts.tv_sec - tar_snode->tv_upd;
                PktCnt_SsnTrackScs(&tar_snode->cs_trc[SF_SESSION_ROLE_SRV], p_ck_sum, tv_pgap);
                PktCnt_SsnInspcScs(&tar_snode->cs_trc[SF_SESSION_ROLE_SRV], tar_snode, p, SF_SESSION_ROLE_SRV);
            }

            //TCP Extra Info
            /*if ( TH_SYN == tcp_flags )
                tar_snode->syn++;
            else if ( 0 == tcp_flags )
                tar_snode->nof++;
            }*/
            if ( TH_PUSH & tcp_flags )
                tar_snode->psh++;

            //Small pkt
            if ( NETFLOW_SMALL_PKT > p->pkth->pktlen )//p->dsize )
                tar_snode->sml++;

            tar_snode->tv_upd = p->pkth->ts.tv_sec;
            tar_snode->fsm.db_ood = 1;
        }
    }

    return 0;
}

static int sf_InitProtpUser(void)
{
    uint32_t row_idx;
    int row_cnt;
    char sql[256] = "";
    MYSQL_RES *mysql_res = NULL;
    NetFLowPortProtoMap *p_ppmap;
    MYSQL_ROW row;

    //approto_ports_user tables
    snprintf(sql, sizeof(sql), "select port,proto_type,approto_idx,approto_desc,pp_switch,renew "
            "from approto_ports_user order by id asc");
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get approto_ports_user table failed!\n", __func__);
    }
    else {
        LogMessage("%s: approto_ports_user-row_cnt %d\n", __func__, row_cnt);

        row_idx = 0;
        p_ppmap = map_netflow_portproto_user;
        if ( row_cnt > 0 ) {
            while ( (row = mysql_fetch_row(mysql_res))
                    && (row_idx < SF_MAX_PROT_PROTO_USER) ) {
                p_ppmap->port = (uint32_t)strtoul(row[0], NULL, 10);
                p_ppmap->pro_bitset = (uint32_t)strtoul(row[1], NULL, 10);
                p_ppmap->fp_index = (uint8_t)strtoul(row[2], NULL, 10);//FLOWSTA_APPRO_USER;
                strncpy(p_ppmap->pp_name, row[3], sizeof(((NetFLowPortProtoMap*)0)->pp_name));
                p_ppmap->pp_switch = (uint8_t)strtoul(row[4], NULL, 10);
                //secondary process do not need to care about this
                p_ppmap->renew = 0;//(uint8_t)strtoul(row[5], NULL, 10);
                p_ppmap->pp_index = row_idx;

                p_ppmap++;
                row_idx++;

                reflect_netflow_protoport_reflect[p_ppmap->fp_index].pro_bitset |= p_ppmap->pro_bitset;
                reflect_netflow_protoport_reflect[p_ppmap->fp_index].ports_user |= (0x01L<<p_ppmap->pp_index);
            }

            // The last records, set switch = 0
            p_ppmap->pp_switch = 0;
        }

        mysql_free_result(mysql_res);
    }

    return 0;
}

#if 0
static int sf_InitProtpSysUser(void)
{
    uint32_t row_idx;
    int row_cnt, i, sql_ret;
    //IPTet ip_tet;
    char sql[256] = "";
    MYSQL_RES *mysql_res = NULL;
    MYSQL_ROW row;
    NetFLowPortProtoMap *p_ppmap;
    uint64_t ppflag_user_renew = 0;

    LogMessage("%s: Initializing\n", __func__);

    //approto_ports_system tables
    snprintf(sql, sizeof(sql), "truncate approto_ports_system");
    MysqlQuery(sf_mysql, sql, NULL);
    snprintf(sql, sizeof(sql), "select id from approto_ports_system");
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get approto_ports_system table failed!\n", __func__);
    }
    else if ( 0 == row_cnt ) {
        mysql_free_result(mysql_res);
        MysqlTransBegin(sf_mysql);

        //Create Instance
        p_ppmap = map_netflow_portproto;
        sql_ret = 0;
        while ( p_ppmap->port > 0 ) {
            snprintf(sql, sizeof(sql), "insert into approto_ports_system (port, proto_type, approto_idx, approto_desc) "
                    "values(%u, %u, %u, '%s')", p_ppmap->port, p_ppmap->pro_bitset, p_ppmap->fp_index, p_ppmap->pp_name);
            sql_ret = MysqlQuery(sf_mysql, sql, NULL);
            if ( sql_ret )
                break;

            p_ppmap++;
        }
        if ( sql_ret ) {
            LogMessage("%s: [%s] failed!\n", __func__, sql);
            MysqlTransRollback(sf_mysql);
        }
        else {
            MysqlTransCommit(sf_mysql);
        }
    }

    LogMessage("%s: approto_ports_system sync, row_cnt %d!\n", __func__, row_cnt);

    //approto_ports_user tables
    snprintf(sql, sizeof(sql), "select port,proto_type,approto_idx,approto_desc,pp_switch,renew "
            "from approto_ports_user order by id asc");
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get approto_ports_user table failed!\n", __func__);
    }
    else {
        LogMessage("%s: approto_ports_user-row_cnt %d\n", __func__, row_cnt);

        row_idx = 0;
        p_ppmap = map_netflow_portproto_user;
        if ( row_cnt > 0 ) {
            while ( (row = mysql_fetch_row(mysql_res))
                    && (row_idx < SF_MAX_PROT_PROTO_USER) ) {
                p_ppmap->port = (uint32_t)strtoul(row[0], NULL, 10);
                p_ppmap->pro_bitset = (uint32_t)strtoul(row[1], NULL, 10);
                p_ppmap->fp_index = (uint8_t)strtoul(row[2], NULL, 10);//FLOWSTA_APPRO_USER;
                strncpy(p_ppmap->pp_name, row[3], sizeof(((NetFLowPortProtoMap*)0)->pp_name));
                p_ppmap->pp_switch = (uint8_t)strtoul(row[4], NULL, 10);
                p_ppmap->renew = (uint8_t)strtoul(row[5], NULL, 10);
                p_ppmap->pp_index = row_idx;

                //save reset-flag
                if ( p_ppmap->pp_switch && p_ppmap->renew )
                    ppflag_user_renew |= (0x01L<<row_idx);

                p_ppmap++;
                row_idx++;

                reflect_netflow_protoport_reflect[p_ppmap->fp_index].pro_bitset |= p_ppmap->pro_bitset;
                reflect_netflow_protoport_reflect[p_ppmap->fp_index].ports_user |= (0x01L<<p_ppmap->pp_index);
            }

            // The last records, set switch = 0
            p_ppmap->pp_switch = 0;

            mysql_free_result(mysql_res);

            //reset renew-flag
            if ( ppflag_user_renew ) {
                snprintf(sql, sizeof(sql), "update approto_ports_user set renew=0");
                sql_ret = MysqlQuery(sf_mysql, sql, NULL);
                if ( sql_ret ) {
                    LogMessage("%s: [%s] failed!\n", __func__, sql);
                    return -1;
                }
            }
        }
        else {
            mysql_free_result(mysql_res);
            MysqlTransBegin(sf_mysql);

            sql_ret = 0;
            for ( i=0; i<(SF_MAX_PROT_PROTO_USER+1); i++ ) {
                snprintf(sql, sizeof(sql), "insert into approto_ports_user (id, port, proto_type, approto_idx, approto_desc, pp_switch, renew) "
                        "values(%u, %u, %u, %u, '%s', %u, %u)",
                        i+1, p_ppmap->port, p_ppmap->pro_bitset, p_ppmap->fp_index, p_ppmap->pp_name,
                        p_ppmap->pp_switch, p_ppmap->renew);
                sql_ret = MysqlQuery(sf_mysql, sql, NULL);
                if ( sql_ret )
                    break;

                //p_ppmap++;
            }

            if ( sql_ret ) {
                LogMessage("%s: [%s] failed!\n", __func__, sql);
                MysqlTransRollback(sf_mysql);
            }
            else {
                MysqlTransCommit(sf_mysql);
            }
        }
    }

    return 0;
}

static int sf_IptetInitFromDB(StatsFlowConfluDataPlane *sfdp_ctl)
{
    uint8_t ppid, direction, fp_index;
    int row_cnt, i, j;
	//IPTet ip_tet;
    char sql[256] = "";
    MYSQL_RES *mysql_res = NULL;
    MYSQL_ROW row;
    IPTetCflStatNode apnode;
    ProtoStackStatsCflNodes *cfl_stack = (ProtoStackStatsCflNodes*)(&sfdp_ctl->stack);
    uint64_t ppflag_user_renew = 0;

    LogMessage("%s: Initializing\n", __func__);

    //IPTET_Table
    snprintf(sql, sizeof(sql), ipt_initfromdb, map_nf2dbtbl[NF_IPTET].tbl_name);
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get nfiptet table failed!\n", __func__);
    }
    else {
        LogMessage("%s: nfiptet row_cnt %d\n", __func__, row_cnt);

        if ( row_cnt > 0 ) {
            while ( (row = mysql_fetch_row(mysql_res)) ) {
                apnode.dbid = (uint64_t)strtoul(row[0], NULL, 10);
                apnode.tet.src = (uint32_t)strtoul(row[1], NULL, 10);
                apnode.tet.dst = (uint32_t)strtoul(row[2], NULL, 10);
                apnode.ppflag.tcp = strtoul(row[3], NULL, 10);
                apnode.ppflag.udp = strtoul(row[4], NULL, 10);
                apnode.ppflag.tcp_user = strtoul(row[5], NULL, 10);
                apnode.ppflag.udp_user = strtoul(row[6], NULL, 10);
                apnode.ppflag.other = strtoul(row[7], NULL, 10);
                apnode.almflag = (uint32_t)strtoul(row[8], NULL, 10);
                apnode.aly_stat |= SFALY_IPT_ACTIVE|SFALY_IPT_INSPECT_PULSE;
                apnode.cnt = 0;
                apnode.bsize = 0;
                apnode.syn = 0;
                apnode.dns = 0;
                apnode.tv_upd = 0;
                //count = atoi(row[2]);
                //total = atoi(row[3]);

                //pp_flag handling
                apnode.ppflag.tcp_user &= ~ppflag_user_renew;
                apnode.ppflag.udp_user &= ~ppflag_user_renew;

                JHashIpTetAdd((IPTetStatNode**)(sfdp_ctl->h_tnode.hatbl), (IPTetStatNodePool*)&sfdp_ctl->tnode,
                        (IPTetStatNode*)&apnode, NULL, 1, 1);
            }
        }

        mysql_free_result(mysql_res);
    }

    //Max Ip-Tet ID
    sfGlobalInfo.max_iptid = 0;
    snprintf(sql, sizeof(sql), "select max(id) from %s",
            map_nf2dbtbl[NF_IPTET].tbl_name);
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get nfiptet table max(id) failed!\n", __func__);
    }
    else {
        if ( (row = mysql_fetch_row(mysql_res)) )
            if ( NULL != row[0] )
                sfGlobalInfo.max_iptid = (uint64_t)strtoul(row[0], NULL, 10);
        mysql_free_result(mysql_res);
    }

    //Check if proto-port scaled
    snprintf(sql, sizeof(sql), "show tables like 'nfprotp_stats_scale%c'", '%');
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
    }
    else {
        if ( row_cnt > 0 ) {
            LogMessage("%s: nf_proto-port_stats enabled scaling\n", __func__);
            sfGlobalInfo.envset_scl_flag |= SF_GLOB_VAR_PP_SCALE_DEEP_LIT;
        }
        else {
            LogMessage("%s: nf_proto-port_stats disable scaling\n", __func__);
        }
        mysql_free_result(mysql_res);
    }

    //Max SSN ID
    sfGlobalInfo.max_ssnid = 0;
    snprintf(sql, sizeof(sql), "select max(id) from %s",
            map_nf2dbtbl[NF_PROSSN].tbl_name);
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get nfiptet table max(id) failed!\n", __func__);
    }
    else {
        if ( (row = mysql_fetch_row(mysql_res)) )
            if ( NULL != row[0] )
                sfGlobalInfo.max_ssnid = strtoul(row[0], NULL, 10);
        mysql_free_result(mysql_res);
    }

    //Current Inspection SSN ID
    sfGlobalInfo.cur_ssnid = 0;
/*    snprintf(sql, sizeof(sql), "select cur_ssn_id from %s",
            map_nf2dbtbl[NF_INS_TRACK].tbl_name);
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get %s failed, default 0!\n", __func__, map_nf2dbtbl[NF_INS_TRACK].tbl_name);
    }
    else {
        if ( (row = mysql_fetch_row(mysql_res)) )
            if ( NULL != row[0] )
                sfGlobalInfo.cur_ssnid = strtoul(row[0], NULL, 10);
        mysql_free_result(mysql_res);
    }*/

    //Stack Statistic data
    snprintf(sql, sizeof(sql), stack_select, map_nf2dbtbl[NF_PROTO].tbl_name);
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get nf_protocol table failed!\n", __func__);
    }
    else if ( row_cnt > 0 ) {
        while ( (row = mysql_fetch_row(mysql_res)) ) {
            //i = netflow_getproidbyname(row[0]);
            ppid = (uint8_t)strtoul(row[0], NULL, 10);
            direction = (uint8_t)strtoul(row[1], NULL, 10);
            if ( (ppid > 0) && (ppid <= NETFLOW_STACK_COUNT) && (direction < SF_STREAM_DIRECTION_TYPES) ) {
                cfl_stack[ppid-1].cnt[direction] = strtoul(row[2], NULL, 10);
                cfl_stack[ppid-1].bsize[direction] = strtoul(row[3], NULL, 10);
            }
        }
        mysql_free_result(mysql_res);
    }
    else {
        mysql_free_result(mysql_res);

        MysqlTransBegin(sf_mysql);

        //Create Instance
        for (i=0; i<NETFLOW_STACK_COUNT; i++) {
            if ( !cfl_stack[i].nd_swt )
                break;

            if ( i < NETFLOW_STACK_APP_STEP ) {
                fp_index = i;
            }
            else {
                if ( !cfl_stack[i].np_user )
                    fp_index = NETFLOW_STACK_APP_STEP + map_netflow_portproto[cfl_stack[i].port_idx].fp_index;
                else
                    fp_index = NETFLOW_STACK_APP_STEP + map_netflow_portproto_user[cfl_stack[i].port_idx].fp_index;
            }

            for (j=0; j<SF_STREAM_DIRECTION_TYPES; j++) {
                snprintf(sql, sizeof(sql), stack_insert,
                        map_nf2dbtbl[NF_PROTO].tbl_name,
                        i+1, map_netfow2dp[fp_index].nf_name,
                        cfl_stack[i].port_idx, cfl_stack[i].np_user, cfl_stack[i].port,
                        j, 0L, 0L, 0);
                if ( MysqlQuery(sf_mysql, sql, NULL) ) {
                    LogMessage("%s: [%s] failed!\n", __func__, sql);
                    MysqlTransRollback(sf_mysql);
                    return -1;
                }
            }
        }

        MysqlTransCommit(sf_mysql);
    }

    LogMessage("%s: done, iptet total %lu, cur_num %lu, node_num %d, max_ssn %lu\n", __func__,
    		sizeof(sfdp_ctl->tnode.nodes)/sizeof(IPTetCflStatNode),
    		sfGlobalInfo.max_iptid, sfdp_ctl->tnode.npcnt, sfGlobalInfo.max_ssnid);

    return 0;
}

static int sf_CflSsnDpAdd(StatsFlowConfluDataPlane *sfdp_ctl, SSNProtoNodeHaTbl *dpssn_ha, SSNProtoNodePool *dpssn)
{
    int i;

    for ( i=0; i<MAX_SSNPROTO_CFL_NODEPOOLS; i++ ) {
        if ( dpssn == sfdp_ctl->p_snode[i] )
            break;

        if ( NULL == sfdp_ctl->p_snode[i] ) {
            sfdp_ctl->p_hnode[i] = dpssn_ha;
            sfdp_ctl->p_snode[i] = dpssn;
            break;
        }
    }

    if ( i >= MAX_SSNPROTO_CFL_NODEPOOLS )
        return -1;

    return 0;
}

static int sf_IptetMergeFromDp(StatsFlowConfluDataPlane *sfdp_ctl, StatsFlowDataPlane *sfdp)
{
    int i, ret;
    uint32_t new_node_cnt = 0, upd_node_cnt = 0;
    uint32_t new_node_cnt_p = 0, upd_node_cnt_p = 0;
    SSNProtoStatsNode *snode;
    IPTetStatNode *tnode;
    ProtoPortNode *pnode;
    IPTetCflStatNode *targ_tnode;
    ProtoPortNode *targ_pnode;
    //SSNProtoStatsCflNode *targ_snode;
    IPTetStatNodePool *t_nodepool = &sfdp->tnode;
    //ProtoPortNodePool *p_nodepool = &sfdp->pnode;

    sf_CflSsnDpAdd(sfdp_ctl, sfdp->p_hnode, sfdp->p_snode);

    tnode = t_nodepool->nodes;
    for(i = 0; i < t_nodepool->npidx; i++, tnode++) {
    	ret = JHashIpTetAdd((IPTetStatNode**)(sfdp_ctl->h_tnode.hatbl), (IPTetStatNodePool*)&sfdp_ctl->tnode,
    			tnode, (IPTetStatNode**)&targ_tnode, 1, 0);
    	if ( 0 != ret ) 			//Node Add Failed
    	    break;

    	//For Debug
        switch ( targ_tnode->fsm ) {
        case NF_NODEIPT_NEW:
            new_node_cnt++;
            break;
        case NF_NODEIPT_UPD:
            upd_node_cnt++;
            break;
        case NF_NODEIPT_NEW_PLUS:
            new_node_cnt_p++;
            break;
        case NF_NODEIPT_UPD_PLUS:
            upd_node_cnt_p++;
            break;
        default:
            break;
        }

        //TCP Session
        snode = tnode->ssn_node;
        while ( snode ) {
            //if ( PROSSN_END == snode->fsm.stat ) {
                snode->p_tnode = targ_tnode;
                //snode->fsm.stat = PROSSN_READY;
            //}

            snode = snode->snxt;
        }

        //Protocol-Port
        pnode = tnode->pp_node;
        while ( pnode ) {
            ret = JHashProPortAdd((ProtoPortNode**)sfdp_ctl->h_pnode.hatbl, (ProtoPortNodePool*)&sfdp_ctl->pnode,
                    pnode, &targ_pnode, (IPTetStatNode*)targ_tnode, 1);
            if ( 0 != ret )
                break;

            /*LogMessage("%s: merge src: %x, dst: %x, ppflag %lx\n", __func__,
                    targ_tnode->tet.src, targ_tnode->tet.dst, targ_tnode->ppflag);
*/
            pnode = pnode->pnxt;
        }
    }

    LogMessage("%s: current node count %d, merge_total(%d) new %d, upd %d, new_p %d, upd_p %d\n", __func__,
    		sfdp_ctl->tnode.npcnt, t_nodepool->npidx,
    		new_node_cnt, upd_node_cnt,
    		new_node_cnt_p, upd_node_cnt_p);

    return 0;
}

static int sf_StackMergeFromDp(StatsFlowConfluDataPlane *sfdp_ctl, ProStackStatNodesTbl *sfdp_stack)
{
    int i, j;
    ProtoStackStatsNodes *pstack = (ProtoStackStatsNodes*)sfdp_stack;
    ProtoStackStatsCflNodes *cfl_stack = (ProtoStackStatsCflNodes*)(&sfdp_ctl->stack);

    //Network Stack Statistic
    for (i=0; i<NETFLOW_STACK_COUNT; i++) {
        if ( !cfl_stack[i].nd_swt )
            break;

        for (j=0; j<SF_STREAM_DIRECTION_TYPES; j++) {
            cfl_stack[i].cnt[j] += pstack[i].cnt[j];
            cfl_stack[i].bsize[j] += pstack[i].bsize[j];
            cfl_stack[i].bps[j] += pstack[i].bsize[j];
        }
    }

    return 0;
}

static int sf_StackResetBps(StatsFlowConfluDataPlane *sfdp_ctl)
{
    int i, j;
    ProtoStackStatsCflNodes *cfl_stack = (ProtoStackStatsCflNodes*)(&sfdp_ctl->stack);

    //Network Stack Statistic
    for (i=0; i<NETFLOW_STACK_COUNT; i++) {
        if ( !cfl_stack[i].nd_swt )
            break;
        for (j=0; j<SF_STREAM_DIRECTION_TYPES; j++)
            cfl_stack[i].bps[j] = 0;
    }

    return 0;
}

static inline void sf_IptetSyncDBConfirm(IPTetCflStatNode* nodes,
        uint32_t node_start, uint32_t node_end, uint32_t scale_sta)
{
    uint32_t i, scl_idx;
    IPTetCflStatNode *tnode;
    ProtoPortCflNode *ppnode;
    //uint64_t ppnflag;

    //LogMessage("%s: node_start %d, node_end %d\n", __func__, node_start, node_end);

    tnode = nodes + node_start;
    for (i=node_start; i<=node_end; i++, tnode++) {
        switch ( tnode->fsm ) {
        case NF_NODEIPT_NEW_TOBE_CFM:
            sfGlobalInfo.max_iptid = tnode->dbid;

            //Clear Stats
            tnode->cnt = 0;
            tnode->bsize = 0;
            tnode->syn = 0;
            tnode->dns = 0;
            tnode->fsm = NF_NODEIPT_SYNCED;
            tnode->aly_stat |= SFALY_IPT_ACTIVE|SFALY_IPT_INSPECT_PULSE;
            break;
        case NF_NODEIPT_UPD_TOBE_CFM:
            //Clear Stats
            tnode->cnt = 0;
            tnode->bsize = 0;
            tnode->syn = 0;
            tnode->dns = 0;
            tnode->fsm = NF_NODEIPT_SYNCED;

            if ( tnode->qry_flag&NF_IPTET_FLOW_DATA_QNC ) {
                tnode->qry_flag &= ~(NF_IPTET_FLOW_DATA|NF_IPTET_FLOW_DATA_QNC);
                tnode->aly_stat |= SFALY_IPT_ACTIVE|SFALY_IPT_INSPECT_PULSE;
            }
            if ( tnode->qry_flag&NF_IPTET_ALM_FLAG_QNC )
                tnode->qry_flag &= ~(NF_IPTET_ALM_FLAG|NF_IPTET_ALM_FLAG_QNC);
            break;
        default:
            break;
        }

        ppnode = tnode->pp_node;
        while ( ppnode ) {
            //ppnflag = SF_CFL_GET_PPFLAG(ppnode->nk.proto_idx, ppnode->nk.apport_idx);
            SF_CFL_SET_PPFLAG(&tnode->ppflag.flag[0], ppnode->nk.user_set,
                    ppnode->nk.proto_idx, ppnode->nk.apport_idx);
            ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].cnt = 0;
            ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].bsz = 0;

            for ( scl_idx=SF_PROTP_SCALE_STAGE_MIN; scl_idx<SF_PROTP_SCALE_STAGE_SAVE; scl_idx++ ) {
                if ( (0x01<<scl_idx) & scale_sta ) {
                    ppnode->scl_st[scl_idx].cnt = 0;
                    ppnode->scl_st[scl_idx].bsz = 0;
                }
            }
            ppnode = ppnode->pnxt;
        }

        if ( (sfGlobalInfo.envset_scl_flag & scale_sta) == sfGlobalInfo.envset_scl_flag ) {      //Ready to Go Next Round
            tnode->pp_node = NULL;
        }

        //release ssn node
        //tnode->ssn_node = NULL;
    }
}

static int sf_IptetSyncToDB(StatsFlowConfluDataPlane *sfdp_ctl, time_t tvs_current,
        time_t *tv_scale, uint32_t *scale_cmb, uint8_t *scale_reset, uint32_t scale_flag)
{
    uint8_t pflag_idx, scl_idx;
    int ret = 0, tvs_upd_gap;
    uint32_t i, j, node_cfm_start;
    uint32_t new_node = 0, upd_count = 0, pp_count = 0, count_sum, count_sum_pre = 0;
    uint32_t protp_cnt_in, protp_bsz_in, protp_cnt_out, protp_bsz_out;
    uint64_t id;
    uint64_t ppflag_ora[NF_IPTET_PFLAG_NUM], ppnflag;
    const char *pp_scale_query;
    //ProtoProtKeyDbUnion ipt_ppu;
    IPTetCflStatNode* tnode = sfdp_ctl->tnode.nodes;
    ProtoPortCflNode *ppnode;

    LogMessage("%s: handle iptet, cur_idx %d\n", __func__, sfdp_ctl->tnode.npidx);

    MysqlTransBegin(sf_mysql);

    //for(i = 0; i < sfdp_ctl->tnode.npidx; i++, tnode++) {
    node_cfm_start = 0;
    for (i=0; i<MAX_IPTET_CONFLUENCE_NODE_SZ; i++, tnode++) {
        if ( NF_NODEIPT_NON == tnode->fsm || NF_NODEIPT_IDLE == tnode->fsm )
            continue;
        else if ( NF_NODEIPT_SYNCED == tnode->fsm
                && (tnode->qry_flag&NF_IPTET_ALM_FLAG) ) {
            tnode->fsm = NF_NODEIPT_UPD;
            LogMessage("%s: sync iptet(id %lu) for new alysist's alarms\n", __func__, tnode->dbid);
        }

        //pp-node for ppflag
        for ( pflag_idx=0; pflag_idx<NF_IPTET_PFLAG_NUM; pflag_idx++ ) {
            ppflag_ora[pflag_idx] = tnode->ppflag.flag[pflag_idx];
        }
        ppnode = tnode->pp_node;
        while ( ppnode ) {
            //ppnflag = SF_CFL_GET_PPFLAG(ppnode->nk.proto_idx, ppnode->nk.apport_idx);
            SF_CFL_SET_PPFLAG(&ppflag_ora[0], ppnode->nk.user_set,
                    ppnode->nk.proto_idx, ppnode->nk.apport_idx);

/*            if ( ppflag_ora[0] != tnode->ppflag.flag[0]
                  || ppflag_ora[1] != tnode->ppflag.flag[1]
                  || ppflag_ora[2] != tnode->ppflag.flag[2]
                  || ppflag_ora[3] != tnode->ppflag.flag[3]) {
                LogMessage("%s: before %lx,%lx,%lx,%lx\n", __func__,
                        tnode->ppflag.flag[0], tnode->ppflag.flag[1],
                        tnode->ppflag.flag[2], tnode->ppflag.flag[3]);

                LogMessage("%s: after %lx,%lx,%lx,%lx, us %d, pi %d, api %d\n", __func__,
                        ppflag_ora[0], ppflag_ora[1], ppflag_ora[2], ppflag_ora[3],
                        ppnode->nk.user_set, ppnode->nk.proto_idx, ppnode->nk.apport_idx);
            }*/

            ppnode = ppnode->pnxt;
        }

        //IP-Tet
        switch ( tnode->fsm ) {
        case NF_NODEIPT_NEW:	//Insert
        case NF_NODEIPT_NEW_PLUS:
            id = 0;
            snprintf(sql_cfl, sizeof(sql_cfl), ipt_insert,
                    map_nf2dbtbl[NF_IPTET].tbl_name,
                    tnode->hsum, tnode->tet.src, tnode->tet.dst, tnode->direction,
                    tnode->tv_upd/*tv_start*/, tnode->tv_upd,
                    tnode->cnt+0L, tnode->bsize+0L, tnode->syn+0L, tnode->dns+0L,
                    ppflag_ora[0], ppflag_ora[1], ppflag_ora[2], ppflag_ora[3], ppflag_ora[4], tnode->almflag);
            ret = MysqlQueryUlid(sf_mysql, sql_cfl, &id);
            if ( ret )
                break;

            tnode->dbid = id;
            tnode->fsm = NF_NODEIPT_NEW_TOBE_CFM;

            //For Test
            new_node++;
            break;
        case NF_NODEIPT_UPD:	//Update
        case NF_NODEIPT_UPD_PLUS:
            if ( tnode->qry_flag&NF_IPTET_FLOW_DATA ) {
                snprintf(sql_cfl, sizeof(sql_cfl), ipt_update,
                        map_nf2dbtbl[NF_IPTET].tbl_name,
                        tnode->direction, tnode->tv_upd,
                        tnode->cnt+0L, tnode->bsize+0L, tnode->syn+0L, tnode->dns+0L,
                        ppflag_ora[0], ppflag_ora[1], ppflag_ora[2], ppflag_ora[3], ppflag_ora[4], tnode->almflag, tnode->dbid);
                ret = MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                tnode->qry_flag |= NF_IPTET_FLOW_DATA_QNC|NF_IPTET_ALM_FLAG_QNC;
                tnode->fsm = NF_NODEIPT_UPD_TOBE_CFM;
            }
            else if ( tnode->qry_flag&NF_IPTET_ALM_FLAG ) {         //Just alarm flag
                snprintf(sql_cfl, sizeof(sql_cfl), ipt_upd_almflag,
                        map_nf2dbtbl[NF_IPTET].tbl_name, tnode->almflag, tnode->dbid);
                ret = MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                tnode->qry_flag |= NF_IPTET_ALM_FLAG_QNC;
                tnode->fsm = NF_NODEIPT_UPD_TOBE_CFM;
            }

        	//For Test
        	upd_count++;
            break;
        default:
            //Node Activation
            if ( tnode->expire ) {
                //remove from database
                snprintf(sql_cfl, sizeof(sql_cfl), ipt_delete,
                        map_nf2dbtbl[NF_IPTET].tbl_name, tnode->dbid);
                ret = MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                snprintf(sql_cfl, sizeof(sql_cfl), protp_delete,
                        map_nf2dbtbl[NF_PROTP].tbl_name, tnode->dbid);
                ret = MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                //LogMessage("%s: ip tuple(id %d) expired\n", __func__, tnode->dbid);
                MysqlTransCommit(sf_mysql);
                MysqlTransBegin(sf_mysql);
                sf_IptetSyncDBConfirm(sfdp_ctl->tnode.nodes, node_cfm_start, i, scale_flag);
                node_cfm_start = i+1;

                //also remove node which didn't update for a long time
                JHashIpTetCflDel(sfdp_ctl->h_tnode.hatbl, &sfdp_ctl->tnode,
                        &tnode->tet, tnode->dbid);
            }
            else {
                tvs_upd_gap = tvs_current - tnode->tv_upd;
                if ( tvs_upd_gap > 300 ) {   //haven't update in the last five minutes
                    tnode->aly_stat &= ~SFALY_IPT_ACTIVE;
                    tnode->aly_stat |= SFALY_IPT_INSPECT_PULSE;
                }
            }
        	break;
        }

        //finish this ip_tet node
        if ( ret )
            break;

        ppnode = tnode->pp_node;
        while ( ppnode ) {
            SF_CFL_GET_PPFLAG(ppnflag, &tnode->ppflag.flag[0], ppnode->nk.user_set,
                    ppnode->nk.proto_idx, ppnode->nk.apport_idx);
            /*ipt_ppu.dk.ipt_id = tnode->dbid;
            ipt_ppu.dk.proto = ppnode->nk.proto;
            ipt_ppu.dk.port = ppnode->nk.port;*/

            //Meta data
            //if ( ppnode->scl_st[scale_stage].cnt > 0 ) {
                if ( (PORT_VEC_IN == ppnode->nk.port_vec)
                        || (PORT_VEC_INVALID == ppnode->nk.port_vec
                                && SF_STREAM_UP == tnode->direction) ) {    //Default, internal side to outer-side-port
                    protp_cnt_in = ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].cnt;
                    protp_bsz_in = ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].bsz;
                    protp_cnt_out = 0;
                    protp_bsz_out = 0;
                }
                else {
                    protp_cnt_in = 0;
                    protp_bsz_in = 0;
                    protp_cnt_out = ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].cnt;
                    protp_bsz_out = ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].bsz;
                }

                if ( ppnflag ) {
                    snprintf(sql_cfl, sizeof(sql_cfl), protp_update,
                            map_nf2dbtbl[NF_PROTP].tbl_name, ppnode->tv_upd,
                            protp_cnt_in+0L, protp_bsz_in+0L, protp_cnt_out+0L, protp_bsz_out+0L,
                            tnode->dbid, map_netflow_proto[ppnode->nk.proto_idx].proto,
                            ppnode->nk.apport_idx, ppnode->nk.user_set);
                    ret = MysqlQuery(sf_mysql, sql_cfl, NULL);
                    if ( ret )
                        break;
                }
                else {
                    snprintf(sql_cfl, sizeof(sql_cfl), protp_insert,
                            map_nf2dbtbl[NF_PROTP].tbl_name,
                            tnode->dbid, tnode->tet.src, tnode->tet.dst, ppnode->tv_upd,
                            map_netflow_proto[ppnode->nk.proto_idx].proto, ppnode->nk.port,
                            ppnode->nk.apport_idx, ppnode->nk.user_set,
                            protp_cnt_in+0L, protp_bsz_in+0L, protp_cnt_out+0L, protp_bsz_out+0L);
                    ret = MysqlQuery(sf_mysql, sql_cfl, NULL);
                    if ( ret )
                        break;

                    if ( SF_GLOB_VAR_PP_SCALE_L0 != scale_flag ) {   //Not just meta-prot_p-data
                        ret = MysqlQuery(sf_mysql, protp_set_pp_id, NULL);
                        if ( ret )
                            break;
                    }
                }
            //}

            //Scaled Data--Sync to DB
            for ( scl_idx=SF_PROTP_SCALE_STAGE_MIN; scl_idx<SF_PROTP_SCALE_STAGE_SAVE; scl_idx++ ) {
                ppnode->scl_st[scl_idx].cnt += ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].cnt;
                ppnode->scl_st[scl_idx].bsz += ppnode->scl_st[SF_PROTP_SCALE_STAGE_META].bsz;

                if ( (0x01<<scl_idx) & scale_flag ) {
                    if ( scale_reset[scl_idx] )
                        pp_scale_query = protp_scale_throw;
                    else
                        pp_scale_query = protp_scale_add;

                    if ( (PORT_VEC_IN == ppnode->nk.port_vec)
                            || (PORT_VEC_INVALID == ppnode->nk.port_vec
                                    && SF_STREAM_UP == tnode->direction) ) {
                        snprintf(sql_cfl_pp_scl, sizeof(sql_cfl_pp_scl), pp_scale_query,
                                scale_cmb_table_name[scl_idx-1],
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                ppnode->scl_st[scl_idx].cnt, ppnode->scl_st[scl_idx].bsz, 0, 0,
                                tnode->direction);
                    }
                    else {
                        snprintf(sql_cfl_pp_scl, sizeof(sql_cfl_pp_scl), pp_scale_query,
                                scale_cmb_table_name[scl_idx-1],
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                0, 0, ppnode->scl_st[scl_idx].cnt, ppnode->scl_st[scl_idx].bsz,
                                tnode->direction);
                    }
                    ret = MysqlQuery(sf_mysql, sql_cfl_pp_scl, NULL);
                    if ( ret )
                        break;

                    pp_count+=1;
                }
            }

            for ( scl_idx=SF_PROTP_SCALE_STAGE_DAY; scl_idx<SF_PROTP_SCALE_STAGE_MAX; scl_idx++ ) {
                if ( (0x01<<scl_idx) & scale_flag ) {
                    if ( scale_reset[scl_idx] )
                        pp_scale_query = protp_scale_throw;
                    else
                        pp_scale_query = protp_scale_add;

                    if ( (PORT_VEC_IN == ppnode->nk.port_vec)
                            || (PORT_VEC_INVALID == ppnode->nk.port_vec
                                    && SF_STREAM_UP == tnode->direction) ) {
                        snprintf(sql_cfl_pp_scl, sizeof(sql_cfl_pp_scl), pp_scale_query,
                                scale_cmb_table_name[scl_idx-1],
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                ppnode->scl_st[SF_PROTP_SCALE_STAGE_HOUR].cnt,
                                ppnode->scl_st[SF_PROTP_SCALE_STAGE_HOUR].bsz, 0, 0,
                                tnode->direction);
                    }
                    else {
                        snprintf(sql_cfl_pp_scl, sizeof(sql_cfl_pp_scl), pp_scale_query,
                                scale_cmb_table_name[scl_idx-1],
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                0, 0,
                                ppnode->scl_st[SF_PROTP_SCALE_STAGE_HOUR].cnt,
                                ppnode->scl_st[SF_PROTP_SCALE_STAGE_HOUR].bsz,
                                tnode->direction);
                    }
                    ret = MysqlQuery(sf_mysql, sql_cfl_pp_scl, NULL);
                    if ( ret )
                        break;

                    pp_count+=1;
                }
            }

            //Next Node
            ppnode = ppnode->pnxt;

            //Debug
            pp_count++;
            if ( 0 )//(pp_count & 0xfff) == 0xfff )
                LogMessage("%s: %s\n", __func__, sql_cfl);
        }

        //finish this ip_tet_protocol_port node
        if ( ret )
            break;

        //sql transaction
        count_sum = new_node+upd_count+pp_count;
        if ( (count_sum-count_sum_pre) > 0xfff ) {
            count_sum_pre = count_sum;

            MysqlTransCommit(sf_mysql);
            MysqlTransBegin(sf_mysql);
            sf_IptetSyncDBConfirm(sfdp_ctl->tnode.nodes, node_cfm_start, i, scale_flag);
            node_cfm_start = i+1;
        }
    }

    if ( ret ) {            //Query Failed
        MysqlTransRollback(sf_mysql);

        tnode = sfdp_ctl->tnode.nodes+node_cfm_start;
        LogMessage("%s: Rollback, node_start %d, node_end %d\n", __func__, node_cfm_start, i);
        for (j=node_cfm_start; j<=i; j++, tnode++) {
            switch ( tnode->fsm ) {
            case NF_NODEIPT_NEW_TOBE_CFM:
                tnode->fsm = NF_NODEIPT_NEW;
                break;
            case NF_NODEIPT_UPD_TOBE_CFM:
                tnode->fsm = NF_NODEIPT_UPD;
                if ( tnode->qry_flag&NF_IPTET_FLOW_DATA_QNC )
                    tnode->qry_flag &= ~NF_IPTET_FLOW_DATA_QNC;
                if ( tnode->qry_flag&NF_IPTET_ALM_FLAG_QNC )
                    tnode->qry_flag &= ~NF_IPTET_ALM_FLAG_QNC;
                break;
            default:
                break;
            }
        }
    }
    else {                  //Query Succeed
        MysqlTransCommit(sf_mysql);
        sf_IptetSyncDBConfirm(sfdp_ctl->tnode.nodes, node_cfm_start,
                MAX_IPTET_CONFLUENCE_NODE_SZ-1, scale_flag);

        //reset cfl_ssn node pool
        //sfdp_ctl->snode.npidx = 0;
        if ( (sfGlobalInfo.envset_scl_flag & scale_flag) == sfGlobalInfo.envset_scl_flag ) {      //Ready to Go Next Round
            LogMessage("%s: reset cfl-protp mbuf\n", __func__);
            pp_count = sfdp_ctl->pnode.npidx;
            sfdp_ctl->pnode.npidx = 0;
            memset(sfdp_ctl->h_pnode.hatbl, 0, sizeof(sfdp_ctl->h_pnode));
        }
    }

    LogMessage("%s: no clear count, nodes num %d, transfer nodes -- new(%d) upd(%d) pp(%d)\n", __func__,
    		sfdp_ctl->tnode.npcnt, new_node, upd_count, pp_count);
    return 0;
}

static int sf_StackSyncToDB(StatsFlowConfluDataPlane *sfdp_ctl)
{
    uint8_t fp_index;
    int ret = 0;
    uint32_t i, j;
    ProtoStackStatsCflNodes *cfl_stack = (ProtoStackStatsCflNodes*)(&sfdp_ctl->stack);

    MysqlTransBegin(sfstack_mysql);

    for (i=0; i<NETFLOW_STACK_COUNT; i++) {
        if ( !cfl_stack[i].nd_swt )
            break;

        if ( cfl_stack[i].nd_new ) {
            if ( i < NETFLOW_STACK_APP_STEP ) {
                fp_index = i;
            }
            else {
                if ( !cfl_stack[i].np_user )
                    fp_index = NETFLOW_STACK_APP_STEP + map_netflow_portproto[cfl_stack[i].port_idx].fp_index;
                else
                    fp_index = NETFLOW_STACK_APP_STEP + map_netflow_portproto_user[cfl_stack[i].port_idx].fp_index;
            }

            for (j=0; j<SF_STREAM_DIRECTION_TYPES; j++) {
                snprintf(sql_cfl_stack, sizeof(sql_cfl_stack), stack_insert,
                        map_nf2dbtbl[NF_PROTO].tbl_name,
                        i+1, map_netfow2dp[fp_index].nf_name,
                        cfl_stack[i].port_idx, cfl_stack[i].np_user, cfl_stack[i].port,
                        j, cfl_stack[i].cnt[j], cfl_stack[i].bsize[j], cfl_stack[i].bps[j]);
                ret = MysqlQuery(sfstack_mysql, sql_cfl_stack, NULL);
                if ( ret )
                    break;
            }
            cfl_stack[i].nd_new = 0;
        }
        else {
            for (j=0; j<SF_STREAM_DIRECTION_TYPES; j++) {
                snprintf(sql_cfl_stack, sizeof(sql_cfl_stack), stack_update,
                        map_nf2dbtbl[NF_PROTO].tbl_name,
                        cfl_stack[i].port,
                        cfl_stack[i].cnt[j], cfl_stack[i].bsize[j], cfl_stack[i].bps[j],
                        i+1, j);
                        //map_netfow2dp[i].nf_name);
                ret = MysqlQuery(sfstack_mysql, sql_cfl_stack, NULL);
                if ( ret )
                    break;
            }
        }
    }

    if ( ret )
        MysqlTransRollback(sfstack_mysql);
    else
        MysqlTransCommit(sfstack_mysql);

    return 0;
}

/*
static int sf_AlySSNSend(uint64_t id_start, uint64_t id_end)
{
    int fd, ret;
    struct sockaddr_un sfaly_uns;
    struct msghdr;
    SSNAlySockSend aly_data;

    if ( -1 == (fd=socket(AF_UNIX, SOCK_STREAM, 0)) ) {
        perror("sfaly: socket error");
        return -1;
    }

    memset(&sfaly_uns, 0, sizeof(sfaly_uns));
    sfaly_uns.sun_family = AF_UNIX;
    snprintf(sfaly_uns.sun_path, sizeof(sfaly_uns.sun_path), "%s", "/var/run/.sfaly_dpfd");

    if ( -1 == access(sfaly_uns.sun_path, F_OK) ) {
        perror("sfaly: Server not valid");
        return -1;
    }

    if ( -1 == connect(fd, (struct sockaddr*)&sfaly_uns, sizeof(sfaly_uns)) ) {
        perror("sfaly: connect error");
        return -1;
    }


    aly_data.type = SF_ALY_PROTO_SESSION;
    aly_data.id_start = id_start;
    aly_data.id_end = id_end;
    aly_data.type = htonl(aly_data.type);
    aly_data.id_start = htonl(aly_data.id_start);
    aly_data.id_end = htonl(aly_data.id_end);

    ret = write(fd, &aly_data, sizeof(aly_data));
    if ( ret < sizeof(aly_data) ) {
        LogMessage("%s: write error\n", __func__);
        return -1;
    }

    close(fd);
    return 0;
}*/

static int sf_ProtoSSNSyncToDB(SSNProtoNodeHaTbl** sfdp_ssn_ha, SSNProtoNodePool **sfdp_ssn)
{
    uint8_t new_ssn_stat, role_idx;
    int i, j;
    int ret = 0;
    uint64_t ipt_id = 0;
    uint32_t ssn_cntsum = 0, ssn_tv_dur, ssn_tv_no_upd;
    uint32_t tvs_current = time(NULL);
    uint32_t ssn_cnt[MAX_SSNPROTO_CFL_NODEPOOLS] = {0}, ssn_upd[MAX_SSNPROTO_CFL_NODEPOOLS] = {0};
    SSNProtoStatsNode *snode;
    SSNCksumTrack *p_track;
    char *p_tr;
    IPTetCflStatNode *p_tnode;
    uint64_t id = 0, max_cur_ssnid;//, id_start, id_end;
    uint64_t ssn_ptrc_b64len;
    char log_buf[128], buf[8];

    for ( i=0; i<MAX_SSNPROTO_CFL_NODEPOOLS; i++ ) {
        if ( NULL == sfdp_ssn[i] )
            break;

        MysqlTransBegin(sfssn_mysql);

        max_cur_ssnid = 0;
        snode = sfdp_ssn[i]->nodes;
        for(j = 0; j < sfdp_ssn[i]->npidx; j++, snode++) {
            if ( PROSSN_IDLE == snode->fsm.stat )   //Session node is not use
                continue;

            if ( PROSSN_RENEW == snode->fsm.stat ) {
                SfSSNStatsNodeDel(sfdp_ssn_ha[i]->hatbl, sfdp_ssn[i], snode);
                continue;
            }

            if ( NULL == snode->p_tnode )               //Session is not aligned with CFL
                continue;
            p_tnode = (IPTetCflStatNode*)(snode->p_tnode);
            ipt_id = p_tnode->dbid;
            /*ip_tet is not ready for this tuple
             * or in case ipt_id have't been confirmed by ip_tet db_sync progress
             * */
            if ( !ipt_id || (ipt_id>sfGlobalInfo.max_iptid) )
                continue;

            ssn_tv_dur = 0;
            if ( tvs_current > snode->tv_upd )      //in case get time with newer packet-time_stamp
                ssn_tv_no_upd = tvs_current - snode->tv_upd;
            else
                ssn_tv_no_upd = 0;
            new_ssn_stat = snode->fsm.stat;
            if ( PROSSN_END == snode->fsm.stat ) {
                ssn_tv_dur = snode->tv_upd - snode->tv_start;
                snode->fsm.stat = PROSSN_RENEW;       //Step to free node
            }
            else if ( (PROSSN_DOING == snode->fsm.stat)
                    && (ssn_tv_no_upd > MAX_SEC_SSN_NODE_TRACK_EXPIRE) ) {
                ssn_tv_dur = snode->tv_upd - snode->tv_start;
                new_ssn_stat = PROSSN_FORCE_END;
                snode->fsm.stat = PROSSN_RENEW;       //Step to free node
            }

            if ( snode->fsm.db_sync ) {
                snprintf(sql_cfl_ssn, sizeof(sql_cfl_ssn), iptssn_update,
                        map_nf2dbtbl[NF_PROSSN].tbl_name,
                        snode->cnt_up, snode->bsz_up, snode->cnt_down, snode->bsz_down,
                        snode->psh, snode->sml, snode->tv_upd, ssn_tv_dur, new_ssn_stat, snode->dbid);
                ret = MysqlQuery(sfssn_mysql, sql_cfl_ssn, NULL);
                if ( ret )
                    break;

                ssn_upd[i]++;
            }
            else {
                snprintf(sql_cfl_ssn, sizeof(sql_cfl_ssn), iptssn_insert,
                        map_nf2dbtbl[NF_PROSSN].tbl_name,
                        ipt_id, snode->qt.proto, snode->qt.direction, snode->qt.cln_p, snode->qt.ser_p,
                        snode->cnt_up, snode->bsz_up, snode->cnt_down, snode->bsz_down,
                        snode->psh, snode->sml, snode->tv_start, snode->tv_upd, ssn_tv_dur, new_ssn_stat);
                ret = MysqlQueryUlid(sfssn_mysql, sql_cfl_ssn, &id);
                if ( ret )
                    break;

                //mark cur max ssn id
                max_cur_ssnid = id;
                snode->fsm.db_sync = 1;
                snode->dbid = id;

                ssn_cnt[i]++;
            }

            for ( role_idx=0; role_idx<SF_SESSION_ROLE_CNT; role_idx++ ) {
                p_track = &snode->cs_trc[role_idx];
                if ( SSN_CS_TRACK_CAP == p_track->cap ) {
                    //sync to DB
                    snprintf(sql_cfl_ssn_ptrc, sizeof(sql_cfl_ssn_ptrc), iptssn_pkt_sample,
                            snode->dbid, ipt_id, p_track->tv_stamp);
                    p_tr = sql_cfl_ssn_ptrc;
                    while ( *p_tr )
                        p_tr++;
                    //Base64 code, raw data
                    ssn_ptrc_b64len = mysql_escape_string(sanitize_buffer,
                            p_track->data_pl, p_track->data_len);
                    DAQ_RteMemcpy(p_tr, sanitize_buffer, ssn_ptrc_b64len);
                    DAQ_RteMemcpy(p_tr+ssn_ptrc_b64len, "')", 3);

                    //Query
                    ret = MysqlQuery(sfssn_mysql, sql_cfl_ssn_ptrc, NULL);
                    if ( ret )
                        break;

                    //release buffer
                    DAQ_APPutMBuf(p_track->data_pl, MPOOL_SF_PPL);
                    p_track->cap = SSN_CS_TRACK_SYNC_DB;
                }
            }
        }

        if ( ret ) {
            MysqlTransRollback(sfssn_mysql);
            break;
        }
        else {
            MysqlTransCommit(sfssn_mysql);
            if ( max_cur_ssnid > 0 )
                sfGlobalInfo.max_ssnid = max_cur_ssnid;
        }
    }

    snprintf(log_buf, sizeof(log_buf), "%s: ssn_pool(%d) ssn count-", __func__, i);
    for ( i=0; i<MAX_SSNPROTO_CFL_NODEPOOLS; i++ ) {
        ssn_cntsum += ssn_cnt[i]+ssn_upd[i];
        snprintf(buf, sizeof(buf), "%d, ", ssn_cnt[i]+ssn_upd[i]);
        strncat(log_buf, buf, sizeof(buf));
    }

    if ( ssn_cntsum > 0 && id > 0 ) {
        LogMessage("%s\n", log_buf);
        //DAQ_SFSendDataPlane((void*)&start_id, 0, DAQ_SF_SSN_ANALYST);

        /*id_end = id;
        id_start = id - ssn_cntsum + 1;
        sf_AlySSNSend(id_start, id_end);*/
    }

    return 0;
}
#endif

static int sf_Pins_InitTimer(CounterNetFlow *pcnf)
{
    struct itimerspec cSpec;
    uint32_t tv_now = time(NULL);
    uint32_t tv_scale;

    tv_scale = (SUR_SF_IPT_PP_SCALE_BASE_TIME<<1) - tv_now % SUR_SF_IPT_PP_SCALE_BASE_TIME;
    LogMessage("%s: start stats-flow mbuf_swap timmer-now %d, scale %d\n", __func__,
            tv_now, tv_scale);

    //Timer StatsFlow & Net Stack
    pcnf->fd_timer_sf = timerfd_create(CLOCK_MONOTONIC, 0);
    pcnf->fd_timer_stack = timerfd_create(CLOCK_MONOTONIC, 0);
    if ( pcnf->fd_timer_sf < 0 || pcnf->fd_timer_stack < 0 )
        return -1;

    cSpec.it_value.tv_sec = tv_scale;
    cSpec.it_value.tv_nsec = 0;
    cSpec.it_interval.tv_sec = SUR_SF_IPT_PP_SCALE_BASE_TIME;
    cSpec.it_interval.tv_nsec = 0;
    if ( timerfd_settime(pcnf->fd_timer_sf, 0, &cSpec, NULL) < 0)
        return -2;

    cSpec.it_value.tv_sec = 1;
    cSpec.it_value.tv_nsec = 0;
    cSpec.it_interval.tv_sec = 1;
    cSpec.it_interval.tv_nsec = 0;
    if ( timerfd_settime(pcnf->fd_timer_stack, 0, &cSpec, NULL) < 0)
        return -2;

    return 0;
}

static int sf_Pins_InitFdpoll(CounterNetFlow *pcnf)
{
    pcnf->fd_epoll = epoll_create(SF_EP_MAX_EVENTS);
    if ( pcnf->fd_epoll < 0 )
        return -1;

    fcntl(pcnf->fd_epoll, F_SETFD, fcntl(pcnf->fd_epoll, F_GETFD) | FD_CLOEXEC);

    return 0;
}

static int sf_Pins_EpollCtl(CounterNetFlow *pcnf)
{
    struct epoll_event cEvent;

    //fd_poll
    sf_Pins_InitFdpoll(pcnf);
    //Timer
    sf_Pins_InitTimer(pcnf);

    cEvent.data.fd = pcnf->fd_timer_sf;
    cEvent.events = EPOLLIN;
    if (epoll_ctl(pcnf->fd_epoll, EPOLL_CTL_ADD, pcnf->fd_timer_sf, &cEvent) < 0)
        return -1;

    cEvent.data.fd = pcnf->fd_timer_stack;
    cEvent.events = EPOLLIN;
    if (epoll_ctl(pcnf->fd_epoll, EPOLL_CTL_ADD, pcnf->fd_timer_stack, &cEvent) < 0)
        return -1;

    return 0;
}

static int sf_PktInspcInit(CounterNetFlow *pcnf)
{
    int ret_m;
    DataplaneAddrs dpMbufs;
    NetFlowPPmArray *sfPortMapArray;

    memset(pcnf, 0, sizeof(CounterNetFlow));
    dpMbufs.sock_id = -1;

    ret_m = DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_STATSFLOW);
    if ( !ret_m ) {
        pcnf->psDPIntef = (StatsFlowDataPlane*)dpMbufs.dp_main;
        pcnf->psDPSsn = (StatsFlowDPSSN*)dpMbufs.dp_extra;
        pcnf->psDPIntef->p_hnode = &pcnf->psDPSsn->h_snode;
        pcnf->psDPIntef->p_snode = &pcnf->psDPSsn->snode;
        pcnf->dpState = SF_DPSTATE_RECORDING;
    }

    ret_m = DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_SF_STACK);
    if ( !ret_m ) {
        pcnf->psDpStack = (ProStackStatNodesTbl*)dpMbufs.dp_main;
    }

    //Init Port-Bitmap
    ret_m = DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_PORT_BITMAP);
    if ( ret_m ) {
        LogMessage("%s: Can't get MBuf for net_port_bitmap.\n", __func__);
        return 1;
    }
    sfPortMapArray = (NetFlowPPmArray*)dpMbufs.dp_main;
    DAQ_RteMemcpy(sfPortMapArray->map_portproto, map_netflow_portproto,
            sizeof(map_netflow_portproto));
    DAQ_RteMemcpy(sfPortMapArray->map_portproto_user, map_netflow_portproto_user,
            sizeof(map_netflow_portproto_user));
    sfPortMapList[0] = sfPortMapArray->map_portproto_user;
    sfPortMapList[1] = sfPortMapArray->map_portproto;

    if ( sf_NetProtoPort_BitMap() )
        return 1;

    sf_Pins_EpollCtl(pcnf);

    return 0;
}

static void *sf_Pins_Loop(void *args)
{
    int fd_num = 0;
    int i;
    CounterNetFlow *pcnf = (CounterNetFlow*)args;
    struct epoll_event cEvs[SF_EP_MAX_EVENTS];

    while ( 1 ) {
        //wait for events to wake up
        fd_num = epoll_wait(pcnf->fd_epoll, cEvs, SF_EP_MAX_EVENTS, -1);
        if ( fd_num < 0 ) {
            if ( EINTR == errno )
                continue;
            else
                break;
        }

        //check events
        for ( i = 0; i < fd_num; i++ ) {
            if( cEvs[i].data.fd == pcnf->fd_timer_sf ) {
                //timer timeout call the timer's callback function
                uint32_t sleep_cnt = 0;
                uint64_t n,len;
                len = read(pcnf->fd_timer_sf, &n, sizeof(uint64_t));
                if(len == sizeof(uint64_t)) {
                    //Request to "NetFlow"
                    pcnf->dpState = SF_DPSTATE_REQ_NEW;
                    if ( !sf_switch_test_and_set_on(&pcnf->dpSwitch) ) {
                        LogMessage("%s: data plane is invalid!\n", __func__);
                        continue;
                    }
                    DAQ_SFIPCReq(NULL, DAQ_SF_DP_SWAP);

                    while ( !sf_switch_test_and_set_off(&pcnf->dpSwitch) ) {
                        usleep(1);
                        sleep_cnt++;
                    }

                    //Request new data plane failed
                    if ( SF_DPSTATE_RECORDING != pcnf->dpState ) {
                        //LogMessage("%s: data plane is not ready!\n", __func__);
                        continue;
                    }

                    /*LogMessage("%s: sleep_cnt %d, Send dp_buf %lx\n", __func__,
                            sleep_cnt, (unsigned long)pcnf->psDPready);*/
                    DAQ_APSendMBuf((void*)pcnf->psDPready, RING_STATSFLOW, MPOOL_STATSFLOW);
                    pcnf->psDPready = NULL;
                }
            }
            else if ( cEvs[i].data.fd == pcnf->fd_timer_stack ) {
                uint32_t sleep_cnt = 0;
                uint64_t n,len;
                len = read(pcnf->fd_timer_stack, &n, sizeof(uint64_t));
                if(len == sizeof(uint64_t)) {
                    //Request to "NetStack"
                    pcnf->dpState = SF_DPSTATE_REQ_NEW;
                    if ( !sf_switch_test_and_set_on(&pcnf->dpSwitch) ) {
                        LogMessage("%s: data plane is invalid!\n", __func__);
                        continue;
                    }
                    DAQ_SFIPCReq(NULL, DAQ_SF_STACK_DP_SWAP);

                    while ( !sf_switch_test_and_set_off(&pcnf->dpSwitch) ) {
                        usleep(1);
                        sleep_cnt++;
                    }

                    //Request new data plane failed
                    if ( SF_DPSTATE_RECORDING != pcnf->dpState ) {
                        //LogMessage("%s: data plane(stack) is not ready!\n", __func__);
                        continue;
                    }

                    /*LogMessage("%s: sleep_cnt %d, Send dp_buf %lx\n", __func__,
                            sleep_cnt, (unsigned long)pcnf->psStackReady);*/
                    DAQ_APSendMBuf((void*)pcnf->psStackReady, RING_SF_STACK, MPOOL_SF_STACK);
                    pcnf->psStackReady = NULL;
                }
            }
        }
    }

    close(pcnf->fd_timer_sf);
    close(pcnf->fd_timer_stack);

    return NULL;
}

static int sf_Pins_ParseConfig(void *args)
{
    return 0;
}

#if 0
static int sf_DBIns_SockInit(int *pfd)
{
    struct sockaddr_un sfaly_uns;
    struct msghdr;

    memset(&sfaly_uns, 0, sizeof(sfaly_uns));
    sfaly_uns.sun_family = AF_UNIX;
    snprintf(sfaly_uns.sun_path, sizeof(sfaly_uns.sun_path), "%s", "/var/run/.sfaly_dpfd");

    if ( -1 == (*pfd=socket(AF_UNIX, SOCK_STREAM, 0)) ) {
        //perror("sfaly: socket error");
        return -1;
    }

    if ( -1 == access(sfaly_uns.sun_path, F_OK) ) {
        //perror("sfaly: Server not valid");
        close(*pfd);
        *pfd = -1;
        return -1;
    }

    if ( -1 == connect(*pfd, (struct sockaddr*)&sfaly_uns, sizeof(sfaly_uns)) ) {
        //perror("sfaly: connect error");
        close(*pfd);
        *pfd = -1;
        return -1;
    }

    return 0;
}

static void sf_DBIns_Closet(int *pfd)
{
    close(*pfd);
    *pfd = -1;

    LogMessage("%s: will try reconnect\n", __func__);
}

static int sf_AlyUnsSend(int fd, void *data, int datalen, void *rbuf, int *rlen)
{
    int ret;
    struct timeval tv;
    fd_set fdset;

    ret = write(fd, data, datalen);
    if ( ret < datalen ) {
        //LogMessage("%s: write error\n", __func__);
        return -1;
    }

    //wait data back
    tv.tv_usec = 0;
    tv.tv_sec = 5;      //timeout 5 seconds
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    ret = select(fd+1, &fdset, NULL, NULL, &tv);
    if ( ret <= 0 ) {
        //LogMessage("%s: wait(select) data back failed: ret %d\n", __func__, ret);
        return -1;
    }

    if ( FD_ISSET(fd, &fdset) ) {
        ret = read(fd, rbuf, *rlen);
        *rlen = ret;
    }

    return 0;
}

static int sf_DBInsAlyUns(int fd, uint32_t aly_type, uint64_t dbid, uint64_t *alarm_flag)
{
    int aly_retlen, ret;
    char alarm_flag_str[32];
    SFAlySockSend aly_data;

    aly_data.type = htonl(aly_type);
    aly_data.id_start = htonl(dbid);
    aly_data.id_end = htonl(dbid);

    memset(alarm_flag_str, 0, sizeof(alarm_flag_str));
    aly_retlen = sizeof(alarm_flag_str);

    ret = sf_AlyUnsSend(fd, &aly_data, sizeof(aly_data), alarm_flag_str, &aly_retlen);
    if ( ret < 0 ) {
        return ret;
    }

    *alarm_flag = strtoull(alarm_flag_str, NULL, 10);
    //LogMessage("%s: aly_ret %lx, len %d\n", __func__, *alarm_flag, aly_retlen);

    return 0;
}

int sf_DBIns_Loop(void *dp_cfl)
{
    uint32_t sf_aly_type;
    int uns_fd, uns_ret;
    uint32_t ssn_hb_cnt = 0;
    uint32_t ipt_idx;//, tvs_current, tvs_dbrec;
    StatsFlowConfluDataPlane *sf_dp_ctl = (StatsFlowConfluDataPlane*)dp_cfl;
    IPTetCflStatNode* tnode;
    uint64_t alarm_flag;
    sigset_t sigset;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    //signal(SIGPIPE, a);

    while ( sf_DBIns_SockInit(&uns_fd) < 0 ) {
        sleep(1);
    }

    LogMessage("%s: Start Inspection!\n", __func__);
    ipt_idx = 0;
    uns_ret = 0;

    do {
        //Socket is not ready
        if ( uns_fd < 0 ) {
            if ( sf_DBIns_SockInit(&uns_fd) < 0 ) {
                sleep(1);
                continue;
            }

            //Send cur max ssn_id
            LogMessage("%s: Aly Reconnected\n", __func__);
            sfGlobalInfo.cur_ssnid = 0;
        }

        //IP Tuple Inspection: Get Node
        if ( 0 == ipt_idx )
            tnode = sf_dp_ctl->tnode.nodes;
        else
            tnode++;
        ipt_idx = (ipt_idx+1)&IPTET_CONFLUENCE_NODE_SZ_MASK;

        //release CPU for distributing resource
        if ( (ipt_idx & 0xffff) == 0xffff ) {
            //LogMessage("%s: we are in ipt_node_idx %d\n", __func__, ipt_idx);
            usleep(1);
        }

        //IP Tuple Inspection: Node check
        if ( NF_NODEIPT_NON != tnode->fsm
                && NF_NODEIPT_IDLE != tnode->fsm
                && tnode->aly_stat
                && !tnode->expire ) {
            if ( tnode->almflag&SFALY_ALARM_IPTSSN_SYN )
                sf_aly_type = SF_ALY_SSN_ALM_FLAG;
            else
                sf_aly_type = SF_ALY_IP_TUPLE;

            uns_ret = sf_DBInsAlyUns(uns_fd, sf_aly_type, tnode->dbid, &alarm_flag);
            if ( uns_ret < 0 ) {
                LogMessage("%s: Aly(IPT) communication failed\n", __func__);
                sf_DBIns_Closet(&uns_fd);
                continue;
            }

            if ( alarm_flag&SFALY_ALARM_IPT_EXPIRE ) {
                tnode->expire = 1;
                //LogMessage("%s: iptet(id-%d) expired, remove from tracking list.\n", __func__, ipt_dbid);
            }
            else if ( (alarm_flag>0) && ((alarm_flag^tnode->almflag)&~tnode->almflag) ) {
                LogMessage("%s: new alarms for ipt(id %lu)--0x%lx(ori-0x%x)\n", __func__,
                        tnode->dbid, alarm_flag, tnode->almflag);
                tnode->almflag |= (alarm_flag&SFALY_ALARM_MASK);
                tnode->qry_flag |= NF_IPTET_ALM_FLAG;
            }

            tnode->aly_stat &= ~SFALY_IPT_INSPECT_PULSE;
            ssn_hb_cnt += 10;
        }

        //Session Inspection
        if ( sfGlobalInfo.cur_ssnid < sfGlobalInfo.max_ssnid ) {
            uns_ret = sf_DBInsAlyUns(uns_fd, SF_ALY_PROTO_SESSION, sfGlobalInfo.max_ssnid, &alarm_flag);
            if ( uns_ret < 0 ) {
                LogMessage("%s: Aly(SSN) communication failed\n", __func__);
                sf_DBIns_Closet(&uns_fd);
                continue;
            }
            sfGlobalInfo.cur_ssnid = sfGlobalInfo.max_ssnid;

            ssn_hb_cnt = 0;
        }
        else if ( ssn_hb_cnt++ & 0x1000000 ) {  //Heart Beat, as ssn
            ssn_hb_cnt = 0;
            uns_ret = sf_DBInsAlyUns(uns_fd, SF_ALY_PROTO_SESSION, sfGlobalInfo.max_ssnid, &alarm_flag);
            if ( uns_ret < 0 ) {
                LogMessage("%s: Aly(SSN) communication failed\n", __func__);
                sf_DBIns_Closet(&uns_fd);
                continue;
            }
        }

/*        snprintf(sql_cfl_dbins, sizeof(sql_cfl_dbins), ipt_select,
                map_nf2dbtbl[NF_IPTET].tbl_name, ipt_dbid);
        row_cnt = MysqlSelectDbRes(sfins_mysql, sql_cfl_dbins, &mysql_res);
        if ( row_cnt <= 0 || NULL == mysql_res ) {
            LogMessage("%s: get nfiptet table(id-%d) failed!\n", __func__, ipt_dbid);
            sleep(1);
            continue;
        }

        if ( !(row=mysql_fetch_row(mysql_res)) ) {
            LogMessage("%s: mysql_fetch_row(id-%d) failed!\n", __func__, ipt_dbid);
            sleep(1);
            continue;
        }

        iptet.src = (uint32_t)strtoul(row[0], NULL, 10);
        iptet.dst = (uint32_t)strtoul(row[1], NULL, 10);
        tvs_dbrec = (uint32_t)strtoul(row[2], NULL, 10);
        aly_data.cnt = (uint32_t)strtoul(row[3], NULL, 10);
        aly_data.syn = (uint32_t)strtoul(row[4], NULL, 10);
        tvs_current = time(NULL);
        mysql_free_result(mysql_res);   //release sql resource
*/
    } while (1);

    close(uns_fd);

    return 0;
}

int sf_CflInit(void *dp_cfl)
{
	int stack_i, nmap_idx;
	ProtoStackStatsCflNodes *pnode;
	StatsFlowConfluDataPlane *sf_dp_ctl = (StatsFlowConfluDataPlane*)dp_cfl;

	LogMessage("%s: dp_cfl %lx\n", __func__, (unsigned long)dp_cfl);

    if ( MysqlConnect(&sf_mysql) ) {
        LogMessage("%s: MysqlConnect(sf_mysql) error\n",__func__);
        return 1;
    }

    if ( MysqlConnect(&sfstack_mysql) ) {
        LogMessage("%s: MysqlConnect(sfstack_mysql) error\n",__func__);
        return 1;
    }

    pnode = (ProtoStackStatsCflNodes*)(&sf_dp_ctl->stack);
    nmap_idx = 0;
    for (stack_i=0; stack_i<FLOWSTA_NET_COUNT; stack_i++, nmap_idx++, pnode++) {
        pnode->nf_stack = map_netfow2dp[nmap_idx].nf_stack;
        pnode->nf_type = map_netfow2dp[nmap_idx].nf_type;
        pnode->port = 0;
        pnode->port_idx = NF_APPRO_NA_NET;
        pnode->nd_swt = 1;
        pnode->np_user = 0;
    }
    for (stack_i=0; stack_i<FLOWSTA_PROTO_COUNT; stack_i++, nmap_idx++, pnode++) {
        pnode->nf_stack = map_netfow2dp[nmap_idx].nf_stack;
        pnode->nf_type = map_netfow2dp[nmap_idx].nf_type;
        pnode->port = 0;
        pnode->port_idx = NF_APPRO_NA_TRANS;
        pnode->nd_swt = 1;
        pnode->np_user = 0;
    }
    for (stack_i=0; stack_i</*FLOWSTA_APPRO_COUNT*/NF_APPRO_COUNT; stack_i++, nmap_idx++, pnode++) {
        pnode->nf_stack = map_netfow2dp[map_netflow_portproto[stack_i].fp_index].nf_stack;
        pnode->nf_type = map_netfow2dp[map_netflow_portproto[stack_i].fp_index].nf_type;
        pnode->port = map_netflow_portproto[stack_i].port;
        pnode->port_idx = map_netflow_portproto[stack_i].pp_index;
        pnode->nd_swt = 1;
        pnode->np_user = 0;
    }

    sf_InitProtpSysUser();

    //User-Defined Ports
    for (stack_i=0; stack_i<(SF_MAX_PROT_PROTO_USER+1); stack_i++, nmap_idx++, pnode++) {
        if ( !map_netflow_portproto_user[stack_i].pp_switch )
            break;

        pnode->nf_stack = map_netfow2dp[map_netflow_portproto_user[stack_i].fp_index].nf_stack;
        pnode->nf_type = map_netfow2dp[map_netflow_portproto_user[stack_i].fp_index].nf_type;
        pnode->port = map_netflow_portproto_user[stack_i].port;
        pnode->port_idx = map_netflow_portproto_user[stack_i].pp_index;
        pnode->nd_swt = 1;
        pnode->np_user = 1;
    }

    //Retrieve data from DB
    sf_IptetInitFromDB(sf_dp_ctl);

    return 0;
}

int sf_Confluence(void *dp_cfl, void *dp, uint8_t dp_type, uint8_t db_sync)
{
    int ret_val = 0;

    /*LogMessage("%s: dp_cfl %lx, merge dp %lx\n", __func__,
            (unsigned long)dp_cfl, (unsigned long)dp);*/

    switch ( dp_type ) {
    case MPOOL_STATSFLOW:
        if ( NULL != dp ) {
            sf_IptetMergeFromDp(dp_cfl, dp);
        }

        if ( db_sync ) {    //sync ip_tet
            uint8_t scale_layer;
            uint8_t scale_reset[SF_PROTP_SCALE_STAGE_MAX] = {0};
            uint32_t scale_flag;
            uint32_t scale_cmb[SF_PROTP_SCALE_STAGE_MAX] = {0};
            time_t tv_cur = time(NULL), tv_scale[SF_PROTP_SCALE_STAGE_MAX];
            struct tm ipt_tm_date, scl_tm_date;
            char scale_pr_buf[256] = {0}, buf[32];

            //Meta Stock
            scale_layer = SF_PROTP_SCALE_STAGE_META;
            tv_scale[scale_layer] = tv_cur;
            localtime_r(&tv_scale[scale_layer], &ipt_tm_date);
            scale_cmb[scale_layer] = 0;
            scale_flag = SF_GLOB_VAR_PP_SCALE_L0;
            scale_reset[scale_layer] = 0;

            if ( (sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_PP_SCALE_DEEP_ALL)
                    && (ipt_tm_date.tm_sec < SUR_SF_IPT_PP_SCALE_BASE_TIME) ) {
                if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_PP_SCALE_L1 ) {
                    scale_layer = SF_PROTP_SCALE_STAGE_MIN;
                    tv_scale[scale_layer] = tv_cur - SUR_SF_IPT_PP_SCALE_VAL_MIN;  //step back
                    localtime_r(&tv_scale[scale_layer], &scl_tm_date);
                    scale_cmb[scale_layer] = ((scl_tm_date.tm_hour&0x07)<<8)|(scl_tm_date.tm_min);
                    scale_flag |= SF_GLOB_VAR_PP_SCALE_L1;
                    scale_reset[scale_layer] = 1;

                    LogMessage("%s: handle protp-scale, tm_hour %d, tm_min %d\n", __func__,
                            scl_tm_date.tm_hour, scl_tm_date.tm_min);
                }
#define SCL_DEBUG            (0x07)
#define SCL_LIT_DEBUG        (0x03)
                //deep layer
                if ( (0 == ipt_tm_date.tm_min)
#ifdef SCL_DEBUG
                        || (SCL_DEBUG == (SCL_DEBUG & ipt_tm_date.tm_min)) ) {
#else
                    ) {
#endif
                    snprintf(scale_pr_buf, sizeof(scale_pr_buf), "scale_deep, ");
                    //Hour
                    if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_PP_SCALE_L2 ) {
                        scale_layer = SF_PROTP_SCALE_STAGE_HOUR;
                        //tv_scale[scale_layer] = tv_cur - SUR_SF_IPT_PP_SCALE_VAL_HOUR;  //step back
                        tv_scale[scale_layer] = tv_cur -                                                        \
                                (ipt_tm_date.tm_sec +                                       /*seconds*/         \
                                 ipt_tm_date.tm_min*60);                                    /*minutes*/
                        if ( 0 == ipt_tm_date.tm_min )
                            tv_scale[scale_layer] -= SUR_SF_IPT_PP_SCALE_VAL_HOUR;              /*previous hour*/
                        localtime_r(&tv_scale[scale_layer], &scl_tm_date);
                        scale_cmb[scale_layer] = (scl_tm_date.tm_mday*24+scl_tm_date.tm_hour)|(scale_layer-1)<<28;
                        scale_flag |= SF_GLOB_VAR_PP_SCALE_L2;
#ifdef SCL_DEBUG
                        if ( SCL_DEBUG == ipt_tm_date.tm_min )
                            scale_reset[scale_layer] = 1;
                        else
                            scale_reset[scale_layer] = 0;
#else
                        scale_reset[scale_layer] = 1;
#endif

                        snprintf(buf, sizeof(buf), "scl_l2: 0x%x-%d, ", scale_cmb[scale_layer], scale_reset[scale_layer]);
                        strncat(scale_pr_buf, buf, sizeof(buf));
                    }

                    //Day
                    if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_PP_SCALE_L3 ) {
                        scale_layer = SF_PROTP_SCALE_STAGE_DAY;
                        //tv_scale[scale_layer] = tv_cur - SUR_SF_IPT_PP_SCALE_VAL_DAY + 1;  //step back
                        tv_scale[scale_layer] = tv_cur - \
                                (ipt_tm_date.tm_sec +                                       /*seconds*/ \
                                 ipt_tm_date.tm_min*60 +                                    /*minutes*/ \
                                 ipt_tm_date.tm_hour*3600);                                 /*hours*/   //step back to beginning of day
                        if ( (0 == ipt_tm_date.tm_min)
                                && (0 == ipt_tm_date.tm_hour) )
                            tv_scale[scale_layer] -= SUR_SF_IPT_PP_SCALE_VAL_DAY;              /*previous day*/
                        localtime_r(&tv_scale[scale_layer], &scl_tm_date);
                        scale_cmb[scale_layer] = (scl_tm_date.tm_yday)|(scale_layer-1)<<28;
                        scale_flag |= SF_GLOB_VAR_PP_SCALE_L3;
                        if ( 1 == ipt_tm_date.tm_hour )
                            scale_reset[scale_layer] = 1;
                        else
                            scale_reset[scale_layer] = 0;

                        snprintf(buf, sizeof(buf), "scl_l3: 0x%x-%d, ", scale_cmb[scale_layer], scale_reset[scale_layer]);
                        strncat(scale_pr_buf, buf, sizeof(buf));
                    }

                    //Month
                    if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_PP_SCALE_L4 ) {
                        scale_layer = SF_PROTP_SCALE_STAGE_MONTH;
                        if ( (0 == ipt_tm_date.tm_min)
                                && (0 == ipt_tm_date.tm_hour)
                                && (1 == ipt_tm_date.tm_mday)) {
                            if ( 0 == ipt_tm_date.tm_mon )                                      /*previous month*/
                                ipt_tm_date.tm_mon = 11;
                            else
                                ipt_tm_date.tm_mon -= 1;
                            tv_scale[scale_layer] = mktime(&ipt_tm_date);
                        }
                        else {
                            tv_scale[scale_layer] = tv_cur - \
                                    (ipt_tm_date.tm_sec +                                       /*seconds*/ \
                                     ipt_tm_date.tm_min*60 +                                    /*minutes*/ \
                                     ipt_tm_date.tm_hour*3600 +                                 /*hours*/ \
                                     (ipt_tm_date.tm_mday-1)*SUR_SF_IPT_PP_SCALE_VAL_DAY);      /*days*/    //step back to beginning of month
                        }
                        localtime_r(&tv_scale[scale_layer], &scl_tm_date);
                        scale_cmb[scale_layer] = (scl_tm_date.tm_mon+1)|(scale_layer-1)<<28;
                        scale_flag |= SF_GLOB_VAR_PP_SCALE_L4;
                        if ( 1 == ipt_tm_date.tm_hour && 1 == ipt_tm_date.tm_mday )
                            scale_reset[scale_layer] = 1;
                        else
                            scale_reset[scale_layer] = 0;

                        snprintf(buf, sizeof(buf), "scl_l4: 0x%x-%d, ", scale_cmb[scale_layer], scale_reset[scale_layer]);
                        strncat(scale_pr_buf, buf, sizeof(buf));
                    }

                    LogMessage("%s: scale_flag 0x%x, %s\n", __func__, scale_flag, scale_pr_buf);
                }

                if ( 0 )//scale_flag & SF_GLOB_VAR_PP_SCALE_DEEP_ALL )
                    ret_val = SUR_SF_IPT_PP_SCALE_SUM_CNT - 1;

                if ( (scale_flag&SF_GLOB_VAR_PP_SCALE_DEEP_ALL)
                        || (SCL_LIT_DEBUG == (SCL_LIT_DEBUG & ipt_tm_date.tm_min)))
                    sf_IptetSyncToDB(dp_cfl, tv_cur, tv_scale, scale_cmb, scale_reset, scale_flag);
            }

            //sf_IptetSyncToDB(dp_cfl, tv_cur, tv_scale, scale_cmb, scale_reset, scale_flag);
        }
        break;
    case MPOOL_SF_STACK:
        sf_StackMergeFromDp(dp_cfl, dp);
        if ( db_sync ) {
            sf_StackSyncToDB(dp_cfl);
            sf_StackResetBps(dp_cfl);
        }
        break;
    default:
        break;
    }

    return ret_val;
}

int sf_CflSsnInit(void)
{
    if ( MysqlConnect(&sfssn_mysql) ) {
        LogMessage("%s: MysqlConnect error(sfssn_mysql)\n",__func__);
        return 1;
    }

    return 0;
}

int sf_CflSession(void *dp_cfl)
{
    StatsFlowConfluDataPlane *sf_dp_ctl = (StatsFlowConfluDataPlane*)dp_cfl;

    sf_ProtoSSNSyncToDB(sf_dp_ctl->p_hnode, sf_dp_ctl->p_snode);

    return 0;
}
#endif

void sf_PktInsCheckOp(void)
{
    int ret, ret_m;
    daq_sf_req_type req_type;
    CounterNetFlow *pins_cnf;
    DataplaneAddrs dpMbufs;

    pins_cnf = &sfPktInspectCons;

    if ( !sf_atomic32_test_on(&pins_cnf->dpSwitch) )
        return;

    ret = DAQ_SFIPCRsp(pins_cnf, sizeof(CounterNetFlow), sf_Pins_ParseConfig, &req_type);
    if ( DAQ_SUCCESS != ret )
        return;

    dpMbufs.sock_id = -1;

    switch (req_type) {
    case DAQ_SF_DP_SWAP_RTN:
        ret_m = DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_STATSFLOW);
        if ( !ret_m ) {
            //Swap data-plane
            pins_cnf->psDPready = pins_cnf->psDPIntef;
            pins_cnf->psDPIntef = (StatsFlowDataPlane*)dpMbufs.dp_main;
            pins_cnf->psDPSsn = (StatsFlowDPSSN*)dpMbufs.dp_extra;
            pins_cnf->psDPIntef->p_hnode = &pins_cnf->psDPSsn->h_snode;
            pins_cnf->psDPIntef->p_snode = &pins_cnf->psDPSsn->snode;
            pins_cnf->dpState = SF_DPSTATE_RECORDING;
        }
        else {
            pins_cnf->dpState = SF_DPSTATE_RECORD_STALL;
        }

        sf_switch_test_and_set_done(&pins_cnf->dpSwitch);
        break;
    case DAQ_SF_STACK_DP_SWAP_RTN:
        ret_m = DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_SF_STACK);
        if ( !ret_m ) {
            pins_cnf->psStackReady = pins_cnf->psDpStack;
            pins_cnf->psDpStack = (ProStackStatNodesTbl*)dpMbufs.dp_main;
            pins_cnf->dpState = SF_DPSTATE_RECORDING;
        }
        else {
            pins_cnf->dpState = SF_DPSTATE_RECORD_STALL;
        }

        sf_switch_test_and_set_done(&pins_cnf->dpSwitch);
        break;
    default:
        break;
    }
}

void sf_PktInspcProc(Packet *p)
{
    uint8_t src_inhome = 0, dst_inhome = 0;
    //uint8_t ip_vection;
    //uint8_t proto_vection;
    StreamDirection sf_stype;
    int i = 0, ret;
    int proto_port_idx = -1;
    uint32_t pktlen;
    uint32_t tcp_flags = 0;
    CounterNetFlow *pins_cnf;
    sfhndr_t *conf_homenet;
    ProtoStackStatsNodes *stack_net = NULL, *stack_pro = NULL, *stack_app = NULL, *stack_app_user = NULL;
    IPTetStatNode *targ_tnode = NULL;

/*    if ( !p )
        return;*/

    pins_cnf = &sfPktInspectCons;

    if ( unlikely(NULL == pins_cnf->psDPIntef) ) {
        //LogMessage("%s: data plane is not ready!\n", __func__);
        return;
    }

    nodesElem = &pins_cnf->psDPIntef->nodes_exp;

    if ( likely(NULL != pins_cnf->psDpStack) ) {
        stack_net = pins_cnf->psDpStack->netsta;
        stack_pro = pins_cnf->psDpStack->prosta;
        stack_app = pins_cnf->psDpStack->aprsta;
        stack_app_user = pins_cnf->psDpStack->aprsta_user;
    }

    /*!(p->frag_flag) ||
            (p->frag_flag && (p->frag_offset == 0) &&
            (p->iph->ip_proto == IPPROTO_UDP))*/

    //there is no need to check p->pkth,because decode has checked it.
    do {
        if ( unlikely(!IPH_IS_VALID(p) || !p->iph) )
            break;

        if ( 4 != IP_VER(p->iph) )      //IPV4 Only
            break;

        nodesElem->itnode.tet.src = p->iph->ip_src.s_addr;
        nodesElem->itnode.tet.dst = p->iph->ip_dst.s_addr;

        if ( unlikely(p->frag_flag) )
            pktlen = 0;
        else
            pktlen = p->pkth->pktlen;

        //Up-Stream/Down-Stream
        DEBUG_WRAP(LogMessage("src_ip - %x, dst_ip - %x, hn %x, mask %x\n",
                nodesElem->itnode.tet.src, nodesElem->itnode.tet.dst,
                snort_conf->home_net[0].addr, snort_conf->home_net[0].mask));
        for ( i=0; i<SPEC_MAX_HOME_SUBNET_NUM; i++ ) {
            conf_homenet = &(snort_conf->home_net[i]);
            if ( 0 == conf_homenet->mask )
                break;

            if ( (nodesElem->itnode.tet.src&conf_homenet->mask) == conf_homenet->addr )
                src_inhome = 1;
            if ( (nodesElem->itnode.tet.dst&conf_homenet->mask) == conf_homenet->addr )
                dst_inhome = 1;
        }

        //Net Stack
        if ( src_inhome && !dst_inhome ) {
            sf_stype = SF_STREAM_UP;
            //ip_vection = FLOWSTA_NET_IP_UP;
        }
        else if ( !src_inhome && dst_inhome ) {
            sf_stype = SF_STREAM_DOWN;
            //ip_vection = FLOWSTA_NET_IP_DOWN;
        }
        else if ( src_inhome && dst_inhome ) {
            sf_stype = SF_STREAM_INTRA;
            //ip_vection = FLOWSTA_NET_IP_INTRA;
        }
        else {
            sf_stype = SF_STREAM_EXTER;
            //ip_vection = FLOWSTA_NET_IP_EXTER;
        }

        if ( likely(NULL != stack_net) ) {
            stack_net[FLOWSTA_NET_IP].cnt[sf_stype] ++;
            stack_net[FLOWSTA_NET_IP].bsize[sf_stype] += pktlen;
/*            stack_net[ip_vection].cnt ++;
            stack_net[ip_vection].bsize += pktlen;*/
        }

        //Ip Tuple
        nodesElem->itnode.cnt = 1;
        nodesElem->itnode.bsz = pktlen;
        nodesElem->itnode.syn = 0;
        nodesElem->itnode.dns = 0;
        nodesElem->itnode.tv_upd = p->pkth->ts.tv_sec;
        nodesElem->itnode.direction = sf_stype;
        ret = JHashIpTetAdd(&pins_cnf->psDPIntef->h_tnode, &pins_cnf->psDPIntef->tnode,
                &nodesElem->itnode, &targ_tnode, 0, 0);
        if ( ret < 0 )
            targ_tnode = NULL;

        //Not for fragmented packets
        if ( p->frag_flag )
            break;

        //Protocol
        //proto_vection = FLOWSTA_PROTO_MESS;
        if ( p->tcph ) {  //TCP
            tcp_flags = p->tcph->th_flags;
            if ( TH_SYN == tcp_flags ) {
                //stack_net[FLOWSTA_NET_TCP_SYN].cnt ++;
            }
            else if ( 0 == tcp_flags ) {
                //stack_net[FLOWSTA_NET_TCP_NOF].cnt ++;
            }

            /*if ( SF_STREAM_UP == sf_stype )
                proto_vection = FLOWSTA_PROTO_TCP_UP;
            else if ( SF_STREAM_DOWN == sf_stype )
                proto_vection = FLOWSTA_PROTO_TCP_DOWN;*/

            proto_port_idx = sf_CheckSetProtoPort(p, &nodesElem->ppnode.nk, NF_PROTP_BS_TCP);
            nodesElem->ppnode.nk.proto_idx = FLOWSTA_PROTO_TCP;
        }
        else if ( p->udph ) {
            /*if ( SF_STREAM_UP == sf_stype )
                proto_vection = FLOWSTA_PROTO_UDP_UP;
            else if ( SF_STREAM_DOWN == sf_stype )
                proto_vection = FLOWSTA_PROTO_UDP_DOWN;*/

            proto_port_idx = sf_CheckSetProtoPort(p, &nodesElem->ppnode.nk, NF_PROTP_BS_UDP);
            nodesElem->ppnode.nk.proto_idx = FLOWSTA_PROTO_UDP;
        }
        else if ( p->icmph ) {
            /*if ( SF_STREAM_UP == sf_stype )
                proto_vection = FLOWSTA_PROTO_ICMP_UP;
            else if ( SF_STREAM_DOWN == sf_stype )
                proto_vection = FLOWSTA_PROTO_ICMP_DOWN;*/

            proto_port_idx = sf_CheckSetProtoPort(p, &nodesElem->ppnode.nk, NF_PROTP_BS_ICMP);
            nodesElem->ppnode.nk.proto_idx = FLOWSTA_PROTO_ICMP;
        }
/*        else if ( IPPROTO_IGMP == p->iph->ip_proto ) {
        }
        else if ( IPPROTO_SCTP == p->iph->ip_proto ) {
        }*/
        else {
            //unknown protocol
            /*if ( SF_STREAM_UP == sf_stype )
                proto_vection = FLOWSTA_PROTO_OTHER_UP;
            else if ( SF_STREAM_DOWN == sf_stype )
                proto_vection = FLOWSTA_PROTO_OTHER_DOWN;*/

            proto_port_idx = sf_CheckSetProtoPort(p, &nodesElem->ppnode.nk, NF_PROTP_BS_OTHER);
            nodesElem->ppnode.nk.proto_idx = FLOWSTA_PROTO_OTHER;
        }

        if ( likely(NULL != stack_pro) ) {
            stack_pro[nodesElem->ppnode.nk.proto_idx].cnt[sf_stype] ++;
            stack_pro[nodesElem->ppnode.nk.proto_idx].bsize[sf_stype] += pktlen;
            /*stack_pro[proto_vection].cnt ++;
            stack_pro[proto_vection].bsize += pktlen;*/
        }

        //DNS Packet
        if ( FLOWSTA_APPRO_DNS == proto_port_idx )
            if ( likely(NULL != targ_tnode) )
                targ_tnode->dns++;

        if ( likely(NULL != stack_app && NULL != stack_app_user) ) {
            if ( nodesElem->ppnode.nk.user_set ) {
                stack_app_user[nodesElem->ppnode.nk.apport_idx].cnt[sf_stype] ++;
                stack_app_user[nodesElem->ppnode.nk.apport_idx].bsize[sf_stype] += pktlen;
            }
            else {
                stack_app[nodesElem->ppnode.nk.apport_idx].cnt[sf_stype] ++;
                stack_app[nodesElem->ppnode.nk.apport_idx].bsize[sf_stype] += pktlen;
            }
        }

        //ip-tet aligned, Protocol-Port
        if ( likely(NULL != targ_tnode) ) {
            if ( TH_SYN == tcp_flags ) {
                targ_tnode->syn++;
            }

            nodesElem->ppnode.nk.tet = targ_tnode->tet;
            nodesElem->ppnode.tv_upd = nodesElem->itnode.tv_upd;
            nodesElem->ppnode.cnt = 1;
            nodesElem->ppnode.bsz = pktlen;

/*            LogMessage("%s: pnode--proto %d, prot %d(%d,%d), cnt %d, bsize %d\n", __func__,
                    nodesElem->ppnode.nk.proto, nodesElem->ppnode.nk.port, p->sp, p->dp,
                    nodesElem->ppnode.cnt, nodesElem->ppnode.bsize);*/

            JHashProPortAdd(&pins_cnf->psDPIntef->h_pnode, &pins_cnf->psDPIntef->pnode,
                    &nodesElem->ppnode, NULL, targ_tnode, 0, 0);
        }

        //Tcp/Udp Session
        if ( SF_STREAM_UP == sf_stype
                || SF_STREAM_DOWN == sf_stype ) {
            PktCnt_ProcSsn(pins_cnf->psDPSsn, targ_tnode, p, sf_stype);
        }
    } while (0);

    //ARP
    if ( likely(NULL != stack_net) ) {
        if(pc.arp > pins_cnf->arp_count){
            pins_cnf->arp_count = pc.arp;
            stack_net[FLOWSTA_NET_ARP].cnt[SF_STREAM_INTRA]++;
            stack_net[FLOWSTA_NET_ARP].bsize[SF_STREAM_INTRA] += p->pkth->pktlen;
        }
    }
}

int sf_PktInspection(/*uint32_t ins_dev_idx, */uint64_t lcore)
{
    int err, ret;
    pthread_t pid;
    cpu_set_t cpuset;

//    if ( 0 != ins_dev_idx ) {   //This means we are in secondary process
        if ( MysqlConnect(&sf_mysql) ) {
            LogMessage("%s: MysqlConnect(sf_mysql) error\n", __func__);
            return 1;
        }

        sf_InitProtpUser();
//    }

    sf_PktInspcInit(&sfPktInspectCons);

    //Packet Timer Inspection
    ret = pthread_create(&pid, NULL, sf_Pins_Loop, &sfPktInspectCons);
    if ( ret < 0 ) {
        LogMessage("%s failed(sf_Pins_Loop): %s\n", __func__, strerror(errno));
        exit(errno);
    }

    if ( lcore ) {
        CPU_ZERO(&cpuset);
        //CPU_SET(19, &cpuset);
        cpuset.__bits[0] = lcore;
        err = pthread_setaffinity_np(pid, sizeof(cpu_set_t), &cpuset);
        if ( 0 != err )
            perror("pthread_setaffinity_np failed");
    }

/*    //Database Inspection
    ret = pthread_create(&pid, NULL, sf_DBIns_Loop, &sfPktInspectCons);
    if ( ret < 0 ) {
        LogMessage("%s failed(sf_DBIns_Loop): %s\n", __func__, strerror(errno));
        exit(errno);
    }

    if ( lcore ) {
        CPU_ZERO(&cpuset);
        //CPU_SET(19, &cpuset);
        cpuset.__bits[0] = lcore;
        err = pthread_setaffinity_np(pid, sizeof(cpu_set_t), &cpuset);
        if ( 0 != err )
            perror("pthread_setaffinity_np failed");
    }*/

    return 0;
}

