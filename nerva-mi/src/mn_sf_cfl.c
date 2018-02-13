

#include "mn_daq.h"
#include "mn_sf_cfl.h"
#include "mn_sql_op.h"
#include "mn_gen.h"
#include "mn_sf_sys_var.h"

/*#include "snort.h"
#include "sfdaq.h"
#include "session_api.h"
#include "session_common.h"
#include "stream_common.h"*/

static const char *server = "localhost";
static const char *database = "surveyor";
static const char *user = "root";
static const char *password = "13246";
/*static const char user[32] = {
        0x72+M_USER_ENC_OS,
        0x6f+M_USER_ENC_OS,
        0x6f+M_USER_ENC_OS,
        0x74+M_USER_ENC_OS,
        0x0 };
static const char password[32] = {
        0x31+M_PASS_ENC_OS,
        0x33+M_PASS_ENC_OS,
        0x32+M_PASS_ENC_OS,
        0x34+M_PASS_ENC_OS,
        0x36+M_PASS_ENC_OS,
        0x0 };*/
static MYSQL *sf_mysql = NULL;
static MYSQL *sfssn_mysql = NULL;
//static MYSQL *sfins_mysql = NULL;
static MYSQL *sfstack_mysql = NULL;

static const char *ipt_initfromdb = "select id,ip_src,ip_dst,tppflag,uppflag,tppflag_user,uppflag_user,pflag_other,sf_sta,geo_id,almflag from %s";
static const char *ipt_insert = "insert into %s (sf_sta,ip_src,ip_dst,geo_id,direction,tv_start,tv_upd,cnt,bsize,syn,dns,"
        "tppflag,uppflag,tppflag_user,uppflag_user,pflag_other,almflag) values(%u,%u,%u,%lu,%u,%u,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%u)";
static const char *ipt_update = "update %s set sf_sta=%u,geo_id=%lu,direction=%u,tv_upd=%u,cnt=cnt+%lu,bsize=bsize+%lu,syn=syn+%lu,dns=dns+%lu,"
        "tppflag=%lu,uppflag=%lu,tppflag_user=%lu,uppflag_user=%lu,pflag_other=%lu,almflag=%u where id=%lu";
static const char *ipt_upd_almflag = "update %s set sf_sta=%u,geo_id=%lu,almflag=%u where id=%lu";
//static const char *ipt_select = "select ip_src,ip_dst,tv_upd,cnt,syn from %s where id=%u";
//static const char *ipt_delete = "delete from %s where id=%lu";
static const char *iptssn_insert = "insert into %s (ipt_id,proto,direction,port_src,port_dst,cnt_up,bsz_up,cnt_down,bsz_down,"
        "flg_psh,bsz_sml,tv_start,tv_upd,tv_dur,state) values(%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u)";
/*static const char *iptssn_update = "update %s set cnt_up=%u,bsz_up=%u,cnt_down=%u,bsz_down=%u,"
        "flg_psh=%u,bsz_sml=%u,tv_upd=%u,tv_dur=%u where id=%lu";*/
static const char *iptssn_update = "update %s set cnt_up=%u,bsz_up=%u,cnt_down=%u,bsz_down=%u,"
        "flg_psh=%u,bsz_sml=%u,tv_upd=%u,tv_dur=%u,state=%u where ipt_id=%lu and id=%lu";
static const char *protp_insert = "insert into %s (ipt_id,ip_src,ip_dst,tv_upd,proto,port,port_idx,user_set,cnt_vi,bsz_vi,cnt_vo,bsz_vo) "
        "values(%lu,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu)";
static const char *protp_set_pp_id = "SET @pp_id=LAST_INSERT_ID()";
static const char *protp_update = "update %s set tv_upd=%u,cnt_vi=cnt_vi+%lu,bsz_vi=bsz_vi+%lu,"
        "cnt_vo=cnt_vo+%lu,bsz_vo=bsz_vo+%lu,id=(select @pp_id := id) "
        "where ipt_id=%lu and proto=%u and port_idx=%u and user_set=%u ORDER BY id DESC LIMIT 1";
static const char *protp_scale_throw = "INSERT INTO %s (ipt_id,geo_id,pp_id,scl_cmb,tv_upd,cnt_vi,bsz_vi,cnt_vo,bsz_vo,direc) "
        "SELECT %u,%lu,@pp_id,%u,%u,%u,%u,%u,%u,%u ON DUPLICATE KEY UPDATE tv_upd=VALUES(tv_upd),cnt_vi=VALUES(cnt_vi),bsz_vi=VALUES(bsz_vi),"
        "cnt_vo=VALUES(cnt_vo),bsz_vo=VALUES(bsz_vo)";
static const char *protp_scale_add = "INSERT INTO %s (ipt_id,geo_id,pp_id,scl_cmb,tv_upd,cnt_vi,bsz_vi,cnt_vo,bsz_vo,direc) "
        "SELECT %u,%lu,@pp_id,%u,%u,%u,%u,%u,%u,%u ON DUPLICATE KEY UPDATE tv_upd=VALUES(tv_upd),cnt_vi=cnt_vi+VALUES(cnt_vi),bsz_vi=bsz_vi+VALUES(bsz_vi),"
        "cnt_vo=cnt_vo+VALUES(cnt_vo),bsz_vo=bsz_vo+VALUES(bsz_vo)";

//static const char *geo_set_ipt_id = "SET @ipt_id=LAST_INSERT_ID()";
/*static const char *geo_scale_throw = "INSERT INTO %s (geo_id,scl_cmb,tv_upd,cnt_up,bsz_up,cnt_dn,bsz_dn) "
        "SELECT %u,%u,%u,%u,%u,%u,%u ON DUPLICATE KEY UPDATE tv_upd=VALUES(tv_upd),cnt_up=VALUES(cnt_up),bsz_up=VALUES(bsz_up),"
        "cnt_dn=VALUES(cnt_dn),bsz_dn=VALUES(bsz_dn)";*/
static const char *geo_scale_add = "INSERT INTO %s (geo_id,scl_cmb,tv_upd,cnt_up,bsz_up,cnt_dn,bsz_dn) "
        "SELECT %lu,%u,%u,%u,%u,%u,%u ON DUPLICATE KEY UPDATE tv_upd=VALUES(tv_upd),cnt_up=cnt_up+VALUES(cnt_up),bsz_up=bsz_up+VALUES(bsz_up),"
        "cnt_dn=cnt_dn+VALUES(cnt_dn),bsz_dn=bsz_dn+VALUES(bsz_dn)";
static const char *geo_scale_reset_cmb = "UPDATE %s SET cnt_up=0,bsz_up=0,cnt_dn=0,bsz_dn=0 WHERE scl_cmb=%u";

//Delete Instance, reference by ipt_id
static const char *nfstats_del_ins_gb = "DELETE t1,t3,t5,t6,t7,t8,t9 FROM nfiptet_stats t1 "
        "LEFT JOIN nfiptet_geo t2 ON t2.ipt_id=t1.id "
        "LEFT JOIN nfssn_stats t3 ON t3.ipt_id=t1.id "
        //"LEFT JOIN nfssn_stats_sfaly t4 ON t4.ipt_id=t1.id "
        "LEFT JOIN nfprotp_stats t5 ON t5.ipt_id=t1.id "
        "LEFT JOIN nfprotp_stats_scale_l1 t6 ON t6.ipt_id=t1.id "
        "LEFT JOIN nfprotp_stats_scale_l2 t7 ON t7.ipt_id=t1.id "
        "LEFT JOIN nfprotp_stats_scale_l3 t8 ON t8.ipt_id=t1.id "
        "LEFT JOIN nfprotp_stats_scale_l4 t9 ON t9.ipt_id=t1.id WHERE t1.id=%lu";


static const char *scale_cmb_protp_table_name [] = {
#if SUR_SF_SCALE_EN_MINUTES
        "nfprotp_stats_scale_l1",
#endif
        "nfprotp_stats_scale_l2",
        "nfprotp_stats_scale_l3",
        "nfprotp_stats_scale_l4",
};

static const char *scale_cmb_geo_table_name [] = {
#if SUR_SF_SCALE_EN_MINUTES
        "nfiptet_geo_scale_l1",
#endif
        "nfiptet_geo_scale_l2",
        "nfiptet_geo_scale_l3",
        "nfiptet_geo_scale_l4",
};

/*static const char *protp_scale_throw = "REPLACE INTO nfprotp_stats_scale (pp_id,scl_cmb,tv_upd,cnt_vi,bsz_vi,cnt_vo,bsz_vo) "
        "SELECT @pp_id,%u,%u,%u,%u,%u,%u";*/
//static const char *protp_delete = "delete from %s where ipt_id=%lu";

static const char *stack_insert = "insert into %s (ps_id,name,port_idx,user,port,direction,cnt,bsz,bps) values(%u,'%s',%u,%u,%u,%u,%lu,%lu,%u)";
static const char *stack_update = "update %s set port=%u,cnt=%lu,bsz=%lu,bps=%u where ps_id=%u and direction=%u";
static const char *stack_select = "SELECT ps_id,direction,cnt,bsz FROM %s ORDER BY ps_id ASC";
static const char *stack_reset_bps = "update %s set bps=0";

static const char *iptssn_pkt_sample = "INSERT INTO nfssn_track_hbpkt (ssn_id,ipt_id,tv_stamp,pkt_sample) VALUES(%lu,%lu,%u,'";


static char sql_cfl[1024] = "";
static char sql_cfl_scl[1024] = "";
static char sql_cfl_ssn[1024] = "";
//static char sql_cfl_dbins[1024] = "";
static char sql_cfl_stack[1024] = "";

//static CounterNetFlow sfPktInspectCons;
static StatsFlowGlobal sfGlobalInfo = {0,0,0,0,0};

//buffer for ssn-packet sample BASE64
static char sanitize_buffer[SSN_CHSUM_SQU_TRACK_BASE64_BUFLEN];
static char sql_cfl_ssn_ptrc[SSN_CHSUM_SQU_TRACK_BASE64_BUFLEN+1024] = "";

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
#endif

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
    mn_MysqlQuery(sf_mysql, sql, NULL);
    snprintf(sql, sizeof(sql), "select id from approto_ports_system");
    row_cnt = mn_MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get approto_ports_system table failed!\n", __func__);
    }
    else if ( 0 == row_cnt ) {
        mysql_free_result(mysql_res);
        mn_MysqlTransBegin(sf_mysql);

        //Create Instance
        p_ppmap = map_netflow_portproto;
        sql_ret = 0;
        while ( p_ppmap->port > 0 ) {
            snprintf(sql, sizeof(sql), "insert into approto_ports_system (port, proto_type, approto_idx, approto_desc) "
                    "values(%u, %u, %u, '%s')", p_ppmap->port, p_ppmap->pro_bitset, p_ppmap->fp_index, p_ppmap->pp_name);
            sql_ret = mn_MysqlQuery(sf_mysql, sql, NULL);
            if ( sql_ret )
                break;

            p_ppmap++;
        }
        if ( sql_ret ) {
            LogMessage("%s: [%s] failed!\n", __func__, sql);
            mn_MysqlTransRollback(sf_mysql);
        }
        else {
            mn_MysqlTransCommit(sf_mysql);
        }
    }

    LogMessage("%s: approto_ports_system sync, row_cnt %d!\n", __func__, row_cnt);

    //approto_ports_user tables
    snprintf(sql, sizeof(sql), "select port,proto_type,approto_idx,approto_desc,pp_switch,renew "
            "from approto_ports_user order by id asc");
    row_cnt = mn_MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
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
                sql_ret = mn_MysqlQuery(sf_mysql, sql, NULL);
                if ( sql_ret ) {
                    LogMessage("%s: [%s] failed!\n", __func__, sql);
                    return -1;
                }
            }
        }
        else {
            mysql_free_result(mysql_res);
            mn_MysqlTransBegin(sf_mysql);

            sql_ret = 0;
            for ( i=0; i<(SF_MAX_PROT_PROTO_USER+1); i++ ) {
                snprintf(sql, sizeof(sql), "insert into approto_ports_user (id, port, proto_type, approto_idx, approto_desc, pp_switch, renew) "
                        "values(%u, %u, %u, %u, '%s', %u, %u)",
                        i+1, p_ppmap->port, p_ppmap->pro_bitset, p_ppmap->fp_index, p_ppmap->pp_name,
                        p_ppmap->pp_switch, p_ppmap->renew);
                sql_ret = mn_MysqlQuery(sf_mysql, sql, NULL);
                if ( sql_ret )
                    break;

                //p_ppmap++;
            }

            if ( sql_ret ) {
                LogMessage("%s: [%s] failed!\n", __func__, sql);
                mn_MysqlTransRollback(sf_mysql);
            }
            else {
                mn_MysqlTransCommit(sf_mysql);
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
    row_cnt = mn_MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
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
                apnode.sf_sta = (uint32_t)strtoul(row[8], NULL, 10);
                apnode.geo_index = strtoul(row[9], NULL, 10);
                apnode.almflag = (uint32_t)strtoul(row[10], NULL, 10);
                apnode.aly_stat |= SFALY_IPT_ACTIVE|SFALY_IPT_INSPECT_PULSE;
                apnode.scl_st[SF_SCALE_STAGE_META].cnt = 0;
                apnode.scl_st[SF_SCALE_STAGE_META].bsz = 0;
                apnode.syn = 0;
                apnode.dns = 0;
                apnode.tv_upd = 0;
                //count = atoi(row[2]);
                //total = atoi(row[3]);

                //pp_flag handling
                apnode.ppflag.tcp_user &= ~ppflag_user_renew;
                apnode.ppflag.udp_user &= ~ppflag_user_renew;

                JHashIpTetAdd((IPTetStatNodeHaTbl*)(sfdp_ctl->h_tnode), (IPTetStatNodePool*)sfdp_ctl->tnode,
                        (IPTetStatNode*)&apnode, NULL, 0x3, (sfdp_ctl->nsock-1));
            }
        }

        mysql_free_result(mysql_res);
    }

    //Max Ip-Tet ID
    sfGlobalInfo.max_iptid = 0;
    snprintf(sql, sizeof(sql), "select max(id) from %s",
            map_nf2dbtbl[NF_IPTET].tbl_name);
    row_cnt = mn_MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
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
    row_cnt = mn_MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
    }
    else {
        if ( row_cnt > 0 ) {
            LogMessage("%s: nf_proto-port_stats enabled scaling\n", __func__);
            sfGlobalInfo.envset_scl_flag |= SF_GLOB_VAR_SCALE_DEEP_LIT;
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
    row_cnt = mn_MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get nfiptet table max(id) failed!\n", __func__);
    }
    else {
        if ( (row = mysql_fetch_row(mysql_res)) )
            if ( NULL != row[0] )
                sfGlobalInfo.max_ssnid = strtoul(row[0], NULL, 10);
        mysql_free_result(mysql_res);
    }

    //Current Inspection ID
    sfGlobalInfo.cur_iptid = 0;
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
    row_cnt = mn_MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
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

        mn_MysqlTransBegin(sf_mysql);

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
                if ( mn_MysqlQuery(sf_mysql, sql, NULL) ) {
                    LogMessage("%s: [%s] failed!\n", __func__, sql);
                    mn_MysqlTransRollback(sf_mysql);
                    return -1;
                }
            }
        }

        mn_MysqlTransCommit(sf_mysql);
    }

    LogMessage("%s: done, iptet total %lu, cur_num %lu, node_num %d/%d, max_ssn %lu\n", __func__,
            sfdp_ctl->tnode[0].total*sfdp_ctl->nsock,
            sfGlobalInfo.max_iptid,
            sfdp_ctl->tnode[0].npcnt, (NULL != sfdp_ctl->tnode[1].nodes ? sfdp_ctl->tnode[1].npcnt:0),
            sfGlobalInfo.max_ssnid);

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
    	ret = JHashIpTetAdd((IPTetStatNodeHaTbl*)(sfdp_ctl->h_tnode), (IPTetStatNodePool*)sfdp_ctl->tnode,
    			tnode, (IPTetStatNode**)&targ_tnode, 0x1, (sfdp_ctl->nsock-1));
    	if ( ret < 0 ) 			//Node Add Failed
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
            ret = JHashProPortAdd((ProtoPortNodeHaTbl*)sfdp_ctl->h_pnode, (ProtoPortNodePool*)sfdp_ctl->pnode,
                    pnode, &targ_pnode, (IPTetStatNode*)targ_tnode, 1, (uint8_t)(ret));
            if ( 0 != ret )
                break;

            /*LogMessage("%s: merge src: %x, dst: %x, ppflag %lx\n", __func__,
                    targ_tnode->tet.src, targ_tnode->tet.dst, targ_tnode->ppflag);
*/
            pnode = pnode->pnxt;
        }
    }

    LogMessage("%s: current node count %d/%d, merge_total(%d) new %d, upd %d, new_p %d, upd_p %d\n", __func__,
    		sfdp_ctl->tnode[0].npcnt, (NULL != sfdp_ctl->tnode[1].nodes ? sfdp_ctl->tnode[1].npcnt:0),
    		t_nodepool->npidx,
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

static inline void sf_IptetSyncDBConfirm(IPTetConfluenceNodeHaTbl *hanodes, IPTetConfluenceNodePool *nodepool,
        uint32_t node_start, uint32_t node_end, uint32_t scale_sta)
{
    uint32_t i, scl_idx;
    IPTetCflStatNode *tnode;
    ProtoPortCflNode *ppnode;
    //uint64_t ppnflag;

    //LogMessage("%s: node_start %d, node_end %d\n", __func__, node_start, node_end);

    tnode = nodepool->nodes + node_start;
    for (i=node_start; i<=node_end; i++, tnode++) {
        switch ( tnode->fsm ) {
        case NF_NODEIPT_NEW_TOBE_CFM:
            sfGlobalInfo.max_iptid = tnode->dbid;

            //Clear Stats
            tnode->scl_st[SF_SCALE_STAGE_META].cnt = 0;
            tnode->scl_st[SF_SCALE_STAGE_META].bsz = 0;
            if ( tnode->geo_index > 0 ) {
                for ( scl_idx=SF_SCALE_STAGE_MIN; scl_idx<SF_SCALE_STAGE_SAVE; scl_idx++ ) {
                    if ( (0x01<<scl_idx) & scale_sta ) {
                        tnode->scl_st[scl_idx].cnt = 0;
                        tnode->scl_st[scl_idx].bsz = 0;
                    }
                }
            }
            tnode->syn = 0;
            tnode->dns = 0;
            tnode->fsm = NF_NODEIPT_SYNCED;
            tnode->aly_stat |= SFALY_IPT_ACTIVE|SFALY_IPT_INSPECT_PULSE;
            break;
        case NF_NODEIPT_UPD_TOBE_CFM:
            //Clear Stats
            tnode->scl_st[SF_SCALE_STAGE_META].cnt = 0;
            tnode->scl_st[SF_SCALE_STAGE_META].bsz = 0;
            if ( tnode->geo_index > 0 ) {
                for ( scl_idx=SF_SCALE_STAGE_MIN; scl_idx<SF_SCALE_STAGE_SAVE; scl_idx++ ) {
                    if ( (0x01<<scl_idx) & scale_sta ) {
                        tnode->scl_st[scl_idx].cnt = 0;
                        tnode->scl_st[scl_idx].bsz = 0;
                    }
                }
            }
            tnode->syn = 0;
            tnode->dns = 0;
            tnode->fsm = NF_NODEIPT_SYNCED;

            if ( tnode->qry_flag&NF_IPTET_FLOW_DATA_QNC ) {
                tnode->qry_flag &= ~(NF_IPTET_FLOW_DATA|NF_IPTET_FLOW_DATA_QNC);
                tnode->aly_stat |= SFALY_IPT_ACTIVE|SFALY_IPT_INSPECT_PULSE;
            }
            if ( tnode->qry_flag&NF_IPTET_DEDICATE_FLAG_QNC )
                tnode->qry_flag &= ~(NF_IPTET_DEDICATE_FLAG|NF_IPTET_DEDICATE_FLAG_QNC);
            break;
        default:
            if ( tnode->expire ) {
                //remove node which didn't update for a long time
                JHashIpTetCflDel(hanodes, nodepool, &tnode->tet, tnode->dbid);
            }
            break;
        }

        ppnode = tnode->pp_node;
        while ( ppnode ) {
            //ppnflag = SF_CFL_GET_PPFLAG(ppnode->nk.proto_idx, ppnode->nk.apport_idx);
            SF_CFL_SET_PPFLAG(&tnode->ppflag.flag[0], ppnode->nk.user_set,
                    ppnode->nk.proto_idx, ppnode->nk.apport_idx);
            ppnode->scl_st[SF_SCALE_STAGE_META].cnt = 0;
            ppnode->scl_st[SF_SCALE_STAGE_META].bsz = 0;

            for ( scl_idx=SF_SCALE_STAGE_MIN; scl_idx<SF_SCALE_STAGE_SAVE; scl_idx++ ) {
                if ( (0x01<<scl_idx) & scale_sta ) {
                    ppnode->scl_st[scl_idx].cnt = 0;
                    ppnode->scl_st[scl_idx].bsz = 0;
                }
            }
            ppnode = ppnode->pnxt;
        }

        if ( (sfGlobalInfo.envset_scl_flag & (SF_GLOB_VAR_SCALE_MASK&scale_sta)) == sfGlobalInfo.envset_scl_flag ) {      //Ready to Go Next Round
            tnode->pp_node = NULL;
        }

        //release ssn node
        //tnode->ssn_node = NULL;
    }
}

static int sf_IptetSyncToDB(StatsFlowConfluDataPlane *sfdp_ctl, uint16_t sock_idx,
        time_t tvs_current, time_t *tv_scale, uint32_t *scale_cmb,
        uint8_t *scale_reset, uint32_t scale_flag)
{
    uint8_t pflag_idx, scl_idx;
    int ret = 0, tvs_upd_gap;
    uint32_t i, j, node_cfm_start;
    uint32_t new_node = 0, upd_count = 0, expire_cnt = 0, geo_scl = 0, pp_count = 0, pp_scl = 0;
    uint32_t count_sum, count_sum_pre = 0;
    uint32_t protp_cnt_in, protp_bsz_in, protp_cnt_out, protp_bsz_out;
    uint64_t id, node_cnt;
    uint64_t ppflag_ora[NF_IPTET_PFLAG_NUM], ppnflag;
    const char *scale_query;
    //ProtoProtKeyDbUnion ipt_ppu;
    IPTetCflStatNode* tnode = sfdp_ctl->tnode[sock_idx].nodes;
    ProtoPortCflNode *ppnode;

    LogMessage("%s: handle iptet, cur_idx %d\n", __func__, sfdp_ctl->tnode[sock_idx].npidx);

    mn_MysqlTransBegin(sf_mysql);
    for ( scl_idx=SF_SCALE_STAGE_MIN; scl_idx<SF_SCALE_STAGE_SAVE; scl_idx++ ) {
        if ( ((0x01<<scl_idx) & scale_flag) && scale_reset[scl_idx] ) {
            snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), geo_scale_reset_cmb,
                        scale_cmb_geo_table_name[scl_idx-1], scale_cmb[scl_idx]);
            ret = mn_MysqlQuery(sf_mysql, sql_cfl_scl, NULL);
        }
    }

    for ( scl_idx=SF_SCALE_STAGE_DAY; scl_idx<SF_SCALE_STAGE_MAX; scl_idx++ ) {
        if ( ((0x01<<scl_idx) & scale_flag) && scale_reset[scl_idx] ) {
            snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), geo_scale_reset_cmb,
                        scale_cmb_geo_table_name[scl_idx-1], scale_cmb[scl_idx]);
            ret = mn_MysqlQuery(sf_mysql, sql_cfl_scl, NULL);
        }
    }
    mn_MysqlTransCommit(sf_mysql);

    mn_MysqlTransBegin(sf_mysql);

    //for(i = 0; i < sfdp_ctl->tnode.npidx; i++, tnode++) {
    node_cfm_start = 0;
    node_cnt = sfdp_ctl->tnode[sock_idx].total;
    for (i=0; i<node_cnt; i++, tnode++) {
        if ( NF_NODEIPT_NON == tnode->fsm || NF_NODEIPT_IDLE == tnode->fsm )
            continue;
        else if ( NF_NODEIPT_SYNCED == tnode->fsm
                && (tnode->qry_flag&NF_IPTET_DEDICATE_FLAG) ) {
            tnode->fsm = NF_NODEIPT_UPD;
            //LogMessage("%s: sync iptet(id %lu) for new alysist's alarms\n", __func__, tnode->dbid);
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
                    tnode->sf_sta, tnode->tet.src, tnode->tet.dst, tnode->geo_index, tnode->direction,
                    tnode->tv_upd/*tv_start*/, tnode->tv_upd,
                    tnode->scl_st[SF_SCALE_STAGE_META].cnt+0L, tnode->scl_st[SF_SCALE_STAGE_META].bsz+0L,
                    tnode->syn+0L, tnode->dns+0L,
                    ppflag_ora[0], ppflag_ora[1], ppflag_ora[2], ppflag_ora[3], ppflag_ora[4], tnode->almflag);
            ret = mn_MysqlQueryUlid(sf_mysql, sql_cfl, &id);
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
                        tnode->sf_sta, tnode->geo_index, tnode->direction, tnode->tv_upd,
                        tnode->scl_st[SF_SCALE_STAGE_META].cnt+0L, tnode->scl_st[SF_SCALE_STAGE_META].bsz+0L,
                        tnode->syn+0L, tnode->dns+0L,
                        ppflag_ora[0], ppflag_ora[1], ppflag_ora[2], ppflag_ora[3], ppflag_ora[4], tnode->almflag, tnode->dbid);
                ret = mn_MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                tnode->qry_flag |= NF_IPTET_FLOW_DATA_QNC|NF_IPTET_DEDICATE_FLAG_QNC;
                tnode->fsm = NF_NODEIPT_UPD_TOBE_CFM;
            }
            else if ( tnode->qry_flag&NF_IPTET_DEDICATE_FLAG ) {         //Just alarm flag
                snprintf(sql_cfl, sizeof(sql_cfl), ipt_upd_almflag,
                        map_nf2dbtbl[NF_IPTET].tbl_name,
                        tnode->sf_sta, tnode->geo_index,
                        tnode->almflag, tnode->dbid);
                ret = mn_MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                tnode->qry_flag |= NF_IPTET_DEDICATE_FLAG_QNC;
                tnode->fsm = NF_NODEIPT_UPD_TOBE_CFM;
            }

        	//For Test
        	upd_count++;
            break;
        default:
            //Node Activation
            if ( tnode->expire ) {
                //remove from database
                /*snprintf(sql_cfl, sizeof(sql_cfl), ipt_delete,
                        map_nf2dbtbl[NF_IPTET].tbl_name, tnode->dbid);
                ret = mn_MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                snprintf(sql_cfl, sizeof(sql_cfl), protp_delete,
                        map_nf2dbtbl[NF_PROTP].tbl_name, tnode->dbid);
                ret = mn_MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;*/

                snprintf(sql_cfl, sizeof(sql_cfl), nfstats_del_ins_gb, tnode->dbid);
                ret = mn_MysqlQuery(sf_mysql, sql_cfl, NULL);
                if ( ret )
                    break;

                LogMessage("%s: ip tuple(id %lu) expired\n", __func__, tnode->dbid);
                /*mn_MysqlTransCommit(sf_mysql);
                mn_MysqlTransBegin(sf_mysql);
                sf_IptetSyncDBConfirm(sfdp_ctl->tnode[sock_idx].nodes, node_cfm_start, i, scale_flag);
                node_cfm_start = i+1;

                //also remove node which didn't update for a long time
                JHashIpTetCflDel(&sfdp_ctl->h_tnode[sock_idx], &sfdp_ctl->tnode[sock_idx],
                        &tnode->tet, tnode->dbid, (sfdp_ctl->nsock-1));*/
                expire_cnt++;
            }
            else {
                tvs_upd_gap = tvs_current - tnode->tv_upd;
                if ( tvs_upd_gap > 86400 ) {   //haven't update in the last 24 hours
                    tnode->aly_stat &= ~SFALY_IPT_ACTIVE;
                    tnode->aly_stat |= SFALY_IPT_INSPECT_PULSE;
                }
            }
        	break;
        }

        //finish this ip_tet node
        if ( ret )
            break;

        //Scaled IPTET-GEO Data--Sync to DB
        if ( tnode->geo_index > 0 ) {
            for ( scl_idx=SF_SCALE_STAGE_MIN; scl_idx<SF_SCALE_STAGE_SAVE; scl_idx++ ) {
                tnode->scl_st[scl_idx].cnt += tnode->scl_st[SF_SCALE_STAGE_META].cnt;
                tnode->scl_st[scl_idx].bsz += tnode->scl_st[SF_SCALE_STAGE_META].bsz;

                if ( ((0x01<<scl_idx) & scale_flag) && (tnode->scl_st[scl_idx].cnt>0) ) {
                    /*if ( scale_reset[scl_idx] )
                        scale_query = geo_scale_throw;
                    else*/
                        scale_query = geo_scale_add;

                    if ( SF_STREAM_UP == tnode->direction ) {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_geo_table_name[scl_idx-1], tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                tnode->scl_st[scl_idx].cnt, tnode->scl_st[scl_idx].bsz, 0, 0);
                    }
                    else {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_geo_table_name[scl_idx-1], tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                0, 0, tnode->scl_st[scl_idx].cnt, tnode->scl_st[scl_idx].bsz);
                    }
                    ret = mn_MysqlQuery(sf_mysql, sql_cfl_scl, NULL);
                    if ( ret )
                        break;

                    geo_scl++;
                }
            }

            for ( scl_idx=SF_SCALE_STAGE_DAY; scl_idx<SF_SCALE_STAGE_MAX; scl_idx++ ) {
                if ( ((0x01<<scl_idx) & scale_flag) && (tnode->scl_st[SF_SCALE_STAGE_HOUR].cnt>0) ) {
                    /*if ( scale_reset[scl_idx] )
                        scale_query = geo_scale_throw;
                    else*/
                        scale_query = geo_scale_add;

                    if ( SF_STREAM_UP == tnode->direction ) {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_geo_table_name[scl_idx-1], tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                tnode->scl_st[SF_SCALE_STAGE_HOUR].cnt,
                                tnode->scl_st[SF_SCALE_STAGE_HOUR].bsz, 0, 0);
                    }
                    else {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_geo_table_name[scl_idx-1], tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                0, 0,
                                tnode->scl_st[SF_SCALE_STAGE_HOUR].cnt,
                                tnode->scl_st[SF_SCALE_STAGE_HOUR].bsz);
                    }
                    ret = mn_MysqlQuery(sf_mysql, sql_cfl_scl, NULL);
                    if ( ret )
                        break;

                    geo_scl++;
                }
            }
        }

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
                    protp_cnt_in = ppnode->scl_st[SF_SCALE_STAGE_META].cnt;
                    protp_bsz_in = ppnode->scl_st[SF_SCALE_STAGE_META].bsz;
                    protp_cnt_out = 0;
                    protp_bsz_out = 0;
                }
                else {
                    protp_cnt_in = 0;
                    protp_bsz_in = 0;
                    protp_cnt_out = ppnode->scl_st[SF_SCALE_STAGE_META].cnt;
                    protp_bsz_out = ppnode->scl_st[SF_SCALE_STAGE_META].bsz;
                }

                if ( ppnflag ) {
                    snprintf(sql_cfl, sizeof(sql_cfl), protp_update,
                            map_nf2dbtbl[NF_PROTP].tbl_name, ppnode->tv_upd,
                            protp_cnt_in+0L, protp_bsz_in+0L, protp_cnt_out+0L, protp_bsz_out+0L,
                            tnode->dbid, map_netflow_proto[ppnode->nk.proto_idx].proto,
                            ppnode->nk.apport_idx, ppnode->nk.user_set);
                    ret = mn_MysqlQuery(sf_mysql, sql_cfl, NULL);
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
                    ret = mn_MysqlQuery(sf_mysql, sql_cfl, NULL);
                    if ( ret )
                        break;

                    if ( SF_GLOB_VAR_SCALE_L0 != (SF_GLOB_VAR_SCALE_MASK&scale_flag) ) {   //Not just meta-prot_p-data
                        ret = mn_MysqlQuery(sf_mysql, protp_set_pp_id, NULL);
                        if ( ret )
                            break;
                    }
                }
            //}

            //Scaled Data--Sync to DB
            for ( scl_idx=SF_SCALE_STAGE_MIN; scl_idx<SF_SCALE_STAGE_SAVE; scl_idx++ ) {
                ppnode->scl_st[scl_idx].cnt += ppnode->scl_st[SF_SCALE_STAGE_META].cnt;
                ppnode->scl_st[scl_idx].bsz += ppnode->scl_st[SF_SCALE_STAGE_META].bsz;

                if ( (0x01<<scl_idx) & scale_flag ) {
                    if ( scale_reset[scl_idx] )
                        scale_query = protp_scale_throw;
                    else
                        scale_query = protp_scale_add;

                    if ( (PORT_VEC_IN == ppnode->nk.port_vec)
                            || (PORT_VEC_INVALID == ppnode->nk.port_vec
                                    && SF_STREAM_UP == tnode->direction) ) {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_protp_table_name[scl_idx-1], tnode->dbid, tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                ppnode->scl_st[scl_idx].cnt, ppnode->scl_st[scl_idx].bsz, 0, 0,
                                tnode->direction);
                    }
                    else {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_protp_table_name[scl_idx-1], tnode->dbid, tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                0, 0, ppnode->scl_st[scl_idx].cnt, ppnode->scl_st[scl_idx].bsz,
                                tnode->direction);
                    }
                    ret = mn_MysqlQuery(sf_mysql, sql_cfl_scl, NULL);
                    if ( ret )
                        break;

                    pp_scl++;
                }
            }

            for ( scl_idx=SF_SCALE_STAGE_DAY; scl_idx<SF_SCALE_STAGE_MAX; scl_idx++ ) {
                if ( (0x01<<scl_idx) & scale_flag ) {
                    if ( scale_reset[scl_idx] )
                        scale_query = protp_scale_throw;
                    else
                        scale_query = protp_scale_add;

                    if ( (PORT_VEC_IN == ppnode->nk.port_vec)
                            || (PORT_VEC_INVALID == ppnode->nk.port_vec
                                    && SF_STREAM_UP == tnode->direction) ) {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_protp_table_name[scl_idx-1], tnode->dbid, tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                ppnode->scl_st[SF_SCALE_STAGE_HOUR].cnt,
                                ppnode->scl_st[SF_SCALE_STAGE_HOUR].bsz, 0, 0,
                                tnode->direction);
                    }
                    else {
                        snprintf(sql_cfl_scl, sizeof(sql_cfl_scl), scale_query,
                                scale_cmb_protp_table_name[scl_idx-1], tnode->dbid, tnode->geo_index,
                                scale_cmb[scl_idx], tv_scale[scl_idx],
                                0, 0,
                                ppnode->scl_st[SF_SCALE_STAGE_HOUR].cnt,
                                ppnode->scl_st[SF_SCALE_STAGE_HOUR].bsz,
                                tnode->direction);
                    }
                    ret = mn_MysqlQuery(sf_mysql, sql_cfl_scl, NULL);
                    if ( ret )
                        break;

                    pp_scl++;
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
        count_sum = new_node+upd_count+(expire_cnt<<8)+pp_count+geo_scl+pp_scl;
        if ( (count_sum-count_sum_pre) > 0xfff ) {
            count_sum_pre = count_sum;

            mn_MysqlTransCommit(sf_mysql);
            mn_MysqlTransBegin(sf_mysql);
            sf_IptetSyncDBConfirm(&sfdp_ctl->h_tnode[sock_idx], &sfdp_ctl->tnode[sock_idx],
                    node_cfm_start, i, scale_flag);
            node_cfm_start = i+1;
        }
    }

    if ( ret ) {            //Query Failed
        mn_MysqlTransRollback(sf_mysql);

        tnode = sfdp_ctl->tnode[sock_idx].nodes+node_cfm_start;
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
                if ( tnode->qry_flag&NF_IPTET_DEDICATE_FLAG_QNC )
                    tnode->qry_flag &= ~NF_IPTET_DEDICATE_FLAG_QNC;
                break;
            default:
                break;
            }
        }

        return MN_ERROR_DB;
    }
    else {                  //Query Succeed
        mn_MysqlTransCommit(sf_mysql);
        sf_IptetSyncDBConfirm(&sfdp_ctl->h_tnode[sock_idx], &sfdp_ctl->tnode[sock_idx],
                node_cfm_start, node_cnt-1, scale_flag);

        //reset cfl_ssn node pool
        //sfdp_ctl->snode.npidx = 0;
        if ( (sfGlobalInfo.envset_scl_flag & (SF_GLOB_VAR_SCALE_MASK&scale_flag)) == sfGlobalInfo.envset_scl_flag ) {      //Ready to Go Next Round
            LogMessage("%s: reset cfl-protp mbuf, ha_len 0x%lx\n", __func__,
                    sizeof(void*)*(sfdp_ctl->h_pnode[sock_idx].size));
            pp_count = sfdp_ctl->pnode[sock_idx].npidx;
            sfdp_ctl->pnode[sock_idx].npidx = 0;
            memset(sfdp_ctl->h_pnode[sock_idx].hatbl, 0,
                    sizeof(void*)*(sfdp_ctl->h_pnode[sock_idx].size));
        }
    }

    LogMessage("%s: no clear count, nodes[%u] num %d, transfer nodes -- new(%u) upd(%u) exp(%u) geo_scl(%u) pp(%u) pp_scl(%u)\n", __func__,
            sock_idx, sfdp_ctl->tnode[sock_idx].npcnt,
            new_node, upd_count, expire_cnt, geo_scl, pp_count, pp_scl);
    return 0;
}

static int sf_StackSyncToDB(StatsFlowConfluDataPlane *sfdp_ctl)
{
    uint8_t fp_index;
    int ret = 0;
    uint32_t i, j;
    ProtoStackStatsCflNodes *cfl_stack = (ProtoStackStatsCflNodes*)(&sfdp_ctl->stack);

    mn_MysqlTransBegin(sfstack_mysql);

    snprintf(sql_cfl_stack, sizeof(sql_cfl_stack), stack_reset_bps, map_nf2dbtbl[NF_PROTO].tbl_name);
    ret = mn_MysqlQuery(sfstack_mysql, sql_cfl_stack, NULL);
    if ( ret ) {
        mn_MysqlTransRollback(sfstack_mysql);
        return MN_ERROR_DB;
    }

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
                ret = mn_MysqlQuery(sfstack_mysql, sql_cfl_stack, NULL);
                if ( ret )
                    break;
            }
            cfl_stack[i].nd_new = 0;
        }
        else {
            for (j=0; j<SF_STREAM_DIRECTION_TYPES; j++) {
                if ( 0 == cfl_stack[i].bps[j] )
                    continue;

                snprintf(sql_cfl_stack, sizeof(sql_cfl_stack), stack_update,
                        map_nf2dbtbl[NF_PROTO].tbl_name,
                        cfl_stack[i].port,
                        cfl_stack[i].cnt[j], cfl_stack[i].bsize[j], cfl_stack[i].bps[j],
                        i+1, j);
                        //map_netfow2dp[i].nf_name);
                ret = mn_MysqlQuery(sfstack_mysql, sql_cfl_stack, NULL);
                if ( ret )
                    break;
            }
        }
    }

    if ( ret ) {
        mn_MysqlTransRollback(sfstack_mysql);
        return MN_ERROR_DB;
    }

    mn_MysqlTransCommit(sfstack_mysql);
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
    uint32_t ssn_cntsum = 0, ssn_cnt_scl = 0;
    uint32_t ssn_tv_dur, ssn_tv_no_upd;
    uint32_t tvs_current = time(NULL);
    uint32_t ssn_cnt[MAX_SSNPROTO_CFL_NODEPOOLS] = {0};
    uint32_t ssn_upd[MAX_SSNPROTO_CFL_NODEPOOLS] = {0};
    uint32_t ssn_idl[MAX_SSNPROTO_CFL_NODEPOOLS] = {0};
    SSNProtoStatsNode *snode;
    SSNCksumTrack *p_track;
    char *p_tr;
    IPTetCflStatNode *p_tnode;
    uint64_t id = 0, max_cur_ssnid;//, id_start, id_end;
    uint64_t ssn_ptrc_b64len;
    char log_buf[256], buf[16];

    for ( i=0; i<MAX_SSNPROTO_CFL_NODEPOOLS; i++ ) {
        if ( NULL == sfdp_ssn[i] )
            break;

        mn_MysqlTransBegin(sfssn_mysql);

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

            if ( snode->fsm.db_ood ) {
                snode->fsm.db_ood = 0;
                snode->fsm.idle_cum = 0;
            }
            else if ( snode->fsm.idle_cum < SSN_FSM_IDLE_ACCUM_MAX ) {
                snode->fsm.idle_cum ++;
            }

            if ( snode->fsm.db_sync ) {
                if ( SSN_FSM_IDLE_ACCUM_MAX != snode->fsm.idle_cum ) {
                    snprintf(sql_cfl_ssn, sizeof(sql_cfl_ssn), iptssn_update,
                            map_nf2dbtbl[NF_PROSSN].tbl_name,
                            snode->cnt_up, snode->bsz_up, snode->cnt_down, snode->bsz_down,
                            snode->psh, snode->sml, snode->tv_upd, ssn_tv_dur, new_ssn_stat,
                            ipt_id, snode->dbid);
                    ret = mn_MysqlQuery(sfssn_mysql, sql_cfl_ssn, NULL);
                    if ( ret )
                        break;

                    ssn_upd[i]++;
                }
                else {
                    ssn_idl[i]++;
                }
            }
            else {
                snprintf(sql_cfl_ssn, sizeof(sql_cfl_ssn), iptssn_insert,
                        map_nf2dbtbl[NF_PROSSN].tbl_name,
                        ipt_id, snode->qt.proto, snode->qt.direction, snode->qt.cln_p, snode->qt.ser_p,
                        snode->cnt_up, snode->bsz_up, snode->cnt_down, snode->bsz_down,
                        snode->psh, snode->sml, snode->tv_start, snode->tv_upd, ssn_tv_dur, new_ssn_stat);
                ret = mn_MysqlQueryUlid(sfssn_mysql, sql_cfl_ssn, &id);
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
                    mn_daq_memcpy(p_tr, sanitize_buffer, ssn_ptrc_b64len);
                    mn_daq_memcpy(p_tr+ssn_ptrc_b64len, "')", 3);

                    //Query
                    ret = mn_MysqlQuery(sfssn_mysql, sql_cfl_ssn_ptrc, NULL);
                    if ( ret )
                        break;

                    //release buffer
                    mn_daq_put_mbuf(p_track->data_pl, MPOOL_SF_PPL);
                    p_track->cap = SSN_CS_TRACK_SYNC_DB;
                }
            }
        }

        if ( ret ) {
            mn_MysqlTransRollback(sfssn_mysql);
            break;
        }
        else {
            mn_MysqlTransCommit(sfssn_mysql);
            if ( max_cur_ssnid > 0 )
                sfGlobalInfo.max_ssnid = max_cur_ssnid;
        }
    }

    snprintf(log_buf, sizeof(log_buf), "%s: ssn_pool(%d) ssn count-", __func__, i);
    for ( i=0; i<MAX_SSNPROTO_CFL_NODEPOOLS; i++ ) {
        ssn_cnt_scl = ssn_cnt[i]+ssn_upd[i];
        snprintf(buf, sizeof(buf), "%d/%d, ", ssn_cnt_scl, ssn_cnt_scl+ssn_idl[i]);
        strncat(log_buf, buf, sizeof(buf));

        ssn_cntsum += ssn_cnt_scl+ssn_idl[i];
    }

    if ( ssn_cntsum > 0 && id > 0 ) {
        LogMessage("%s\n", log_buf);
        //DAQ_SFSendDataPlane((void*)&start_id, 0, DAQ_SF_SSN_ANALYST);

        /*id_end = id;
        id_start = id - ssn_cntsum + 1;
        sf_AlySSNSend(id_start, id_end);*/
    }

    if ( ret )
        return MN_ERROR_DB;

    return 0;
}

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

static int sf_DBInsAlyUns(int fd, /*uint32_t aly_type, uint64_t dbid*/
        SFAlySockSend *aly_data, uint64_t *aly_flag)
{
    int aly_retlen, ret;
    char alarm_flag_str[32];
    char *pstr_ret;
/*    SFAlySockSend aly_data;

    aly_data.type = htonl(aly_type);
    aly_data.id_start = htonl(dbid);
    aly_data.id_end = htonl(dbid);*/

    memset(alarm_flag_str, 0, sizeof(alarm_flag_str));
    aly_retlen = sizeof(alarm_flag_str);

    ret = sf_AlyUnsSend(fd, aly_data, sizeof(SFAlySockSend), alarm_flag_str, &aly_retlen);
    if ( ret < 0 ) {
        return ret;
    }

    *aly_flag = strtoull(alarm_flag_str, NULL, 10);
    pstr_ret = strchr(alarm_flag_str, ',');
    if ( NULL != pstr_ret ) {
        pstr_ret++;
        *(aly_flag+1) = strtoull(pstr_ret, NULL, 10);
    }
    else {
        *(aly_flag+1) = 0;
    }

    //LogMessage("%s: aly_ret %s, flag %lx, data_extra %lu, len %d\n", __func__,
    //        alarm_flag_str, *aly_flag, *(aly_flag+1), aly_retlen);

    return 0;
}

int sf_DBIns_Loop(void *dp_cfl)
{
    uint8_t geo_map_step;
    uint16_t sock_idx, sock_geo_idx;
    uint32_t sf_aly_type;
    int uns_fd, uns_ret;
    uint32_t ssn_hb_cnt = 0;
    uint32_t ipt_idx, ipt_geo_idx;//, tvs_current, tvs_dbrec;
    StatsFlowConfluDataPlane *sf_dp_ctl = (StatsFlowConfluDataPlane*)dp_cfl;
    IPTetCflStatNode* tnode;
    IPTetCflStatNode* tnode_geo;
    uint64_t ipt_proc_cnt, geo_map_proc_cnt;
    uint32_t alarm_flag;
    uint32_t aly_sta;
    uint64_t sf_aly_flag[4];
    sigset_t sigset;
    SFAlySockSend aly_data;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    //signal(SIGPIPE, a);

    while ( sf_DBIns_SockInit(&uns_fd) < 0 ) {
        sleep(1);
    }

    LogMessage("%s: Start Inspection!\n", __func__);
    sock_idx = 0;
    sock_geo_idx = 0;
    ipt_idx = 0;
    ipt_geo_idx = 0;
    ipt_proc_cnt = 0;
    geo_map_proc_cnt = 0;
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
            sfGlobalInfo.cur_iptid = 0;
            sfGlobalInfo.cur_ssnid = 0;
        }

        //IpTet Geo map, 100
        geo_map_step = 100;
        //LogMessage("%s: step from %u.\n", __func__, ipt_geo_idx);
        while(geo_map_step--) {
            if ( geo_map_proc_cnt >= sf_dp_ctl->tnode[sock_geo_idx].npcnt ) {
                ipt_geo_idx = 0;    //Step to Beginning
                geo_map_proc_cnt = 0;
                if ( sock_geo_idx < (sf_dp_ctl->nsock-1) )
                    sock_geo_idx = sock_geo_idx + 1;
                else
                    sock_geo_idx = 0;
            }

            if ( 0 == ipt_geo_idx )
                tnode_geo = sf_dp_ctl->tnode[sock_geo_idx].nodes;
            else
                tnode_geo++;
            //ipt_geo_idx = (ipt_geo_idx+1)&IPTET_CONFLUENCE_NODE_SZ_MASK;
            if ( ipt_geo_idx < (sf_dp_ctl->tnode[sock_geo_idx].total-1) )
                ipt_geo_idx = ipt_geo_idx + 1;
            else
                ipt_geo_idx = 0;

            //Count Nodes
            geo_map_proc_cnt++;

            if ( !tnode_geo->dbid )
                continue;

            if ( !tnode_geo->expire
                    && (tnode_geo->sf_sta & SFALY_STA_FLAG_GEO) )
                continue;

            aly_data.type = htonl(SF_ALY_GEO_MAP);
            aly_data.pad[0] = htonl(tnode_geo->sf_sta);
            aly_data.id_1 = htonl(tnode_geo->dbid);
            aly_data.id_2 = htonl(tnode_geo->dbid);
            uns_ret = sf_DBInsAlyUns(uns_fd, &aly_data, sf_aly_flag);
            if ( uns_ret < 0 ) {
                LogMessage("%s: Aly(IPT-GEO) communication failed\n", __func__);
                sf_DBIns_Closet(&uns_fd);
                break;
            }

            //Handling Analyst State
            aly_sta = (uint32_t)((sf_aly_flag[0] >> 32) & SFALY_STA_MASK);
            if ( (aly_sta>0) && ((aly_sta^tnode_geo->sf_sta)&~tnode_geo->sf_sta) ) {
                /*LogMessage("%s: new sf_sta for ipt(id %lu)--0x%lx(ori-0x%x)\n", __func__,
                        tnode->dbid, aly_sta, tnode->sf_sta);*/
                tnode_geo->sf_sta |= (aly_sta&SFALY_STA_MASK);
                tnode_geo->geo_index = (uint64_t)sf_aly_flag[1];
                tnode_geo->qry_flag |= NF_IPTET_DEDICATE_FLAG;
            }

            ssn_hb_cnt += 5;
        }

        //IP Tuple Inspection: Get Node
        if ( ipt_proc_cnt >= sf_dp_ctl->tnode[sock_idx].npcnt ) {
            ipt_idx = 0;    //Step to next numa node' mbuf
            ipt_proc_cnt = 0;
            if ( sock_idx < (sf_dp_ctl->nsock-1) )
                sock_idx = sock_idx + 1;
            else
                sock_idx = 0;
        }

        if ( 0 == ipt_idx )
            tnode = sf_dp_ctl->tnode[sock_idx].nodes;
        else
            tnode++;
        //ipt_idx = (ipt_idx+1)&IPTET_CONFLUENCE_NODE_SZ_MASK;
        if ( ipt_idx < (sf_dp_ctl->tnode[sock_idx].total-1) )
            ipt_idx = ipt_idx + 1;
        else
            ipt_idx = 0;

        //Count Nodes
        ipt_proc_cnt++;

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

            aly_data.type = htonl(sf_aly_type);
            aly_data.pad[0] = htonl(tnode->sf_sta);
            aly_data.id_1 = htonl(tnode->dbid);
            aly_data.id_2 = htonl(tnode->dbid);
            uns_ret = sf_DBInsAlyUns(uns_fd, &aly_data, sf_aly_flag);
            if ( uns_ret < 0 ) {
                LogMessage("%s: Aly(IPT) communication failed\n", __func__);
                sf_DBIns_Closet(&uns_fd);
                continue;
            }

            //Handling Alarm Flag
            alarm_flag = (uint32_t)(sf_aly_flag[0] & SFALY_ALARM_MASK);
            if ( alarm_flag&SFALY_ALARM_IPT_EXPIRE ) {
                tnode->expire = 1;
                //LogMessage("%s: iptet(id-%d) expired, remove from tracking list.\n", __func__, ipt_dbid);
            }
            else if ( (alarm_flag>0) && ((alarm_flag^tnode->almflag)&~tnode->almflag) ) {
                LogMessage("%s: new alarms for ipt(id %lu)--0x%lx(ori-0x%x)\n", __func__,
                        tnode->dbid, alarm_flag, tnode->almflag);
                tnode->almflag |= (alarm_flag&SFALY_ALARM_MASK);
                tnode->qry_flag |= NF_IPTET_DEDICATE_FLAG;
            }

            tnode->aly_stat &= ~SFALY_IPT_INSPECT_PULSE;
            ssn_hb_cnt += 10;
        }

        //Session Inspection
        if ( (sfGlobalInfo.cur_iptid < sfGlobalInfo.max_iptid)
                || (sfGlobalInfo.cur_ssnid < sfGlobalInfo.max_ssnid) ) {
            aly_data.type = htonl(SF_ALY_PROTO_SESSION);
            aly_data.id_1 = htonl(sfGlobalInfo.max_iptid);
            aly_data.id_2 = htonl(sfGlobalInfo.max_ssnid);
            uns_ret = sf_DBInsAlyUns(uns_fd, &aly_data, sf_aly_flag);
            if ( uns_ret < 0 ) {
                LogMessage("%s: Aly(SSN) communication failed\n", __func__);
                sf_DBIns_Closet(&uns_fd);
                continue;
            }
            sfGlobalInfo.cur_iptid = sfGlobalInfo.max_iptid;
            sfGlobalInfo.cur_ssnid = sfGlobalInfo.max_ssnid;

            ssn_hb_cnt = 0;
        }
        else if ( ssn_hb_cnt++ & 0x1000000 ) {  //Heart Beat, as ssn
            ssn_hb_cnt = 0;

            aly_data.type = htonl(SF_ALY_PROTO_SESSION);
            aly_data.id_1 = htonl(sfGlobalInfo.max_iptid);
            aly_data.id_2 = htonl(sfGlobalInfo.max_ssnid);
            uns_ret = sf_DBInsAlyUns(uns_fd, &aly_data, sf_aly_flag);
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

int sf_CflInit(void *dp_cfl, uint16_t rsock, uint16_t nsock)
{
	uint16_t i;
	int stack_i, nmap_idx;
	ProtoStackStatsCflNodes *pnode;
	StatsFlowConfluDataPlane *sf_dp_ctl = (StatsFlowConfluDataPlane*)dp_cfl;
	DataplaneAddrs sf_dp_addrs;

	LogMessage("%s: dp_cfl %lx, nsock %u\n", __func__,
	        (unsigned long)dp_cfl, nsock);

    sf_dp_ctl->nsock = nsock;
    for (i=0; i<nsock; i++) {
        sf_dp_addrs.sock_id = i&(rsock-1);

	    //IP-TET
        if ( 0 != mn_daq_get_mbuf((void*)&sf_dp_addrs, MPOOL_SF_CFL_IPT_HA) )
            return -1;
        sf_dp_ctl->h_tnode[i].hatbl = (IPTetCflStatNode**)sf_dp_addrs.dp_main;
        sf_dp_ctl->h_tnode[i].size = MAX_IPTET_CONFLUENCE_HASHSZ;
        LogMessage("%s: h_tnode 0x%lx, size %lu\n", __func__,
                (unsigned long)sf_dp_ctl->h_tnode[i].hatbl, sf_dp_ctl->h_tnode[i].size);

        if ( 0 != mn_daq_get_mbuf((void*)&sf_dp_addrs, MPOOL_SF_CFL_IPTET) )
            return -1;
        sf_dp_ctl->tnode[i].nodes = (IPTetCflStatNode*)sf_dp_addrs.dp_main;
        sf_dp_ctl->tnode[i].total = MAX_IPTET_CONFLUENCE_NODE_SZ;
        LogMessage("%s: tnode %lx, total %lu\n", __func__,
                (unsigned long)sf_dp_ctl->tnode[i].nodes, sf_dp_ctl->tnode[i].total);

        //PROTP
        if ( 0 != mn_daq_get_mbuf((void*)&sf_dp_addrs, MPOOL_SF_CFL_PP_HA) )
            return -1;
        sf_dp_ctl->h_pnode[i].hatbl = (ProtoPortCflNode**)sf_dp_addrs.dp_main;
        sf_dp_ctl->h_pnode[i].size = MAX_PROTOPORT_CFL_HASHSZ;
        LogMessage("%s: h_pnode %lx, size %lu\n", __func__,
                (unsigned long)sf_dp_ctl->h_pnode[i].hatbl, sf_dp_ctl->h_pnode[i].size);

        if ( 0 != mn_daq_get_mbuf((void*)&sf_dp_addrs, MPOOL_SF_CFL_PROTP) )
            return -1;
        sf_dp_ctl->pnode[i].nodes = (ProtoPortCflNode*)sf_dp_addrs.dp_main;
        sf_dp_ctl->pnode[i].total = MAX_PROTOPORT_CFL_NODE_SZ;
        LogMessage("%s: pnode %lx, size %lu\n", __func__,
                (unsigned long)sf_dp_ctl->pnode[i].nodes, sf_dp_ctl->pnode[i].total);
    }

    if ( mn_MysqlConnect(&sf_mysql, server, database, user, password) ) {
        sf_mysql = NULL;
        LogMessage("%s: MysqlConnect(sf_mysql) error\n",__func__);
        return 1;
    }

    if ( mn_MysqlConnect(&sfstack_mysql, server, database, user, password) ) {
        sfstack_mysql = NULL;
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

int sf_Confluence(void *dp_cfl, void *dp, unsigned sock_id, uint8_t dp_type, uint8_t db_sync)
{
    uint16_t sock_i;
    int ret_val = 0, db_ret = 0;
    StatsFlowConfluDataPlane *sf_dp_ctl = (StatsFlowConfluDataPlane*)dp_cfl;

    /*LogMessage("%s: dp_cfl %lx, merge dp %lx\n", __func__,
            (unsigned long)dp_cfl, (unsigned long)dp);*/

    switch ( dp_type ) {
    case MPOOL_STATSFLOW:
        if ( NULL != dp ) {
            sf_IptetMergeFromDp(dp_cfl, dp);
        }

        if ( db_sync ) {    //sync ip_tet
            uint8_t scale_layer;
            uint8_t scale_reset[SF_SCALE_STAGE_MAX] = {0};
            uint32_t scale_flag;
            uint32_t scale_cmb[SF_SCALE_STAGE_MAX] = {0};
            time_t tv_cur = time(NULL), tv_scale[SF_SCALE_STAGE_MAX];
            struct tm ipt_tm_date, scl_tm_date;
            char scale_pr_buf[256] = {0}, buf[32];

            //check DB connection
            if ( NULL == sf_mysql ) {
                if ( mn_MysqlConnect(&sf_mysql, server, database, user, password) ) {
                    sf_mysql = NULL;
                    LogMessage("%s: MysqlConnect(sf_mysql) error\n",__func__);
                    break;
                }
            }

            //Meta Stock
            scale_layer = SF_SCALE_STAGE_META;
            tv_scale[scale_layer] = tv_cur;
            localtime_r(&tv_scale[scale_layer], &ipt_tm_date);
            scale_cmb[scale_layer] = 0;
            scale_flag = SF_GLOB_VAR_SCALE_L0;
            scale_reset[scale_layer] = 0;

            if ( (sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_SCALE_DEEP_ALL)
                    && (ipt_tm_date.tm_sec < SUR_SF_IPT_PP_SCALE_BASE_TIME) ) {
                if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_SCALE_L1 ) {
                    scale_layer = SF_SCALE_STAGE_MIN;
                    tv_scale[scale_layer] = tv_cur - SUR_SF_IPT_PP_SCALE_VAL_MIN;  //step back
                    localtime_r(&tv_scale[scale_layer], &scl_tm_date);
                    scale_cmb[scale_layer] = ((scl_tm_date.tm_hour&0x07)<<8)|(scl_tm_date.tm_min);
                    scale_flag |= SF_GLOB_VAR_SCALE_L1;
                    scale_reset[scale_layer] = 1;

                    LogMessage("%s: handle protp-scale, tm_hour %d, tm_min %d\n", __func__,
                            scl_tm_date.tm_hour, scl_tm_date.tm_min);
                }
#define SCL_DEBUG            (0x0f)
#define SCL_LIT_DEBUG        (0x07)
                //deep layer
                if ( (0 == ipt_tm_date.tm_min)
#ifdef SCL_DEBUG
                        || (SCL_DEBUG == (SCL_DEBUG & ipt_tm_date.tm_min)) ) {
#else
                    ) {
#endif
                    snprintf(scale_pr_buf, sizeof(scale_pr_buf), "scale_deep, ");
                    //Hour
                    if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_SCALE_L2 ) {
                        scale_layer = SF_SCALE_STAGE_HOUR;
                        //tv_scale[scale_layer] = tv_cur - SUR_SF_IPT_PP_SCALE_VAL_HOUR;  //step back
                        tv_scale[scale_layer] = tv_cur -                                                        \
                                (ipt_tm_date.tm_sec +                                       /*seconds*/         \
                                 ipt_tm_date.tm_min*60);                                    /*minutes*/
                        if ( 0 == ipt_tm_date.tm_min ) {
                            tv_scale[scale_layer] -= SUR_SF_IPT_PP_SCALE_VAL_HOUR;              /*previous hour*/
                        }
                        localtime_r(&tv_scale[scale_layer], &scl_tm_date);
                        scale_cmb[scale_layer] = (scl_tm_date.tm_mday*24+scl_tm_date.tm_hour)|(scale_layer-1)<<28;
                        scale_flag |= SF_GLOB_VAR_SCALE_L2;
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
                    if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_SCALE_L3 ) {
                        scale_layer = SF_SCALE_STAGE_DAY;
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
                        scale_flag |= SF_GLOB_VAR_SCALE_L3;
                        if ( 1 == ipt_tm_date.tm_hour )
                            scale_reset[scale_layer] = 1;
                        else
                            scale_reset[scale_layer] = 0;

                        snprintf(buf, sizeof(buf), "scl_l3: 0x%x-%d, ", scale_cmb[scale_layer], scale_reset[scale_layer]);
                        strncat(scale_pr_buf, buf, sizeof(buf));
                    }

                    //Month
                    if ( sfGlobalInfo.envset_scl_flag&SF_GLOB_VAR_SCALE_L4 ) {
                        scale_layer = SF_SCALE_STAGE_MONTH;
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
                        scale_flag |= SF_GLOB_VAR_SCALE_L4;
                        if ( 1 == ipt_tm_date.tm_hour && 1 == ipt_tm_date.tm_mday )
                            scale_reset[scale_layer] = 1;
                        else
                            scale_reset[scale_layer] = 0;

                        snprintf(buf, sizeof(buf), "scl_l4: 0x%x-%d, ", scale_cmb[scale_layer], scale_reset[scale_layer]);
                        strncat(scale_pr_buf, buf, sizeof(buf));
                    }

                    LogMessage("%s: scale_flag 0x%x, %s\n", __func__, scale_flag, scale_pr_buf);
                }

                if ( 0 )//scale_flag & SF_GLOB_VAR_SCALE_DEEP_ALL )
                    ret_val = SUR_SF_IPT_PP_SCALE_SUM_CNT - 1;

                if ( (scale_flag&SF_GLOB_VAR_SCALE_DEEP_ALL)
                        || (SCL_LIT_DEBUG == (SCL_LIT_DEBUG & ipt_tm_date.tm_min))) {
                    for (sock_i=0; sock_i<sf_dp_ctl->nsock; sock_i++) {
                        db_ret = sf_IptetSyncToDB(dp_cfl, sock_i,
                                tv_cur, tv_scale, scale_cmb, scale_reset, scale_flag);
                    }
                }
            }

            //sf_IptetSyncToDB(dp_cfl, tv_cur, tv_scale, scale_cmb, scale_reset, scale_flag);
        }

        if ( MN_ERROR_DB == db_ret ) {
            if ( mn_MysqlResolve(&sf_mysql, server, database, user, password) ) {
                sf_mysql = NULL;
                LogMessage("%s: MysqlResolve(sf_mysql) error\n",__func__);
            }
        }

        break;
    case MPOOL_SF_STACK:
        if ( NULL != dp ) {
            sf_StackMergeFromDp(dp_cfl, dp);
        }

        if ( db_sync ) {
            //check DB connection
            if ( NULL == sfstack_mysql ) {
                if ( mn_MysqlConnect(&sfstack_mysql, server, database, user, password) ) {
                    sfstack_mysql = NULL;
                    LogMessage("%s: MysqlConnect(sfstack_mysql) error\n",__func__);
                    break;
                }
            }

            db_ret = sf_StackSyncToDB(dp_cfl);
            sf_StackResetBps(dp_cfl);
        }

        if ( MN_ERROR_DB == db_ret ) {
            if ( mn_MysqlResolve(&sfstack_mysql, server, database, user, password) ) {
                sfstack_mysql = NULL;
                LogMessage("%s: MysqlResolve(sfstack_mysql) error\n",__func__);
            }
        }

        break;
    default:
        break;
    }

    return ret_val;
}

int sf_CflSsnInit(void)
{
    if ( mn_MysqlConnect(&sfssn_mysql, server, database, user, password) ) {
        sfssn_mysql = NULL;
        LogMessage("%s: MysqlConnect error(sfssn_mysql)\n",__func__);
        return 1;
    }

    return 0;
}

int sf_CflSession(void *dp_cfl)
{
    int db_ret = 0;
    StatsFlowConfluDataPlane *sf_dp_ctl = (StatsFlowConfluDataPlane*)dp_cfl;

    //check DB connection
    if ( NULL == sfssn_mysql ) {
        if ( mn_MysqlConnect(&sfssn_mysql, server, database, user, password) ) {
            sfssn_mysql = NULL;
            LogMessage("%s: MysqlConnect(sfssn_mysql) error\n",__func__);
            return 0;
        }
    }

    db_ret = sf_ProtoSSNSyncToDB(sf_dp_ctl->p_hnode, sf_dp_ctl->p_snode);

    if ( MN_ERROR_DB == db_ret ) {
        if ( mn_MysqlResolve(&sfssn_mysql, server, database, user, password) ) {
            sfssn_mysql = NULL;
            LogMessage("%s: MysqlResolve(sfstack_mysql) error\n",__func__);
        }
    }

    return 0;
}

