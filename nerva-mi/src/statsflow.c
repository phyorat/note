


#include "statsflow.h"

#include "snort.h"
#include "sfdaq.h"
#include "session_api.h"
#include "session_common.h"
#include "stream_common.h"
/*
static const char *server = "localhost";
static const char *database = "surveyor";
static const char *user = "root";
static const char *password = "11111";
static MYSQL *sf_mysql;

static const char *sfstack_apport_user_select = "select port,proto_type,approto_idx,approto_desc,pp_switch,renew "
        "from approto_ports_user order by id asc";
*/
static CounterNetFlow sfPktInspectCons;
static StackProtpConfig sfPortMapList[3];   //0: user; 1: system; 2: user-cache
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
/*
static int MysqlConnect(MYSQL **sql_ins)
{
    *sql_ins = mysql_init(NULL);

    if(!mysql_real_connect(*sql_ins, server, user,
                password, database, 0, NULL, CLIENT_INTERACTIVE)) {
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
*/
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

#define NET_PORT_BM_SET(bm, port, mi, stc, stc_top)     do {    \
                                                            mi = (((port)>>6)&0xfc0)+(((port)>>6)&0x3f);    \
                                                            *((bm)+(mi)) |= (0x01L<<((port)&0x3f)); \
                                                            /*if (mi2 != mi) {                        \
                                                                *((stc)+(mi)) = *((stc)+(mi2));     \
                                                                while (++mi2 < mi) {                \
                                                                    *((stc)+(mi2)) = *((stc)+(mi)); \
                                                                }                                   \
                                                            }                                       */\
                                                            *((stc)+(mi)) += 1;                     \
                                                            if ( stc_top < (stc+mi) )               \
                                                                stc_top = stc + mi;                 \
                                                        } while(0);

#define NET_PORT_BM_ACCUM(stc, stc_top)                 do {                                \
                                                            *(stc+1) += *stc;               \
                                                            stc++;                          \
                                                        } while( stc < stc_top );

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

static int sf_NetProtoPort_BitMap(uint8_t region)
{
    uint8_t pm_idx, pm_s = 0, pm_e = 2, i_nd;
    uint8_t pp_idx;
    uint16_t map_idx;//, map_idx2;
    uint64_t targ_bm, bitset;
    NetFLowPortProtoMap *p_ppmap;
    uint16_t *pstc, *pstc_top;

    if ( 0 == region ) {
        pm_s = 0;
        pm_e = 1;
    }

    DAQ_RteMemcpy(sfPortMapList[0].data_conf, sfPortMapList[2].data_conf,
            sizeof(NetFLowPortProtoMap)<<SF_MAX_PROT_PROTO_USER_SHIFT);

    //Init Port-Bitmap
    //0, User defined port; 1, System default
    for ( pm_idx=pm_s; pm_idx<pm_e; pm_idx++ ) {
        p_ppmap = (NetFLowPortProtoMap*)(sfPortMapList[pm_idx].data_conf);
        map_idx = 0;
        //map_idx2 = 0;
        pstc = pstc_top = sfPortMapInstance[pm_idx]->stc;
        memset(sfPortMapInstance[pm_idx], 0, sizeof(NetProtoPortIdBitmap));
        for ( i_nd=0; i_nd<sfPortMapList[pm_idx].item_cnt; i_nd++ ) {
            if ( p_ppmap->pp_switch ) {
                NET_PORT_BM_SET(sfPortMapInstance[pm_idx]->bm, p_ppmap->port, map_idx,
                        pstc, /*map_idx2*/pstc_top);

                //LogMessage("%s: pm_idx %d, port %d\n", __func__, pm_idx, p_ppmap->port);
            }
            p_ppmap++;
        }

        //Accum port count.
        NET_PORT_BM_ACCUM(pstc, pstc_top);

        //Set port_index
        p_ppmap = (NetFLowPortProtoMap*)(sfPortMapList[pm_idx].data_conf);
        for ( i_nd=0; i_nd<sfPortMapList[pm_idx].item_cnt; i_nd++ ) {
            if ( p_ppmap->pp_switch ) {
                NET_PORT_BM_GET_BIT(sfPortMapInstance[pm_idx]->bm, p_ppmap->port, map_idx, targ_bm, bitset);
                NET_PORT_BM_PP_IDX(sfPortMapInstance[pm_idx]->stc, map_idx, targ_bm, bitset, pp_idx);

                sfPortMapInstance[pm_idx]->bi[pp_idx] = i_nd;
            }
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
                /*LogMessage("%s: port[%d] %d, mi %d, tbm 0x%lx, bs 0x%lx\n", __func__,
                        c_cnt, port, map_idx, targ_bm, bitset);*/
                if ( bitset ) {
                    NET_PORT_BM_PP_IDX(sfPortMapInstance[pm_idx]->stc, map_idx, targ_bm, bitset, pp_idx);
                    p_ppmap = (NetFLowPortProtoMap*)(sfPortMapList[pm_idx].data_conf);
                    pp_idx = sfPortMapInstance[pm_idx]->bi[pp_idx];
                    //LogMessage("%s: found, pm[%u], port %u, pp_idx %u\n", __func__, pm_idx, port, pp_idx);
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
                p_ppmap = (NetFLowPortProtoMap*)(sfPortMapList[pm_idx].data_conf);
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
/*
static int sf_InitProtpUser(void)
{
    uint32_t row_idx;
    int row_cnt;
    char sql[256] = "";
    MYSQL_RES *mysql_res = NULL;
    NetFLowPortProtoMap *p_ppmap;
    MYSQL_ROW row;

    //approto_ports-user tables
    snprintf(sql, sizeof(sql), "%s", sfstack_apport_user_select);
    row_cnt = MysqlSelectDbRes(sf_mysql, sql, &mysql_res);
    if ( row_cnt < 0 ) {
        LogMessage("%s: get approto_ports-user table failed!\n", __func__);
    }
    else {
        LogMessage("%s: approto_ports-user-row_cnt %d\n", __func__, row_cnt);

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

                if ( p_ppmap->pp_switch ) {
                    reflect_netflow_protoport_reflect[p_ppmap->fp_index].pro_bitset |= p_ppmap->pro_bitset;
                    reflect_netflow_protoport_reflect[p_ppmap->fp_index].ports_user |= (0x01L<<p_ppmap->pp_index);
                }

                p_ppmap++;
                row_idx++;
            }

            // The last records, set switch = 0
            p_ppmap->pp_switch = 0;
        }

        mysql_free_result(mysql_res);
    }

    return 0;
}
*/
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

static int sf_Pins_CacheConfig(void *args)
{
//    uint8_t i;
    DAQ_Filter_Config *protp_conf = (DAQ_Filter_Config*)args;

/*    NetFLowPortProtoMap *p_ppmap = (NetFLowPortProtoMap*)(protp_conf->content);
    for ( i=0; i<SF_MAX_PROT_PROTO_USER; i++ ) {
        LogMessage("%s: protp_user, port %u, name %s, fpi %u, pp_idx %u\n", __func__,
                p_ppmap->port,
                p_ppmap->pp_name,
                p_ppmap->fp_index,
                p_ppmap->pp_index);
        p_ppmap++;
    }*/

    DAQ_RteMemcpy(sfPortMapList[2].data_conf, protp_conf->content, protp_conf->config_size);

    return 0;
}

static int sf_PktInspcInit(CounterNetFlow *pcnf)
{
    int ret, ret_m;
    daq_sf_req_type req_type = DAQ_SF_REQ_INVALID_RTN;
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
    if ( 0 != DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_PORT_BITMAP) ) {
        LogMessage("%s: Can't get MBuf for net_port_bitmap.\n", __func__);
        return -1;
    }
    sfPortMapInstance[0] = (NetProtoPortIdBitmap*)dpMbufs.dp_main;

    if ( 0 != DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_PORT_BITMAP) ) {
        LogMessage("%s: Can't get MBuf for net_port_user_bitmap.\n", __func__);
        DAQ_APPutMBuf(sfPortMapInstance[0], MPOOL_PORT_BITMAP);
        return -1;
    }
    sfPortMapInstance[1] = (NetProtoPortIdBitmap*)dpMbufs.dp_main;

    ret_m = DAQ_APGetMBuf((void*)&dpMbufs, MPOOL_PORT_BITMAP);
    if ( ret_m ) {
        LogMessage("%s: Can't get MBuf for net_port_bitmap.\n", __func__);
        return 1;
    }
    sfPortMapArray = (NetFlowPPmArray*)dpMbufs.dp_main;
    DAQ_RteMemcpy(sfPortMapArray->map_portproto, map_netflow_portproto,
            sizeof(map_netflow_portproto));
    sfPortMapList[0].item_cnt = SF_MAX_PROT_PROTO_USER;
    sfPortMapList[0].data_conf = sfPortMapArray->map_portproto_user;
    sfPortMapList[1].item_cnt = NF_APPRO_COUNT;
    sfPortMapList[1].data_conf = sfPortMapArray->map_portproto;
    sfPortMapList[2].item_cnt = SF_MAX_PROT_PROTO_USER;
    sfPortMapList[2].data_conf = sfPortMapArray->map_portp_user_cache;

    //Get protp-config from master
    do {
        ret = DAQ_SFIPCRsp(NULL, 0, sf_Pins_CacheConfig, &req_type);
        if ( DAQ_SUCCESS != ret )
            return -1;
        sleep(1);
    } while( DAQ_SF_SET_CONFIG_RTN!=req_type );

    if ( sf_NetProtoPort_BitMap(1) )
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

int sf_PktInsCheckOp(void)
{
    int ret, ret_m;
    daq_sf_req_type req_type = DAQ_SF_REQ_INVALID_RTN;
    CounterNetFlow *pins_cnf;
    DataplaneAddrs dpMbufs;

    pins_cnf = &sfPktInspectCons;

    if ( !sf_atomic32_test_on(&pins_cnf->dpSwitch) )
        return -1;

    ret = DAQ_SFIPCRsp(pins_cnf, sizeof(CounterNetFlow), sf_Pins_CacheConfig, &req_type);
    if ( DAQ_SUCCESS != ret )
        return -1;

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

            if ( pins_cnf->dpProtpBMReset ) {
                sf_NetProtoPort_BitMap(0);

                //Since we just got new ipt-dp, no need to do data-clear.
                //JDIstResetNodes(pins_cnf->psDPIntef);
                memset(pins_cnf->psDpStack, 0, sizeof(ProStackStatNodesTbl));
                LogMessage("%s: statsflow config(port bitmap) updated\n", __func__);

                pins_cnf->psDPIntef->sf_flag |= STATSFLOW_SF_PROTP_UPD;
                pins_cnf->psDpStack->ps_flag |= STATSFLOW_SF_PROTP_UPD;
                pins_cnf->dpProtpBMReset = 0;
            }
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
    case DAQ_SF_SET_CONFIG_RTN:
        pins_cnf->dpProtpBMReset = 1;
        break;
    default:
        break;
    }

    return req_type;
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
    //sfhndr_t *conf_homenet;
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
            if ( 0 == snort_conf->home_net[i].mask )
                break;

            if ( (nodesElem->itnode.tet.src&snort_conf->home_net[i].mask)
                    == snort_conf->home_net[i].addr )
                src_inhome = 1;
            if ( (nodesElem->itnode.tet.dst&snort_conf->home_net[i].mask)
                    == snort_conf->home_net[i].addr )
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
/*        if ( MysqlConnect(&sf_mysql) ) {
            LogMessage("%s: MysqlConnect(sf_mysql) error\n", __func__);
            return 1;
        }

        sf_InitProtpUser();*/
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

