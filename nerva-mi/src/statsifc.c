
//#include "util.h"
#include "statsifc.h"
#include "mn_sql_op.h"
#include "mn_gen.h"

static const char *server = "localhost";
static const char *database = "surveyor";
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
static const char *user = "root";
static const char *password = "11111";
static MYSQL *sp_mysql = NULL;

static Ifaceinfo if_info;
static Ifaceinfo sPinfo[STATS_IF_MAX];

/*
static int MysqlConnect()
{
	sp_mysql = mysql_init(NULL);
    if(!mysql_real_connect(sp_mysql, server, user,
                password, database, 0, NULL, 0))
    {
    	printf("Failed to connect to database %s:%s@%s/%s: %s\n",
                user, password, server,
                database, mysql_error(sp_mysql));
		return 1;
    }
    return 0;
}

static int MysqlQuery(char *sql, unsigned int *row_id)
{
	int result;

    if( 0 != (result=mysql_query(sp_mysql, sql)) ) {
        printf("Error (%s) executing query: %s\n", mysql_error(sp_mysql), sql);
        return -1;
    }

    if(row_id != NULL)
        *row_id = mysql_insert_id(sp_mysql);
    return 0;
}

static int MysqlSelectAsUInt(char *sql, unsigned int *result)
{
    int rval = 0;
    MYSQL_RES *mysql_res;
    MYSQL_ROW tuple;

    if(mysql_query(sp_mysql, sql) != 0) {
        printf("Error (%s) executing query: %s\n", mysql_error(sp_mysql), sql);
        return -1;
    }

    mysql_res = mysql_store_result(sp_mysql);
    if((tuple = mysql_fetch_row(mysql_res)))
    {
        if(tuple[0] == NULL)
            *result = 0;
        else
            *result = atoi(tuple[0]);
        rval = 1;
    }
    mysql_free_result(mysql_res);
    return rval;
}*/
/*
static int sp_initMysqlDatabase(const char *server, const char *database, const char *user, const char *password)
{
    if( mn_MysqlConnect(&sp_mysql, server, database, user, password) ) {
        sp_mysql = NULL;
        syslog(LOG_NOTICE, "%s: MysqlConnect error\n",__func__);
        return 1;
    }

    return 0;
}*/

int stats_ifport_init(void)
{
/*    if(sp_initMysqlDatabase(server, database, user, password)) {
        printf("%s: InitMysqlDatabase error\n", __func__);
        return 1;
    }*/

    memset(&sPinfo, 0, sizeof(sPinfo));
    strncpy(if_info.if_name, "psi_d", 7);

    printf("%s: InitMysqlDatabase OK\n", __func__);

    return 0;
}

int stats_ifport_scale(xstatsinfo *xtinfo, uint8_t pid)
{
    int ret;
    uint32_t s_cnt;
    char sql_str[1024] = "";

    //check DB connection
    if ( NULL == sp_mysql ) {
        if ( mn_MysqlConnect(&sp_mysql, server, database, user, password) ) {
            sp_mysql = NULL;
            LogMessage("%s: MysqlConnect(sp_mysql) error\n",__func__);
            return 0;
        }
    }

    //Update SQL
    if ( '\0' == sPinfo[pid].if_name[0] ) {
        sPinfo[pid].uRxPrbyte = xtinfo->uRxPrbyte;
        sPinfo[pid].uTxPrbyte = xtinfo->uTxPrbyte;
        snprintf(sPinfo[pid].if_name, sizeof(sPinfo[pid].if_name), "%s%d",
                if_info.if_name, pid);
    }

    if_info.cIfup = xtinfo->cIfup;
    if_info.uRxPrcnt = xtinfo->uRxPrcnt;
    if_info.uRxPrbyte = xtinfo->uRxPrbyte;
    if_info.uRxPrbps = xtinfo->uRxPrbyte - sPinfo[pid].uRxPrbyte;
    if_info.uTxPrcnt = xtinfo->uTxPrcnt;
    if_info.uTxPrbyte = xtinfo->uTxPrbyte;
    if_info.uTxPrbps = xtinfo->uTxPrbyte - sPinfo[pid].uTxPrbyte;

    if ( (1 == if_info.cIfup) && (xtinfo->link_speed > 0) ) {
        //bps * 8 * 84[Eth-frame-len] * 100 / (link_speed * 1024 * 1024 * 64[ip-pkt-len])
        if_info.uRxIfperc = (float)(if_info.uRxPrbps*525)/(float)(xtinfo->link_speed*524288);
        if ( if_info.uRxIfperc > 100.00 )
            if_info.uRxIfperc = 100.00;
        if_info.uTxIfperc = (float)(if_info.uTxPrbps*525)/(float)(xtinfo->link_speed*524288);
        if ( if_info.uTxIfperc > 100.00 )
            if_info.uTxIfperc = 100.00;
    }
    else {
        if_info.uRxIfperc = 0;
        if_info.uTxIfperc = 0;
    }

    snprintf(sql_str, sizeof(sql_str), SQL_SELECT_IFINFO, sPinfo[pid].if_name);
    ret = mn_MysqlSelectUint(sp_mysql, sql_str, &s_cnt);
    if ( ret < 0 ) {
        //try to re-connect
        if ( mn_MysqlResolve(&sp_mysql, server, database, user, password) ) {
            sp_mysql = NULL;
            LogMessage("%s: MysqlResolve(sfstack_mysql) error\n",__func__);
        }
        return 0;
    }

    /*LogMessage("%s: MysqlSelectAsUInt (name:%s) ret %d, s_cnt %u\n",
            __func__, sPinfo[pid].if_name, ret, s_cnt);*/

    mn_MysqlTransBegin(sp_mysql);
    if ( ret > 0 && s_cnt > 0) {
        //LogMessage("%s: updating, link_state %d\n", __func__, if_info.cIfup);
        snprintf(sql_str, sizeof(sql_str), SQL_UPDATE_IFINFO,
        		if_info.cIfup,
        		if_info.uRxPrcnt, if_info.uRxPrbyte,
        		if_info.uTxPrcnt, if_info.uTxPrbyte,
        		if_info.uRxPrbps, if_info.uTxPrbps,
        		if_info.uRxIfperc, if_info.uTxIfperc,
        		xtinfo->link_speed,
        		sPinfo[pid].if_name);
    }
    else {
        //LogMessage("%s: inserting\n", __func__);
        snprintf(sql_str, sizeof(sql_str), SQL_INSERT_IFINFO,
                sPinfo[pid].if_name, if_info.cIfup,
                if_info.uRxPrcnt, if_info.uRxPrbyte,
                if_info.uTxPrcnt, if_info.uTxPrbyte,
                if_info.uRxPrbps, if_info.uTxPrbps,
                if_info.uRxIfperc, if_info.uTxIfperc,
                xtinfo->link_speed);
    }

    ret = mn_MysqlQuery(sp_mysql, sql_str, NULL);
    if ( ret ) {
        mn_MysqlTransRollback(sp_mysql);
    }
    else {
        mn_MysqlTransCommit(sp_mysql);
    }

    //memcpy(&sPinfo[pid], &if_info, sizeof(if_info));
    sPinfo[pid].uRxPrbyte = xtinfo->uRxPrbyte;
    sPinfo[pid].uTxPrbyte = xtinfo->uTxPrbyte;

	return 0;
}



