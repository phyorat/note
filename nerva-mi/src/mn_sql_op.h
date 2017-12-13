#ifndef __MN_SQL_OP_H__
#define __MN_SQL_OP_H__

#include <stddef.h>
#include <syslog.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>


static inline int mn_MysqlConnect(MYSQL **sql_ins,
        const char *server,
        const char *database,
        const char *user,
        const char *password)
{
    *sql_ins = mysql_init(NULL);

    if(!mysql_real_connect(*sql_ins, server, user,
                password, database, 0, NULL, /*0*/CLIENT_INTERACTIVE)) {
        syslog(LOG_NOTICE, "Failed to connect to database %s:%s@%s/%s: %s\n",
                user, password, server,
                database, mysql_error(*sql_ins));
        mysql_close(*sql_ins);
        return 1;
    }

    mysql_autocommit(*sql_ins, 0);

    return 0;
}

static inline int mn_MysqlResolve(MYSQL **sql_ins,
        const char *server,
        const char *database,
        const char *user,
        const char *password)
{
    if ( 0 == mysql_ping(*sql_ins) )
        return 0;

    mysql_close(*sql_ins);

    return mn_MysqlConnect(sql_ins, server, database, user, password);
}

static inline int mn_MysqlSelectDbRes(MYSQL *sql_conn, char *sql_str, MYSQL_RES **mysql_res)
{
    int totalrows;

    if (mysql_query(sql_conn, sql_str) != 0) {
        syslog(LOG_NOTICE, "Error (%s) executing query: %s\n", mysql_error(sql_conn), sql_str);
        return -1;
    }

    *mysql_res = mysql_store_result(sql_conn);
    totalrows = mysql_num_rows(*mysql_res);
    //numfields = mysql_num_fields(*mysql_res);

    return totalrows;
}

static inline int mn_MysqlSelectUint(MYSQL *sql_conn, char *sql, unsigned int *result)
{
    int rval = 0;
    MYSQL_RES *mysql_res;
    MYSQL_ROW tuple;

    *result = 0;

    if(mysql_query(sql_conn, sql) != 0) {
        printf("Error (%s) executing query: %s\n", mysql_error(sql_conn), sql);
        return -1;
    }

    mysql_res = mysql_store_result(sql_conn);
    if((tuple = mysql_fetch_row(mysql_res))) {
        if( NULL != tuple[0] ) {
            *result = atoi(tuple[0]);
            rval = 1;
        }
    }
    mysql_free_result(mysql_res);

    return rval;
}

static inline int mn_MysqlTransBegin(MYSQL *sql_conn)
{
    if( 0 != mysql_query(sql_conn, "BEGIN;") ) {
        syslog(LOG_NOTICE, "Error (%s) executing begin transaction\n", mysql_error(sql_conn));
        return -1;
    }

    return 0;
}

static inline int mn_MysqlTransCommit(MYSQL *sql_conn)
{
    if( 0 != mysql_query(sql_conn, "COMMIT;") ) {
        syslog(LOG_NOTICE, "Error (%s) executing commit transaction\n", mysql_error(sql_conn));
        return -1;
    }

    return 0;
}

static inline int mn_MysqlTransRollback(MYSQL *sql_conn)
{
    if( 0 != mysql_query(sql_conn, "ROLLBACK;") ) {
        syslog(LOG_NOTICE, "Error (%s) executing rollback transaction\n", mysql_error(sql_conn));
        return -1;
    }

    return 0;
}

static inline int mn_MysqlQuery(MYSQL *sql_conn, const char *sql, unsigned int *row_id)
{
    int result;

    if( 0 != (result=mysql_query(sql_conn, sql)) ) {
        syslog(LOG_NOTICE, "Error (%s) executing query: %s\n", mysql_error(sql_conn), sql);
        return -1;
    }

    if(row_id != NULL)
        *row_id = mysql_insert_id(sql_conn);
    return 0;
}

static inline int mn_MysqlQueryUlid(MYSQL *sql_conn, const char *sql, unsigned long *row_id)
{
    int result;

    if( 0 != (result=mysql_query(sql_conn, sql)) ) {
        syslog(LOG_NOTICE, "Error (%s) executing query: %s\n", mysql_error(sql_conn), sql);
        return -1;
    }

    if(row_id != NULL)
        *row_id = mysql_insert_id(sql_conn);
    return 0;
}

#endif  /*__MN_SQL_OP_H__*/


