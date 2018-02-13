
#include "mn_daq.h"

#include <rte_memcpy.h>

const DAQ_Module_t* daq_mod = NULL;
DAQ_Mode daq_mode = DAQ_MODE_PASSIVE;
void* daq_hand = NULL;
int daq_dlt = -1;

extern int mn_config_flag;

void* StringVector_New(void)
{
    StringVector* sv = calloc(sizeof(*sv), sizeof(char));
    sv->v = calloc(sizeof(*sv->v), sizeof(char));
    sv->n = 0;
    return sv;
}

char* StringVector_Get(void* pv, unsigned index)
{
    StringVector* sv = (StringVector*) pv;

    if (!sv || index >= sv->n)
        return NULL;

    return sv->v[index];
}

int StringVector_Add(void* pv, const char* s)
{
    StringVector* sv = (StringVector*) pv;
    char** v;

    if (!sv || !s)
        return 0;

    v = realloc(sv->v, (sv->n + 2) * sizeof(char*));

    if (!v)
        return 0;

    sv->v = v;
    sv->v[sv->n++] = strdup(s);
    sv->v[sv->n] = NULL;

    return 1;
}

void StringVector_Delete(void* pv) {
    unsigned i;
    StringVector* sv = (StringVector*) pv;

    if (!sv)
        return;

    for (i = 0; i < sv->n; i++)
        free(sv->v[i]);

    free(sv->v);
    free(sv);
}

static void *ConfigDaqVar(char *args)
{
    void *daqvar;

    if (!args)
        return NULL;

    daqvar = StringVector_New();
    if (!daqvar) {
        printf("can't allocate memory for daq_var.");
        return NULL;
    }

    if (!StringVector_Add(daqvar, args)) {
        printf("can't allocate memory for daq_var.");
        return NULL;
    }

    return daqvar;
}

static void MN_DAQ_LoadVars(DAQ_Config_t* cfg, void *daqvars)
{
    unsigned i = 0;

    do {
        char* key = StringVector_Get(daqvars, i++);
        char* val = NULL;

        if (!key)
            break;

        val = strchr(key, '=');

        if (val)
            *val++ = '\0';

        daq_config_set_value(cfg, key, val);
        printf("%s: key %s, val %s\n", __func__, key, val);

        if (val)
            *--val = '=';
    } while (1);
}

/**************************************************************************//**
 *
 * pktgen_main_rx_tx_pfloop - reseive from linux interface using pfring, and send
 *
 * DESCRIPTION
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

#define PKT_TIMEOUT  1000
#define PKT_SNAPLEN  1514

int mn_daq_WasStarted(void)
{
    DAQ_State s;

    if (!daq_mod || !daq_hand)
        return 0;

    s = daq_check_status(daq_mod, daq_hand);

    return (DAQ_STATE_STARTED == s);
}

int mn_daq_stop(void)
{
    int err = daq_stop(daq_mod, daq_hand);

    if (err) {
        syslog(LOG_NOTICE, "Can't stop DAQ (%d) - %s!\n", err,
                daq_get_error(daq_mod, daq_hand));
    }

    if (daq_hand) {
        daq_shutdown(daq_mod, daq_hand);
        daq_hand = NULL;
    }

    daq_unload_modules();
    daq_mod = NULL;

    return err;
}

int mn_daq_put_mbuf(void *mbuf, uint8_t pool_idx)
{
    int err = 0;

    err = daq_sf_put_mbuf(daq_mod, daq_hand, mbuf, pool_idx);

    return err;
}

void *mn_daq_memcpy(void *mbuf_dst, const void *mbuf_src, uint32_t buf_len)
{
    return daq_rte_memcpy(daq_mod, mbuf_dst, mbuf_src, buf_len);
}

int mn_daq_get_mbuf(void *mbufs, uint8_t pool_idx)
{
    return daq_sf_get_mbufs(daq_mod, daq_hand, mbufs, pool_idx);
}

void mn_daq_breakloop_ext(void)
{
    daq_breakloop_ext(daq_mod);
}

int mn_daq_Init(ApDpLoadInfo *dpl, char *lcore_mask, uint64_t ap_lcores, char *intf, uint8_t log_dm)
{
    int err;
    DAQ_Config_t cfg;
    char var_buf[32];
    char buf[256] = "";
    char type[32];
    char dir[64] = { 0 };
    const char * pdirs[2];

    rte_memcpy(type, "dpdk", 5);
    rte_memcpy(dir, "/usr/local/lib/daq", 19);

    //lOAD Modules
    pdirs[0] = dir;
    pdirs[1] = NULL;
    err = daq_load_modules(pdirs);
    if (err) {
        syslog(LOG_NOTICE, "Can't load DAQ modules = %d\n", err);
        return -1;
    }

    //Module
    daq_mod = daq_find_module(type);
    if (!daq_mod) {
        syslog(LOG_NOTICE, "Can't find %s DAQ!\n", type);
        //return -1;
    }

    //Mode
    daq_mode = DAQ_MODE_PASSIVE;

    //Config
    memset(&cfg, 0, sizeof(cfg));
    cfg.name = intf;
    cfg.snaplen = PKT_SNAPLEN;
    cfg.timeout = PKT_TIMEOUT;
    cfg.mode = daq_mode;
    cfg.extra = NULL;
    cfg.flags = 0;
    cfg.lcore_utl_flag = ap_lcores;
    cfg.ap_dpl = dpl;

    daq_config_set_value(&cfg, NULL, NULL);
    daq_config_set_value(&cfg, "dpdk_args", "-n 2 --proc-type=primary --base-virtaddr=0x2aaa4a90000");
    daq_config_set_value(&cfg, "dpdk_c_args", lcore_mask);

    cfg.flags |= DAQ_CFG_PROMISC | DAQ_CFG_MINERVA;
    if ( log_dm ) {
        cfg.flags |= DAQ_CFG_SYSLOG;
        mn_config_flag |= DAQ_CFG_SYSLOG;
    }

    err = daq_initialize(daq_mod, &cfg, &daq_hand, buf, sizeof(buf));
    if (err) {
        syslog(LOG_NOTICE, "Can't initialize DAQ %s (%d) - %s\n", type, err, buf);
        return -1;
    }

    if (daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_UNPRIV_START) {
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);
    }

    //Filter
    /*    err = daq_set_filter(daq_mod, daq_hand, bpf);
     if ( err ) {
     syslog(LOG_NOTICE, "Can't set DAQ BPF filter to '%s' (%s)!\n",
     bpf, daq_get_error(daq_mod, daq_hand));
     }*/

    daq_config_clear_values(&cfg);

    return 0;
}

void mn_daq_start(void)
{
    int err;

    //Start
    err = daq_start(daq_mod, daq_hand);
    if (err) {
        syslog(LOG_NOTICE, "Can't start DAQ (%d) - %s!\n", err,
                daq_get_error(daq_mod, daq_hand));
    }
    else if (!(daq_get_capabilities(daq_mod, daq_hand) & DAQ_CAPA_UNPRIV_START)) {
        daq_dlt = daq_get_datalink_type(daq_mod, daq_hand);
    }
}

void mn_daq_acquire(void)
{
    daq_acquire(daq_mod, daq_hand, 0, NULL, NULL);
}

