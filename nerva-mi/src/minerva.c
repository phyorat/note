/*
 * COPYRIGHT 2016, @UNIONSMART
 *
 */

#include <syslog.h>
#include <signal.h>
#include <dirent.h>

#include "mn_daq.h"
#include "minerva.h"
#include "statsifc.h"
#include "mn_sf_cfl.h"
#include "mn_gen.h"
#include "mn_sf_sys_var.h"

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#include <heartbeat.h>


static int exit_signal = 0;
int mn_config_flag = 0;

static int CheckNumaNodes(void)
{
   char filename[1024];
   int  num_nodes = 0;
   struct dirent *de;
   DIR *dir;

   snprintf(filename, sizeof(filename), "/sys/devices/system/node");

   if ((dir = opendir(filename)))
   {
       while ((de = readdir(dir)))
       {
           if (strncmp(de->d_name, "node", 4) != 0)
               continue;
           num_nodes++;
       }
   }
   closedir(dir);

   LogMessage("minerva: Number of numa nodes is %d\n", num_nodes);

   return num_nodes;
}

static void SigExitHandler(int signal)
{

    printf("%s: catch signal %d\n", __func__, signal);

    if (exit_signal != 0)
        return;

    exit_signal = signal;

    mn_daq_breakloop_ext();
}

/*static inline uint8_t user_rte_get_huge_maps()
{
    uint8_t numa_maps_c;
    FILE *fp;
    char line[256];

    numa_maps_c = 0;
    fp = popen("for i in $(pgrep surveyor); "
            "do cat /proc/$i/numa_maps |grep -e '/mnt/huge/rtemap_0'"
            " | awk '{print $4}'; done", "r");
    while (fgets(line, sizeof(line), fp) != NULL) {
        if ( !strncmp(line, "huge", 4) )
            numa_maps_c++;
    }

    return numa_maps_c;
}*/

int main(int argc, char *argv[])
{
    uint8_t i, log_daemon = 0;
    uint8_t sur_c, numa_maps_c = 0;
    uint64_t pkt_count = 0, pkts_prev = 0;
    uint64_t lcore_utl = 0, numa_node_c = 0;
    struct rte_ring *pkt_mbuf_ring;
    struct rte_mbuf *pkt_mp;
    struct timespec t_elapse;
    //char cmd[64];
    char lcore[32];
    char intf[32];
    char prog_name[16] = {"minerva"};
    char *p_arg;

//    struct rte_mempool *mp_dpl_cfg;
//    struct rte_ring *mr_dpl_cfg;
    ApDpLoadInfo dpl;

    //"-c f00 -n 2 --proc-type=primary"

    memset(lcore, 0, sizeof(lcore));
    memset(intf, 0, sizeof(intf));
    for (i=1; i<argc; i++) {
        p_arg = argv[i];
        if ( '-' != *p_arg )
            break;

        switch( *(p_arg+1) ) {
        case 'c':
            i++;
            if ( i<argc )
                strncpy(lcore, argv[i], sizeof(lcore)-1);
            break;
        case 'C':
            i++;
            if ( i<argc )
                lcore_utl = strtoul(argv[i], NULL, 16);
            break;
        case 'N':
            i++;
            if ( i<argc )
                numa_node_c = strtoul(argv[i], NULL, 10);
            break;
        case 'M':
            log_daemon = 1;
            break;
        case 'P':
            i++;
            if ( i<argc )
                strncpy(intf, argv[i], sizeof(intf)-1);
            break;
        default:
            syslog(LOG_NOTICE, "%s: Invalid parameter '%c'\n", prog_name, *(p_arg+1));
            break;
        }
    }

    if ( 0 == lcore[0] || 0 == intf[0] ) {
        syslog(LOG_NOTICE, "%s: No valid core-mask or interface\n", prog_name);
        return -1;
    }

    InitHeartBeat();
    signal(SIGTERM, SigExitHandler);
    signal(SIGINT, SigExitHandler);

        /* printf("%s: ret %d, master core %d, state %d\n", __func__,
         *           ret, rte_get_master_lcore(), rte_eal_get_lcore_state(0));
         *
         * enum rte_lcore_state_t {
         *     WAIT,       /**< waiting a new command
         *     RUNNING,    /**< executing command
         *     FINISHED,   /**< command executed
         * };
         * */

//    t_elapse.tv_sec = 0;
//    t_elapse.tv_nsec = 1;

    dpl.rsock = CheckNumaNodes();
    if ( 0 == dpl.rsock ) {
        syslog(LOG_NOTICE, "%s: Invalid Numa Node Number!\n", prog_name);
        return -1;
    }

    if ( dpl.rsock < numa_node_c )
        dpl.nsock = numa_node_c;
    else
        dpl.nsock = dpl.rsock;

    syslog(LOG_NOTICE, "%s: Numa Node Number: %u\n", prog_name, dpl.nsock);

    dpl.npool = mn_sf_daq_mbuf_get_count();
    dpl.nring = mn_sf_daq_ring_get_count();
    dpl.ap_name = prog_name;
    dpl.mpools = mn_sf_daq_mbuf_coll;
    dpl.rings = mn_sf_daq_ring_coll;
    dpl.sf_init = sf_CflInit;
    dpl.sf_confluence = sf_Confluence;
    dpl.sf_ssn_init = sf_CflSsnInit;
    dpl.sf_cfl_ssn = sf_CflSession;
    dpl.sf_cfl_dbins = sf_DBIns_Loop;
    dpl.sp_init = stats_ifport_init;
    dpl.sp_scale = stats_ifport_scale;

    if ( mn_daq_Init(&dpl, lcore, lcore_utl, intf, log_daemon) ) {
        syslog(LOG_NOTICE, "%s: daq init failed\n", prog_name);
        return -1;
    }

    mn_daq_start();

    while( !exit_signal ) {

        mn_daq_acquire();

        //Get pkt_mbuf from ring
        if ( 0 ) {//0 == rte_ring_dequeue(pkt_mbuf_ring, (void**)&pkt_mp) ) {
            rte_pktmbuf_free(pkt_mp);
            pkt_count++;
        }
        else {
            //nanosleep(&t_elapse, NULL);
            //printf("running minerva\n");
            //sleep(1);

/*            if ( pkts_prev < pkt_count ) {
                snprintf(cmd, sizeof(cmd), "echo %lu > /tmp/minerva_pkts_p%d_q%d",
                        pkt_count, pif_ins[1].port_id, pif_ins[1].queue_id);
                system(cmd);

                pkts_prev = pkt_count;
            }*/
        }

/*        if ( 1 == pif_ins[1].cap_arch ) {
            numa_maps_c = user_rte_get_huge_maps();
            if ( sur_c != numa_maps_c ) {
                syslog(LOG_INFO, "%s: RTE_EAL missing, check for "
                        "problem and restart me.\n", prog_name);
                break;
            }
        }*/
    }

    LogMessage("%s: pkt_count %lu\n", prog_name, pkt_count);

    return 0;
}
