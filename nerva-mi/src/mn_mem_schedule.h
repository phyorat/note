#ifndef __MN_MEM_SCHEDULE_H__
#define __MN_MEM_SCHEDULE_H__


#define DAQ_DP_MP_NUMAEX_NODE_NUM           16      /* Co-relate to numa nodes, but externed/multipled/virtualized.
                                                    ** adjust -N parameter
                                                    ** according to working memory size.*/

#ifdef BUILD_SP_WALRUS                /*****SPECIES--WALRUS*****/
//Distributed
#define MAX_IPTET_HASHSZ                    (0x20000)//4096
#define IPTET_HASHSZ_MASK                   (MAX_IPTET_HASHSZ-1)
#define MAX_IPTET_NODE_SZ                   (0x40000)//8192
//#define IPTET_PKTCNT_MASK                 (MAX_IPTET_PKTCNT_SZ-1)

#define MAX_PROTOPORT_HASHSZ                (0x40000)
#define PROTOPORT_HASHSZ_MASK               (MAX_PROTOPORT_HASHSZ-1)
#define MAX_PROTOPORT_NODE_SZ               (0x80000)

#define MAX_SSNPROTO_HASHSZ                 (0x20000)
#define SSNPROTO_HASHSZ_MASK                (MAX_SSNPROTO_HASHSZ-1)
#define MAX_SSNPROTO_NODE_SZ                (0x40000)//8192
#define SSNPROTO_NODE_SZ_MASK               (MAX_SSNPROTO_NODE_SZ-1)

//Confluence
#define MAX_IPTET_CONFLUENCE_HASHSZ         (0x100000)
#define IPTET_CONFLUENCE_HASHSZ_MASK        (MAX_IPTET_CONFLUENCE_HASHSZ-1)
#define MAX_IPTET_CONFLUENCE_NODE_SZ        (0x800000)
#define IPTET_CONFLUENCE_NODE_SZ_MASK       (MAX_IPTET_CONFLUENCE_NODE_SZ-1)

#define MAX_PROTOPORT_CFL_HASHSZ            (0x100000)
#define PROTOPORT_CFL_HASHSZ_MASK           (MAX_PROTOPORT_CFL_HASHSZ-1)
#define MAX_PROTOPORT_CFL_NODE_SZ           (0x800000)

/*#define MAX_SSNPROTO_CFL_HASHSZ             (0x100000)
#define SSNPROTO_CFL_HASHSZ_MASK            (MAX_SSNPROTO_CFL_HASHSZ-1)
#define MAX_SSNPROTO_CONFLUENCE_NODE_SZ     (0x400000)*/
#define MAX_SSNPROTO_CFL_NODEPOOLS          (16)
                                      /*****END OF WALRUS SPECIES*****/
#elif defined(BUILD_SP_SEALION)       /*****SPECIES--SEALION*****/
//Distributed
#define MAX_IPTET_HASHSZ                    (0x10000)//4096
#define IPTET_HASHSZ_MASK                   (MAX_IPTET_HASHSZ-1)
#define MAX_IPTET_NODE_SZ                   (0x20000)//8192
//#define IPTET_PKTCNT_MASK                 (MAX_IPTET_PKTCNT_SZ-1)

#define MAX_PROTOPORT_HASHSZ                (0x40000)
#define PROTOPORT_HASHSZ_MASK               (MAX_PROTOPORT_HASHSZ-1)
#define MAX_PROTOPORT_NODE_SZ               (0x80000)

#define MAX_SSNPROTO_HASHSZ                 (0x20000)
#define SSNPROTO_HASHSZ_MASK                (MAX_SSNPROTO_HASHSZ-1)
#define MAX_SSNPROTO_NODE_SZ                (0x40000)//8192
#define SSNPROTO_NODE_SZ_MASK               (MAX_SSNPROTO_NODE_SZ-1)

//Confluence
#define MAX_IPTET_CONFLUENCE_HASHSZ         (0x100000)
#define IPTET_CONFLUENCE_HASHSZ_MASK        (MAX_IPTET_CONFLUENCE_HASHSZ-1)
#define MAX_IPTET_CONFLUENCE_NODE_SZ        (0x800000)
#define IPTET_CONFLUENCE_NODE_SZ_MASK       (MAX_IPTET_CONFLUENCE_NODE_SZ-1)

#define MAX_PROTOPORT_CFL_HASHSZ            (0x100000)
#define PROTOPORT_CFL_HASHSZ_MASK           (MAX_PROTOPORT_CFL_HASHSZ-1)
#define MAX_PROTOPORT_CFL_NODE_SZ           (0x800000)

/*#define MAX_SSNPROTO_CFL_HASHSZ             (0x100000)
#define SSNPROTO_CFL_HASHSZ_MASK            (MAX_SSNPROTO_CFL_HASHSZ-1)
#define MAX_SSNPROTO_CONFLUENCE_NODE_SZ     (0x400000)*/
#define MAX_SSNPROTO_CFL_NODEPOOLS          (16)
                                      /*****END OF SEALION SPECIES*****/
#else                                 /*****SPECIES--SEAL*****/
//Distributed
#define MAX_IPTET_HASHSZ                    (0x10000)//4096
#define IPTET_HASHSZ_MASK                   (MAX_IPTET_HASHSZ-1)
#define MAX_IPTET_NODE_SZ                   (0x20000)//8192
//#define IPTET_PKTCNT_MASK                 (MAX_IPTET_PKTCNT_SZ-1)

#define MAX_PROTOPORT_HASHSZ                (0x40000)
#define PROTOPORT_HASHSZ_MASK               (MAX_PROTOPORT_HASHSZ-1)
#define MAX_PROTOPORT_NODE_SZ               (0x80000)

#define MAX_SSNPROTO_HASHSZ                 (0x20000)
#define SSNPROTO_HASHSZ_MASK                (MAX_SSNPROTO_HASHSZ-1)
#define MAX_SSNPROTO_NODE_SZ                (0x40000)//8192
#define SSNPROTO_NODE_SZ_MASK               (MAX_SSNPROTO_NODE_SZ-1)

//Confluence
#define MAX_IPTET_CONFLUENCE_HASHSZ         (0x100000)
#define IPTET_CONFLUENCE_HASHSZ_MASK        (MAX_IPTET_CONFLUENCE_HASHSZ-1)
#define MAX_IPTET_CONFLUENCE_NODE_SZ        (0x800000)
#define IPTET_CONFLUENCE_NODE_SZ_MASK       (MAX_IPTET_CONFLUENCE_NODE_SZ-1)


#define MAX_PROTOPORT_CFL_HASHSZ            (0x100000)
#define PROTOPORT_CFL_HASHSZ_MASK           (MAX_PROTOPORT_CFL_HASHSZ-1)
#define MAX_PROTOPORT_CFL_NODE_SZ           (0x400000)

/*#define MAX_SSNPROTO_CFL_HASHSZ             (0x100000)
#define SSNPROTO_CFL_HASHSZ_MASK            (MAX_SSNPROTO_CFL_HASHSZ-1)
#define MAX_SSNPROTO_CONFLUENCE_NODE_SZ     (0x400000)*/
#define MAX_SSNPROTO_CFL_NODEPOOLS          (16)
#endif                              /*****END OF SEAL SPECIES*****/


/*******STATSFLOW MBUF_RING*******/
#define SUR_SF_MP_NUM_POOL_SIZE             4
#define SUR_SF_RING_MSG_TOLERATE            8
#define SUR_SF_RING_MSG_QUEUE_SIZE          SUR_SF_RING_MSG_TOLERATE
#define SUR_SF_MP_CFL_MASTER_NUM            1
#define SUR_SF_MP_SSN_MASTER_NUM            1
/*******STATSFLOW MBUF_RING END*******/


/*******SQUIRREL********/
//RING QUEUE
#define SP_RING_SND_CNT         1024
#define SP_RING_RET_CNT         2048
//MPOOL
#define SP_MPOOL_BUF_LEN        2048
/*******SQUIRREL END********/


#endif  /*End of __MN_MEM_SCHEDULE_H__*/


