#ifndef __MN_SF_SYS_VAR_H__
#define __MN_SF_SYS_VAR_H__

#include <daq.h>

#include "mn_sf_cfl.h"

extern daq_dpdk_mpool_collect mn_sf_daq_mbuf_coll [];
extern daq_dpdk_ring_collect mn_sf_daq_ring_coll [];
uint16_t mn_sf_daq_mbuf_get_count(void);
uint16_t mn_sf_daq_ring_get_count(void);

extern NetFlowProtoMap map_netflow_proto[];
extern NetFLowPortProtoMap map_netflow_portproto[NETFLOW_PORTPROTO_MAP_MAX];
extern NetFLowPortProtoMap map_netflow_portproto_user[SF_MAX_PROT_PROTO_USER];
extern NetFlowProtoPortReflect reflect_netflow_protoport_reflect[];
extern NetFlowItemToName map_netfow2dp[];
extern NetFlowDBTblName map_nf2dbtbl[];

#endif  /*__MN_SF_SYS_VAR_H__*/
