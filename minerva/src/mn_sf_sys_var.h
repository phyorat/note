#ifndef __MN_SF_SYS_VAR_H__
#define __MN_SF_SYS_VAR_H__

#include <mn_sf_cfl.h>

extern NetFlowProtoMap map_netflow_proto[];
extern NetFLowPortProtoMap map_netflow_portproto[NETFLOW_PORTPROTO_MAP_MAX];
extern NetFLowPortProtoMap map_netflow_portproto_user[NETFLOW_PORTPROTO_MAP_MAX];
extern NetFlowProtoPortReflect reflect_netflow_protoport_reflect[];
extern NetFlowItemToName map_netfow2dp[];
extern NetFlowDBTblName map_nf2dbtbl[];

#endif  /*__MN_SF_SYS_VAR_H__*/
