#!/bin/bash

if [ "" == "$1" ] || [ "" == "$2" ]; then
    echo "Invalid parameter(ndproto_scale)"
    exit
fi

#Proto List
proto_list="tcp udp icmp"

#Tables
nfproto_pers="protocol_stats"
nfproto_scale="nfproto_$1"
ns_name="name"
ns_seq="dt_seq"
ns_cnt="count"
ns_bph="bsize"

dt_stall_mark="1010101010"
if [ "hour" == "$1" ]; then
    dt_scale_gap="24"
elif [ "day" == "$1" ]; then
    dt_scale_gap="30"
elif [ "week" == "$1" ]; then
    dt_scale_gap="7"
elif [ "month" == "$1" ]; then
    dt_scale_gap="12"
elif [ "year" == "$1" ]; then
    dt_scale_gap="2099"
else
    echo "Invalid NetFlow Scale"
    exit
fi

#current data_time
cur_datatime=$(($2))
#cur_datatime=$((RANDOM%${dt_scale_gap}))
echo "crontab: NetFlow updating proto: scale--$nfproto_scale, datetime--$cur_datatime"

update_netflow_scaling () {
    proto="$1"
    proto_stall="$1_stall"
    #myvariable=$(mysql surveyor -u root -p11111<<<"SELECT count, total FROM protocol_stats where name='tcp'")
    nfproto_stat_now=($(mysql --defaults-extra-file=/home/lhzy06/p_test/netflow_mysql.conf surveyor<<<"SELECT count as '', total as '' FROM $nfproto_pers where name='$proto'"))
    nfproto_stat_pre=($(mysql --defaults-extra-file=/home/lhzy06/p_test/netflow_mysql.conf surveyor<<<"SELECT ${ns_cnt} as '', ${ns_bph} as '' FROM $nfproto_scale where $ns_name='$proto_stall'"))
    nfproto_stat_scale=($(mysql --defaults-extra-file=/home/lhzy06/p_test/netflow_mysql.conf surveyor<<<"SELECT ${ns_cnt} as '', ${ns_bph} as '' FROM $nfproto_scale where $ns_name='$proto' and $ns_seq='$cur_datatime'"))

    #Table-Stall
    if [ "" == "${nfproto_stat_pre[0]}" ]; then
        $(mysql --defaults-extra-file=/home/lhzy06/p_test/netflow_mysql.conf surveyor<<<"INSERT INTO $nfproto_scale($ns_name,$ns_seq,$ns_cnt,$ns_bph) VALUES('$proto_stall',$dt_stall_mark,${nfproto_stat_now[0]},${nfproto_stat_now[1]})")
        stats_cnt=${nfproto_stat_now[0]}
        stats_bph=${nfproto_stat_now[1]}
else
        $(mysql --defaults-extra-file=/home/lhzy06/p_test/netflow_mysql.conf surveyor<<<"update $nfproto_scale set ${ns_cnt}=${nfproto_stat_now[0]},${ns_bph}=${nfproto_stat_now[1]} where name='$proto_stall'")
        stats_cnt=$((${nfproto_stat_now[0]}-${nfproto_stat_pre[0]}))
        stats_bph=$((${nfproto_stat_now[1]}-${nfproto_stat_pre[1]}))
    fi

    #Database Table is empty
    if [ "" == "${nfproto_stat_scale[0]}" ]; then
        $(mysql --defaults-extra-file=/home/lhzy06/p_test/netflow_mysql.conf surveyor<<<"INSERT INTO $nfproto_scale($ns_name,$ns_seq,$ns_cnt,$ns_bph) VALUES('$proto',$cur_datatime,${stats_cnt},${stats_bph})")
    else
        $(mysql --defaults-extra-file=/home/lhzy06/p_test/netflow_mysql.conf surveyor<<<"update $nfproto_scale set ${ns_cnt}=${stats_cnt},${ns_bph}=${stats_bph} where name='$proto' and $ns_seq='$cur_datatime'")
    fi
}

for proto in $proto_list; do
    update_netflow_scaling $proto
done

