#!/bin/bash

hl_dec=0
ip2dec () {
    local a b c d ip=$@
    IFS=. read -r a b c d <<< "$ip"
    hl_dec=$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))
}

ip2dec "$@"
hx=$(echo "obase=16; $hl_dec" | bc)
hlx=$(printf '%08x' 0x$hx)
echo $hlx
vhlx=${hlx:6:2}${hlx:4:2}${hlx:2:2}${hlx:0:2}
vhlx=$(printf '%08x' 0x$vhlx)
echo $vhlx
echo $((0x$vhlx))

