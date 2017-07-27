#!/bin/bash

dec2ip () {
    local ip dec=$@
    for e in {3..0}
    do
        ((octet = dec / (256 ** e) ))
        ((dec -= octet * 256 ** e))
        ip+=$delim$octet
        delim=.
    done
    printf '%s\n' "$ip"
}

v="$@"
vh=$(echo "obase=16; $v" | bc)
echo $vh
vhl=${vh:6:2}${vh:4:2}${vh:2:2}${vh:0:2}
echo $vhl
vl=$((0x$vhl))
dec2ip "$vl"

