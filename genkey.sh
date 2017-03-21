#!/bin/bash 

TOPPATH=$(readlink -f "$0")
TOPPATH=$(dirname "$TOPPATH")
cd ${TOPPATH}

source enc.conf

if [ "" == "$1" ]; then
  D_REV=$(cat ${REV_FILE} | sed -e '$!d' )
else
  D_REV=${REV_PR}${1}
fi

openssl rand -base64 -out key.bin 2048
openssl smime -encrypt -binary -aes256 -in key.bin -outform DEM -out ${key_enc} ${D_REV}/${SHA_PUBKEY}


