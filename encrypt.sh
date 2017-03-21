#!/bin/bash 

TOPPATH=$(readlink -f "$0")
TOPPATH=$(dirname "$TOPPATH")
cd ${TOPPATH}

source enc.conf

md5file="md5sm"
keyfile="hec.bin"

ZIP_NAME="SPI_NIDS_UPGD_enc_shell.zip"

if [ "ALL" == "$1" ]; then
  file_list="SPI_NIDS_BASE.tar.gz SPI_NIDS_USSI.tar.gz SPI_NIDS_SUR.tar.gz SPI_NIDS_RULES.tar.gz SPI_NIDS_WEB.tar.gz"
  ZIP_NAME="SPI_NIDS_UPGD_enc_shell.zip"
else
  file_list="SPI_NIDS_${1}.tar.gz"
  ZIP_NAME="SPI_NIDS_${1}_enc_shell.zip"
fi

if [ "" == "$2" ]; then
  REV=
  D_REV=$(cat ${REV_FILE} | sed -e '$!d' )
else
  REV=${2}
  D_REV=${REV_PR}${2}
fi

func_enc_zip () {
  P_NAME=${1%.tar.gz}
  if [ "$1" != "${P_NAME}.tar.gz" ]; then
    return
  fi

  ./genkey.sh ${REV}

  #Encrypt Upgrade Pack File
  enc_name="${P_NAME}.enc"
  openssl enc -aes-256-cbc -salt -in $1 -out $enc_name -pass file:./key.bin

  #import MD5SUM
  md5n=`md5sum $enc_name | awk '{print $1}'`
  echo ${md5n} > ${md5file}
  openssl rsautl -encrypt -inkey ${D_REV}/${RSA_PUBKEY} -pubin -in ${md5file} -out ${keyfile}

  #import KEY
  cat ${key_enc} >> ${keyfile}

  #pack to zip
  rm -f "${P_NAME}_enc.zip"
#  zip --password usi13264 -j "${P_NAME}_enc.zip" ${keyfile} ${enc_name} ${D_REV}/${SN}
  ../predefine/ids_zp ${D_REV}/${SN} "${P_NAME}_enc.zip" ${keyfile} ${enc_name} ${D_REV}/${SN}
  ../predefine/ids_zp ${D_REV}/${SN} "${ZIP_NAME}" "${P_NAME}_enc.zip"

  echo "processing serial rev: ${D_REV}"

  rm ${md5file} ${keyfile} ${enc_name}
}

#encrypt and zip
rm -f "${ZIP_NAME}"
for p in $file_list; do
  if [ -f $p ] ; then
    func_enc_zip $p
  fi
done


