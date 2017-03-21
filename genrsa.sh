#!/bin/bash 

TOPPATH=$(readlink -f "$0")
TOPPATH=$(dirname "$TOPPATH")
cd ${TOPPATH}

source enc.conf

#Prepare Reversion Folder
if [ "" == "$1" ]; then
  touch ${REV_FILE}
  REV=$(cat ${REV_FILE} | sed -e '$!d' | sed "s/${REV_PR}//")
  if [ "" == "${REV}" ]; then
    REV=1
  else
    REV=$((${REV}+1))
  fi
  echo ${REV_PR}${REV} >> ${REV_FILE}
else
  REV=${1}
fi

mkdir -p ../${DECDIR}/${REV_PR}${REV}
mkdir -p ${REV_PR}${REV}


#generate SN
#od -xAn -N16 < /dev/urandom |tr -d  " |\n" > ${SN}
#!!!RUN it on target machine and copy it here, use appropriate parameter "${REV}"
#../predefine/un_ids_gsn ${REV}
SNC="${SN}-${REV}"

#For RSA
openssl genrsa -out ${RSA_PRIKEY} 2048
openssl rsa -in ${RSA_PRIKEY} -out ${RSA_PUBKEY} -outform PEM -pubout

#For SMIME
openssl req -x509 -nodes -days 100000 -sha256 -newkey rsa:2048 -keyout ${SHA_PRIKEY} -out ${SHA_PUBKEY} -subj '/C=CN/ST=SiChuan/L=ChengDu/O=USI/OU=usi/CN=www.usi.com/emailAddress=usi@usi.com'

#Archive KEYs
mv ${RSA_PRIKEY} ../${DECDIR}/${REV_PR}${REV}
mv ${SHA_PRIKEY} ../${DECDIR}/${REV_PR}${REV}
cp ${SNC} ../${DECDIR}/${REV_PR}${REV}/${SN}
mv ${RSA_PUBKEY} ${REV_PR}${REV}
mv ${SHA_PUBKEY} ${REV_PR}${REV}
cp ${SNC} ${REV_PR}${REV}/${SN}


