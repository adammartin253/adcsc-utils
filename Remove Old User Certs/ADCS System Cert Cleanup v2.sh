#!/bin/bash

# This script will remove all instances of a system keychain cert where: 
# 1) The certificate subject matches the cert subject below. 
# 2) It does not have the latest expiration date.

certSubject="Common-text-here i.e domain name"

certList=$( security find-certificate -c "${certSubject}" -p -a )

# echo "$certList"
# exit

# Get each cert into an array element

# Remove spaces
certList=$( echo "$certList" | sed 's/ //g' )
# Put a space after the end of each cert
certList=$( echo "$certList" | sed 's/-----ENDCERTIFICATE-----/-----ENDCERTIFICATE----- /g' )
# echo "$certList"
OIFS="$IFS"
IFS=' '
# read -a certArray <<< "${certList}"
declare -a certArray=($certList)
IFS="$OIFS"


i=-1
dateHashList=''
# Print what we got...
for cert in "${certArray[@]}"; do 
  let "i++"
  echo '---------'
  #   echo "$cert"
  #   echo '--'
  # Fix the begin/end certificate
  cert=$( echo "$cert" | sed 's/-----BEGINCERTIFICATE-----/-----BEGIN CERTIFICATE-----/g' )
  cert=$( echo "$cert" | sed 's/-----ENDCERTIFICATE-----/-----END CERTIFICATE-----/g' )
  #   echo "$cert"
  #   echo "$cert" | openssl x509 -text
  certMD5=$( echo "$cert" | openssl x509 -noout -fingerprint -sha1 -inform pem | cut -d "=" -f 2 | sed 's/://g' )
  certDate=$( echo "$cert" | openssl x509 -text | grep 'Not After' | sed -E 's|.*Not After : ||' )
  certDateFormatted=`date -jf "%b %d %T %Y %Z" "${certDate}" +%Y%m%d%H%M%S`
  echo "Cert ${i} : ${certDate} => $certDateFormatted"
  echo "Cert ${i} : ${certMD5}"
  NL=$'\n'
  dateHashList="${dateHashList}${NL}${certDateFormatted} ${certMD5}"
done
echo

dateHashList=$( echo "$dateHashList" | sort )
lines=$( echo "$dateHashList" | wc -l | tr -d ' ' )
let "lines--"
echo "[info] There are $lines lines in the certificate date-hash list."
echo

i=0
OIFS="$IFS"
IFS=$'\n'       # make newlines the only separator
for dateHash in $dateHashList; do
  let "i++"
  dateNum="${dateHash%% *}"
  hash="${dateHash##* }"
  echo "${i}| Hash : \"$hash\" | dateNum : \"$dateNum\""
  if [[ i -ne $lines ]]; then
    echo "=> This cert will be removed"
sudo security delete-certificate -Z $hash /Library/Keychains/System.keychain
    echo
  else
    echo "=> This cert will not be touched because it has the latest expiration date."
  fi
done
IFS="$OIFS"

exit 0