#!/bin/bash

LOCALCERTSDIR=/usr/local/share/ca-certificates/extra
ETCCERTSDIR=/etc/ssl/certs
TESTURL=https://wikipedia.com
UPDATECERTSCOMMAND=update-ca-certificates
verbose=0
fresh=0

while [ $# -gt 0 ];
do
  case $1 in
    --verbose|-v)
      verbose=1;;
    --fresh|-f)
      fresh=1;;
    --localcertsdir)
      shift
      LOCALCERTSDIR="$1";;
    --etccertsdir)
      shift
      ETCCERTSDIR="$1";;
    --url)
      shift
      TESTURL="$1";;
    --help|-h|*)
      echo "$0: [--verbose] [--fresh]"
      exit;;
  esac
  shift
done

cd "$LOCALCERTSDIR"

for cert in "${LOCALCERTSDIR}"/lab*.pem;
do
  if wget ${TESTURL} --ca-certificate="${cert}" -q -O /dev/null; 
  then
    cp "$i" "${i%.pem}.crt"
    if test $fresh -eq 1; then
      find "$ETCCERTSDIR" -type l -exec rm {} \;
    fi
    `$UPDATECERTSCOMMAND`
    break
  fi
done
