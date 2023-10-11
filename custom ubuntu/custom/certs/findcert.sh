#!/bin/bash

LOCALCERTSDIR=/usr/local/share/ca-certificates/extra
ETCCERTSDIR=/etc/ssl/certs
TESTURL=https://wikipedia.com
UPDATECERTSCOMMAND=update-ca-certificates
verbose=0
fresh=0
update=0

while [ $# -gt 0 ];
do
  case $1 in
    --verbose|-v)
      verbose=1;;
    --fresh|-f)
      fresh=1;;
    --update|-u)
      update=1;;
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

function log() {
    test "$verbose" = 1 && eval $@
}

for cert in lab*.pem;
do
  log echo -n "Testing cert: $cert ..."
  if wget ${TESTURL} --ca-certificate="${cert}" -q -O /dev/null; 
  then
    log echo "Success!"
    log echo "Copying $cert to ${LOCALCERTSDIR}/${cert%.pem}.crt"
    cp "$cert" "${LOCALCERTSDIR}/${cert%.pem}.crt"
    if [ "$fresh" = 1 ]; then
      log echo "Clearing ${ETCCERTSDIR}."
      find "$ETCCERTSDIR" -type l -exec rm {} \;
    fi
    test $update -eq 1 && eval $UPDATECERTSCOMMAND
    break
  else
    log echo "Nope."
  fi
done
