#!/bin/bash

DIR=/opt/cowrie/dl
LOG=/var/log/miami.log
WARDEN_DIR=""

# checking new files in a directory
inotifywait -m -q -e create --format '%w%f' $DIR | while read FILE
  do
    DATE=`date +"%Y-%m-%d %H:%M:%S"`
    declare -a IPLIST
    COUNT=0
    # check if file is text or binary
    if file -i $FILE | grep -q "text"; then
      echo "$DATE new malware stored in text file $FILE" >> $LOG
      # grep IP addresses in plaintext
      grep -E -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $FILE | sort | uniq | while read IP
        do
          echo "$DATE IP $IP found in file $FILE" >> $LOG
          IPLIST[$COUNT]=$IP
          COUNT=$((COUNT+1))
        done
    else
      echo "$DATE new malware stored in binary file $FILE" >> $LOG
      # grep IP addresses in strings extracted from binary file
      strings $FILE | grep -E -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | sort | uniq | while read IP
        do
          echo "$DATE IP $IP found in file $FILE" >> $LOG
          IPLIST[$COUNT]=$IP
          COUNT=$((COUNT+1))
        done
    fi
    # prepare IDEA event
    if $COUNT > 0; then
      IDEA='{
"Format": "IDEA0",
"DetectTime": "'$DATE'",
"Category": ["Malware.Virus", "Intrusion.Botnet"],
"Source": [{
    "IP4": ['
      for i in `seq 0 $COUNT`;
        do
          IDEA+=$IPLIST[$i]
        done
      IDEA+=']
  }],
"Node": [{
    "Name": ["miami"],
    "Type": ["Honeypot"],
    "SW": ["MIAMI"]
  }]
}'
      # write IDEA to file
      echo $IDEA > $WARDEN_DIR/miami.idea
    fi
    unset IPLIST
  done
