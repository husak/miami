#!/bin/bash

DIR=/opt/cowrie/dl
LOG=/var/log/miami.log

# continuously checking new files
inotifywait -m -q -e create --format '%w%f' $DIR | while read FILE
  do
    # check if file is text or binary
    if file -i $FILE | grep -q "text"; then
      echo "new malware stored in text file $FILE" >> $LOG
      # grep IP addresses in plaintext
      grep -E -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $FILE | while read IP
        do
          echo "IP $IP found in file $FILE" >> $LOG
        done
    else
      echo "new malware stored in binary file $FILE" >> $LOG
      # grep IP addresses in strings extracted from binary file
      strings $FILE | grep -E -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | while read IP
        do
          echo "IP $IP found in file $FILE" >> $LOG
        done
    fi
  done
