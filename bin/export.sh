#!/usr/bin/env bash

DIR=$PWD/export
BASE='https://drupal.org/security'

TYPE='contrib'
if [[ $1 = 'core' ]]; then
  TYPE='/'
elif [[ $1 = 'contrib' ]]; then
  TYPE='/contrib'
else
  echo "Specify 'core' or 'contrib' to begin downloading SA pages"
  exit 1
fi

if [ -z "$2" ]; then
  echo "Set the last page number to download for. e.g. 64 for https://drupal.org/security/contrib?page=64"
  exit 1
fi

curl -s $BASE$TYPE > $DIR/$TYPE-0.html
for (( i=1; i<=$2; i++ ))
do
  curl -s $BASE$TYPE?page=$i > $DIR/$1-$i.html
done

echo $1 $2 > $DIR/LASTRUN
echo `DATE` >> $DIR/LASTRUN
