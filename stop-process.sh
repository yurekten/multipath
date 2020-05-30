#!/bin/bash

process_name="start_sdn_controller"
process_list=`ps -ef | grep $process_name | awk {'print $2'} `

if [[ -n $process_list ]]
then
   echo "Process list: $process_list"
   sudo kill -9 $process_list
else
  echo "$process_name : No process exists"
fi


date