#!/bin/bash

process_name="start_sdn_controller"
for iter in 1 2 3
do
  process_list=`ps -ef | grep $process_name | awk {'print $2'}`
  process_count=`ps -ef | grep $process_name | awk {'print $2'} | wc -l`

  if (( $process_count > 1 ))
  then
     echo "$iter Process list: $process_list"
     sudo kill -9 $process_list
  else
    echo "$process_name : No process exists"
  fi
done

date