#!/bin/bash

time_value=`date "+%H%M%S"`
filename="reports/$time_value-test-statistics.txt"
echo "Test result will be directed to $filename"

for iter in {1..10}
do
  echo "$iter . iteration started."
  echo "$iter . iteration started." &>> $filename
  echo "iperf3 -c 10.0.88.16 -f M -t 30" &>> $filename
  iperf3 -c 10.0.88.16 -f M -t 30 &>> $filename
  echo "$iter . iteration completed."
  echo "$iter . iteration completed."&>> $filename

  sleep 10
done
  chmod 777 $filename
date