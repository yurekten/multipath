# Multipath routing  OpenFlow1.4

An Implementation of a Multipath Routing in Ryu (OpenFlow1.4).


## clear setup
```bash
cd <project_path>
./stop-process.sh
```


## start setup
```bash
cd <project_path>
./stop-process.sh
python3 ./start_sdn_controller.py

# in other console
sudo python3 fat_tree_topology.py
#or sudo python3 test_topology.py
#in containernet console
#containerner> pingall

#watch switch in diff console
sudo watch -d -n 1 ovs-ofctl dump-flows s3001 -O OpenFlow14

#test switch flows

sudo ovs-appctl ofproto/trace s3001 in_port=4,ip,nw_src=10.0.88.1,nw_dst=10.0.88.10
```

