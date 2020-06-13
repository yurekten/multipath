# Multipath Routing Implementation

An Implementation of a Multipath Routing in Ryu (OpenFlow1.4).




## clear setup
Open new shell window.

```bash
cd <project_path>
./stop-process.sh
```


## start setup
<project_path> is source project root directory. Change <project_path> with actual path in command below.

### In Console 1 (to clear SDN controller setup)
```bash
cd <project_path>
./stop-process.sh
```

### In Console 2 (to start SDN controller)
```bash
cd <project_path>
python3 ./start_sdn_controller.py
```

### In Console 3 (to start network)
```bash
cd <project_path>
sudo python3 test_topology.py
```

execute pingall command

```bash
containerner> pingall
```
Result will be like below. At the same time, watch SDN Controller console (Console 2) 
```bash
...
lyn01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 ber01 mun01 mil01 pra01 vie01 zag01 rom01 
ber01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 lyn01 mun01 mil01 pra01 vie01 zag01 rom01 
mun01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 lyn01 ber01 mil01 pra01 vie01 zag01 rom01 
mil01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 lyn01 ber01 mun01 pra01 vie01 zag01 rom01 
pra01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 lyn01 ber01 mun01 mil01 vie01 zag01 rom01 
vie01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 lyn01 ber01 mun01 mil01 pra01 zag01 rom01 
zag01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 lyn01 ber01 mun01 mil01 pra01 vie01 rom01 
rom01 -> lon01 ams01 bru01 par01 ham01 fra01 str01 zur01 lyn01 ber01 mun01 mil01 pra01 vie01 zag01 
*** Results: 0% dropped (240/240 received)
containernet> 
```

Connect to lon01 and rom01 hosts in new terminals. When you execute commands below, Two terminal starts

```bash
containerner> xterm lon01 &
containerner> xterm rom01 &
```

#### In Terminal rom01
```bash
iperf3 -s -f M
```

```bash
---------------------------------------
Server listining on 5201
---------------------------------------
```

#### In Terminal rom01

```bash
iperf3 -c 10.0.88.16 -f M -t 20
```


### In Console 4 (to watch SDN Switch flows)
```bash
sudo watch -d -n 1 ovs-ofctl dump-flows lon -O OpenFlow14
```
Results will be like that initially
```bash
Every 1,0s: ovs-ofctl dump-flows lon -O OpenFlow14                                                                                                                                bambam: Sat Jun 13 15:27:00 2020

OFPST_FLOW reply (OF1.4) (xid=0x2):
 cookie=0x0, duration=313.664s, table=0, n_packets=198, n_bytes=11880, priority=65535,dl_dst=01:80:c2:00:00:0e,dl_type=0x88cc actions=CONTROLLER:65535
 cookie=0x100002, duration=313.693s, table=0, n_packets=0, n_bytes=0, priority=999,ipv6 actions=drop
 cookie=0x100001, duration=313.693s, table=0, n_packets=90, n_bytes=6392, priority=0 actions=CONTROLLER:65535
#test switch flows
sudo watch -d -n 1 ovs-ofctl dump-flows s3001 -O OpenFlow14
```


# test SDN switch

```bash
sudo ovs-appctl ofproto/trace lon in_port=4,ip,nw_src=10.0.88.1,nw_dst=10.0.88.16
```


```bash
1,nw_dst=10.0.88.16
Flow: ip,in_port=1,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,nw_src=10.0.88.1,nw_dst=10.0.88.16,nw_proto=0,nw_tos=0,nw_ecn=0,nw_ttl=0

bridge("lon")
-------------
 0. ip,in_port=1,nw_src=10.0.88.1,nw_dst=10.0.88.16, priority 30008, cookie 0x10285
    output:2

Final flow: unchanged
Megaflow: recirc_id=0,eth,ip,in_port=1,dl_dst=00:00:00:00:00:00,nw_src=10.0.88.1,nw_dst=10.0.88.16,nw_frag=no
Datapath actions: 2
```