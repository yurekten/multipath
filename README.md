# Multipath routing  OpenFlow1.4

An Implementation of a Multipath Routing in Ryu (OpenFlow1.4).


## clear setup
```bash
cd <project_path>
./stop-process.sh deneme
```

## start setup
```python
python3 ./start_sdn_controller.py
sudo python3 test_topology.py 
# or sudo python3 fat_tree_topology.py
```


Implementation is based on:
* [Theory](https://wildanmsyah.wordpress.com/2018/01/13/multipath-routing-with-load-balancing-using-ryu-openflow-controller)
* [Testing](https://wildanmsyah.wordpress.com/2018/01/21/testing-ryu-multipath-routing-with-load-balancing-on-mininet)





