import datetime
import json
import os
import time
import csv

def extract_data():
    root_dir = "../reports"
    stats = {}
    stats["root"] = root_dir
    stats["files"] = []
    for root, dirs, files in os.walk(root_dir):
        for name in files:
            file_name = os.path.join(root, name)
            if file_name.endswith(".json"):
                with open(file_name) as json_file:
                    data = json.load(json_file)
                    stats["files"].append((name, data,))

    if len(stats["files"]) >= 2:
        last_stats = sorted(stats["files"], key=lambda x: x[0])[-2:]
        stat = last_stats[0][1]
        stat_file = last_stats[0][0]
        print(stat_file)
        all_results = get_all_results(stat)
        all_results = sorted(all_results, key=lambda x: x[1])
        dp_name = "1005"
        dp1_results = [n for n in all_results if n[1] == dp_name]

        dp1_pkt_count = sum([item[3] for item in dp1_results])
        dp1_byte_count = sum([item[4] for item in dp1_results])

        print("dp %s: total_flow_macth: %s, total_byte_match: %s " % (dp_name, dp1_pkt_count, dp1_byte_count))
        dp_name = "1016"
        dp2_results = [n for n in all_results if n[1] == dp_name]

        dp2_pkt_count = sum([item[3] for item in dp2_results])
        dp2_byte_count = sum([item[4] for item in dp2_results])

        print("dp %s: total_flow_macth: %s, total_byte_match: %s " % (dp_name, dp2_pkt_count, dp2_byte_count))
        with open('%s-result-summary.csv' % stat_file, mode='w') as out_file:
            file_writer = csv.writer(out_file, delimiter='\t', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for res in all_results:
                file_writer.writerow(list(res))

def get_all_results(stat):
    results = []
    for rule_set_id, value in stat["rule_set"].items():
        if "datapath_list" in value:
            datapath_list = value["datapath_list"]
            for dp_name in datapath_list:
                flows = datapath_list[dp_name]["ip_flow"]
                add_dp_results(flows, dp_name, results, rule_set_id)
    return results


def add_dp_results(flows, dp_name, results, rule_set_id):

    key_list = list(flows.keys())
    flow_id = key_list[0]
    flow = flows[flow_id]
    byte_count = 0
    packet_count = 0
    if "packet_count" in flow and flow["packet_count"] is not None:
        packet_count = flow["packet_count"]
    if "byte_count" in flow and flow["byte_count"] is not None:
        byte_count = flow["byte_count"]
    results.append((rule_set_id, dp_name, flow_id, packet_count, byte_count))


if __name__ == '__main__':


    extract_data()


    pass
