import datetime
import json
import os
import time

if __name__ == '__main__':
    root_dir = "../reports"
    stats = {}
    stats["root"] = root_dir
    stats["files"] = {}
    for root, dirs, files in os.walk(root_dir):
        for name in files:
            file_name = os.path.join(root, name)
            print(file_name)
            if file_name.endswith(".json"):
                with open(file_name) as json_file:
                    data = json.load(json_file)
                    stats["files"][name] = data

    for file in stats["files"]:
        print(file)

    print("completed")
