from subprocess import Popen, PIPE
import requests

process = Popen(["sudo", './kdd99extractor', "-e"], stdout=PIPE, stderr=PIPE)

line = ""
for c in iter(lambda: process.stdout.read(1), b""):
    if(c.decode("utf-8")=='\n'): 
        try:
            res = requests.get(f"http://172.28.140.219:5000/new_request/{line}")
            print(res)
        except:...
        line = ""
    else: line+=c.decode("utf-8")