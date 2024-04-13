from flask import Flask, render_template
import torch
import torch.nn as nn
import json
app = Flask(__name__)

def transform(f):
                features = f.copy()
                features[1] = 0 if features[1] == "icmp" else 1 if features[1] == "tcp" else 2
                f = features[3]
                features[3] = 0 if f=="OTH" else 1 if f=="REJ" else 2 if f=="RSTO" else 3 if f=="RSTOS0" else 4 if f=="RSTR" else 5 if f=="S0" else 6 if f=="S1" else 7 if f=="S2" else 8 if f=="S3" else 9 if f=="SF" else 10
                j = "{'IRC': 0, 'X11': 1, 'Z39_50': 2, 'auth': 3, 'bgp': 4, 'courier': 5, 'csnet_ns': 6, 'ctf': 7, 'daytime': 8, 'discard': 9, 'domain': 10, 'domain_u': 11, 'echo': 12, 'eco_i': 13, 'ecr_i': 14, 'efs': 15, 'exec': 16, 'finger': 17, 'ftp': 18, 'ftp_data': 19, 'gopher': 20, 'hostnames': 21, 'http': 22, 'http_443': 23, 'http_8001': 24, 'imap4': 25, 'iso_tsap': 26, 'klogin': 27, 'kshell': 28, 'ldap': 29, 'link': 30, 'login': 31, 'mtp': 32, 'name': 33, 'netbios_dgm': 34, 'netbios_ns': 35, 'netbios_ssn': 36, 'netstat': 37, 'nnsp': 38, 'nntp': 39, 'ntp_u': 40, 'other': 41, 'pm_dump': 42, 'pop_2': 43, 'pop_3': 44, 'printer': 45, 'private': 46, 'red_i': 47, 'remote_job': 48, 'rje': 49, 'shell': 50, 'smtp': 51, 'sql_net': 52, 'ssh': 53, 'sunrpc': 54, 'supdup': 55, 'systat': 56, 'telnet': 57, 'tim_i': 58, 'time': 59, 'urh_i': 60, 'urp_i': 61, 'uucp': 62, 'uucp_path': 63, 'vmnet': 64, 'whois': 65}"
                m = json.loads(j.replace("'", '"'))
                features[2] = m[features[2]]
                for i in range(len(features)):
                    features[i] = float(features[i])
                return features

class IntrusionDetectionModel(nn.Module):
    def __init__(self, input_size):
        super(IntrusionDetectionModel, self).__init__()
        self.fc1 = nn.Linear(input_size, 64)
        self.fc2 = nn.Linear(64, 32)
        self.fc3 = nn.Linear(32, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        x = self.sigmoid(self.fc3(x))
        return x



model = IntrusionDetectionModel(input_size=28)
model.load_state_dict(torch.load("./model_2.pth"))

model.eval()
incoming_requests = []
this_pc = ["172.28.140.219", "172.28.128.1"]
@app.route('/')
def home():
    print("Here")
    return render_template("index.html", requests=incoming_requests)

@app.route("/direct/<request>")
def direct(request):
    try:
        inputs = request.split(",")
        features = transform(inputs)
        res = model(torch.Tensor(features))
        t = '{"type":"normal"}' if res[0]>0.5 else '{"type":"anomaly"}'
        return t
    except Exception as e:
        print(e)
        return '{"type":"error"}'

@app.route("/new_request/<request>")
def new_request(request):
    # print(request)
    inputs = request.split(",")
    from_add = inputs[-3]
    to_add = inputs[-5]
    if (from_add in this_pc) and (to_add in this_pc):...
    else: 
        try:
            # {
            # 'protocol_type': 
            # {'icmp': 0, 'tcp': 1, 'udp': 2}, 
            # 'service': 
            # {'IRC': 0, 'X11': 1, 'Z39_50': 2,
            # 'auth': 3, 'bgp': 4, 'courier': 5,
            # 'csnet_ns': 6, 'ctf': 7, 'daytime': 8,
            # 'discard': 9, 'domain': 10, 'domain_u': 11,
            # 'echo': 12, 'eco_i': 13, 'ecr_i': 14,
            # 'efs': 15, 'exec': 16, 'finger': 17,
            # 'ftp': 18, 'ftp_data': 19, 'gopher': 20,
            # 'hostnames': 21, 'http': 22, 'http_443': 23,
            # 'http_8001': 24, 'imap4': 25, 'iso_tsap': 26,
            # 'klogin': 27, 'kshell': 28, 'ldap': 29,
            # 'link': 30, 'login': 31, 'mtp': 32,
            # 'name': 33, 'netbios_dgm': 34, 'netbios_ns': 35,
            # 'netbios_ssn': 36, 'netstat': 37,
            # 'nnsp': 38, 'nntp': 39, 'ntp_u': 40,
            # 'other': 41, 'pm_dump': 42, 'pop_2': 43,
            # 'pop_3': 44, 'printer': 45, 'private': 46,
            # 'red_i': 47, 'remote_job': 48, 'rje': 49, 'shell': 50,
            # 'smtp': 51, 'sql_net': 52, 'ssh': 53, 'sunrpc': 54,
            # 'supdup': 55, 'systat': 56, 'telnet': 57, 'tim_i': 58,
            # 'time': 59, 'urh_i': 60, 'urp_i': 61, 'uucp': 62,
            # 'uucp_path': 63, 'vmnet': 64, 'whois': 65}, 
            # 'flag': {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH': 10},
            # 'class': {'anomaly': 0, 'normal': 1}}

            features = transform(inputs[:-5])
            print(features)
            res = model(torch.Tensor(features))
            print(res, "normal" if res[0]>0.5 else "anomaly")
            incoming_requests.append((inputs[:-5], from_add, to_add, "normal" if res[0]>0.5 else "anomaly"))
        except Exception as e:
            raise e
    return "success"

if __name__ == '__main__':
    app.run()