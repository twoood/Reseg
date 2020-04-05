'''
Object to store the ip objects

HostObject

ip - ip_name (string)
hosts - list
    [{
        "ip": ip_name (string),
        "payload": payload_amount(int)
        "egress":
        [
            "port": port_number(int)
            "packets": packets_sent(int)
        ]

    }]
'''
class HostObject:
    def __init__(self, ip):
        self.ip = ip
        self.hosts = []
        self.total = 0
        

    def get_ip(self):
        return self.ip
    
    def add_egress(self, egress_ip, egress_port, payload_amount):
        self.total+=1
        host_found = self.find_host(egress_ip, egress_port)
        if host_found != "No match":
            self.add_packet_info(host_found, payload_amount, egress_port)
        else:
            self.hosts.append({
                "ip":egress_ip, 
                "payload":payload_amount,
                "egress":[{"port":egress_port, "packets":1}]})

    def find_host(self, egress_ip, egress_port):
        for host in self.hosts:
            if host["ip"] == egress_ip:
                return host
        return "No match"

    def add_packet_info(self, found_host, payload_amount, e_port):
        match = False
        found_host["payload"]+=payload_amount
        for port in found_host["egress"]:
            if port["port"] == e_port:
                port["packets"] += 1
                match = True
        if not match:
            found_host["egress"].append({"port":e_port, "packets":1})

    def get_total(self):
        return self.total

    def get_payload(self):
        return self.payload_total

    def get_host_traffic(self):
        host_values = {}
        packs = 0
        pay_load = 0
        for host in self.hosts:
            pay_load+=host["payload"]
            for packet_vals in host["egress"]:
                packs+=packet_vals["packets"]
            host_values[host["ip"]] = {"packets": packs, "payload_size": pay_load}
        return host_values

