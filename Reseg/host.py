class HostObject:
    def __init__(self, ip):
        self.ip = ip
        self.hosts = []
        self.total = 1

    def get_ip(self):
        return self.ip
    
    def add_egress(self, egress_ip, egress_port):
        self.total+=1
        host = self.find_host(egress_ip, egress_port)
        if host != "No match":
            self.add_packet_info(host, egress_port)
        else:
            self.hosts.append({"ip":egress_ip, "egress":[{"port":egress_port, "packets":1}]})

    def find_host(self, egress_ip, egress_port):
        for host in self.hosts:
            if host["ip"] == egress_ip:
                return host
        return "No match"

    def add_packet_info(self, host, e_port):
        match = False
        for port in host["egress"]:
            if port["port"] == e_port:
                port["packets"] += 1
                match = True
        if not match:
            host["egress"].append({"port":e_port, "packets":1})

    def get_total(self):
        return self.total

    def get_host_traffic(self):
        host_values = {}
        packets = 0
        for host in self.hosts:
            for packet_vals in host["egress"]:
                packets+=packet_vals["packets"]
            host_values[host["ip"]] = packets
        return host_values

