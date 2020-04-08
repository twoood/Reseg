import pdb
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
        """ 
        Constructor of HostObject 
    
        Parameters: 
        ip (string): ip address of host 
    
        Returns: 
        None
    
        """
        self.ip = ip
        self.hosts = []
        self.total = 0

    def get_ip(self):
        """ 
        Getter for ip of HostObject 
    
        Parameters: 
        None
    
        Returns: 
        self.ip (string)
    
        """
        return self.ip
    
    def add_egress(self, egress_ip, egress_port, payload_amount):
        """ 
        Add new node to HostObject 
    
        Parameters: 
        egress_ip (string)
        egress_port (int)
        payload_amount (int)
    
        Returns: 
        None
    
        """
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
        """ 
        Find a node if it is already in the host data structure 
    
        Parameters: 
        egress_ip (string)
        egress_port (int)
    
        Returns: 
        host (dictionary element)
        "No match"
    
        """        
        for host in self.hosts:
            if host["ip"] == egress_ip:
                return host
        return "No match"

    def add_packet_info(self, found_host, payload_amount, e_port):
        """ 
        Add host info to self.hosts dictionary 
    
        Parameters: 
        found_host (dictionary element)
        payload_amount (int)
        e_port (int)
    
        Returns: 
        None
    
        """
        match = False
        found_host["payload"]+=payload_amount
        for port in found_host["egress"]:
            if port["port"] == e_port:
                port["packets"] += 1
                match = True
        if not match:
            found_host["egress"].append({"port":e_port, "packets":1})

    def get_total(self):
        """ 
        Getter for total packets sent from HostObject 
    
        Parameters: 
        None
    
        Returns: 
        self.total (int)
    
        """
        return self.total

    def get_payload(self):
        """ 
        Getter for total payloads sent from HostObject 
    
        Parameters: 
        None
    
        Returns: 
        self.payload_total (int)
    
        """        
        return self.payload_total

    def get_host_traffic(self):
        """ 
        Getter for outgoing host traffic information sent from HostObject 
    
        Parameters: 
        None
    
        Returns: 
        host_values (dict)
    
        """         
        host_values = {}
        packs = 0
        pay_load = 0
        for host in self.hosts:
            pay_load+=host["payload"]
            for packet_vals in host["egress"]:
                packs+=packet_vals["packets"]
            host_values[host["ip"]] = {"packets": packs, "payload_size": pay_load}
        return host_values

