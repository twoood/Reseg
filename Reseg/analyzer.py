import sys
from scapy.all import *
from host import HostObject
import pdb

pack = rdpcap(sys.argv[1])


unique_hosts = []
host_information = {}



def identify_hosts(packets):
    for packet in packets:
        # pdb.set_trace()
        try:
            if packet.type == 2048:
                if packet['IP'].src not in unique_hosts:
                    unique_hosts.append(packet['IP'].src)
                    host_information[packet['IP'].src] = HostObject(packet["IP"].src)
                else:
                    port = 0
                    if packet['IP'].proto == 6:
                        port = packet['IP']['TCP'].dport
                    elif packet['IP'].proto == 17:
                        port = packet['IP']['UDP'].dport
                    elif packet['IP'].proto == 1:
                        port = "icmp"
                    else:
                        print("Unknown protocol")
                    host_information[packet['IP'].src].add_egress(packet['IP'].src, port)

            elif packet.type == 34525:
                print("IPv6 packet")
            elif packet.type == 2054:
                print("ARP packet")
            else:
                print(str(packet.type) + " not recognized")
        except Exception as e:
            # pdb.set_trace()
            print("Exception " + str(e))
            

    for host_ip, host_info in host_information.items():
        print(str(host_ip) + " : " +str(host_info.get_total()))



identify_hosts(pack)


    
