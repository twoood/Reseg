import sys
import logging
from scapy.all import *
import PySimpleGUI as sg 
from host import HostObject
import pdb

analysis_info = {}


## add pysimplegui
## add subnets
## add threshold

logging.basicConfig(level=logging.WARNING)

def identify_hosts(packets):
    unique_hosts = []
    host_information = {}
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
                        logging.warning("Unknown protocol")
                    host_information[packet['IP'].src].add_egress(packet['IP'].dst, port)

            elif packet.type == 34525:
                logging.debug("IPv6 packet")
            elif packet.type == 2054:
                logging.debug("ARP packet")
            else:
                logging.warning(str(packet.type) + " not recognized")
        except Exception as e:
            # pdb.set_trace()
            print("Exception " + str(e))
            
    host_dict = {}
    for host_ip, host_info in host_information.items():
        host_dict[host_ip] = host_info.get_host_traffic()
    
    return host_dict

def threshold_enforce(traffic_dict, ip_totals, threshold):
    suggested_seg={}

    for name, h_object in traffic_dict.items():
        for ip, packet in h_object.items():
            if (packet/ip_totals[name]) > (threshold/100):
                suggested_seg[name] = ip  

    for host, client in suggested_seg.items():
        print(str(host)+ " suggested to segement with " + str(client))




def main():
    layout = [      
            [sg.Text('Please enter path of PCAP file and any subnets')],      
            [sg.Text('PCAP', size=(15, 1)), sg.InputText('./testv1.pcapng')],   
            [sg.Text('Threshold', size=(15, 1)), sg.InputText('70%(default)')],    
            [sg.Text('Subnets', size=(15, 1)), sg.InputText('10.10.10.x, 10.10.20.x')],            
            [sg.Submit(), sg.Cancel()]      
            ]      

    window = sg.Window('Traffic Analysis').Layout(layout)         
    button, values = window.Read()
    window.close() 
    logging.debug(button, values[0], values[1], values[2])

    pack = rdpcap(values[0])
    if values[2] != '10.10.10.x, 10.10.20.x':
        print("Not currently implemented")
    
    if values[1] != '70%(default)':
        threshold = values[1]
    else:
        threshold = 70

    analysis_info = identify_hosts(pack)

    ip_totals={}
    for name, h_object in analysis_info.items():
        total=0
        print(str(name))
        for ip, packet in h_object.items():
            print(str(ip) + " : " + str(packet))
            total+=packet
        ip_totals[name]=total
        print('Total Traffic :  ' + str(total) + '\n')  

    threshold_enforce(analysis_info, ip_totals, threshold)


if __name__ == "__main__":
    main()

 
