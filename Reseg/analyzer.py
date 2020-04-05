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
                    host_information[packet['IP'].src].add_egress(packet['IP'].dst, port, len(packet.payload))

            elif packet.type == 34525:
                logging.debug("IPv6 packet")
            elif packet.type == 2054:
                logging.debug("ARP packet")
            elif packet.type == 36864:
                logging.debug("Loopback packet")
            elif packet.type == 24578:
                logging.debug("DEC MOP Remote Console packet")
            else:
                logging.warning(str(packet.type) + " not recognized")
        except Exception as e:
            print("Exception " + str(e))
            
    host_dict = {}
    for host_ip, host_info in host_information.items():
        host_dict[host_ip] = host_info.get_host_traffic()
    return host_dict

def threshold_enforce(traffic_dict, ip_totals, payloads, threshold, slider):
    suggested_seg={}

    for name, h_object in traffic_dict.items():
        for ip, packet in h_object.items():
            if (packet['packets']/ip_totals[name]) > (int(threshold)/100):
                suggested_seg[name] = ip  

    
    # for host, client in suggested_seg.items():
    #     print(str(host)+ " suggested to resegement with " + str(client))

    return suggested_seg




def main():
    layout = [      
            [sg.Text('Please enter path of PCAP and any subnets')],      
            [sg.Text('PCAP', size=(15, 1)), sg.InputText('./segmented_pcap')],   
            [sg.Text('Overall Threshold (%)', size=(15, 1)), sg.InputText('50 (default)')], 
            [sg.Text('Adjust the Slider to Favor Data over Total Packets')],
            [sg.Slider(range=(1, 100), orientation='h', size=(34, 20), default_value=75)],         
            [sg.Submit(), sg.Cancel()]      
            ]      

    window = sg.Window('Traffic Analysis').Layout(layout)         
    button, values = window.Read()
    window.close() 
    logging.debug(button, values[0], values[1])

    for filename in os.listdir(values[0]):
        if filename.endswith(".pcapng") or filename.endswith(".pcap"): 
            pack = rdpcap(os.path.join(values[0],filename))
            logging.debug("Pcap file found:" + str(filename))
        else:
            continue

    threshold = 50
    slider = 75
    if values[1] != '50 (default)':
        threshold = values[1]
    
    if values[2] != 75:
        slider = values[2]

    analysis_info = identify_hosts(pack)

    ip_totals={}
    payload_totals={}
    for name, h_object in analysis_info.items():
        total=0
        total_payload=0
        print(str(name))
        for ip, packet in h_object.items():
            print(str(ip) + " : " + str(packet))
            total+=packet['packets']
            total_payload+=packet['payload_size']
        ip_totals[name]=total
        payload_totals[name]=total_payload
        print('Total Traffic :  ' + str(total))
        print('Total Payload :  ' + str(total_payload) + '\n')
    suggestions={}
    suggestions=threshold_enforce(analysis_info, ip_totals, payload_totals, threshold, slider)
    suggest="With a threshold of " + str(threshold) + "%\n\n"
    for host, client in suggestions.items():
       suggest+=(str(host)+ " suggested to resegement with " + str(client)+ "\n")
    sg.Popup(suggest,title="Results")


if __name__ == "__main__":
    main()

 
