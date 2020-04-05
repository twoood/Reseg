import sys
import logging
from scapy.all import *
import PySimpleGUI as sg 
from host import HostObject
from visualizer import draw_graphs
import pdb

analysis_info = {}

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

def segment_weight_decision(ip_name, pay_percent, pack_percent, pack_dict, total_hits, payload_totals, global_threshold):
    weighted_pack = (pack_dict['packets']/total_hits[ip_name])*(pack_percent/100)
    weighted_pay = (pack_dict['payload_size']/payload_totals[ip_name])*(pay_percent/100)
    return ((weighted_pack+weighted_pay) > (int(global_threshold)/100))

def on_same_subnet(host, client, segment_dict):
    if client in segment_dict.keys():
        if segment_dict[client] == host:
            return True
    if host in segment_dict.keys():
        if segment_dict[host] == client:
            return True
    host_list = host.split(".")[:-1]
    client_list = client.split(".")[:-1]
    match = 0
    for num in range(0,3):
        if host_list[num] == client_list[num]:
            match+=1
    if match == 3:
        return True
    return False


def threshold_enforce(traffic_dict, ip_totals, payloads, threshold, slider):
    suggested_seg={}
    payload_percent=slider
    packet_percent=100-slider

    for name, h_object in traffic_dict.items():
        for ip, packet in h_object.items():
            if segment_weight_decision(name, payload_percent, packet_percent, packet, ip_totals, payloads, threshold):
                if not on_same_subnet(name, ip, suggested_seg):
                    suggested_seg[name] = ip
    return suggested_seg




def main():
    visualize_list=[]
    layout = [      
            [sg.Text('Please enter path of PCAP and any subnets')],      
            [sg.Text('PCAP', size=(15, 1)), sg.InputText('./segmented_pcap')],   
            [sg.Text('Overall Threshold (%)', size=(15, 1)), sg.InputText('50 (default)')], 
            [sg.Text('Adjust the Slider to the Right to Favor Data over Total Packets')],
            [sg.Slider(range=(0, 100), orientation='h', size=(34, 20), default_value=75)],         
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
            visualize_list.append(str(name) + " " + str(ip) + " {'weight':"+ str(packet['packets']) + "}")
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
    draw_graphs(visualize_list)


if __name__ == "__main__":
    main()

 
