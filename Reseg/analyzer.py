import sys
import logging
from scapy.all import *
import PySimpleGUI as sg 
from host import HostObject
from visualizer import draw_graphs
import pdb

analysis_info = {}

logging.basicConfig(level=logging.WARNING)

## %ages leaving own subnet 

def identify_hosts(packet_list):
    
    unique_hosts = []
    host_information = {}
    for packets in packet_list:
        for packet in packets:
            try:
                if packet.type == 2048:
                    if packet['IP'].src not in unique_hosts:
                        unique_hosts.append(packet['IP'].src)
                        host_information[packet['IP'].src] = HostObject(packet["IP"].src)
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
                pdb.set_trace()
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

def if_already_suggested(host_name, subnet_name):
    print(host_name)

def threshold_enforce(traffic_dict, ip_totals, payloads, threshold, slider, seg_enforce):
    suggested_seg={}
    payload_percent=slider
    packet_percent=100-slider
    for name, h_object in traffic_dict.items():
        out_of_subnet={"packets":0,"payload_size":0}
        for ip, packet in h_object.items():
            if name.split('.')[:-1] != ip.split('.')[:-1] and name.split('.')[:-2] == ip.split('.')[:-2]:
                out_of_band_name='.'.join(ip.split('.')[:-1])+".x"
                out_of_subnet['packets']+=packet['packets']
                out_of_subnet['payload_size']+=packet['payload_size']
            if segment_weight_decision(name, payload_percent, packet_percent, packet, ip_totals, payloads, threshold):
                if not on_same_subnet(name, ip, suggested_seg) and ip != '224.0.0.251':
                    suggested_seg[name] = ip
        if seg_enforce and segment_weight_decision(name, payload_percent, packet_percent, out_of_subnet, ip_totals, payloads, threshold):
            suggested_seg[name] = out_of_band_name + " subnet"
    return suggested_seg




def main():
    visualize_list=[]
    layout = [      
            [sg.Text('Please enter path of PCAP and any subnets')],      
            [sg.Text('PCAP', size=(15, 1)), sg.InputText('./segmented_pcap')],   
            [sg.Text('Overall Threshold (%)', size=(15, 1)), sg.InputText('50 (default)')], 
            [sg.Text('Adjust the Slider to the Favor Packets or Data')],
            [sg.T("Packets"), sg.Slider(range=(0, 100), orientation='h', size=(34, 20), default_value=50), sg.T("Data"),], 
            [sg.Checkbox('Enforce on Whole Subnets', size=(30, 1))],
            [sg.Checkbox('Generate Diagrams', size=(20, 1))],
            [sg.Checkbox('Write Results', size=(12, 1))],        
            [sg.Submit(), sg.Cancel()]      
            ]      

    window = sg.Window('Traffic Analysis').Layout(layout)         
    button, values = window.Read()
    window.close() 
    logging.debug(button, values[0], values[1])
    pack=[]
    for filename in os.listdir(values[0]):
        if filename.endswith(".pcapng") or filename.endswith(".pcap"): 
            print("Found PCAP File: "+ str(filename))
            pack.append(rdpcap(os.path.join(values[0],filename)))
            logging.debug("Pcap file found:" + str(filename))
        else:
            continue

    threshold = 50
    slider = 50
    if values[1] != '50 (default)':
        threshold = values[1]
    ############
    #threshold = 25
    ############
    if values[2] != 50:
        slider = values[2]
    segment_enforcement = values[3]
    diagrams = values[4]
    save_file = values[5]
    analysis_info = identify_hosts(pack)


    ip_totals={}
    payload_totals={}
    output_string_list=[]
    for name, h_object in analysis_info.items():
        total=0
        total_payload=0
        out_of_bounds_packets=0
        out_of_bounds_payloads=0
        print(str(name))
        output_string_list.append(name)
        for ip, packet in h_object.items():
            if name.split('.')[:-1] != ip.split('.')[:-1] and name.split('.')[:-2] == ip.split('.')[:-2]:
                out_of_bounds_packets+=packet['packets']
                out_of_bounds_payloads+=packet['payload_size']
            visualize_list.append(str(name) + " " + str(ip) + " {'weight':"+ str(packet['packets']) + "}")
            print(str(ip) + " : " + str(packet))
            output_string_list.append(str(ip) + " : " + str(packet))
            total+=packet['packets']
            total_payload+=packet['payload_size']
        ip_totals[name]=total
        payload_totals[name]=total_payload
        oob_packs = round((out_of_bounds_packets/total)*100, 2)
        oob_pay = round((out_of_bounds_payloads/total_payload)*100, 2)
        print('Total Traffic :  ' + str(total))
        output_string_list.append('Total Traffic :  ' + str(total))
        print('Total Payload :  ' + str(total_payload) + '\n')
        output_string_list.append('Total Payload :  ' + str(total_payload))
        print('Percent out of subnet traffic :  ' + str(oob_packs) + '%')
        output_string_list.append('Percent out of subnet traffic :  ' + str(oob_packs) + '%')
        print('Percent out of subnet payloads :  ' + str(oob_pay) + '%\n')
        output_string_list.append('Percent out of subnet payloads :  ' + str(oob_pay) + '%\n\n')
    
    suggestions={}
    suggestions=threshold_enforce(analysis_info, ip_totals, payload_totals, threshold, slider, segment_enforcement)
    suggest="With a threshold of " + str(threshold) + "%\n"
    suggest+="Favoring " + str(slider) + "% of total payloads and " + str(100-slider) + "% of total packets.\n\n"
    for host, client in suggestions.items():
       suggest+=(str(host)+ " suggested to resegement with " + str(client)+ "\n")
    sg.Popup(suggest,title="Results")
    if diagrams:
        draw_graphs(visualize_list, save_file)
    if save_file:
        with open("Segmentation_Stats.txt", "w+") as seg_stats:
            for info in output_string_list:
                seg_stats.write(info + "\n")
            seg_stats.write(suggest)


        


if __name__ == "__main__":
    main()

 
