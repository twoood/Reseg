import matplotlib.pyplot as plt
import networkx as nx



## add output of image

def draw_graphs(list_edges, write_to_file):
    color_range = len(list_edges)
    with open("./edges", "w+") as f_edge:
        for l_item in list_edges:
            f_edge.write(l_item+"\n")
    visualize_entry_list=[]
    intermediate_list={}
    for entry in list_edges:
        new_inbound=''
        new_outbound=''
        inbetween=''
        outbound_net=''
        inbound_net=''
        new=False
        entry_split = entry.split(' ')
        weight = entry_split[2]
        weight_value = int(weight.split(':')[-1].split('}')[0])
        in_host = entry_split[0]
        out_host = entry_split[1]
        count = 0
        for period in range(0, (in_host.count("."))):
            if in_host.split('.')[period] == out_host.split('.')[period]:
                count+=1
        if count > 2:
            visualize_entry_list.append(entry)
        elif  out_host == "224.0.0.251":
            print("multicast removed from diagram")
        else:
            outbound_net='.'.join(out_host.split('.')[:-1])+'.x'
            inbound_net='.'.join(in_host.split('.')[:-1])+'.x'
            new_inbound = in_host + " " + inbound_net
            inbetween=inbound_net+ " " + outbound_net
            r_inbetween=outbound_net + " " + inbound_net
            new_outbound = outbound_net + " " + out_host
            if new_inbound in intermediate_list.keys():
                intermediate_list[new_inbound]+=weight_value
            else:  
                intermediate_list[new_inbound]=weight_value
            if inbetween in intermediate_list.keys():
                intermediate_list[inbetween]+=weight_value
            elif r_inbetween in intermediate_list.keys():
                intermediate_list[r_inbetween]+=weight_value
            else:
                intermediate_list[inbetween]=weight_value
            if new_inbound in intermediate_list.keys():
                intermediate_list[new_inbound]+=weight_value
            else:
                intermediate_list[new_inbound]=weight_value

    for key, value in intermediate_list.items():
        visualize_entry_list.append(key + " {'weight':" + str(value)+ "}")
    #import pdb; pdb.set_trace()
    edge_string=visualize_entry_list
    #["10.10.10.10 10.10.10.11 {'weight':3}","10.10.10.10 10.10.10.12 {'weight':7}"]

    net_graph=nx.parse_edgelist(edge_string, create_using=nx.Graph(), nodetype=str)

    pos = nx.circular_layout(net_graph)
    color_range = net_graph.number_of_edges()
    colors = range(color_range)
    options = {
        "node_color": "#A0CBE2",
        "edge_color": colors,
        "width": 2,
        "edge_cmap": plt.cm.Blues,
        "with_labels": True,
        "font_size":7
    }

    print(nx.info(net_graph))

    nx.draw(net_graph, pos, **options)
    if write_to_file:
        plt.savefig("Graph.png", format="PNG")
    plt.show()