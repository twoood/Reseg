import matplotlib.pyplot as plt
import networkx as nx



## add output of image

def draw_graphs(list_edges, write_to_file):
    color_range = len(list_edges)
    with open("./edges", "w+") as f_edge:
        for l_item in list_edges:
            f_edge.write(l_item+"\n")
    edge_string=list_edges
    #["10.10.10.10 10.10.10.11 {'weight':3}","10.10.10.10 10.10.10.12 {'weight':7}"]

    net_graph=nx.parse_edgelist(edge_string, create_using=nx.Graph(), nodetype=str)

    pos = nx.spring_layout(net_graph)
    color_range = net_graph.number_of_edges()
    colors = range(color_range)
    options = {
        "node_color": "#A0CBE2",
        "edge_color": colors,
        "width": 4,
        "edge_cmap": plt.cm.Blues,
        "with_labels": True,
    }

    print(nx.info(net_graph))

    nx.draw(net_graph, pos, **options)
    if write_to_file:
        plt.savefig("Graph.png", format="PNG")
    plt.show()