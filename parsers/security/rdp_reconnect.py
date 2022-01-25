import networkx
import re

def add_node(network, node_name, node_properties):
    network.add_node(node_name)
    for k,v in node_properties.items():
        network.nodes[node_name][k] = v


def add_edge(network, node1, node2, edge_properties):
    network.add_edge(node1, node2)
    for k,v in edge_properties.items():
        network.edges[node1,node2][k] = v

def parse(network, d, user_props, properties):
    user_ = d['UserName']
    try:
        domain, user = user_.split('\\', 1)
    except:
        user = user_

    host_pc = d['Computer']
    try:
        host_pc, domain = host_pc.split('.', 1)
    except:
        pass

    target_pc = d['RemoteHost']
    m = re.match(r"(.*)\s\(([^)].*\))", target_pc)
    if m.group(1) == "-":
        server = m.group(2)
    else:
        server = m.group(1)
    try:
        server = server.replace(")", "")
    except:
        pass

    user = user.lower().strip()
    host_pc = host_pc.lower().strip()
    server = server.lower().strip()


    properties['title'] = d['MapDescription'] + f": {user} authenticated from {server} to {host_pc} using Domain {domain}"
    properties['user'] = user

    if server != 'localhost' and server != "-" and server != "::1":
        #add_node(network, user, user_props)
        #if host_pc != user:
        #    add_edge(network, host_pc, user, properties)
        #add_edge(network, user, server, properties)
        add_edge(network, server, host_pc, properties)