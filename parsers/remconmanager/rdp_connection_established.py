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

def parse(network, d, user_props, properties, mode):
    user_ = d['UserName']
    try:
        domain, user = user_.split('\\', 1)
    except:
        domain = "NA"
        user = user_

    target_pc = d['Computer']
    try:
        target_pc, domain = target_pc.split('.', 1)
    except:
        pass

    src_pc = d['RemoteHost']

    user = user.lower().strip()
    src_pc = src_pc.lower().strip()
    target_pc = target_pc.lower().strip()


    properties['title'] = d['MapDescription'] + f": User {user} authenticated as {user} from {src_pc} to {target_pc} using Domain {domain}"
    properties['user'] = user

    if mode == 'user':
        add_node(network, user, user_props)
        add_edge(network, src_pc, user, properties)
        add_edge(network, user, target_pc, properties)
    elif mode == 'host':
        add_edge(network, src_pc, target_pc, properties)