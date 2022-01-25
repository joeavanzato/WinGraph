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

    target_user_ = d['PayloadData1']
    try:
        target, userportion = target_user_.split(':', 1)
        try:
            domain_user, target_user = userportion.split('\\', 1)
        except:
            domain_user = "NA"
            target_user = userportion
    except:
        target_user = target_user_

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
    target_user = target_user.lower().strip()
    host_pc = host_pc.lower().strip()
    server = server.lower().strip()

    try:
        prefix, logon_type = d['PayloadData2'].split(" ")
        logon_type = logon_type.strip()
    except:
        logon_type = "NA"
    properties['LogonType'] = logon_type

    properties['title'] = d['MapDescription'] + f": Logon Type {logon_type} for user {user} authenticated as {target_user} from {host_pc} to {server} using Domain {domain_user}"
    properties['user'] = user
    properties['target_user'] = target_user
    if server != 'localhost' and server != "-" and server != "::1" and logon_type in ["3", "8", "9", "10"] and target_user!="-":
        #add_node(network, user, user_props)
        #add_node(network, target_user, user_props)
        #if host_pc != user:
        #    add_edge(network, host_pc, user, properties)
        #if user != target_user:
        #    add_edge(network, user, target_user, properties)
        #if target_user != server:
        #    add_edge(network, target_user, server, properties)

        add_edge(network, server, host_pc, properties)