import os
import sys
import yaml
import argparse
import requests
import zipfile
import subprocess
import csv
import networkx
import pyvis


import parsers.security.explicit_logon
import parsers.security.local_logon
import parsers.security.rdp_reconnect
import parsers.remconmanager.rdp_connection_established

def parse_args():
    arguments = {}
    parser = argparse.ArgumentParser(usage = '''
    ### WinGraph ###
    Collect Remote Event Logs and Graph Connections
    Assist in Identifying Lateral Movement and Abnormal Activity
    
    --ed / --evidence_dir - Provide a directory containing, with any nesting, Event Log (.evtx) Files which will be used for analysis.
    -t / --target_list - Provide a file which is a line-delimited list of host-names from which Event Logs will be collected.
    -uf / --users - Provide a comma-delimited list of users to filter for.
    -hf / --hosts - Provide a comma-delimited list of hosts to filter for.
    -m / --mode - Either 'user' or 'host' - defines how node-assigment and visualization is performed.
    -f / --follow - How many steps to follow newly-discovered hosts for Event Log retrieval - default is 0.
    -p / --parsed - Provide a Directory containing already-parsed Event Logs in CSV format (EvtxECmd output).
    
    Usage Examples:
    py main.py -ed F:\\test
    
    ''')
    parser.add_argument("-ed", "--evidence_dir", help="Directory containing pre-collected Windows Event Logs", required=False, nargs=1, type=str)
    parser.add_argument("-t", "--target_list", help="File containing line-delimited list of targets to collect Event Logs from (ShareMap and Copy)", required=False, nargs=1, type=str)
    parser.add_argument("-uf", "--users", help="Comma-Delimited List of Users to Hunt for", required=False, nargs=1, type=str)
    parser.add_argument("-hf", "--hosts", help="Comma-Delimited List of Hosts to Hunt for", required=False, nargs=1, type=str)
    parser.add_argument("-m", "--mode", help="Node-Assigment Mode - User<->Host with Connection Type as Edge or Host<->Host with Users as Edge - 'user', 'host' - Default is User<->Host", required=False, nargs=1, type=str)
    parser.add_argument("-f", "--follow", help="Follow Newly-Discovered Hosts to Retrieve Additional Data - How many steps to follow", required=False, nargs=1, type=str)
    parser.add_argument('-p', '--parsed', help="Provide a directory containing pre-parsed Event Logs in CSV Format", required=False, nargs=1, type=str)
    parser.add_argument('-exe', '--evtxecmd', help="Provide full dir containing EvtxECmd.exe and Maps directory.", required=False, nargs=1, type=str)
    args = parser.parse_args()

    if args.evidence_dir:
        if not os.path.isdir(args.evidence_dir[0]):
            print(f"Could not find specified evidence directory: {args.evidence_dir[0]}")
        else:
            arguments['evidence_directory'] = args.evidence_dir[0]

    if args.target_list:
        if not os.path.isfile(args.target_list[0]):
            print(f"Could not find specified target file: {args.target_list[0]}")
        else:
            arguments['targets'] = args.target_list[0]

    if not args.evidence_dir and not args.target_list and not args.parsed:
        print("No Target List and No Evidence Directory Specified - Running against Local Event Logs")
        arguments['local'] = True

    if args.users:
        try:
            user_list = args.users[0].split(',')
        except ValueError:
            user_list = []
            user_list[0] = args.users[0]
        arguments['users'] = user_list

    if args.hosts:
        try:
            host_list = args.hosts[0].split(',')
        except ValueError:
            host_list = []
            host_list[0] = args.hosts[0]
        arguments['hosts'] = host_list

    if args.evtxecmd:
        if not os.path.isdir(args.evtxecmd[0]):
            print("Please provide a valid directory for EvtxECmd: "+str(args.evtxecmd[0]))
        else:
            arguments['evtxecmd_dir'] = args.evtxecmd[0]

    if args.follow:
        try:
            arguments['follow_steps'] = int(args.follow[0])
        except:
            print(f"Illegal --follow Argument: {args.follow[0]}")
            print("Please use an integer for -f / --follow!")
            sys.exit(1)
    else:
        arguments['follow_steps'] = 0

    if args.mode:
        if args.mode[0] == "user" or args.mode[0] == "host":
            arguments['mode'] = args.mode[0]
        else:
            print("Mode can currently only be 'user' or 'host' - defaulting to 'host'")
            arguments['mode'] = 'host'
    else:
        arguments['mode'] = 'host'

    if args.parsed:
        if not os.path.isdir(args.parsed[0]):
            print(f"Could not find directory containing parsed logs: {args.parsed[0]}")
            sys.exit(1)
        else:
            arguments['parsed_logs'] = args.parsed[0]

    return arguments


def read_config(file):
    with open(file, 'r') as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError as error:
            print(error)
            sys.exit(1)
    return config


def update_evtxecmd():
    print("Updating EvtxECmd.exe")
    evtx_url = 'https://f001.backblazeb2.com/file/EricZimmermanTools/EvtxECmd.zip'
    evtz_zip = 'evtxecmd_zip.zip'
    req = requests.get(evtx_url, stream=True)
    with open(evtz_zip, 'wb') as f:
        for chunk in req.iter_content(chunk_size=128):
            f.write(chunk)
    path = os.path.abspath(evtz_zip)
    zip = zipfile.ZipFile(path)
    zip.extractall('.')
    zip.close()
    try:
        os.remove(evtz_zip)
    except:
        print("Could not clean-up EvtxECmd ZIP")
        pass


def event_log_list(dir):
    file_list = []
    for root, dirs, files in os.walk(dir):
        for f in files:
            if f.endswith('.evtx'):
                path = root + "\\" + f
                file_list.append(path)
    print(f"Found {str(len(file_list))} EVTX Files")
    return file_list


def parse_logs(file_list, evtxecmd_dir):
    evtx_binary = evtxecmd_dir+'\\EvtxECmd.exe'
    count = 0
    for file in file_list:
        command_string = evtx_binary + f' -f "{file}" --csv storage --csvf "{str(count)+"_"+os.path.basename(file)+".csv"}" --maps "{evtxecmd_dir}\\Maps"'
        try:
            subprocess.run(command_string, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error Executing: {command_string}")
            print(e)
        count += 1


def path_create():
    if os.path.isdir('storage'):
        pass
    else:
        try:
            os.mkdir('storage')
        except PermissionError as e:
            print(e)
            sys.exit(1)


def get_parsed_list(dir):
    file_list = []
    for root, dirs, files in os.walk(dir):
        for f in files:
            if f.endswith('.csv'):
                path = root + "\\" + f
                file_list.append(path)
    print(f"Found {str(len(file_list))} CSV Files")
    return file_list


def formation(network, log_files, mode):
    fields = ['RecordNumber','EventRecordId','TimeCreated','EventId','Level','Provider','Channel','ProcessId','ThreadId',
              'Computer','ChunkNumber','UserId','MapDescription','UserName','RemoteHost','PayloadData1','PayloadData2',
              'PayloadData3','PayloadData4','PayloadData5','PayloadData6','ExecutableInfo','HiddenRecord','SourceFile',
              'Keywords','ExtraDataOffset','Payload']
    for file in log_files:
        print(f"PARSING: {file}")
        with open(file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                d = {}
                i = 0
                for i in range(len(row)):
                    d[fields[i]] = row[i]
                if d['Provider'] == 'Microsoft-Windows-Security-Auditing':
                    #parse_security(network, d, mode)
                    pass
                elif d['Provider'] == 'Microsoft-Windows-TerminalServices-RemoteConnectionManager':
                    parse_remconman(network, d, mode)


def parse_remconman(network, d, mode):
    properties = {}
    user_props = {}
    user_props['color'] = 'green'
    properties['title'] = d['MapDescription']
    if d['EventId'] == '1149':
        parsers.remconmanager.rdp_connection_established.parse(network, d, user_props, properties, mode)


def parse_security(network, d, mode):
    properties = {}
    user_props = {}
    user_props['color'] = 'green'
    properties['title'] = d['MapDescription']
    if d['EventId'] == '4648':
        parsers.security.explicit_logon.parse(network, d, user_props, properties, mode)
    if d['EventId'] == '4624':
        parsers.security.local_logon.parse(network, d, user_props, properties, mode)
    if d['EventId'] == '4778':
        parsers.security.rdp_reconnect.parse(network, d, user_props, properties, mode)


def add_node(network, node_name, node_properties):
    network.add_node(node_name)
    for k,v in node_properties.items():
        network.nodes[node_name][k] = v


def add_edge(network, node1, node2, edge_properties):
    network.add_edge(node1, node2)
    for k,v in edge_properties.items():
        network.edges[node1,node2][k] = v


def network_setup():
    net = networkx.Graph()
    return net


def show_network(network):
    p_net = pyvis.network.Network(height='100%', width='100%', bgcolor='#222222', font_color='white', directed=True)
    #p_net.set_edge_smooth('dynamic')
    p_net.set_edge_smooth('continuous')
    p_net.hrepulsion(damping=.9, central_gravity=.0005, spring_strength=.0005, spring_length=300, node_distance=200)
    p_net.from_nx(network)
    p_net.show('base.html')
    networkx.write_graphml(network, 'output.graphml')


def main():
    print("WINGRAPH - Event Log Graph Visualizer")
    arguments = parse_args()
    config = read_config('config.yml')


    if not 'evtxecmd_dir' in arguments:
        update_evtxecmd()
        arguments['evtxecmd_dir'] = 'EvtxECmd'
    elif not os.path.isfile(arguments['evtxecmd_dir']+"\\evtxecmd.exe"):
        print("Could not find EvtxECmd.exe - updating now..")
        update_evtxecmd()
        arguments['evtxecmd_dir'] = 'EvtxECmd'
    elif os.path.isfile(arguments['evtxecmd_dir']+"\\evtxecmd.exe"):
        print("Found EvtxECmd.exe!")

    path_create()

    if 'evidence_directory' in arguments and not 'parsed_logs' in arguments:
        file_list = event_log_list(arguments['evidence_directory'])
        parse_logs(file_list, arguments['evtxecmd_dir'])
        log_files = get_parsed_list('storage')
    elif 'parsed_logs' in arguments:
        log_files = get_parsed_list(arguments['parsed_logs'])

    network = network_setup()
    formation(network, log_files, arguments['mode'])
    show_network(network)







main()