import os
import sys
import yaml
import argparse
import requests
import zipfile
import subprocess

def parse_args():
    arguments = {}
    parser = argparse.ArgumentParser(usage = '''
    ### WinGraph ###
    Collect Remote Event Logs and Graph Connections
    Assist in Identifying Lateral Movement and Abnormal Activity
    ''')
    parser.add_argument("-ed", "--evidence_dir", help="Directory containing pre-collected Windows Event Logs", required=False, nargs=1, type=str)
    parser.add_argument("-t", "--target_list", help="File containing line-delimited list of targets to collect Event Logs from (ShareMap and Copy)", required=False, nargs=1, type=str)
    parser.add_argument("-uf", "--users", help="Comma-Delimited List of Users to Hunt for", required=False, nargs=1, type=str)
    parser.add_argument("-hf", "--hosts", help="Comma-Delimited List of Hosts to Hunt for", required=False, nargs=1, type=str)
    parser.add_argument("-m", "--mode", help="Node-Assigment Mode - User<->Host with Connection Type as Edge or Host<->Host with Users as Edge - 'user', 'host' - Default is User<->Host", required=False, nargs=1, type=str)
    parser.add_argument("-f", "--follow", help="Follow Newly-Discovered Hosts to Retrieve Additional Data - How many steps to follow", required=False, nargs=1, type=str)
    parser.add_argument('-p', '--parsed', help="Provide a directory containing pre-parsed Event Logs in CSV Format", required=False, nargs=1, type=str)
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

    if not args.evidence_dir and not args.target_list:
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

    if args.follow:
        try:
            arguments['follow_steps'] = int(args.follow[0])
        except:
            print(f"Illegal --follow Argument: {args.follow[0]}")
            print("Please use an integer for -f / --follow!")
            sys.exit(1)
    else:
        arguments['follow_steps'] = 0

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
    file_list = os.listdir(os.getcwd())
    if 'evtxecmd.exe' in file_list:
        print("Found EvtxECmd Binary")
        return
    else:
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
        os.remove(evtz_zip)


def event_log_list(dir):
    file_list = []
    for root, dirs, files in os.walk(dir):
        for f in files:
            if f.endswith('.evtx'):
                path = root + "\\" + f
                file_list.append(path)
    print(f"Found {str(len(file_list))} EVTX Files")
    return file_list


def parse_logs(file_list):



    evtx_binary = 'EvtxECmd\\EvtxECmd.exe'
    for file in file_list:
        command_string = evtx_binary + f' -f "{file}" --csv storage --maps "EvtxECmd\\Maps"'
        try:
            subprocess.run(command_string, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error Executing: {command_string}")
            print(e)


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

def main():
    print("WINGRAPH - Event Log Graph Visualizer")
    arguments = parse_args()
    config = read_config('config.yml')
    update_evtxecmd()
    path_create()
    if 'evidence_directory' in arguments:
        file_list = event_log_list(arguments['evidence_directory'])
        if not 'parsed_logs' in arguments:
            parse_logs(file_list)
            log_files = get_parsed_list('storage')
        else:
            log_files = get_parsed_list(arguments['parsed_logs'])






main()