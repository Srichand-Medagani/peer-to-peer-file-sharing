import os
import sys
import json
import random
import time
from socket import *
from threading import *
from simple_chalk import chalk
from cryptography.fernet import Fernet

curr_path = os.path.dirname(os.path.realpath(__file__))

IP = 'localhost'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 and int(sys.argv[1]) else 8080

REPLICATION_FACTOR = 3

pre_agreed_key = b'Z4-L_1FMlhMiHJgNtI5hCyry2nV6-brcEW2lOsFZ7K8='
fernet_enc_dec = Fernet(pre_agreed_key)

s_sock = socket(AF_INET, SOCK_STREAM)
s_sock.bind((IP, PORT))
s_sock.listen(5)
print('CDS is running... IP: {0} PORT: {1}'.format(IP, PORT))

peer_count = 0
'''
    active_peers - stores metadata related to peers such as IP address, port number
'''
active_peers = {}
'''
    filesystem_metadata - used to store info such as file name, owner,
        access previleges, delete flag.
'''
fs_metadata = {}

'''
    converts a python dictionary to an encrypted text
    dictionary -> json -> encode -> cipher
'''
def encrypt_pipeline(json_obj):
    cipher = fernet_enc_dec.encrypt(json.dumps(json_obj).encode('ascii'))
    return cipher

'''
    converts a cipher text to a python dictionary
    cipher -> decode -> json -> dictionary
'''
def decrypt_pipeline(cipher):
    dictionary = json.loads(fernet_enc_dec.decrypt(cipher).decode('ascii'))
    return dictionary

def dump_json_data(file_content, path):
    path = os.path.join(curr_path, path)
    with open(path, "w") as write_file:
        json.dump(file_content, write_file, indent=4)

peer_credentials_db = {}

with open(os.path.join(curr_path, 'peer_credentials_db.txt'), 'rb') as file:
    peer_credentials_db = decrypt_pipeline(file.read())

def select_n_nonrepititive_peers(n = REPLICATION_FACTOR):
    n = len(active_peers) if n > len(active_peers) else n
    nonrepititive_random_selection_index = random.sample(range(0, len(active_peers)), n)
    active_peers_ids = list(active_peers.keys())
    replicated_peers = []

    for index in nonrepititive_random_selection_index:
        replicated_peers.append(active_peers_ids[index])

    return replicated_peers

def process_peer_request(peer_sock, address):
    login_request = decrypt_pipeline(peer_sock.recv(1024))

    while True:
        username = login_request['username']
        password = login_request['password']

        if username in peer_credentials_db and peer_credentials_db[username] == password:
            response = encrypt_pipeline({
                'payload': 'Login successful!'
            })
            peer_sock.send(response)
            break
        else:
            response = encrypt_pipeline({
                'error': 401,
                'payload': 'Username & Password combination doesn\'t exist'
            })
            peer_sock.send(response)
        login_request = decrypt_pipeline(peer_sock.recv(1024))

    global peer_count
    peer_count += 1
    peer_id = 'peer_{0}'.format(peer_count)

    peer_details = decrypt_pipeline(peer_sock.recv(1024))
    peer_sock.send(encrypt_pipeline({
        'message': 'Peer {0}, You are now connected to CDS!'.format(peer_count),
        'peer_id': peer_id
    }))
    active_peers[peer_id] = {
        'IP': peer_details['IP'],
        'PORT': peer_details['PORT']
    }
    dump_json_data(active_peers, 'active_peers.json')
    dump_json_data(fs_metadata, 'fs_metadata.json')
    cmd = ''

    while cmd != '<quit>':
        peer_request = decrypt_pipeline(peer_sock.recv(1024))
        cmd = peer_request['cmd']
        if not cmd:
            break
        cmd_parsed = cmd.split()

        if cmd_parsed[0] == 'touch':
            response = {}
            if cmd_parsed[1] in fs_metadata:
                response = {
                    'error': 400,
                    'payload': '{0} already exists in the system'.format(cmd_parsed[1])
                }
            else:
                fs_metadata[cmd_parsed[1]] = {
                    'owner': peer_id,
                    'permissions': cmd_parsed[2],
                    'replicated_peers': select_n_nonrepititive_peers(),
                    'encryption_key': str(Fernet.generate_key()),
                    'write_in_progress': 'false',
                    'deleted': 'false',
                    'is_directory': 'false'
                }
                dump_json_data(fs_metadata, 'fs_metadata.json')
                for key, values in active_peers.items():
                    if key != peer_id:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'mkdir':
            response = {}
            if cmd_parsed[1] in fs_metadata:
                response = {
                    'error': 400,
                    'payload': '{0} already exists in the system'.format(cmd_parsed[1])
                }
            else:
                fs_metadata[cmd_parsed[1]] = {
                    'owner': peer_id,
                    'permissions': cmd_parsed[2],
                    'replicated_peers': [process for process in active_peers.keys()],
                    'deleted': 'false',
                    'encryption_key': str(Fernet.generate_key()),
                    'is_directory': 'true'
                }
                dump_json_data(fs_metadata, 'fs_metadata.json')
                for key, values in active_peers.items():
                    if key != peer_id:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'rmdir':
            response = {}
            if cmd_parsed[1] not in fs_metadata or fs_metadata[cmd_parsed[1]]['deleted'] == 'true':
                response = {
                    'error': 404,
                    'payload': 'folder: {0} not found!'.format(cmd_parsed[1])
                }
            else:
                fs_metadata[cmd_parsed[1]]['deleted'] = 'true'
                dump_json_data(fs_metadata, 'fs_metadata.json')
                for key, values in active_peers.items():
                    if key != peer_id:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'cat':
            response = {}
            if cmd_parsed[1] not in fs_metadata:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
                peer_sock.send(encrypt_pipeline(response))
                continue
            else:
                # fetch file metadata
                metadata = fs_metadata[cmd_parsed[1]]
                has_access = peer_id == metadata['owner'] or int(metadata['permissions']) == 1

                if fs_metadata[cmd_parsed[1]]['deleted'] == 'true':
                    response = {
                        'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                        'error': 404
                    }
                elif metadata['is_directory'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is a directory'.format(cmd_parsed[1])
                    }
                elif has_access:
                    response['encryption_key'] = metadata['encryption_key']
                    response['replicated_peer_info'] = {}
                    replicated_peers = metadata['replicated_peers']
                    for replicated_peer in replicated_peers:
                        if replicated_peer != peer_id:
                            response['replicated_peer_info'][replicated_peer] = active_peers[replicated_peer]
                    fs_metadata[cmd_parsed[1]]['write_in_progress'] = 'true'
                else:
                    response = {
                        'payload': '{0} does not have permission to access {1}'.format(peer_id, cmd_parsed[1]),
                        'error': 401
                    }
                dump_json_data(fs_metadata, 'fs_metadata.json')
                peer_sock.send(encrypt_pipeline(response))
                peer_response = decrypt_pipeline(peer_sock.recv(1024))
                if peer_response['payload'] == 'WRITE_ACK':
                    fs_metadata[cmd_parsed[1]]['write_in_progress'] = 'false'
                dump_json_data(fs_metadata, 'fs_metadata.json')
        elif cmd_parsed[0] == 'read':
            response = {}
            if cmd_parsed[1] not in fs_metadata:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                # fetch file metadata
                metadata = fs_metadata[cmd_parsed[1]]
                if 'deleted' in metadata and metadata['deleted'] == 'true':
                    if metadata['owner'] == peer_id:
                        response = {
                            'error': 401,
                            'payload': 'file: {0} is deleted\nRun `restore [filename]` to restore the file'.format(cmd_parsed[1])
                        }
                    else:
                        response = {
                            'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                            'error': 404
                        }
                elif metadata['is_directory'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is a directory'.format(cmd_parsed[1])
                    }
                elif metadata['write_in_progress'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is being accessed currently'.format(cmd_parsed[1])
                    }
                else:
                    # unless the file is access restricted(3), when only the owner can access
                    has_access = peer_id == metadata['owner'] or int(metadata['permissions']) != 3
                    if has_access:
                        response['encryption_key'] = metadata['encryption_key']
                        replicated_peers = metadata['replicated_peers']
                        response['replicated_peer_info'] = {}
                        for replicated_peer in replicated_peers:
                            response['replicated_peer_info'][replicated_peer] = active_peers[replicated_peer]
                    else:
                        response = {
                            'payload': '{0} does not have permission to access {1}'.format(peer_id, cmd_parsed[1]),
                            'error': 401
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'rm':
            response = {}
            if cmd_parsed[1] not in fs_metadata:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                # fetch file metadata
                metadata = fs_metadata[cmd_parsed[1]]
                # unless the file is access restricted(3), when only the owner can delete
                has_access = peer_id == metadata['owner']
                if metadata['write_in_progress'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is being accessed currently'.format(cmd_parsed[1])
                    }
                elif not has_access:
                    response = {
                        'payload': '{0} does not have permission to delete {1}'.format(peer_id, cmd_parsed[1]),
                        'error': 401
                    }
                elif metadata['deleted'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is deleted already'.format(cmd_parsed[1])
                    }
                else:
                    fs_metadata[cmd_parsed[1]]['deleted'] = 'true'
                    request = encrypt_pipeline({
                        'cmd': cmd
                    })

                    deleted_in_peers = []
                    for peer in metadata['replicated_peers']:
                        # Donot delete the file in the owner
                        if peer != metadata['owner']:
                            peer_details = active_peers[peer]
                            peer_IP = peer_details['IP']
                            peer_PORT = peer_details['PORT']
                            print('Connecting to {0}... {1}:{2}'.format(peer, peer_IP, peer_PORT))
                            rep_peer_sock = socket(AF_INET, SOCK_STREAM)
                            rep_peer_sock.connect((peer_IP, int(peer_PORT)))
                            rep_peer_sock.send(request)
                            rep_peer_response = decrypt_pipeline(rep_peer_sock.recv(1024))
                            if 'error' in rep_peer_response:
                                print(rep_peer_response['payload'])
                            else:
                                deleted_in_peers.append(peer)
                                print(rep_peer_response['payload'])
                            print()
                    response = {
                        'payload': '{0} deleted successfully accross {1}.'.format(cmd_parsed[1], deleted_in_peers)
                    }
                    for peer in deleted_in_peers:
                        fs_metadata[cmd_parsed[1]]['replicated_peers'].remove(peer)
                    dump_json_data(fs_metadata, 'fs_metadata.json')
            print(response)
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'restore':
            response = {}
            if cmd_parsed[1] not in fs_metadata:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                metadata = fs_metadata[cmd_parsed[1]]
                if 'deleted' in metadata and metadata['deleted'] != "true":
                    response = {
                        'payload': 'file: {0} does not exists in the bin'.format(cmd_parsed[1]),
                        'error': 400
                    }
                elif metadata['owner'] != peer_id:
                    response = {
                        'payload': 'file: {0} can be restored only by the owner'.format(cmd_parsed[1]),
                        'error': 403
                    }
                else:
                    # send peers where replication should occur, set deleted to false
                    response['peers_to_replicate'] = []
                    for peer in select_n_nonrepititive_peers():
                        fs_metadata[cmd_parsed[1]]['replicated_peers'].append(peer)
                        response['peers_to_replicate'].append({
                            "IP": active_peers[peer]["IP"],
                            "PORT": active_peers[peer]["PORT"]
                        })
                    response['payload'] = 'SIG_REPLICATE'
                fs_metadata[cmd_parsed[1]]['deleted'] = 'false'
                peer_sock.send(encrypt_pipeline(response))
                dump_json_data(fs_metadata, 'fs_metadata.json')
        elif cmd_parsed[0] == 'ls':
            response = {
                'payload': []
            }
            for key, value in fs_metadata.items():
                line = ''

                # if file is restricted, or deleted and owner is not the current peer, do not show the file
                if (value['permissions'] == "3" or value['deleted'] == 'true') and value['owner'] != peer_id:
                    continue

                file_name = key

                line += 'd' if value['is_directory'] == 'true' else '-'
                line += ' '

                if value['permissions'] == '1':
                    line += 'r/w'
                elif value['permissions'] == '2':
                    line += 'r/w' if value['owner'] == peer_id else 'r'
                else:
                    line += 'r*'
                line += ' '

                line += file_name
                response['payload'].append(line)
            print(response)
            peer_sock.send(encrypt_pipeline(response))
    print(peer_id, 'is disconnected!')
    # remove peer info
    active_peers.pop(peer_id, None)
    dump_json_data(active_peers, 'active_peers.json')

def malicious_activity_checker():
    request = {
        'cmd': 'FILE_LISTING_RQST'
    }
    while True:
        time.sleep(150)
        for peer, value in active_peers.items():
            print('Checking for malicious activity in {0}'.format(peer))
            peer_IP = value['IP']
            peer_PORT = value['PORT']
            peer_sock = socket(AF_INET, SOCK_STREAM)
            peer_sock.connect((peer_IP, int(peer_PORT)))
            peer_sock.send(encrypt_pipeline(request))
            peer_response = decrypt_pipeline(peer_sock.recv(1024))
            print(peer_response)
            red_flag = False

            # check for maliciously deleted files
            for key, value in fs_metadata.items():
                if red_flag:
                    break
                if 'deleted' not in value or ('deleted' in value and value['deleted'] != 'true'):
                    if key not in peer_response['file_list']:
                        red_flag = True

                elif value['owner'] != peer_response['peer_id']:
                    red_flag = True

            # check for maliciously added files
            for file in peer_response['file_list']:
                if red_flag:
                    break
                if file not in fs_metadata:
                    red_flag = True

            if red_flag:
                print('{0} has been compromised'.format(peer_response['peer_id']))
        print()

def register_peer():
    while True:
        inp = input()
        inp_parsed = inp.split()

        if len(inp_parsed) == 2:
            [username, password] = inp_parsed
            peer_credentials_db[username] = password
            print('Peer registered')

def main():
    # malicious_activity_checker_thread = Thread(target = malicious_activity_checker)
    # malicious_activity_checker_thread.start()

    peer_registration_thread = Thread(target = register_peer)
    peer_registration_thread.start()

    while True:
        peer_sock, address = s_sock.accept()
        peer_request_processor_thread = Thread(target = process_peer_request, args=(peer_sock, address))
        peer_request_processor_thread.setDaemon(True)
        peer_request_processor_thread.start()

if __name__ == '__main__':
    main()

s_sock.close()