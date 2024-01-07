import socket
import struct
import time
import threading

import request_pb2 as request
import response_pb2 as response

HOST = "192.168.1.77"
PORT = 58680


def tx_command(sock, command):
    tx_data = command.SerializeToString()
    tx_data = struct.pack('<I', len(tx_data) | 0x80000000) + tx_data
    sock.sendall(tx_data)

    rx_data = sock.recv(1024)
    if len(rx_data) == 0:
        raise Exception("received no data")

    rx = response.VSPResponse()
    rx.ParseFromString(rx_data[4:])
    if rx.status != 0 or len(rx.message) > 0:
        raise Exception(rx.message)

    return rx


def heartbeat():
    print('Starting heartbeat loop..')
    i = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while 1:
            s.sendto(struct.pack('<I', i), (HOST, PORT))
            i += 1
            time.sleep(1)


def event_loop(cookie):
    print('Starting event loop..')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as event_sock:
        event_sock.connect((HOST, PORT))

        event_command = request.VSPRequest()
        event_command.ID = request.IDS.OPEN_EVENT
        event_command.open_event.cookie = cookie
        tx_command(event_sock, event_command)

        hb = threading.Thread(target=heartbeat)
        hb.start()

        while 1:
            event_data = event_sock.recv(1024)
            if len(event_data) == 0:
                continue
            event_resp = response.VSPResponse()
            event_resp.ParseFromString(event_data[4:])
            print("EVENT:", event_resp.message)


def recvall(sock, n):
    d = bytearray()
    while len(d) < n:
        packet = sock.recv(n - len(d))
        if not packet:
            return None
        d.extend(packet)
    return d


def data_loop(cookie):
    print('Starting data loop..')
    counter = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_sock:
        data_sock.connect((HOST, PORT))

        data_command = request.VSPRequest()
        data_command.ID = request.IDS.OPEN_DATA
        data_command.open_data.cookie = cookie
        tx_command(data_sock, data_command)

        while 1:
            raw_msglen = recvall(data_sock, 4)
            if not raw_msglen:
                return None
            msglen = struct.unpack('<I', raw_msglen)[0]
            print(f'Receiving {counter}.bin.. len:{msglen}')

            msgdata = recvall(data_sock, msglen)
            print(f'Received {counter}.bin! len:{len(msgdata)}')

            with open(f"{counter}.bin", "wb") as file:
                file.write(msgdata)
            counter += 1


command_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
command_sock.connect((HOST, PORT))

print('Connecting..')
command = request.VSPRequest()
command.ID = request.IDS.OPEN
command.open.CopyFrom(request.OPEN_RQ())

rsp = tx_command(command_sock, command)

event_thread = threading.Thread(target=event_loop, args=(rsp.open.cookie,))
event_thread.start()

data_thread = threading.Thread(target=data_loop, args=(rsp.open.cookie,))
data_thread.start()

time.sleep(1)

print('Loading userset..')
command = request.VSPRequest()
command.ID = request.IDS.USERSET_LOAD
command.userset_load.index = 2
command.userset_load.force = 1
tx_command(command_sock, command)

print('Enabling auto-trigger..')
command = request.VSPRequest()
command.ID = request.IDS.AUTO_TRIGGER
command.auto_trigger.threshold = 1024
command.auto_trigger.timeout = 0
tx_command(command_sock, command)

print('ACQUISITION START..')
command = request.VSPRequest()
command.ID = request.IDS.ACQUISITION
command.acquisition.operation = request.ACQUISITION_OPERATIONS.START
tx_command(command_sock, command)

print('ACQUISITION PREPARE..')
command = request.VSPRequest()
command.ID = request.IDS.ACQUISITION
command.acquisition.operation = request.ACQUISITION_OPERATIONS.PREPARE
tx_command(command_sock, command)

print('\r\nReady for exposure, toggle generator now')

# input("Press Enter to trigger...")
#
# print('ACQUISITION TRIGGER..')
# command = request.VSPRequest()
# command.ID = request.IDS.ACQUISITION
# command.acquisition.operation = request.ACQUISITION_OPERATIONS.TRIGGER
# tx_command(command_sock, command)
