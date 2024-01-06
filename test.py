import socket
import struct
import sys
import time
import threading

import request_pb2
import response_pb2

HOST = "192.168.1.77"
PORT = 58680

def heartbeat():
    i = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while 1:
            s.sendto(struct.pack('<I', i), (HOST, PORT))
            i += 1
            time.sleep(1)


def event_loop(secret):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as event_sock:
        event_sock.connect((HOST, PORT))

        event_req = request_pb2.VSPRequest()
        event_req.f1 = 4
        event_req.f4.f1 = secret
        event_req = event_req.SerializeToString()
        event_req = struct.pack('<I', len(event_req) | 0x80000000) + event_req
        event_sock.sendall(event_req)

        event_data = event_sock.recv(1024)
        if len(event_data) == 0:
            raise Exception("received no data")

        event_resp = response_pb2.VSPResponse()
        event_resp.ParseFromString(event_data[4:])
        print(event_resp)
        if len(event_resp.f2) > 0:
            raise Exception(event_resp.f2)

        hb = threading.Thread(target=heartbeat)
        hb.start()

        while 1:
            event_data = event_sock.recv(1024)
            if len(event_data) == 0:
                continue
            event_resp = response_pb2.VSPResponse()
            event_resp.ParseFromString(event_data[4:])
            print("EVENT:", event_resp)


def recvall(sock, n):
    d = bytearray()
    while len(d) < n:
        packet = sock.recv(n - len(d))
        if not packet:
            return None
        d.extend(packet)
    return d


def data_loop(secret):
    counter = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_sock:
        data_sock.connect((HOST, PORT))

        data_pkt = request_pb2.VSPRequest()
        data_pkt.f1 = 5
        data_pkt.f5.f1 = secret
        data_pkt = data_pkt.SerializeToString()
        data_pkt = struct.pack('<I', len(data_pkt) | 0x80000000) + data_pkt
        data_sock.sendall(data_pkt)

        data_data = data_sock.recv(1024)
        if len(data_data) == 0:
            raise Exception("received no data")

        data_resp = response_pb2.VSPResponse()
        data_resp.ParseFromString(data_data[4:])
        print(data_resp)
        if len(data_resp.f2) > 0:
            raise Exception(data_resp.f2)

        while 1:
            raw_msglen = recvall(data_sock, 4)
            if not raw_msglen:
                return None
            msglen = struct.unpack('<I', raw_msglen)[0]
            print(msglen)

            msgdata = recvall(data_sock, msglen)
            print(len(msgdata))

            with open(f"{counter}.bin", "wb") as file:
                file.write(msgdata)
            counter += 1



command_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
command_sock.connect((HOST, PORT))

pkt = request_pb2.VSPRequest()
pkt.f1 = 3
pkt.f3.CopyFrom(request_pb2.OPEN())
pkt = pkt.SerializeToString()
pkt = struct.pack('<I', len(pkt) | 0x80000000) + pkt
command_sock.sendall(pkt)

data = command_sock.recv(1024)
if len(data) == 0:
    raise Exception("received no data")

rsp = response_pb2.VSPResponse()
rsp.ParseFromString(data[4:])
print(rsp)
if len(rsp.f2) > 0:
    raise Exception(rsp.f2)

event_thread = threading.Thread(target=event_loop, args=(rsp.f3.f1,))
event_thread.start()

data_thread = threading.Thread(target=data_loop, args=(rsp.f3.f1,))
data_thread.start()

# pkt = request_pb2.VSPRequest()
# pkt.f1 = 15
# pkt.f15.f1 = 2 #CORRECTED FRAME
# pkt = pkt.SerializeToString()
# pkt = struct.pack('<I', len(pkt) | 0x80000000) + pkt
# command_sock.sendall(pkt)
#
# data = command_sock.recv(1024)

# if len(data) == 0:
#     raise Exception("received no data")
# rsp.ParseFromString(data[4:])
# print(rsp)

pkt = request_pb2.VSPRequest()
pkt.f1 = 14
pkt.f14.f1 = 1 #START
pkt = pkt.SerializeToString()
pkt = struct.pack('<I', len(pkt) | 0x80000000) + pkt
command_sock.sendall(pkt)

data = command_sock.recv(1024)
if len(data) == 0:
    raise Exception("received no data")
rsp.ParseFromString(data[4:])
print(rsp)


pkt = request_pb2.VSPRequest()
pkt.f1 = 14
pkt.f14.f1 = 3 #PREPARE
pkt = pkt.SerializeToString()
pkt = struct.pack('<I', len(pkt) | 0x80000000) + pkt
command_sock.sendall(pkt)

data = command_sock.recv(1024)
if len(data) == 0:
    raise Exception("received no data")
rsp.ParseFromString(data[4:])
print(rsp)

input("Press Enter to continue...")

pkt = request_pb2.VSPRequest()
pkt.f1 = 14
pkt.f14.f1 = 4 #TRIGGER
pkt = pkt.SerializeToString()
pkt = struct.pack('<I', len(pkt) | 0x80000000) + pkt
command_sock.sendall(pkt)

data = command_sock.recv(1024)
if len(data) == 0:
    raise Exception("received no data")
rsp.ParseFromString(data[4:])
print(rsp)
