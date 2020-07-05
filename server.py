#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import sys
import re
import struct
import logging
from thread import start_new_thread
from binascii import unhexlify


HOST = 'localhost'
PORT = 5430

RESP_DUMMY_HEADER = b'T\x00\x00\x00\x2e\x00\x01\x00\x00\x00\x00?column?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\xff\xff\x00\x01\x00\x00\x00\x00\x00\x09\x00\x00'


def str_datagram(data):
    s = ''
    for b in data:
        if 32 <= ord(b) <= 126:
            s += str(b)
        else:
            s += "\\" + str(ord(b))
    return s


def int_to_bytes(val, endianness='big'):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)

    fmt = '%%0%dx' % (width // 4)
    s = unhexlify(fmt % val)
    if endianness == 'little':
        s = s[::-1]
    return s.rjust(4, '\x00')


def recv_exact(conn, sz):
    data = conn.recv(sz)
    while len(data) < sz:
        data = data + conn.recv(sz - len(data))
    return data


def read_msg(conn):
    data = recv_exact(conn, 4)
    sz = struct.unpack(">I", data[0:4])[0]
    if sz > 4:
        return recv_exact(conn, sz - 4)
    else:
        return ''


def probe_msg(conn):
    data = conn.recv(1)
    return data[0]


def client_thread(conn):
    data = read_msg(conn)
    if data == b'\x04\xd2\x16\x2f':
        logging.info('ssl request')
        conn.sendall('N')
        data = read_msg(conn)
    logging.info('request: ' + str_datagram(data))

    server_version = b'server_version\x00v9.2.0-7\x00'
    protocol_version = b'protocol_version\x00196616\x00'

    conn.sendall(b'R\x00\x00\x00\x08\x00\x00\x00\x00')  # auth ok
    conn.sendall(b'S' + int_to_bytes(4 + len(server_version)) + server_version)
    conn.sendall(b'S' + int_to_bytes(4 + len(protocol_version)) + protocol_version)
    conn.sendall(b'K\x00\x00\x00\x0c\xff\xff\xff\xff\xff\xff\xff\xff')  # backend pid+secret
    conn.sendall(b'Z\x00\x00\x00\x05I')  # ready to serve

    pending = list()

    while True:
        msg_type = probe_msg(conn)

        if msg_type == 'X':
            logging.info('terminate')
            break

        elif msg_type == 'S':
            read_msg(conn)
            pending.append(b'Z\x00\x00\x00\x05I')
            conn.sendall(''.join(pending))
            pending = list()

        elif msg_type == 'H':
            read_msg(conn)
            conn.sendall(''.join(pending))
            pending = list()

        elif msg_type == 'Q':
            data = read_msg(conn)
            q = unicode(data).strip().strip('\x00')
            logging.info('query: ' + q)

            desc = q.split()[0].upper() + '\x00'
            out, err = execute(q)

            if err:
                resp_err = b'SERROR\x00C22000\x00M' + err + '\x00\x00'
                conn.sendall(b'E' + int_to_bytes(4 + len(resp_err)) + resp_err)
            elif out:
                resp = b'\x00\x01' + int_to_bytes(len(out)) + out
                conn.sendall(RESP_DUMMY_HEADER)
                conn.sendall(b'D' + int_to_bytes(4 + len(resp)) + resp)
                conn.sendall(b'C' + int_to_bytes(4 + len(desc)) + desc)  # comand complete
            else:
                conn.sendall(b'C' + int_to_bytes(4 + len(desc)) + desc)  # comand complete

            conn.sendall(b'Z\x00\x00\x00\x05I')

        elif msg_type == 'P':
            data = read_msg(conn)
            args = data.split('\x00')

            n = unicode(args[0]).strip()
            q = unicode(args[1]).strip()
            logging.info('prepare %s: %s' % (n, q))

            if not n:
                # 2-phase anon prepare
                pending.append(b'm\x00\x00\x00\x0eSELECT\x00\x00\x00\x00')  # describe query
                pending.append(b'1\x00\x00\x00\x04')

            else:
                # 3-phase named prepare
                pending.append(b'1\x00\x00\x00\x04')
                extended_phase = msg_type

                while True:
                    msg_type = probe_msg(conn)

                    if msg_type in ('S', 'H'):
                        read_msg(conn)
                        if msg_type == 'S':
                            pending.append(b'Z\x00\x00\x00\x05I')
                        conn.sendall(''.join(pending))
                        pending = list()

                    elif msg_type == 'D' and extended_phase == 'P':
                        data = read_msg(conn)
                        args = data.split('\x00')
                        logging.info('describe %s' % args[0])

                        pending.append(b't\x00\x00\x00\x06\x00\x00')  # bind parameter data types
                        pending.append(RESP_DUMMY_HEADER)  # describe columns
                        pending.append(b'm\x00\x00\x00\x0eSELECT\x00\x00\x00\x00')  # describe query

                    elif msg_type == 'D' and extended_phase == 'B':
                        read_msg(conn)
                        logging.info('describe')

                        pending.append(RESP_DUMMY_HEADER)  # describe columns

                    elif msg_type == 'B':
                        data = read_msg(conn)
                        args = data.split('\x00')
                        logging.info('bind %s' % args[0])

                        pending.append(b'2\x00\x00\x00\x04')
                        extended_phase = msg_type

                    elif msg_type == 'E':
                        read_msg(conn)
                        logging.info('execute')

                        out, err = execute(q)

                        if err:
                            resp_err = b'SERROR\x00C22V23\x00V7137\x00M' + err + '\x00\x00'
                            pending.append(b'E' + int_to_bytes(4 + len(resp_err)) + resp_err)

                        elif out:
                            resp = b'\x00\x01' + int_to_bytes(len(err or out)) + (err or out)
                            pending.append(b'D' + int_to_bytes(4 + len(resp)) + resp)
                            pending.append(b's\x00\x00\x00\x04')

                    elif msg_type == 'C':
                        data = read_msg(conn)
                        args = data.split('\x00')
                        logging.info('close %s' % args[0])

                        pending.append(b'3\x00\x00\x00\x04')
                        break

                    else:
                        logging.warning('unexpected message inside named prepare: %s' % msg_type)
                        break

        else:
            logging.warning('request type %s not supported' % msg_type)
            read_msg(conn)

    conn.close()


def execute(query):
    return 'not supported\x00', None


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    logging.info('Socket created')
    try:
        s.bind((HOST, PORT))
        logging.info('Socket bind complete')
    except socket.error as msg:
        logging.error('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    s.listen(50)
    logging.info('Socket now listening')

    while True:
        conn, addr = s.accept()
        logging.info('Connected with ' + addr[0] + ':' + str(addr[1]))
        start_new_thread(client_thread, (conn,))

    s.close()
