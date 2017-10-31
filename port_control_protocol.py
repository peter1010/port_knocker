#!/usr/bin/env python3

import os
import sys
import socket
import struct
import ipaddress

#Opcodes as per RFC6887
ANNOUNCE = 0
MAP = 1
PEER = 2

_V0_MAP_UDP = 1
_V0_MAP_TCP = 2


#Results as per RFC6887
SUCCESS = 0
UNSUPP_VERSION = 1
NOT_AUTHORIZED = 2
MALFORMED_REQUEST = 3
UNSUPP_OPCODE = 4
UNSUPP_OPTION = 5
MALFORMED_OPTION = 6
NETWORK_FAILURE = 7
NO_RESOURCES = 8
UNSUPP_PROTOCOL = 9
USER_EX_QUOTA = 10
CANNOT_PROVIDE_EXTERNAL = 11
ADDRESS_MISMATCH = 12
EXCESSIVE_REMOTE_PEERS = 13

_V0_NETWORK_FAILURE = 3
_V0_NO_RESOURCES = 4
_V0_UNSUPP_OPCODE = 5

TCP = 6
UDP = 17

class PCPMessage:

    @property
    def version(self):
        return self._msg[0]

    @property
    def opcode(self):
        raw_opcode = self._msg[1] & 0x7F
        if (self.version == 0) and (raw_opcode in (_V0_MAP_UDP, _V0_MAP_TCP)):
            # Convert V0 opcodes to V2
            return MAP
        else:
            return raw_opcode

    @property
    def lifetime(self):
        if self.version == 0:
            if self.opcode == MAP:
                idx = 8
            else:
                return None
        else:
            idx = 4
        return struct.unpack(">L", self._msg[idx:idx+4])[0]

    @property
    def internal_port(self):
        if self.opcode in (MAP, PEER):
            if self.version == 0:
                idx = 4
            else:
                idx = 40
            return struct.unpack(">H", data._msg[idx:idx+2])[0]
        else:
            return None
            
    @property
    def external_port(self):
        if self.opcode in (MAP, PEER):
            if self.version == 0:
                idx = 6
            else:
                idx = 42
            return struct.unpack(">H", data._msg[idx:idx+2])[0]
        else:
            return None

    @property
    def protocol(self):
        if self.version == 0:
            raw_opcode = self._msg[1] & 0x7F
            if raw_opcode == _V0_MAP_UDP:
                return UDP
            elif raw_opcode == _V0_MAP_TCP:
                return TCP
            return None
        elif self.opcode == MAP:
            return self._msg[36]
        else:
            return None

    @property
    def remote_peer_port(self):
        if self.opcode == PEER:
            return struct.unpack(">H", data._msg[60:62])[0]
        return None

    @property
    def remote_peer_ip(self):
        if self.opcode == PEER:
            address = self._msg[64:80]
            return ipaddress.ip_address(address)
        return None


class PCPResponse(PCPMessage):

    def __init__(self, msg):
        self._msg = msg

    def check_is_valid(self):
        if self.version not in (0,2):
            return False
        if (self._msg[1] & 0x80) != 0x80:
            return False
        if self.opcode not in (ANNOUNCE, MAP, PEER):
            return False
        return True

    @property
    def result_code(self):
        if self.version == 0:
            result = struct.unpack(">H", self._msg[2:4])[0]
            if result == _V0_NETWORK_FAILURE:
                return NETWORK_FAILURE
            if result == _V0_NO_RESOURCES:
                return NO_RESOURCES
            if result == _V0_UNSUPP_OPCODE:
                return UNSUPP_OPCODE
            return result
        else:
            return self._msg[3]

    @property
    def epoch(self):
        if self.version == 0:
            idx = 4
        else:
            idx = 8
        return struct.unpack(">L", self._msg[idx:idx+4])[0]

    @property
    def external_ip(self):
        if self.version == 0:
            if self.opcode == ANNOUNCE:
                idx = 8
                size = 4
            else:
                return None
        elif self.opcode in (MAP, PEER):
            idx = 44
            size = 16
        else:
            return None
        return ipaddress.ip_address(self._msg[idx:idx+size])
        


class PCPRequest(PCPMessage):

    def __init__(self, version, opcode):
        if version == 0:
            if opcode not in (ANNOUNCE, MAP):
                raise NotImplemented
        elif version == 2:
            if opcode not in (ANNOUNCE, MAP, PEER):
                raise NotImplemented
        else:
            raise NotImplemented
        self._msg = bytes((version, opcode))

    def check_is_valid(self):
        if self.version not in (0,2):
            return False
        if (self._msg[1] & 0x80) == 0x80:
            return False
        if self.opcode not in (ANNOUNCE, MAP, PEER):
            return False
        return True

    def update_contents(self, idx, data):
        if not isinstance(data, bytes):
            data = bytes((data,))
        diff = len(self._msg) - idx
        if diff < 0:
            self._msg = self._msg + bytes((0,) * -diff)
        self._msg = self._msg[:idx] + data + self._msg[idx+len(data):]


    def add_lifetime(self, lifetime):
        if self.version == 0:
            if self.opcode == MAP:
                idx = 8
            else:
                raise NotImplemented
        else:
            idx = 4
        self.update_contents(idx, struct.pack(">L", lifetime))

    def add_our_ip(self, ip_addr):
        if self.version == 2:
            _bytes = ip_addr.packed
            if len(_bytes) < 16:
                _bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF" + _bytes
            self.update_contents(8, struct.pack(">16s", _bytes))

    def add_protocol(self, protocol):
        if self.opcode in (MAP, PEER):
            if self.version == 0:
                if protocol == UDP:
                    self.update_contents(1, _V0_MAP_UDP)
                elif protocol == TCP:
                    self.update_contents(1, _V0_MAP_TCP)
                else:
                    raise NotImplemented
            else:
                self.update_contents(36, protocol)
        else:
            raise NotImplemented

    def add_suggested_external_port(self, port):
        if self.opcode in (MAP, PEER):
            if self.version == 0:
                idx = 6
            else:
                idx = 42
            self.update_contents(idx, struct.pack(">H", port))
        else:
            raise NotImplemented

    def add_internal_port(self, port):
        if self.opcode in (MAP, PEER):
            if self.version == 0:
                idx = 4
            else:
                idx = 40
            self.update_contents(idx, struct.pack(">H", port))
        else:
            raise NotImplemented


    @property
    def message(self):
        if self.version == 0:
            if self.opcode == ANNOUNCE:
                minLen = 2
            elif self.opcode == MAP:
                minLen = 12
            else:
                raise NotImplemented
        else:
            if self.opcode == ANNOUNCE:
                minLen = 24
            elif self.opcode == MAP:
                minLen = 24 + 36
            elif self.opcode == PEER:
                minLen = 24 + 36 + 20
            else:
                raise NotImplemented
        diff = len(self._msg) - minLen
        if diff < 0:
            self._msg = self._msg + bytes((0,) * -diff)
        return self._msg
        


class PortControlProtocol:

    def __init__(self):
        self._pcp_version = 2

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect(("192.168.1.1", 5351))
        address, port = self.sock.getsockname()
        self._our_address = ipaddress.ip_address(address)


    def request_external_ip(self):
        Request = PCPRequest(self._pcp_version, ANNOUNCE)
        Request.add_our_ip(self._our_address)
        self.sock.sendall(Request.message)
        data = PCPResponse(self.sock.recv(512))
        if data.check_is_valid():
            if data.result_code == UNSUPP_VERSION:
                self._pcp_version = data.version
                return self.request_external_ip()
            elif data.result_code == SUCCESS:
                return data.external_ip
            else:
                print (data.result_code)

    def request_map(self):
        Request = PCPRequest(self._pcp_version, MAP)
        print(Request.message)
        Request.add_our_ip(self._our_address)
        print(Request.message)
        Request.add_protocol(TCP)
        print(Request.message)
        Request.add_suggested_external_port(8080)
        print(Request.message)
        Request.add_internal_port(80)
        print(Request.message)
        Request.add_lifetime(7200)
        print(Request.message)
        self.sock.sendall(Request.message)
        data = PCPResponse(self.sock.recv(512))
        if data.check_is_valid():
            if data.result_code == UNSUPP_VERSION:
                self._pcp_version = data.version
                return self.request_map()
            elif data.result_code == SUCCESS:
                return data.external_ip
            else:
                print ("result", data.result_code)


        pass

def main():
    app = PortControlProtocol()
    app.connect()
    print(app.request_external_ip())
    app.request_map()

if __name__ == "__main__":
    main()
