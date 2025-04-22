import socket
import struct
import datetime
import sys
import argparse
from collections import defaultdict

class EnhancedSniffer:
    def __init__(self, show_payload=False, resolve_dns=False, output_file=None):
        self.show_payload = show_payload
        self.resolve_dns = resolve_dns
        self.output_file = output_file
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.start_time = datetime.datetime.now()
        
        # ANSI color codes
        self.COLORS = {
            'TCP': '\033[94m',    # Blue
            'UDP': '\033[92m',    # Green
            'ICMP': '\033[91m',    # Red
            'OTHER': '\033[93m',  # Yellow
            'RESET': '\033[0m'
        }

    def resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ip

    def parse_packet(self, raw_packet):
        ip_header = raw_packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        
        # Protocol mapping
        protocol_name = {1:'ICMP', 6:'TCP', 17:'UDP'}.get(protocol, 'OTHER')
        self.protocol_stats[protocol_name] += 1
        
        # Transport layer parsing
        src_port = dst_port = payload = ''
        data_offset = (iph[0] & 0xF) * 4
        
        if protocol == 6 and len(raw_packet) > data_offset:  # TCP
            tcp_header = raw_packet[data_offset:data_offset+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcph[0]
            dst_port = tcph[1]
            
        elif protocol == 17 and len(raw_packet) > data_offset:  # UDP
            udp_header = raw_packet[data_offset:data_offset+8]
            udph = struct.unpack('!HHHH', udp_header)
            src_port = udph[0]
            dst_port = udph[1]
            
        # Payload extraction
        if self.show_payload and len(raw_packet) > data_offset:
            payload = raw_packet[data_offset:]
            payload = ' '.join(f'{b:02x}' for b in payload[:16]) + ('...' if len(payload) > 16 else '')
            
        return {
            'timestamp': datetime.datetime.now(),
            'protocol': protocol_name,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'payload': payload
        }

    def display_packet(self, packet_info):
        color = self.COLORS.get(packet_info['protocol'], self.COLORS['OTHER'])
        
        if self.resolve_dns:
            src_host = self.resolve_hostname(packet_info['src_ip'])
            dst_host = self.resolve_hostname(packet_info['dst_ip'])
        else:
            src_host = packet_info['src_ip']
            dst_host = packet_info['dst_ip']
            
        output = [
            f"{packet_info['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')}",
            f"{color}{packet_info['protocol']}{self.COLORS['RESET']}",
            f"{src_host}:{packet_info['src_port']} -> {dst_host}:{packet_info['dst_port']}"
        ]
        
        if self.show_payload:
            output.append(f"Payload: {packet_info['payload']}")
            
        print(' | '.join(output))
        
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(' | '.join(output) + '\n')

    def show_stats(self):
        duration = datetime.datetime.now() - self.start_time
        print("\n\n=== Sniffer Statistics ===")
        print(f"Duration: {duration}")
        print(f"Total packets: {self.packet_count}")
        print("Protocol breakdown:")
        for proto, count in self.protocol_stats.items():
            print(f"  {proto}: {count}")
        print("========================")

    def start(self):
        try:
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            host_ip = socket.gethostbyname(socket.gethostname())
            sniffer.bind((host_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            print(f"Enhanced Sniffer started at {self.start_time}")
            print("Press CTRL+C to stop...\n")

            while True:
                raw_packet = sniffer.recvfrom(65535)[0]
                packet_info = self.parse_packet(raw_packet)
                self.display_packet(packet_info)
                self.packet_count += 1

        except PermissionError:
            print("ERROR: Must run as Administrator!")
            sys.exit(1)
        except KeyboardInterrupt:
            self.show_stats()
        finally:
            if 'sniffer' in locals():
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sniffer.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enhanced Network Sniffer')
    parser.add_argument('-p', '--payload', action='store_true', help='Show packet payload')
    parser.add_argument('-d', '--dns', action='store_true', help='Resolve DNS names')
    parser.add_argument('-o', '--output', help='Save output to file')
    args = parser.parse_args()

    sniffer = EnhancedSniffer(
        show_payload=args.payload,
        resolve_dns=args.dns,
        output_file=args.output
    )
    sniffer.start()