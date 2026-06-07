import struct
from scapy.all import rdpcap, IP, TCP, Raw

def debug():
    # Global Header
    global_hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    # Ethernet + IP + TCP
    eth = b'\x00'*12 + b'\x08\x00'
    ip = b'\x45\x00\x00\x32\x12\x34\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02'
    tcp = b'\x04\xd2\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x18\x20\x00\x00\x00\x00\x00'
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n"
    pkt_data = eth + ip + tcp + payload
    # Packet Header (ts_sec, ts_usec, incl_len, orig_len)
    pkt_hdr = struct.pack('<IIII', 1717000000, 0, len(pkt_data), len(pkt_data))
    
    path = "test_debug.pcap"
    with open(path, "wb") as f:
        f.write(global_hdr + pkt_hdr + pkt_data)
        
    pkts = rdpcap(path)
    print("Total packets parsed:", len(pkts))
    for p in pkts:
        print("Layers:", p.summary())
        if p.haslayer(TCP):
            print("Has TCP layer")
        if p.haslayer(Raw):
            print("Has Raw layer, load:", p[Raw].load)
            
if __name__ == "__main__":
    debug()
