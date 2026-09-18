import scapy.all as scapy
import optparse
import socket

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP Range (e.g. 192.168.1.1/24)")
    parser.add_option("--find_gateway_ip", action="store_true", dest="find_gateway", help="Find and see the IP address of the default gateway.")
    
    (options, arguments) = parser.parse_args()
    if not options.target and not options.find_gateway:
        parser.print_help()
        exit()
    return options

def get_gateway_ip():
    try:
        return scapy.conf.route.route("0.0.0.0")[2]
    except Exception:
        return None

def get_hostname(ip):
    """Attempts to resolve an IP to a hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        return "Unknown vendor/hostname"

def scan(ip):
    # Create ARP Request
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    client_list = []
    for element in answered_list:
        received_packet = element[1]
        client_dict = {
            "ip": received_packet.psrc,
            "mac": received_packet.hwsrc,
            "len": len(received_packet), # Length of the packet
            "count": 1,                   # In a single scan, count is typically 1
            "hostname": get_hostname(received_packet.psrc)
        }
        client_list.append(client_dict)
    return client_list

def print_result(results_list, target):
    print("\nCurrently scanning: Finished!   |   Screen View: Unique Hosts")
    print(f"{len(results_list)} Captured ARP Req/Rep packets, from {len(results_list)} hosts.")
    
    total_size = sum(item['len'] for item in results_list)
    print(f"Total size: {total_size}")
    
    print("\n   IP\t\t      At MAC Address\t Count     Len    MAC Vendor / Hostname")
    print("-----------------------------------------------------------------------------------")
    
    for client in results_list:
        print(f"{client['ip']:<15}\t{client['mac']:<17}    {client['count']:<5}      {client['len']:<5}  {client['hostname']}")

options = get_arguments()

if options.find_gateway:
    gateway_ip = get_gateway_ip()
    if gateway_ip:
        print(f"\n[+] Gateway IP: {gateway_ip}")
    else:
        print("[-] Couldn't find default gateway's IP.")

if options.target:
    print(f"\n[*] Scanning target: {options.target}")
    scan_results = scan(options.target)
    print_result(scan_results, options.target)