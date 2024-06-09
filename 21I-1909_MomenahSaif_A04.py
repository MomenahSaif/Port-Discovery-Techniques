import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Suppress scapy IPv6 warning
from scapy.all import *
import shutil
import nmap


def icmp_ping_scan(target):
    print("-----Performing ICMP Ping Scan------")
    icmp = IP(dst=target)/ICMP() # Craft ICMP packet with the target IP address
    resp = sr1(icmp, timeout=2, verbose=False)# Send the ICMP packet and wait for response
    if resp:                           # Check if response received
        print("ICMP Ping Scan Response:", resp.summary())
        if "echo-reply" in resp.summary():
            print("The host is reachable")
        else:
            print("The host is unreachable")
    else:
        print("No response")
    
def udp_ping_scan(target):
    print("-----Performing UDP Ping Scan------") 
    udp = IP(dst=target)/UDP(dport=0)
    resp = sr1(udp, timeout=2, verbose=False) # Send the UDP packet and wait for response
    if resp:  # Check if a response was received
        print("UDP Ping Scan Response:", resp.summary())
        if "SA" in resp.summary():# Check if SYN-ACK flag is present in the response summary
           print("The port is unfiltered (open)")
        elif "RA" in resp.summary(): # Check if RST-ACK flag is present in the response summary
              print("The port is filtered (closed)")
    else:
        print("No response")   
    
def tcp_syn_scan(target,port):
    print("-------Performing TCP SYN Scan-------")
    response = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=2, verbose=False)# Craft TCP SYN packet with the target IP address and specified port
    if response:
        print("TCP SYN Scan Response:", response.summary())# Print the summary of the received response
        if "SA" in response.summary():# Check if SYN-ACK flag is present in the response summary
           print("The port is unfiltered (open)")
        elif "RA" in response.summary():
              print("The port is filtered (closed)")
    else:
        print("No response")
    
    
def tcp_stealth_scan(target,port):
    print("-------Performing TCP Stealth Scan-------")
    stealth_resp = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=2, verbose=False)# Craft TCP SYN packet with the target IP address and specified port, send it and wait for a response
    if stealth_resp:
        if stealth_resp.getlayer(TCP).flags == 0x12: # SYN-ACK
            send_rst = sr(IP(dst=target)/TCP(dport=port, flags="R"), timeout=2, verbose=False)
            print("Port", port, "is open") # Print a message indicating the port is open
        elif stealth_resp.getlayer(TCP).flags == 0x14: # RST
            print("Port", port, "is closed")
    else:
        print("No response")
    
    
def inv_tcp_scan(target,port,flag):
    print("Performing Inverse TCP Flag Scan on", target, "port", port, "with", flag, "flag")    
    ip_packet = IP(dst=target) # Craft the IP packet    
    tcp_packet = TCP(dport=port, flags=flag)# Craft the TCP packet with specified flags    
    packet = ip_packet / tcp_packet# Combine the IP and TCP packets    
    response = sr1(packet, timeout=2, verbose=False)# Send the packet and receive the response    
    if response is not None:# Check the response
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x14:
                print(" The port is closed")                
            elif response.getlayer(TCP).flags == 0x12:
                print("The port is open")                
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                print("The port is filtered")                
    else:
        print("No response")
        
      
    
def ack_ttl_scan(target,port):
    print("-------Performing ACK FLag TTL Scan-------")  
    ack_resp = sr1(IP(dst=target)/TCP(dport=port, flags="A"), timeout=2, verbose=False)# Craft TCP ACK packet with the target IP address and specified port, send it and wait for a response
    if ack_resp:
        if ack_resp.getlayer(TCP).flags == 0x4: # # Check if the TCP flags in the response indicate RST
            print("Port", port, "is unfiltered")
        else:
            print("Port", port, "is filtered")
    else:
        print("No response")
         
def ack_windows_scan(target,port):
    print("-------Performing ACK Flag Windows Scan-------")  
    ack_resp = sr1(IP(dst=target)/TCP(dport=port, flags="A"), timeout=2, verbose=False)# Craft TCP ACK packet with the target IP address and specified port, send it and wait for a response
    if ack_resp:
        if ack_resp.getlayer(TCP).window == 0: # Zero window size
            print("Port", port, "is unfiltered")
        else:
            print("Port", port, "is filtered")
    else:
        print("No response")

def maimon_scan(target, port):
    print("Performing Maimon Scan on", target, "port", port)
    packet = IP(dst=target)/TCP(dport=port, sport=port, flags="S")
    response = sr1(packet, timeout=2, verbose=False)# Send the packet and receive response
    if response is None:# Check if response received and determine port status
        print(f"Port {port}/TCP is filtered or open")
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x14:  # RST+ACK
            print(f"Port {port}/TCP is closed")
        elif response.getlayer(TCP).flags == 0x12:  # SYN+ACK
            print(f"Port {port}/TCP is open")
    else:
        print(f"Unexpected response received for port {port}/TCP")
            
def check_os(target_ip,system):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-p 139 -O')  # Perform OS detection  #sudo nmap -p 1-1000 -sS 192.168.100.68 (use the command to know open port and enter it instead of 139)
    if target_ip in nm.all_hosts():
        os_guess = nm[target_ip]['osmatch']
        for os_info in os_guess:
            if 'osclass' in os_info:
                for os_class in os_info['osclass']:
                    if 'osfamily' in os_class and os_class['osfamily'] == system:
                        print(f"{target_ip} is running on ",system)
                        return True
    print(f"{target_ip} is not running on ",system)
    return False
    
    
    


   
def print_centered(text, color_code):#Def to make the name of tool
    terminal_width = shutil.get_terminal_size().columns# Get the width of the terminal window  
    left_padding = (terminal_width - len(text)) // 2# Calculate the left padding to center the text    
    print("\033[{}m{}{}\033[0m".format(color_code, " " * left_padding, text))# Print the text with the specified color and centered alignment
    
def print_menu():
    print("-" * shutil.get_terminal_size().columns)
    print_centered("Port Discovery Tool", 92)  # 92 is the ANSI color code for green
    print_centered("Made by Momenah Saif-21I-1909", 96)  # 96 is the ANSI color code for cyan
    print("-" * shutil.get_terminal_size().columns)
    print("Menu of Port Discovery Techniques:")
    print("1. ICMP Ping Scan")
    print("2. UDP Ping Scan")
    print("3. TCP Ping Scan")
    print("0. Exit")

def main():
    print_menu()
    target = input("Enter target IP address to start the scanning tool: ")
    port = input("Enter target port for scans: ")
    port=int(port)#convert input string into integar
    while True:
        print("\n","*" * 40)
        option = input("Enter your choice from the menu: ")

        if option == '1':
            icmp_ping_scan(target)
        elif option == '2':
            udp_ping_scan(target)
        elif option == '3':
            print("\tSelect TCP Scan Type:")#Menu of TCP Scan
            print("\t1. SYN Scan")
            print("\t2. Stealth Scan")
            print("\t3. Inverse TCP Scan")
            print("\t4. ACK Scan")
            tcp_option = input("Enter your choice: ")
            if tcp_option == '1':
                tcp_syn_scan(target,port)
            elif tcp_option == '2':
                tcp_stealth_scan(target,port)
            elif tcp_option == '3':
                  print("\t\tSelect TCP Inverse Scan Type:")
                  print("\t\t1. FIN Scan")
                  print("\t\t2. NULL Scan")
                  print("\t\t3. XMAS Scan")
                  print("\t\t4. Maimon Scan")
                  inv_option = input("Enter your choice: ")
                  if inv_option == '1':
                     inv_tcp_scan(target,port, "F")
                  elif inv_option == '2':
                       inv_tcp_scan(target,port, "")
                  elif inv_option == '3':
                       if check_os(target,"Windows"):
                          print("Not possible")#check OS
                       else:   
                          inv_tcp_scan(target,port, "FPU") 
                  elif inv_option == '4':
                       maimon_scan(target, port)          
            elif tcp_option == '4':
                  print("\t\tSelect ACK Flag Scan Type:")
                  print("\t\t1. TTL Scan")
                  print("\t\t2. Window Scan")
                  ack_option = input("Enter your choice: ")
                  if ack_option == '1':
                     ack_ttl_scan(target,port)
                  elif ack_option == '2':
                       ack_windows_scan(target,port)  
            else:
                print("Invalid option")
        elif option == '0':
            print("Exiting...")#Exit the code
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()
