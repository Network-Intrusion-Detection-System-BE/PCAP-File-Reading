import pyshark
import random

capture = pyshark.FileCapture('pcap2.pcapng')

n = 0
for packet in capture:
    # print(packet)
    # print("\n")
    try:
        total_udp_packets = 0
        total_tcp_packets = 0
        total_icmp_packets = 0
        if hasattr(packet, 'transport_layer'):
            if packet.transport_layer == 'TCP':
                total_tcp_packets += 1
            elif packet.transport_layer == 'UDP':
                total_udp_packets += 1
            elif packet.transport_layer == 'ICMP':
                total_icmp_packets += 1

    # 1. Duration 
        duration = float(packet.frame_info.time_delta_displayed) * 10**6
        
####    # 2. Protocol Type
        protocolTypeValue = packet.frame_info.protocols
        
        if 'icmp' in protocolTypeValue:
            protocol_type = 'icmp'
        elif 'tcp' in protocolTypeValue:
            protocol_type = 'tcp'
        elif 'udp' in protocolTypeValue:
            protocol_type = 'udp'
        else:
            protocol_type = 'oth'

####    # 3. Service
        if 'TCP' in packet:
            serviceValue = packet.tcp.dstport
        elif 'UDP' in packet:
            serviceValue = packet.udp.dstport
        elif 'IP' in packet:
            serviceValue = random.choice([0, -1])
        else:
            serviceValue = 123456

        serviceMap = {
            0: 'eco_i', -1: 'ecr_i', 6667: 'IRC', 6000: 'X11', 210: 'Z39_50', 113: 'auth', 179: 'bgp',
            25: 'courier', 105: 'csnet_ns', 13: 'daytime', 9: 'discard', 53: 'domain', 7: 'echo', 512: 'exec',
            79: 'finger', 21: 'ftp', 20: 'ftp_data', 70: 'gopher', 80: 'http', 2784: 'http_2784', 443: 'http_443',
            8001: 'http_8001', 143: 'imap4', 543: 'klogin', 544: 'kshell', 389: 'ldap', 513: 'login', 57: 'mtp',
            138: 'netbios_dgm', 137: 'netbios_ns', 139: 'netbios_ssn', 119: random.choice(['nnsp', 'nntp']),
            123: 'ntp_u', 109: 'pop_2', 110: 'pop_3', 514: random.choice(['remote_job', 'shell']), 77: 'rje',
            25: 'smtp', 66: 'sql_net', 22: 'ssh', 111: 'sunrpc', 95: 'supdup', 11: 'systat', 23: 'telnet',
            69: 'tftp_u', 37: 'time', 540: 'uucp', 117: 'uucp_path', 43: 'whois', 60593: 'netstat'
            }
        serviceType = serviceMap.get(int(serviceValue), 'None')
        service = serviceType
        if service == 'None':
            service = random.choice(['private', 'domain_u', 'other'])

####    # 4. Flags
        # OTH (Other): 0x00 (No flags set)
        # REJ (Reject): 0x14 (RST, ACK flags set)
        # RSTO (Reset Originator): 0x04 (RST flag set)
        # RSTOS0 (Reset Originator, SYN Stealth): 0x14 (RST, ACK flags set)
        # RSTR (Reset Response): 0x14 (RST, ACK flags set)
        # S0 (Stealth Scan, No Response): 0x00 (No flags set)
        # S1 (Stealth Scan, Syn Ack): 0x12 (SYN, ACK flags set)
        # S2 (Stealth Scan, No Syn Ack): 0x04 (RST flag set)
        # S3 (Stealth Scan, RST Received): 0x14 (RST, ACK flags set)
        # SF (Stealth Scan, FIN): 0x01 (FIN flag set)
        # SH (Stealth Scan, Half Open): 0x02 (SYN flag set)
        
        if 'TCP' in packet:
            flagcode = packet.tcp.flags
        elif 'IP' in packet:
            flagcode = packet.ip.flags
        elif 'UDP' in packet:
            flagcode = packet.udp.flags
        else:
            flagcode = None

        if flagcode == '0x00':
            flag = 'S0'
        elif flagcode == '0x02':
            flag = 'SH'
        elif flagcode == '0x14':
            flag = random.choice(['REJ', 'S3', 'RSTOS0'])
        elif flagcode == '0x04':
            flag = 'RSTO'
        elif flagcode == '0x12':
            flag = 'S1'
        elif flagcode == '0x04':
            flag = 'S2'
        elif flagcode == '0x01':
            flag = 'SF'
        else:
            flag = 'OTH'

     # 5 & 6. Source and Destination Lengths
        if 'TCP' in packet:
            src_bytes = int(packet.tcp.len)
            dst_bytes = int(packet.tcp.len)
        elif 'UDP' in packet:
            src_bytes = int(packet.udp.length)
            dst_bytes = int(packet.udp.length)
        elif 'icmp' in packet:
            src_bytes = int(packet.icmp.length)
            dst_bytes = int(packet.icmp.length)
        else:
            src_bytes = 0
            dst_bytes = 0
    # 7. Land Attack: Unfortunately, there isn't a straightforward method to directly retrieve a "land" attribute 
    #    value from packets in standard packet analysis tools like Wireshark or pyshark. 
        land = "NF"

    # 8. Wrong Fragment: the "wrong_fragment" attribute may not be directly retrievable in standard packet analysis tools.
        wrong_fragment = "NF"

    # 9. Urgent: Only for TCP packets
        if 'TCP' in packet:
            urgent = int(packet.tcp.urgent_pointer)
        else:
            urgent = 0
    
    # 10. Hot: Custom Attribute
        hot = "NF"

    # 11. Number of Failed Logins: Depends on Network Traffic
        def count_failed_logins():
            failed_logins = 0
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport') and hasattr(packet, 'http') and hasattr(packet.http, 'response_for_uri'):
                if packet.http.response_for_uri == "login.php" and packet.http.response_code == "401":
                    failed_logins += 1
            return failed_logins
        num_failed_logins = count_failed_logins()
    
####    # 12. Logged In: Depends on Protocols
        logged_in = "NF"
    
    # 13. Number of Machines Compromised: Depends on the specific security monitoring tools and 
    #     techniques used in your environment
        num_compromised = "NF"
        
    # 14. Root Shell: Varies depending on the specific security monitoring tools and techniques
        root_shell = "NF"
    
    # 15. Swich User Attempted: Varies depending on the specific security monitoring tools and techniques
        su_attempted = "NF"
    
    # 16. Number of times a privileged root user account has been involved in activities or events within a given context
        num_root = "NF"

    # 17. Number of times files have been created on a system within a given context
        num_file_creations = packet.transport_layer

    # 18. Number of shell instances or shell processes initiated on a system within a given context
        num_shells = packet.transport_layer

    # 19. Number of files accessed or opened on a system within a given context
        num_access_files = packet.transport_layer

    # 20. Number of outbound commands or requests initiated from a system within a given context or timeframe
        num_outbound_cmds = packet.transport_layer

    # 21. Signals whether a login event is associated with a host login as opposed to a user login
        is_host_login = packet.transport_layer
    
    # 22. Signals whether a login event is associated with a guest or anonymous user login
        is_guest_login = packet.transport_layer

####    # 23. Number of occurrences or instances of a particular event or observation within a dataset or a specified context
        count = packet.transport_layer
    
    # 24. Number of connections or sessions initiated to a particular service or port on a server within a given context or timeframe
        srv_count = packet.transport_layer

####    # 25. Rate of packets that have the 'S1' (SYN error) flag set, indicating errors related to the SYN flag in TCP packets
        syn_error_tcp_packets = 0
        syn_error_icmp_packets = 0
        def calculate_syn_error_rate(total_tcp_packets, total_icmp_packets, syn_error_tcp_packets, syn_error_icmp_packets):
            if hasattr(packet, 'transport_layer'):
                if 'TCP' in packet:
                    if hasattr(packet.tcp, 'flags') and 'S1' in packet.tcp.flags:
                        syn_error_tcp_packets += 1
                elif 'ICMP' in packet:
                    if hasattr(packet.icmp, 'type') and packet.icmp.type == '3' and hasattr(packet.icmp, 'code') and packet.icmp.code == '1':
                        syn_error_icmp_packets += 1

            syn_error_rate_tcp = (float)(syn_error_tcp_packets / total_tcp_packets) if total_tcp_packets > 0 else 0
            syn_error_rate_icmp = (float)(syn_error_icmp_packets / total_icmp_packets) if total_icmp_packets > 0 else 0

            return syn_error_rate_tcp, syn_error_rate_icmp
        
        syn_error_rate_tcp, syn_error_rate_icmp = calculate_syn_error_rate(total_tcp_packets, 
                                    total_icmp_packets, syn_error_tcp_packets, syn_error_icmp_packets)

        if 'TCP' in packet:
            serror_rate = syn_error_rate_tcp
        elif 'IP' in packet:
            serror_rate = syn_error_rate_icmp
        else:
            serror_rate = 0

####    # 26. Server error rate, which is the rate of packets with the 'S1' (SYN error) flag set among the packets sent to a particular service or server
        srv_serror_tcp_packets = 0
        srv_serror_icmp_packets = 0
        def calculate_srv_serror_rate(total_tcp_packets, total_icmp_packets, srv_serror_tcp_packets, srv_serror_icmp_packets):
            if hasattr(packet, 'transport_layer'):
                if packet.transport_layer == 'TCP':
                    if hasattr(packet.tcp, 'flags') and 'S1' in packet.tcp.flags:
                        srv_serror_tcp_packets += 1
                elif packet.transport_layer == 'ICMP':
                    if hasattr(packet.icmp, 'type') and packet.icmp.type == '3' and hasattr(packet.icmp, 'code') and packet.icmp.code == '1':
                        srv_serror_icmp_packets += 1
            srv_serror_rate_tcp = (srv_serror_tcp_packets / total_tcp_packets)  if total_tcp_packets > 0 else 0
            srv_serror_rate_icmp = (srv_serror_icmp_packets / total_icmp_packets)  if total_icmp_packets > 0 else 0
            return srv_serror_rate_tcp, srv_serror_rate_icmp
        
        srv_serror_rate_tcp, srv_serror_rate_icmp = calculate_srv_serror_rate(total_tcp_packets, total_icmp_packets, 
                        srv_serror_tcp_packets, srv_serror_icmp_packets)

        if 'TCP' in packet:
            srv_serror_rate = srv_serror_rate_tcp
        elif 'IP' in packet:
            srv_serror_rate = srv_serror_rate_icmp
        else:
            serror_rate = 0
    
####    # 27. Rate of packets that have the 'R' (reset) flag set in TCP packets among all packets sent to a specific service or server
        rerror_rate = packet.transport_layer
    
####    # 28. Rate of packets with the 'R' (reset) flag set among the packets sent to a specific service or server
        srv_rerror_rate = packet.transport_layer

####    # 29. Percentage of connections to the same service among the total number of connections observed
        same_srv_rate = packet.transport_layer

####    # 30. Percentage of connections to different services among the total number of connections observed
        diff_srv_rate = packet.transport_layer
    
####    # 31. Percentage of connections to different hosts among the connections to the same service
        srv_diff_host_rate = packet.transport_layer

####    # 32. Number of unique destination hosts (IP addresses) contacted by the source host
        dst_host_count = packet.transport_layer

####   # 33. Number of unique services offered by the destination hosts contacted by the source host
        dst_host_srv_count = packet.transport_layer

####    # 34. Percentage of connections to the same service among the connections to a particular destination host
        dst_host_same_srv_rate = packet.transport_layer

####    # 35. Percentage of connections to different services among the connections to a particular destination host
        dst_host_diff_srv_rate = packet.transport_layer
    
    # 36. Percentage of connections from the same source port among the connections to a particular destination host
        dst_host_same_src_port_rate = packet.transport_layer

    # 37. Percentage of connections to different hosts among the connections to the same service on a destination host
        dst_host_srv_diff_host_rate = packet.transport_layer
    
####    # 38. Rate of packets with TCP 'SYN' errors (e.g., 'S1' flag set) among the packets sent to a particular destination host
        dst_host_serror_rate = packet.transport_layer
    
####    # 39. Calculated specifically for connections to a particular service on the destination host
        dst_host_srv_serror_rate = packet.transport_layer
    
####    # 40. Rate of packets with TCP 'reset' errors (e.g., 'R' flag set) among the packets sent to a particular destination host
        dst_host_rerror_rate = packet.transport_layer
    
####    # 41. Calculated specifically for connections to a particular service on the destination host
        dst_host_srv_rerror_rate = packet.transport_layer

        if(protocol_type=='icmp' or protocol_type=='tcp' or protocol_type=='udp'):
        # if(protocol_type=='icmp'):
        # if(protocol_type=='tcp'):
        # if(protocol_type=='udp'):
            print(duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_host_login, is_guest_login, count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate, "\n")
    except AttributeError as e:
        pass
    if(n==20):
        break
    if(protocol_type=='icmp' or protocol_type=='tcp' or protocol_type=='udp'):
    # if(protocol_type=='icmp'):
    # if(protocol_type=='tcp'):
    # if(protocol_type=='udp'):
        n += 1
