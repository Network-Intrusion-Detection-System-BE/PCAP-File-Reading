import random

a = {'IRC', 'X11', 'Z39_50', 'aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois'}
b = {'IRC', 'X11', 'Z39_50', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'hostnames', 'http', 'http_443', 'imap4', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois'}

print(a-b)
print(b-a)
print(len(a))
print(len(a.union(b)))

c =         ['aol', 'ctf',  'efs', 'harvest', 'hostnames', 'iso_tsap', 'link', 'name', 'netstat', 'pm_dump', 'printer', 'private', 'red_i', 'tim_i', 'urh_i', 'urp_i',
         'vmnet', ]

print(len(c))

serviceMap = {
            0: 'eco_i',
            -1: 'ecr_i',
            6667: 'IRC',
            6000: 'X11',
            210: 'Z39_50',
            113: 'auth',
            179: 'bgp',
            25: 'courier',
            105: 'csnet_ns',
            13: 'daytime',
            9: 'discard',
            53: 'domain',
            7: 'echo',
            512: 'exec',
            79: 'finger',
            21: 'ftp',
            20: 'ftp_data',
            70: 'gopher',
            80: 'http',
            2784: 'http_2784',
            443: 'http_443',
            8001: 'http_8001',
            143: 'imap4',
            543: 'klogin',
            544: 'kshell',
            389: 'ldap',
            513: 'login',
            57: 'mtp',
            138: 'netbios_dgm',
            137: 'netbios_ns',
            139: 'netbios_ssn',
            119: random.choice(['nnsp', 'nntp']),
            123: 'ntp_u',
            109: 'pop_2',
            110: 'pop_3',
            514: random.choice(['remote_job', 'shell']),
            77: 'rje',
            25: 'smtp',
            66: 'sql_net',
            22: 'ssh',
            111: 'sunrpc',
            95: 'supdup',
            11: 'systat',
            23: 'telnet',
            69: 'tftp_u',
            37: 'time',
            540: 'uucp',
            117: 'uucp_path',
            43: 'whois'
        }

print(len(serviceMap))
print(len(set(serviceMap.keys())))
k = serviceMap.get(514)
print(k)
k = serviceMap.get(514)
print(k)
k = serviceMap.get(514)
print(k)
k = serviceMap.get(514)
print(k)
k = serviceMap.get(514)
print(k)
k = serviceMap.get(514)
print(k)
k = serviceMap.get(78)
print(k)