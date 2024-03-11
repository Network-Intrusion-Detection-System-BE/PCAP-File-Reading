import pyshark
capture = pyshark.LiveCapture(interface=r'\Device\NPF_{D41D8EE1-2739-4FA1-8873-024D3F68E9E1}',
                              output_file=r'C:\Temp\samp1.pcap')
capture.sniff(timeout=1)
pkts = [pkt for pkt in capture._packets]
print(len(capture))
capture.close()
