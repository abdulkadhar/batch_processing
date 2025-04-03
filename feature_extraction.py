from scapy.all import rdpcap
import json


def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    data = []

    for pkt in packets:
        if pkt.haslayer("IP"):
            data.append(
                {
                    "src_ip": pkt["IP"].src,
                    "dst_ip": pkt["IP"].dst,
                    "protocol": pkt["IP"].proto,
                    "payload_size": len(pkt),
                }
            )

    return json.dumps(data)


def extract_pcap_summary(pcap_file):
    packets = rdpcap(pcap_file)
    summary = []

    for pkt in packets[:100]:  # Limit to first 100 packets for efficiency
        if pkt.haslayer("IP"):
            summary.append(
                f"Src: {pkt['IP'].src}, Dst: {pkt['IP'].dst}, Proto: {pkt['IP'].proto}, Size: {len(pkt)} bytes"
            )

    return "\n".join(summary)


print(extract_pcap_summary("arpspoof.pcap"))
