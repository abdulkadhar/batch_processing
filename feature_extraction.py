from scapy.all import rdpcap
from transformers import pipeline
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


# Load the LLM (zero-shot attack detection)
model_pipeline = pipeline(
    "text-generation",
    model="mistralai/Mistral-7B-Instruct-v0.2",
    token="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",
)


def split_pcap_into_batches(pcap_file, batch_size=100):
    """Splits the PCAP into multiple batches of packets"""
    packets = rdpcap(pcap_file)
    batches = [packets[i : i + batch_size] for i in range(0, len(packets), batch_size)]
    return batches


def extract_batch_features(batch):
    """Extracts key features from a batch of packets"""
    features = []
    for pkt in batch:
        if pkt.haslayer("IP"):
            features.append(
                f"Src: {pkt['IP'].src}, Dst: {pkt['IP'].dst}, Proto: {pkt['IP'].proto}, Size: {len(pkt)} bytes"
            )
    return "\n".join(features)


def process_batch_with_llm(batch_summary):
    """Uses LLM to analyze network traffic for threats"""
    prompt = f"""
    The following is a batch of network traffic data:
    {batch_summary}

    Identify any possible network attacks, including DDoS, port scanning, or malicious behavior.
    """
    response = model_pipeline(prompt, max_length=500)
    return response[0]["generated_text"]


def analyze_pcap(pcap_file, batch_size=100):
    """Splits the PCAP, processes it in batches, and aggregates results"""
    batches = split_pcap_into_batches(pcap_file, batch_size)
    results = []

    for i, batch in enumerate(batches):
        batch_summary = extract_batch_features(batch)
        batch_result = process_batch_with_llm(batch_summary)
        results.append(f"Batch {i+1}: {batch_result}")

    # Aggregate final decision
    final_analysis = "\n".join(results)
    return final_analysis


# Example usage
final_result = analyze_pcap("arpspoof.pcap", batch_size=100)
print(final_result)

# print(extract_pcap_summary("arpspoof.pcap"))
