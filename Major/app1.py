import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import nest_asyncio
import pickle
import time

# Allow nested event loops for live capture
nest_asyncio.apply()

# Load the pre-trained model
@st.cache_resource
def load_model():
    with open('knn.pkl', 'rb') as file:
        model = pickle.load(file)
    return model

loaded_model = load_model()

# Define CICIDS2018 columns
cicids2018_columns = [
    "Source IP", "Destination IP", "Protocol", "Source Port", "Dst Port",
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", 
    "Fwd Pkt Len Max", "Bwd Pkt Len Max", "Flow Byts/s", "Flow Pkts/s"
]

# Packet data processing function
flow_tracker = {}

def packet_to_cicids_format(packet, flow_tracker):
    try:
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = None
        src_port = None
        dst_port = None

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        packet_length = len(packet)

        flow_key = (src_ip, dst_ip, protocol, src_port, dst_port)
        timestamp = time.time()

        if flow_key not in flow_tracker:
            flow_tracker[flow_key] = {
                "start_time": timestamp,
                "end_time": timestamp,
                "total_bytes": packet_length,
                "total_fwd_packets": 1,
                "total_bwd_packets": 0,
                "fwd_packet_length_max": packet_length,
                "bwd_packet_length_max": 0,
            }
        else:
            flow_data = flow_tracker[flow_key]
            flow_data["end_time"] = timestamp
            flow_data["total_bytes"] += packet_length
            flow_data["total_fwd_packets"] += 1
            flow_data["fwd_packet_length_max"] = max(
                flow_data["fwd_packet_length_max"], packet_length
            )

        flow_data = flow_tracker[flow_key]
        flow_duration = flow_data["end_time"] - flow_data["start_time"]
        flow_bytes_per_sec = flow_data["total_bytes"] / flow_duration if flow_duration > 0 else 0
        flow_packets_per_sec = flow_data["total_fwd_packets"] / flow_duration if flow_duration > 0 else 0

        return {
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Source Port": src_port,
            "Dst Port": dst_port,
            "Flow Duration": flow_duration,
            "Tot Fwd Pkts": flow_data["total_fwd_packets"],
            "Tot Bwd Pkts": flow_data["total_bwd_packets"],
            "Fwd Pkt Len Max": flow_data["fwd_packet_length_max"],
            "Bwd Pkt Len Max": flow_data["bwd_packet_length_max"],
            "Flow Byts/s": flow_bytes_per_sec,
            "Flow Pkts/s": flow_packets_per_sec
        }
    except Exception as e:
        return None

# Live packet capture function
def capture_packets(interface, duration):
    packet_data = []

    def process_packet(packet):
        packet_info = packet_to_cicids_format(packet, flow_tracker)
        if packet_info:
            packet_data.append(packet_info)

    sniff(iface=interface, prn=process_packet, timeout=duration)
    return pd.DataFrame(packet_data, columns=cicids2018_columns)

# Streamlit interface
st.title("Real-Time Network Packet Capture and Classification with Scapy")

interface = st.text_input("Enter Network Interface (e.g., 'en0')", "en0")
capture_duration = st.slider("Capture Duration (seconds)", 1, 60, 10)

if st.button("Start Capture"):
    st.write("Capturing packets...")
    packet_df = capture_packets(interface, capture_duration)

    if not packet_df.empty:
        st.write("Captured Packets:")
        st.dataframe(packet_df)

        # Map Protocol values for model
        if 'Protocol' in packet_df.columns:
            packet_df['Protocol'] = packet_df['Protocol'].map({'TCP': 6, 'UDP': 17})

        # Handle missing values
        packet_df = packet_df.fillna(0)

        # Align with model input
        if set(loaded_model.feature_names_in_).issubset(packet_df.columns):
            model_input = packet_df[loaded_model.feature_names_in_]
            predictions = loaded_model.predict(model_input)
            packet_df['Prediction'] = predictions
            st.write("Predictions:")
            st.dataframe(packet_df)
        else:
            st.error("Data columns do not match the model's expected input!")
    else:
        st.warning("No packets captured.")