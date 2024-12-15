import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import nest_asyncio
import pickle
import time
import os
from datetime import datetime

# Allow nested event loops for live capture
nest_asyncio.apply()

# Pre-trained model paths
MODEL_PATHS = {
    "Random Forest": "randomforest.pkl",
    "Decision Tree": "decisiontree.pkl",
    "Logistic Regression": "logisticRegression.pkl",
    "K-Nearest Neighbors": "knn.pkl"
}

# Load the pre-trained model
@st.cache_resource
def load_model(model_name):
    with open(MODEL_PATHS[model_name], 'rb') as file:
        model = pickle.load(file)
    return model

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
            flow_data["fwd_packet_length_max"] = max(flow_data["fwd_packet_length_max"], packet_length)

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

# Live packet capture
def capture_packets(interface, duration):
    packet_data = []

    def process_packet(packet):
        packet_info = packet_to_cicids_format(packet, flow_tracker)
        if packet_info:
            packet_data.append(packet_info)

    sniff(iface=interface, prn=process_packet, timeout=duration)
    return pd.DataFrame(packet_data, columns=cicids2018_columns)

# Logs saving function
def save_logs(logs_df):
    if os.path.exists("logs.csv"):
        existing_df = pd.read_csv("logs.csv")
        logs_df = pd.concat([existing_df, logs_df])
    logs_df.to_csv("logs.csv", index=False)

# Sidebar navigation
pages = ["Home", "Capture Packets", "Logs", "About Us", "Reference"]
page = st.sidebar.radio("Navigate", pages)

# Homepage
if page == "Home":
    st.title("Network Intrusion Detection System using Machine Learning")
    st.image("ids.jpg", caption="Network IDS Project", use_container_width=True)
    st.write("""
    ### Project Overview  
             
This project leverages machine learning to detect malicious activities in network traffic in real-time. By analyzing live network packets, we aim to classify traffic as either benign (normal) or malicious (threats like attacks or unauthorized access).
             
The process starts by capturing network traffic data, followed by extracting key features such as packet size, IP addresses, port numbers, and TCP flags. These features are then used to train machine learning models, allowing the system to identify abnormal traffic patterns indicative of security threats.
             
Our approach ensures continuous monitoring of network activity, offering an effective and proactive defense mechanism to safeguard against potential cyber-attacks.  
    """)

# Capture Packets Page
elif page == "Capture Packets":
    st.title("Live Packet Capture and Detection")

    # Model selection
    model_name = st.selectbox("Choose a Model", list(MODEL_PATHS.keys()))
    loaded_model = load_model(model_name)

    # Packet capture settings
    interface = st.text_input("Enter Network Interface (e.g., 'en0')", "en0")
    capture_duration = st.slider("Capture Duration (seconds)", 1, 60, 10)

    if st.button("Start Capture"):
        st.write("Capturing packets...")
        packet_df = capture_packets(interface, capture_duration)

        if not packet_df.empty:
            st.write("Captured Packets:")
            st.dataframe(packet_df)

            # Map Protocol values for the model
            if "Protocol" in packet_df.columns:
                packet_df["Protocol"] = packet_df["Protocol"].map({"TCP": 6, "UDP": 17}).fillna(0)

            # Align with model input
            model_input_columns = loaded_model.feature_names_in_
            if set(model_input_columns).issubset(packet_df.columns):
                model_input = packet_df[model_input_columns]
                predictions = loaded_model.predict(model_input)
                packet_df["Prediction"] = predictions
                st.write("Results:")
                st.dataframe(packet_df)

                # Save malicious logs
                malicious_logs = packet_df[packet_df["Prediction"] != 1]
                if not malicious_logs.empty:
                    save_logs(malicious_logs)
                    st.warning("Malicious packets detected! Logs have been updated.")
                non_malicious_logs = packet_df[packet_df["Prediction"] == 1]
                if not non_malicious_logs.empty:
                    save_logs(non_malicious_logs)
                    st.warning("No attacks detected.")    
            else:
                st.error("Captured data does not match the model's expected input columns.")
        else:
            st.warning("No packets captured.")

# Logs Page
elif page == "Logs":
    st.title("Detected Attack Logs")
    if os.path.exists("logs.csv"):
        logs_df = pd.read_csv("logs.csv")
        st.dataframe(logs_df)
    else:
        st.write("No logs available.")



    # About Us Page
elif page == "About Us":
    st.title("About Us")
    
    # Display the team photo
    st.image('team.jpg', caption='Our Project Team', use_container_width=True)
    
    st.write("""
    ### Project Team  
    - **Pravardhan N Shetty**  
    - **Joshua Dsouza**  
    - **Varun Prakash Shetty**  
    - **G Mohammed Nihal**

    This is our major project for the final year as Computer Science students at **Sahyadri College of Engineering and Management**. The goal of this project is to detect malicious network activities in real-time using machine learning techniques. By analyzing live network packets and extracting relevant features, we aim to classify traffic as either benign or malicious.

    As a team, we have worked together to develop a system that continuously monitors network traffic, providing an effective defense mechanism against potential cyber-attacks. This project represents the culmination of our academic learning and is designed to showcase our skills in network security, machine learning, and data analysis.
    """)


elif page == "Reference":
    st.title("Intrusion Categories")

    st.write("""
    ### Intrusion Categories:

    1. **Benign (Normal Traffic)**
       - Regular, safe network traffic without any malicious activity.

    2. **DoS (Denial of Service)**
       - A type of attack aimed at making a machine or network resource unavailable by overwhelming it with a flood of traffic. 
       - **Subtypes**: 
         - **DoS Hulk**: A flood-based attack aimed at consuming system resources.
         - **DoS GoldenEye**: Similar to DoS Hulk but with different techniques and vectors.

    3. **DDoS (Distributed Denial of Service)**
       - A large-scale attack where multiple compromised systems target a single system, overwhelming it with traffic and causing it to crash.
    
    4. **PortScan**
       - A technique used by attackers to identify open ports on a target system by sending packets to a range of ports and analyzing the responses.

    5. **Botnet Activity**
       - A network of compromised devices (bots) used by attackers to launch attacks such as DDoS, spamming, or data theft.

    6. **Brute Force**
       - An attack where attackers attempt to gain access to systems by trying all possible combinations of passwords or encryption keys.
       - **Subtypes**: 
         - **SSH-Bruteforce**: Attack on SSH service by trying many password combinations.
         - **FTP-Bruteforce**: Attack on FTP service with similar techniques.

    7. **Web Attack**
       - Attacks targeting web applications or servers to exploit vulnerabilities.
       - **Subtypes**: 
         - **SQL Injection**: Attack where malicious SQL statements are inserted into input fields to exploit database vulnerabilities.
         - **XSS (Cross-Site Scripting)**: Injecting malicious scripts into webpages to target users.
         - **Brute Force**: Attack on web applications using brute force methods.

    8. **Infiltration**
       - Attacks where the intruder gains unauthorized access to a network or system to gather information or take control.

    9. **Heartbleed Attack**
       - A vulnerability in OpenSSL that allows attackers to steal sensitive information from the memory of affected systems.

    10. **Data Exfiltration**
        - The unauthorized transfer of data from a target system to an external location.
    
    ### TCP vs UDP:

    - **TCP (Transmission Control Protocol)** is a connection-oriented protocol used for reliable communication between devices. It ensures that data is delivered in the correct order and without errors.
    
    - **UDP (User Datagram Protocol)** is a connectionless protocol that does not guarantee reliability, order, or error checking. It is faster than TCP, making it ideal for real-time applications like streaming.

    **UDP 17** and **TCP6** are identifiers for network services:
    - **UDP 17** refers to the *Quote of the Day (QOTD)* service, used for sending short text messages over the network.
    - **TCP6** refers to **TCP over IPv6**, an updated version of TCP that operates over IPv6 networks.
    """)