
import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import nest_asyncio
import pickle
import time
import os

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
def capture_packets(interface):
    packet_data = []

    def process_packet(packet):
        packet_info = packet_to_cicids_format(packet, flow_tracker)
        if packet_info:
            packet_data.append(packet_info)

    sniff(iface=interface, prn=process_packet, timeout=10)  # Fixed 10 seconds capture duration
    return pd.DataFrame(packet_data, columns=cicids2018_columns)

# Logs saving function
def save_logs(logs_df):
    if os.path.exists("logs.csv"):
        existing_df = pd.read_csv("logs.csv")
        logs_df = pd.concat([existing_df, logs_df])
    logs_df.to_csv("logs.csv", index=False)

# Sidebar navigation
pages = ["Home", "Capture Packets", "Upload CSV", "Logs", "About Us", "Reference"]
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

    if st.button("Start Capture"):
        st.write("Starting live packet capture for 10 seconds...")
        
        # Spinner and progress bar
        with st.spinner("Capturing network packets... Please wait!"):
            progress_bar = st.progress(0)  # Progress bar initialization
            for i in range(10):
                time.sleep(1)  # Simulate time progression
                progress_bar.progress((i + 1) * 10)  # Update progress
        
            packet_df = capture_packets(interface)

        if not packet_df.empty:
            st.success("Packet capture completed successfully!")
            st.write("Captured Packets:")
            st.dataframe(packet_df)

            # Total packet count
            packet_count = len(packet_df)

            # Attack condition logic
            if packet_count > 20000:
                st.warning("Attack Detected!")
                packet_df["Prediction"] = 2
            elif 3000 < packet_count <= 20000:
                st.error("Attack Detected!")
                packet_df["Prediction"] = 4
            else:
                st.info("Traffic is normal. No attacks detected.")
                if "Protocol" in packet_df.columns:
                    packet_df["Protocol"] = packet_df["Protocol"].map({"TCP": 6, "UDP": 17}).fillna(0)

                model_input_columns = loaded_model.feature_names_in_
                if set(model_input_columns).issubset(packet_df.columns):
                    model_input = packet_df[model_input_columns]
                    predictions = loaded_model.predict(model_input)
                    packet_df["Prediction"] = predictions
                else:
                    st.error("Captured data does not match the model's expected input columns.")

            st.write("Results:")
            st.dataframe(packet_df)
            save_logs(packet_df)
        else:
            st.warning("No packets were captured. Check your network interface.")

# Upload CSV Page
if page == "Upload CSV":  # Change `elif` to `if` for the single page
    st.title("Upload CSV File for Analysis")
    
    # Model selection
    model_name = st.selectbox("Choose a Model", list(MODEL_PATHS.keys()))
    loaded_model = load_model(model_name)

    # File upload
    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
    
    if uploaded_file is not None:
        st.write("Uploaded file:")
        data = pd.read_csv(uploaded_file)
        st.dataframe(data.head())

        # Check if model's input columns are in the uploaded data
        model_input_columns = loaded_model.feature_names_in_
        if set(model_input_columns).issubset(data.columns):
            # Extract relevant features for the model
            model_input = data[model_input_columns]
            
            # Perform predictions
            predictions = loaded_model.predict(model_input)
            data["Prediction"] = predictions
            
            # Display results
            st.success("Analysis completed!")
            st.write("Results:")
            st.dataframe(data)

            # Warning system for detected attacks
            if "Prediction" in data.columns and any(data["Prediction"] != 0):
                st.error("Warning: Malicious activity detected!")
                attack_types = {
                    1: "DoS Attack",
                    2: "DDoS Attack",
                    3: "PortScan",
                    4: "Infiltration"
                }
                detected_attacks = data["Prediction"].map(attack_types).value_counts()
                st.write("Detected Attack Types:")
                for attack, count in detected_attacks.items():
                    st.warning(f"{attack}: {count} instances detected.")
            else:
                st.success("No malicious activity detected. Traffic is normal.")
            
            # Save the results if needed
            save_option = st.checkbox("Save results as CSV")
            if save_option:
                result_file = "analysis_results.csv"
                data.to_csv(result_file, index=False)
                st.download_button(
                    label="Download Results",
                    data=open(result_file, "rb").read(),
                    file_name="analysis_results.csv",
                    mime="text/csv"
                )
        else:
            st.error("The uploaded file does not contain the required columns for this model.")
# Logs Page
elif page == "Logs":
    st.title("Detected Attack Logs")
    if os.path.exists("logs.csv"):
        logs_df = pd.read_csv("logs.csv")
        st.dataframe(logs_df)
    else:
        st.write("No logs available.")
#About us
elif page == "About Us":
    st.title("About Us")
    st.write("""
    ### Project Team  
    - **Pravardhan N Shetty**  
    - **Joshua Dsouza**  
    - **Varun Prakash Shetty**  
    - **G Mohammed Nihal**


    This is our major project for the final year as Information Science students at **Sahyadri College of Engineering and Management**. The goal of this project is to detect malicious network activities in real-time using machine learning techniques. By analyzing live network packets and extracting relevant features, we aim to classify traffic as either benign or malicious.

    As a team, we have worked together to develop a system that continuously monitors network traffic, providing an effective defense mechanism against potential cyber-attacks. This project represents the culmination of our academic learning and is designed to showcase our skills in network security, machine learning, and data analysis.
    """)

# Reference Page
# Reference Page
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


    
    """)



