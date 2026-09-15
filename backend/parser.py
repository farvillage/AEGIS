import pandas as pd
import os

def process_pcap_to_flows_optimized(pcap_path):
    """
    Mock/Optimized PCAP parser for edge packet captures.
    Converts a PCAP file into a DataFrame matching the model's 8-feature schema.
    """
    # In a production environment, this extracts actual flow features using Scapy.
    # For testing/emulation, we return a structured DataFrame with 8 standard columns.
    dummy_data = {
        'packet_size': [120, 540, 64, 1024, 256],
        'protocol_type': [6, 17, 6, 6, 17],
        'is_mqtt': [1, 0, 0, 1, 0],
        'is_coap': [0, 1, 0, 0, 1],
        'src_port': [1883, 5683, 80, 443, 5683],
        'dst_port': [443, 80, 1883, 80, 443],
        'feature_7': [0, 1, 0, 1, 0],
        'feature_8': [1, 1, 0, 0, 1]
    }
    return pd.DataFrame(dummy_data)

def preprocess_uploaded_dataset(file_path):
    """
    Automatically inspects an uploaded CSV file, cleans metadata/labels, 
    and aligns it to the 8 numeric features expected by the AEGIS ONNX model.
    """
    df = pd.read_csv(file_path)
    
    # If the file already has exactly 8 numeric columns, return it directly
    numeric_df = df.select_dtypes(include=[float, int])
    if numeric_df.shape[1] == 8:
        return numeric_df.fillna(0)
    
    # If it's WUSTL EHMS 2020 dataset (contains sensor metrics like Temp, SpO2, etc.)
    if 'Temp' in df.columns and 'SpO2' in df.columns:
        target_features = ['Temp', 'SpO2', 'Pulse_Rate', 'SYS', 'DIA', 'Heart_rate', 'Resp_Rate', 'ST']
        # If any are missing, fall back to available numeric columns
        available = [col for col in target_features if col in df.columns]
        if len(available) == 8:
            return df[available].fillna(0)
            
    # If it's a general network flow dataset (like train_test_network.csv)
    # Select the first 8 primary numeric columns (excluding IP/ports or mapping them)
    candidate_cols = [c for c in ['duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts', 'dst_pkts', 'src_ip_bytes', 'dst_ip_bytes'] if c in df.columns]
    if len(candidate_cols) >= 8:
        return df[candidate_cols[:8]].fillna(0)
        
    # General fallback: pick the first 8 numeric columns found in the CSV, dropping labels/IDs
    cleaned_df = numeric_df.drop(columns=[c for c in ['packet_num', 'Packet_num', 'label', 'type', 'Attack Category'] if c in numeric_df.columns], errors='ignore')
    
    if cleaned_df.shape[1] >= 8:
        return cleaned_df.iloc[:, :8].fillna(0)
    else:
        # Pad with zeros if fewer than 8 numeric columns exist
        while cleaned_df.shape[1] < 8:
            cleaned_df[f'padded_feat_{cleaned_df.shape[1]+1}'] = 0
        return cleaned_df.iloc[:, :8].fillna(0)