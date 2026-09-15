import time
import os
import sys
import pandas as pd

# Ensure the root directory is in the path to import backend modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.parser import process_pcap_to_flows_optimized
from backend.benchmark import AegisBenchmarkCollector
from backend.model import OptimizedAegisInference

def run_local_iomt_simulation(data_path):
    print(f"[*] Initializing AEGIS Local Simulation (5G Edge / IoMT)")
    print(f"[*] Target analysis file: {data_path}")
    
    benchmark = AegisBenchmarkCollector()
    
    # Check if optimized ONNX model exists
    model_path = "aegis_wustl_model.onnx"
    if not os.path.exists(model_path):
        print(f"[!] Warning: '{model_path}' not found. Ensure the model is exported or path is correct.")
        return

    inference_engine = OptimizedAegisInference(model_path)
    
    # Ingest data simulating edge data plane traffic
    if data_path.endswith('.csv'):
        df = pd.read_csv(data_path)
    elif data_path.endswith('.pcap') or data_path.endswith('.pcapng'):
        df = process_pcap_to_flows_optimized(data_path)
    else:
        print("[!] Unsupported file format. Use .csv or .pcap")
        return

    print(f"[*] Data loaded successfully. Total records: {len(df)}")
    print("[*] Executing ultra-low latency edge inference...")

    y_true_mock = [0] * len(df)
    y_pred_list = []
    benchmark.reset_metrics()

    batch_size = 50
    for i in range(0, len(df), batch_size):
        batch_df = df.iloc[i:i+batch_size]
        
        benchmark.start_measurement()
        _, attack_count = inference_engine.predict(batch_df)
        latency = benchmark.stop_measurement()
        
        print(f"[MEC Edge] Batch {i//batch_size + 1}: Processed {len(batch_df)} packets | Latency: {latency:.2f}ms | Anomalies: {attack_count}")
        y_pred_list.extend([1 if attack_count > 0 else 0] * len(batch_df))

    metrics = benchmark.calculate_security_metrics(y_true_mock[:len(y_pred_list)], y_pred_list)
    
    print("\n=== SCIENTIFIC METRICS REPORT (DESIGN SCIENCE RESEARCH) ===")
    for key, value in metrics.items():
        print(f" - {key}: {value}")

if __name__ == "__main__":
    sample_data = "aegis_dataset_sample.csv"
    
    if not os.path.exists(sample_data):
        print(f"[!] Dataset file '{sample_data}' not found.")
        print("[*] Creating a sample CSV file with 8 features for immediate testing...")
        
        # Generate a dummy CSV dataset matching the model's 8 expected features
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
        pd.DataFrame(dummy_data).to_csv(sample_data, index=False)
        print(f"[+] Sample file '{sample_data}' created successfully.")
    
    run_local_iomt_simulation(sample_data)