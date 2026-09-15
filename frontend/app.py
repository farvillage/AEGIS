import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
import pandas as pd
import numpy as np

# Ensure the root directory is in the path to import backend modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.model import OptimizedAegisInference
from backend.parser import process_pcap_to_flows_optimized
from backend.grc import calculate_grc_risk_score
from backend.xai import generate_shap_explanation

# --- Theme Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class CollapsibleDropdown(ctk.CTkFrame):
    """Custom accordion dropdown widget matching clean expander style without scrollbars."""
    def __init__(self, master, title="Who am I?", **kwargs):
        super().__init__(master, fg_color="#0a0a0a", border_color="#484aaa", border_width=1, corner_radius=6, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.is_open = True

        # Toggle Button Header
        self.toggle_btn = ctk.CTkButton(
            self,
            text=f"▼  {title}",
            command=self.toggle,
            fg_color="transparent",
            hover_color="#1a1a1a",
            text_color="#e2e8f0",
            anchor="w",
            font=("Courier", 13, "bold"),
            height=30
        )
        self.toggle_btn.grid(row=0, column=0, sticky="ew", padx=10, pady=5)

        # Content Frame
        self.content_frame = ctk.CTkFrame(self, fg_color="#000000", corner_radius=0)
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Text box configuration
        self.content_text = ctk.CTkTextbox(
            self.content_frame,
            width=230,
            height=280,
            fg_color="#000000",
            text_color="#e2e8f0",
            font=("Courier", 11),
            wrap="word"
        )
        self.content_text.pack(fill="both", expand=True)
        self.content_text.insert("0.0", 
            "Ygor Gesteira\n"
            "Master's Researcher @ Instituto Federal da Paraíba (IFPB)\n\n"
            "Currently developing AEGIS as part of my Master's research, focusing on machine learning applications for cybersecurity in Internet of Medical Things (IoMT).\n\n"
            "\"With great power comes great responsibility\" - Stan Lee\n\n"
            "ygorgesteira@gmail.com"
        )
        self.content_text.configure(state="disabled")

    def toggle(self):
        if self.is_open:
            self.content_frame.grid_remove()
            self.toggle_btn.configure(text=f"►  Who am I?")
            self.is_open = False
        else:
            self.content_frame.grid()
            self.toggle_btn.configure(text=f"▼  Who am I?")
            self.is_open = True


class AegisDesktopApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Configuration
        self.title("AEGIS Engine")
        self.geometry("1000x720")
        self.configure(fg_color="#000000")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Initialize ONNX inference engine (CICIoMT trained model)
        model_path = "models/aegis_ciciomt_model.onnx"
        if os.path.exists(model_path):
            self.inference_engine = OptimizedAegisInference(model_path)
        else:
            self.inference_engine = None

        # --- Sidebar (About Section) ---
        self.sidebar_frame = ctk.CTkFrame(self, width=280, fg_color="#0a0a0a", corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        self.sidebar_title = ctk.CTkLabel(
            self.sidebar_frame, 
            text="About:", 
            font=("Courier", 18, "bold"),
            text_color="#e2e8f0"
        )
        self.sidebar_title.pack(padx=20, pady=(25, 15), anchor="w")

        # Collapsible dropdown accordion
        self.dropdown = CollapsibleDropdown(self.sidebar_frame, title="Who am I?")
        self.dropdown.pack(padx=15, pady=5, fill="x")

        # --- Main Content Area ---
        self.main_frame = ctk.CTkFrame(self, fg_color="#000000")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)

        self.header_label = ctk.CTkLabel(
            self.main_frame, 
            text="AEGIS", 
            font=("Courier", 32, "bold"), 
            text_color="#e2e8f0"
        )
        self.header_label.pack(anchor="w", pady=(0, 5))

        self.sub_label_1 = ctk.CTkLabel(
            self.main_frame, 
            text="Real-time intrusion detection.", 
            font=("Courier", 13), 
            text_color="#e2e8f0"
        )
        self.sub_label_1.pack(anchor="w", pady=(0, 5))

        self.sub_label_2 = ctk.CTkLabel(
            self.main_frame, 
            text="Upload raw network captures (.pcap) or processed datasets (.csv) from medical sensors to detect malicious behavioral anomalies instantly.", 
            font=("Courier", 12), 
            text_color="#a0aec0"
        )
        self.sub_label_2.pack(anchor="w", pady=(0, 20))

        # Upload Button
        self.upload_btn = ctk.CTkButton(
            self.main_frame,
            text="Upload Network Traffic Capture",
            command=self.load_file,
            fg_color="#484aaa",
            hover_color="#3a3c88",
            text_color="#ffffff",
            font=("Courier", 13, "bold"),
            height=40
        )
        self.upload_btn.pack(anchor="w", pady=10)

        # Log / Output Box
        self.log_box = ctk.CTkTextbox(
            self.main_frame,
            width=680,
            height=340,
            fg_color="#0a0a0a",
            text_color="#e2e8f0",
            border_color="#484aaa",
            border_width=1,
            font=("Courier", 12)
        )
        self.log_box.pack(anchor="w", pady=10)
        self.log_box.insert("0.0", "System ready. Click 'Upload Network Traffic Capture' to begin...\n")

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Network Traffic Capture",
            filetypes=[("Network Files", "*.csv *.pcap *.pcapng")]
        )
        if not file_path:
            return

        file_name = os.path.basename(file_path)
        self.log_box.delete("0.0", "end")
        self.log_box.insert("0.0", f"Data detected: {file_name}\nAEGIS engine active. Running analysis...\n")
        
        threading.Thread(target=self.process_file_background, args=(file_path, file_name), daemon=True).start()

    def process_file_background(self, file_path, file_name):
        try:
            if not self.inference_engine:
                self.log_box.insert("end", "\n[Error] ONNX model 'aegis_ciciomt_model.onnx' not found in models directory.")
                return

            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
                
                # Automatically map/extract WUSTL expected features if raw columns are present
                target_features = ['Temp', 'SpO2', 'Pulse_Rate', 'SYS', 'DIA', 'Heart_rate', 'Resp_Rate', 'ST']
                if all(col in df.columns for col in target_features):
                    df_processed = df[target_features].fillna(0)
                else:
                    # Fallback to numeric columns matching model dimension requirement
                    numeric_df = df.select_dtypes(include=[np.number])
                    cleaned = numeric_df.drop(columns=[c for c in ['packet_num', 'Packet_num', 'label', 'type', 'Attack Category'] if c in numeric_df.columns], errors='ignore')
                    if cleaned.shape[1] >= 8:
                        df_processed = cleaned.iloc[:, :8].fillna(0)
                    else:
                        df_processed = cleaned.reindex(columns=range(8), fill_value=0).fillna(0)
            elif file_path.endswith(('.pcap', '.pcapng')):
                df_processed = process_pcap_to_flows_optimized(file_path)
            else:
                self.log_box.insert("end", "\n[Error] Unsupported file format.")
                return

            if df_processed.empty:
                self.log_box.insert("end", "\n[Error] No valid flows extracted from file.")
                return

            # Run Inference
            df_result, attack_count = self.inference_engine.predict(df_processed)
            total_rows = len(df_result)
            normal_count = total_rows - attack_count

            # Calculate GRC Quantitative Risk Score
            risk_score, risk_level = calculate_grc_risk_score(attack_count, total_rows)

            # Generate XAI Explanation Metadata
            xai_report = generate_shap_explanation(self.inference_engine, df_processed)

            summary = (
                f"\n--- Behavioral Analysis & GRC Report ---\n"
                f"AEGIS evaluated {total_rows:,} total network flows:\n"
                f" - {attack_count:,} malicious flows flagged.\n"
                f" - {normal_count:,} normal flows verified.\n\n"
                f"--- GRC Quantitative Risk Assessment ---\n"
                f" - Risk Score: {risk_score:.2f}% (Level: {risk_level})\n"
                f" - Compliance Impact: CIA Triad Weighted Evaluation Complete.\n\n"
                f"--- XAI Compliance Audit Trail (SHAP) ---\n"
                f" - Primary Driving Feature: {xai_report['top_influencing_feature']}\n"
                f" - Audit Status: Logged for Regulatory Verification (LGPD/HIPAA).\n\n"
            )
            if attack_count > 0:
                summary += f"Alert: {attack_count:,} malicious network flow(s) identified in CICIoMT telemetry.\n" # Updated from WUSTL
            else:
                summary += "All network traffic flows classified as normal.\n"

            self.log_box.insert("end", summary)

        except Exception as e:
            self.log_box.insert("end", f"\n[Exception Error]: {str(e)}")

if __name__ == "__main__":
    app = AegisDesktopApp()
    app.mainloop()