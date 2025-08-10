import os
import subprocess
import threading
import datetime
import tkinter as tk
from tkinter import ttk, messagebox

import pyshark
import pandas as pd
import numpy as np
import joblib
import asyncio

# ---------------------------
# Existing functions:
# ---------------------------

def capture_pcap(interface, capture_duration, output_pcap):
    """Capture network packets from a specific interface for a given duration."""
    try:
        print(f"Capturing network traffic for {capture_duration} seconds from interface {interface}...")
        capture = pyshark.LiveCapture(interface=interface, output_file=output_pcap)
        capture.sniff(timeout=capture_duration)
        capture.close()  # Ensure the file handle is closed
        print(f"Packet capture completed: {output_pcap}")
    except Exception as e:
        print(f"An error occurred while capturing traffic: {e}")
        return False  # Indicate failure
    return True  # Indicate success

def run_cfm(cfm_path, input_file, output_folder):
    """Run CICFlowMeter on the given .pcap file to generate flow statistics."""
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        print(f"Input pcap file {input_file} is missing or empty. Skipping CICFlowMeter.")
        return False

    try:
        print(f"Running CICFlowMeter on {input_file}...")
        original_working_dir = os.getcwd()
        bin_directory = os.path.dirname(cfm_path)
        os.chdir(bin_directory)

        os.makedirs(output_folder, exist_ok=True)

        abs_input_file = os.path.abspath(os.path.join(original_working_dir, input_file))
        abs_output_folder = os.path.abspath(os.path.join(original_working_dir, output_folder))

        command = f'"{os.path.basename(cfm_path)}" "{abs_input_file}" "{abs_output_folder}"'
        print(f"Changing directory to: {bin_directory}")
        print(f"Command being executed: {command}")

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
            cwd=bin_directory
        )
        stdout, stderr = process.communicate()
        os.chdir(original_working_dir)  # Return to original directory

        if process.returncode != 0:
            print(f"Error running CICFlowMeter (Return Code: {process.returncode}):\nSTDERR:\n{stderr}\nSTDOUT:\n{stdout}")
            return False
        else:
            print("CICFlowMeter completed successfully.")
            expected_csv_filename = os.path.basename(abs_input_file) + '_Flow.csv'
            expected_csv_path = os.path.join(abs_output_folder, expected_csv_filename)
            if os.path.exists(expected_csv_path):
                print(f"Generated CSV file: {expected_csv_path}")
                return expected_csv_path
            else:
                print(f"Warning: CICFlowMeter finished but expected CSV file not found at {expected_csv_path}")
                print(f"Files in output dir: {os.listdir(abs_output_folder)}")
                return None
    except Exception as e:
        print(f"An error occurred while running CICFlowMeter: {e}")
        if 'original_working_dir' in locals() and os.getcwd() != original_working_dir:
             os.chdir(original_working_dir)
        return False

def predict_with_model(model_path, csv_file_path, feature_columns):
    """Load data, preprocess, and predict using the trained model."""
    if not csv_file_path or not os.path.exists(csv_file_path):
         print(f"CSV file path is invalid or file does not exist: {csv_file_path}")
         return None

    try:
        print(f"Loading model from {model_path}...")
        model = joblib.load(model_path)
        print("Model loaded successfully.")

        print(f"Loading data from {csv_file_path}...")
        df = pd.read_csv(csv_file_path)
        print(f"Data loaded. Shape: {df.shape}")

        # Clean column names (remove leading/trailing spaces)
        df.columns = df.columns.str.strip()
        print("Column names cleaned.")

        missing_cols = [col for col in feature_columns if col not in df.columns]
        if missing_cols:
            print(f"Error: Missing required feature columns in CSV: {missing_cols}")
            print(f"Available columns: {list(df.columns)}")
            return None

        df_features = df[feature_columns].copy()  # Avoid SettingWithCopyWarning
        print(f"Selected features. Prediction shape: {df_features.shape}")

        # Replace infinite values and handle NaN
        df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_features.fillna(0, inplace=True)
        df_features = df_features.astype(float)

        print("Making predictions...")
        if df_features.empty:
            print("No data available after preprocessing for prediction.")
            return None

        predictions = model.predict(df_features)
        print("Predictions generated.")

        # Add predictions to the original DataFrame
        df['Prediction'] = predictions

        return df

    except FileNotFoundError:
        print(f"Error: Model file not found at {model_path}")
        return None
    except KeyError as e:
        print(f"Error: A feature column expected by the model was not found: {e}")
        return None
    except Exception as e:
        print(f"An error occurred during prediction: {e}")
        import traceback
        traceback.print_exc()
        return None

# ---------------------------
# UI Code with Tkinter
# ---------------------------

class NetworkPredictionUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Prediction UI")

        # Label and dropdown for interface selection
        tk.Label(self, text="Select Network Interface:").pack(pady=5)
        self.interfaces = ["Ethernet 2", "Wi-Fi", "Loopback"]
        self.interface_var = tk.StringVar(value=self.interfaces[0])
        self.interface_combo = ttk.Combobox(self, textvariable=self.interface_var, values=self.interfaces, state='readonly')
        self.interface_combo.pack(pady=5)

        # Button to start the pipeline
        self.start_button = tk.Button(self, text="Capture and Predict", command=self.start_pipeline)
        self.start_button.pack(pady=10)

        # Status label for progress updates
        self.status_label = tk.Label(self, text="Status: Idle")
        self.status_label.pack(pady=5)

        # Frame for the table (Treeview widget)
        self.table_frame = tk.Frame(self)
        self.table_frame.pack(pady=10, fill="both", expand=True)
        self.tree = None  # Will hold the Treeview widget

    def start_pipeline(self):
        self.start_button.config(state="disabled")
        self.status_label.config(text="Status: Running...")
        threading.Thread(target=self.run_pipeline, daemon=True).start()

    def run_pipeline(self):
        # Create an event loop for this thread to support asyncio-based libraries like PyShark
        asyncio.set_event_loop(asyncio.new_event_loop())

        try:
            # Update these paths as appropriate for your environment:
            cfm_path = r"C:\Users\rites\Python Env\Real-Time-Feature-Extraction-of-Packets-using-CICFLOWMETER\cicflowmeter-4\CICFlowMeter-4.0\bin\cfm.bat"
            input_folder = r"C:\Users\rites\in"
            output_folder = r"C:\Users\rites\out"
            model_path = r"C:\Users\rites\Python Env\ns_v1\random_forest_model.pkl"

            capture_duration = 30  # Duration for packet capture (in seconds)

            # Expected feature list (must match what your model was trained on)
            expected_features = [
                'Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
                'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
                'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
                'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
                'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
                'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
                'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
                'Fwd Header Len', 'Bwd Header Len',
                'Fwd Pkts/s', 'Bwd Pkts/s',
                'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
                'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
                'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
                'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
                'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
                'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg',
                'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
                'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
                'Active Mean', 'Active Std', 'Active Max', 'Active Min',
                'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
            ]

            os.makedirs(input_folder, exist_ok=True)
            os.makedirs(output_folder, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_pcap = os.path.join(input_folder, f"traffic_{timestamp}.pcap")

            if not capture_pcap(self.interface_var.get(), capture_duration, output_pcap):
                self.update_status("Packet capture failed.")
                return

            generated_csv_path = run_cfm(cfm_path, output_pcap, output_folder)
            if not generated_csv_path:
                self.update_status("CICFlowMeter processing failed.")
                return

            predictions_df = predict_with_model(model_path, generated_csv_path, expected_features)
            if predictions_df is None:
                self.update_status("Prediction failed.")
                return

            # Map numerical predictions to string values: 0 => "Normal", 1 => "Port Scan"
            if "Prediction" in predictions_df.columns:
                predictions_df["Prediction"] = predictions_df["Prediction"].replace({0: "Normal", 1: "Port Scan"})

            # Filter DataFrame to show only "Src IP", "Dst IP", "Dst Port" and "Prediction"
            desired_columns = ["Src IP", "Dst IP", "Dst Port", "Prediction"]
            available_columns = [col for col in desired_columns if col in predictions_df.columns]
            if not available_columns:
                self.update_status("Required columns not found in predictions.")
                return
            filtered_df = predictions_df[available_columns]

            # Display the filtered DataFrame in a table format and highlight Port Scan rows
            self.display_predictions_table(filtered_df)
            # Optional: Save the predictions DataFrame to a CSV file
            output_csv_path = os.path.join(output_folder, f"predictions_{timestamp}.csv")
            filtered_df.to_csv(output_csv_path, index=False)
            print(f"Predictions saved to {output_csv_path}")

            self.update_status("Completed successfully.")

        finally:
            self.start_button.config(state="normal")

    def update_status(self, message):
        self.status_label.config(text=f"Status: {message}")

    def display_predictions_table(self, df):
        # Remove any existing table
        if self.tree:
            self.tree.destroy()

        # Create a new Treeview widget with the filtered columns
        self.tree = ttk.Treeview(self.table_frame)
        self.tree["columns"] = list(df.columns)
        self.tree["show"] = "headings"  # Hide default tree column

        # Configure headings and column alignment
        for col in df.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        # Configure a tag for rows with "Port Scan" predictions to be highlighted
        self.tree.tag_configure("port_scan", background="PeachPuff")

        # Insert each row from the filtered DataFrame
        for _, row in df.iterrows():
            if row["Prediction"] == "Port Scan":
                self.tree.insert("", "end", values=list(row), tags=("port_scan",))
            else:
                self.tree.insert("", "end", values=list(row))
        self.tree.pack(fill="both", expand=True)

if __name__ == "__main__":
    app = NetworkPredictionUI()
    app.mainloop()
