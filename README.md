# AEGIS

**AEGIS** is a standalone native desktop application and research prototype for real-time network intrusion detection, quantitative GRC risk analysis, and explainable AI auditing in Internet of Medical Things (IoMT) environments.

## Overview

AEGIS Desktop is designed as a native, zero-browser security analysis platform for macOS and Windows.

The application uses **CustomTkinter** for its desktop interface and **ONNX Runtime** for direct, in-memory machine learning inference. By removing the need for a local web server or browser-based interface, AEGIS provides a lightweight execution environment suitable for security analysis and research.

Beyond intrusion detection, the platform extends the traditional classification workflow with **quantitative governance, risk, and compliance (GRC) analysis** and **explainable artificial intelligence (XAI)**. Detection results can be translated into measurable risk using the **CIA triad** while TreeSHAP-based feature attribution provides an interpretable audit trail for individual predictions.

The project is intended as a research prototype for cybersecurity applications involving **IoMT infrastructures**, particularly environments where security incidents can have significant implications for confidentiality, integrity, and availability.

## Key Features

### Native Desktop Architecture

* Runs as a standalone desktop application on the operating system.
* Does not require a web browser.
* Does not require a local web server or background application ports.
* Uses CustomTkinter for native window rendering.

### Network Intrusion Detection

* Supports raw network traffic captures in `.pcap` and `.pcapng` formats.
* Supports structured telemetry datasets in `.csv` format.
* Uses Scapy for packet parsing and network flow aggregation.
* Performs machine learning inference directly in memory through ONNX Runtime.
* Uses an optimized ONNX classification model for efficient execution.

### Quantitative GRC Risk Analysis

* Converts intrusion detection results into measurable security risk scores.
* Evaluates potential impact across the **Confidentiality, Integrity, and Availability (CIA)** triad.
* Provides a quantitative perspective on detected threats rather than relying solely on classification labels.
* Designed with critical medical and IoMT infrastructure in mind.

### Explainable AI and Compliance Auditing

* Uses **TreeSHAP** to identify the features contributing to individual model predictions.
* Provides local feature attribution for greater model transparency.
* Generates audit information that can be used to analyze and document security decisions.
* Supports research into explainable cybersecurity systems and regulatory compliance contexts such as **LGPD** and **HIPAA**.

### Security Operations Interface

* Provides a piano-black operator interface designed for security operations workflows.
* Uses a minimal dark visual language to prioritize telemetry and threat information.
* Includes an integrated researcher profile accordion.
* Designed to keep detection, risk analysis, and explainability within a single interface.

## Technology Stack

| Component                | Technology      |
| ------------------------ | --------------- |
| Desktop UI               | CustomTkinter   |
| Machine Learning Runtime | ONNX Runtime    |
| Machine Learning         | Scikit-learn    |
| Explainable AI           | TreeSHAP / SHAP |
| Network Processing       | Scapy           |
| Data Processing          | Pandas          |
| Model Format             | ONNX            |
| Application Packaging    | PyInstaller     |
| Development Language     | Python          |

## Project Structure

## Project Structure
```text
AEGIS/
├── assets/
│   ├── aegisicon.icns
│   └── aegisicon.png
├── backend/
│   ├── benchmark.py
│   ├── grc.py (Quantitative GRC risk and CIA triad scoring)
│   ├── main.py
│   ├── model.py (ONNX Runtime feature mapping and inference logic)
│   ├── parser.py (Scapy packet parser and flow aggregator)
│   └── xai.py (TreeSHAP local feature attribution and audit generation)
├── data/
│   └── aegis_dataset_sample.csv
├── frontend/
│   └── app.py (CustomTkinter native desktop UI controller)
├── models/
│   └── aegis_ciciomt_model.onnx
├── testbed/
│   └── topology.py
├── .gitignore
├── aegis.spec
├── pyproject.toml
├── README.md
└── uv.lock
```

### Backend

* `benchmark.py` — Model benchmarking and evaluation utilities.
* `grc.py` — Quantitative GRC risk calculation and CIA triad scoring.
* `main.py` — Core application and backend logic.
* `model.py` — Feature mapping and machine learning inference logic using ONNX Runtime.
* `parser.py` — Scapy-based packet parsing and network flow aggregation.
* `xai.py` — TreeSHAP feature attribution and explainability audit generation.

### Frontend

* `app.py` — CustomTkinter native desktop interface and application controller.

### Data

* `aegis_dataset_sample.csv` — Sample network telemetry dataset used for testing and analysis.

### Models

* `aegis_ciciomt_model.onnx` — Optimized ONNX classification model used for inference.

### Assets

* `aegisicon.png` — Source branding asset.
* `aegisicon.icns` — Native macOS application dock icon.

### Testbed

* `topology.py` — Network testbed topology configuration and experimentation setup.

### Project Configuration

* `aegis.spec` — PyInstaller multi-module build configuration.
* `pyproject.toml` — Python project and dependency configuration.
* `uv.lock` — Locked dependency versions for reproducible environments.

## Running from Source

### 1. Install Dependencies

Install the required Python packages:

```bash
pip install customtkinter pandas scikit-learn onnxruntime shap scapy pyinstaller
```

### 2. Run the Application

Start the AEGIS desktop interface:

```bash
python3 frontend/app.py
```

The application should open as a native desktop window.

## Building the Application

AEGIS uses **PyInstaller** to package the application into a standalone executable.

### 1. Clean Previous Builds

```bash
rm -rf dist build
```

### 2. Build Using the Spec File

```bash
pyinstaller aegis.spec --clean
```

### 3. Locate the Application

The generated standalone application will be available inside the:

```text
dist/
```

directory.

On macOS, the result is packaged as a native `.app` application. On Windows, PyInstaller generates the corresponding executable package.

## Research Context

AEGIS is part of research into the application of machine learning and explainable artificial intelligence to cybersecurity in **Internet of Medical Things (IoMT)** environments.

The project explores the combination of:

* Network intrusion detection
* Machine learning inference
* Network traffic analysis
* Quantitative cybersecurity risk assessment
* CIA triad-based impact analysis
* Explainable AI
* Compliance-oriented audit trails
* IoMT

The objective is to move beyond simple threat classification by connecting **detection, risk quantification, and model explainability** within a single security analysis workflow.

## Author

**Ygor Gesteira**

Master's Researcher at **Instituto Federal da Paraíba (IFPB)**

Research focus: machine learning applications for cybersecurity in Internet of Medical Things (IoMT) environments.
