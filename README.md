# 🕵️‍♂️ TorTraceAnalyzer
### Automated Multi-Layer Forensic Suite for Tor Activity Detection

**TorTraceAnalyzer** is a modular forensic engine designed to identify, correlate, and report Tor Browser activity across a target system. Unlike basic scanners, this suite performs **Behavioral Analysis** by cross-referencing artifacts from memory, filesystem, and network logs to detect **Unusual Tor Activity**

---

## 🚀 Key Features

* **4-Layer Forensic Engine:** Deep-dive analysis across Memory, System, Network, and Application layers.
* **Correlation:** Automated identification of high-risk patterns (e.g., simultaneous file compression and Tor network activity).
* **Forensic Confidence Index (FCI):** A weighted mathematical determination of suspect activity.
* **Dynamic Timeline Reconstruction:** Rebuilds an investigation timeline using internal metadata timestamps extracted directly from evidence reports.
* **Agnostic Report Ingestion:** Compatible with output from industry-standard tools including **Autopsy, Volatility, FTK Imager, and Wireshark**.
* **Modern Investigative HUD:** A responsive, glass-morphism dashboard built for high-contrast visibility in forensic environments.

---

## 📦 Standalone Executable (Windows)

For forensic investigators who require a portable, zero-install solution, a standalone executable is available. This version bundles all dependencies and the engine into a single file.

1.  Navigate to the **[Releases](https://github.com/Rady0-0/TorTraceAnalyzer/releases)** tab.
2.  Download the latest `TorTraceAnalyzer_v2.exe`.
3.  Launch the application. No Python installation or environment setup is required.

> **Note:** As this is an unsigned forensic tool, Windows Defender may flag it. You can safely click **"More Info" -> "Run Anyway"** to start the suite.

---

## 📊 Forensic Methodology

The suite scavenges for "Smoking Gun" artifacts across four critical investigative layers:

1.  **Memory Layer:** Identifies volatile traces including core Tor processes (`tor.exe`), parent browsers, and bridge proxies (`obfs4proxy`).
2.  **System Layer:** Extracts execution history from **Windows Prefetch**, **UserAssist**, and identifies delivery methods via **Removable Media (USB)** logs.
3.  **Network Layer:** Detects standard SOCKS proxy ports (9050/9150) and generic **VPN/Tunneling interfaces** (TAP/TUN adapters).
4.  **Application Layer:** Parses browser-specific configuration files (`settings.json`) and history databases (`places.sqlite`).

---

## 📈 The FCI Scoring System

To assist investigators, the tool calculates a **Forensic Confidence Index (FCI)**. This score is a weighted average of detections across all four layers, providing a definitive investigative determination:

$$FCI = \left( \frac{\sum (Weight_i \times Detected_i)}{\sum Weight_i} \right) \times 100$$

* **0-30%:** Inconclusive Activity
* **31-70%:** Probable Tor Usage
* **71-100%:** Conclusive Evidence of Tor Activity

---

## 🛠️ Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Rady0-0/TorTraceAnalyzer.git](https://github.com/Rady0-0/TorTraceAnalyzer.git)
    cd TorTraceAnalyzer
    ```
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Launch the Suite:**
    ```bash
    python gui.py
    ```

---

## 📸 Dashboard Preview
![Dashboard](screenshot.png) 
*Version 2.0 featuring high-tech floating panels and multi-layer artifact highlighting.*

---

## 📂 Project Structure

* `main.py`: The central forensic engine and correlation logic.
* `gui.py`: Modern HUD interface for evidence ingestion.
* `artifact_correlation.py`: The behavioral analysis "brain."
* `file_parser.py`: Universal evidence ingestion module.
* `report_generator.py`: Automated evidence documentation.

---

## ⚖️ Disclaimer

*This tool was developed as part of a BSc Digital Forensics major project. It is intended for educational and authorized investigative use only. The developers assume no liability for unauthorized analysis or misuse of this software.*