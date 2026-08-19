🔎 PCAP Analyzer

A Python-based network traffic analysis tool for inspecting PCAP / PCAPNG capture files and identifying useful network and security indicators.

Built for network troubleshooting, traffic analysis, incident investigation, and learning Wireshark-style packet analysis from the command line.

⸻

✨ Features

* 📦 Analyze .pcap and .pcapng capture files
* 🌐 Inspect network conversations and connections
* 🔍 Analyze TCP traffic and connection behavior
* 🔄 Detect TCP retransmissions and suspicious traffic patterns
* 🧩 Analyze ARP traffic and identify possible IP/MAC conflicts
* 🕵️ Identify indicators of potential Man-in-the-Middle activity
* 🔐 TLS traffic analysis
* 📊 Generate a readable security-oriented analysis report
* ⚡ Command-line based and lightweight
* 🐍 Written entirely in Python

⸻

🧠 What does it analyze?

PCAP Analyzer looks at different aspects of captured network traffic, including:

ARP Analysis

Helps identify unusual ARP behavior such as:

* Multiple IP addresses associated with the same MAC
* IP/MAC identity conflicts
* Possible ARP spoofing indicators
* Potential MITM paths

TCP Analysis

Analyzes TCP conversations for indicators such as:

* Retransmissions
* Connection resets
* Abnormal connection behavior
* Packet loss indicators
* TCP connection statistics

TLS Analysis

The TLS engine provides additional inspection of encrypted traffic and can help identify useful metadata and suspicious patterns without decrypting the encrypted payload.

⸻

🚀 Installation

Clone the repository:

git clone git@github.com:NetShell-IR/pcap-analyzer.git
cd pcap-analyzer

Create a virtual environment:

python3 -m venv .venv

Activate it:

macOS / Linux

source .venv/bin/activate

Windows

.venv\Scripts\activate

Install the required dependencies:

pip install -r requirements.txt

⸻

▶️ Usage

Run the analyzer against a capture file:

python3 pcap_analyzer.py capture.pcap

For PCAPNG:

python3 pcap_analyzer.py capture.pcapng

The analyzer processes the capture and produces a security-oriented report containing detected network events and anomalies.

⸻

📁 Project Structure

pcap-analyzer/
│
├── pcap_analyzer.py     # Main PCAP analysis engine
├── tls_engine.py        # TLS traffic analysis
├── requirements.txt     # Python dependencies
├── README.md            # Project documentation
└── .gitignore           # Ignored files

⸻

📊 Example Findings

Depending on the capture, the analyzer may report findings such as:

[HIGH] Possible MITM path reconstructed
[HIGH] MAC address claimed by multiple IPs
[MEDIUM] ARP identity conflict detected
[MEDIUM] High TCP retransmission rate
[INFO] TCP connection reset detected

These findings should be treated as indicators, not automatic proof of an attack. Network conditions such as congestion, packet loss, asymmetric routing, or capture-point limitations can produce similar symptoms.

⸻

🛡️ Use Cases

PCAP Analyzer can be useful for:

* 🔧 Network troubleshooting
* 🕵️ Incident response
* 🔐 Security analysis
* 📡 Network engineering
* 🧪 Security labs
* 🎓 Learning packet analysis
* 🦈 Wireshark-assisted investigations

⸻

⚠️ Important

PCAP Analyzer is an analysis and investigation tool.

The accuracy of detected anomalies depends on the quality and completeness of the captured traffic. Results should always be validated against the surrounding network context.

Only analyze traffic that you are authorized to inspect.

⸻

🗺️ Roadmap

Planned improvements include:

* Improved TLS fingerprinting
* DNS traffic analysis
* HTTP/HTTPS metadata analysis
* Better TCP anomaly detection
* Automated protocol statistics
* JSON report output
* HTML report generation
* IOC extraction
* Command-line arguments and filtering
* Unit tests
* Automated GitHub Actions testing

⸻

🤝 Contributing

Contributions, bug reports, ideas, and improvements are welcome.

If you find a bug or have an idea for a new detection method, feel free to open an issue or submit a pull request.

⸻

📜 License

License information will be added to the project.

⸻

⭐ If you find this project useful

Give the repository a star and follow the project as it evolves.

PCAP Analyzer — Turn packets into evidence.
