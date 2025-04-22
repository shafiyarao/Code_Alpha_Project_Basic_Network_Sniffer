# Enhanced Network Sniffer  

👋 Hi, I’m **@saad-838**  
🔍 A Python-based tool for capturing and analyzing network packets.  

---

### 🌟 Features  
- Capture raw network packets  
- Analyze protocols (TCP, UDP, ICMP, etc.)  
- Resolve DNS names for IP addresses  
- Display packet payloads (optional)  
- Save captured data to a file  
- Generate packet statistics (protocol breakdown, total packets, etc.)  

---

### 🛠️ Usage  

```bash
python sniffer.py [options]
```

#### Options  
- `-p`, `--payload`: Show packet payload  
- `-d`, `--dns`: Resolve DNS names  
- `-o`, `--output`: Save output to a file  

#### Example  
```bash
python sniffer.py --payload --dns --output capture.log
```

---

### 📦 Requirements  
- Python 3.x  
- Administrative privileges (for raw socket operations)  

---

### 📂 Code Structure  
- **EnhancedSniffer Class**: Handles packet capture, parsing, and display.  
- **Main Script**: Parses command-line arguments and initializes the sniffer.  

---

### 📄 Example Output  
```plaintext
2023-10-05 14:30:45.123456 | TCP | 192.168.1.1:54321 -> 192.168.1.2:80  
2023-10-05 14:30:45.234567 | UDP | 192.168.1.2:12345 -> 192.168.1.3:53  
2023-10-05 14:30:45.345678 | ICMP | 192.168.1.1 -> 192.168.1.2  
```

---

### ⚠️ Disclaimer  
This tool is intended for **educational and legitimate network analysis purposes only**. Ensure you have proper authorization before using it on any network.  

---

✨ **Welcome to the Enhanced Network Sniffer!** Feel free to explore, contribute, or reach out for collaboration opportunities.  

<!---
saad-838/saad-838 is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->  
