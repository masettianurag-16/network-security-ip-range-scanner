# Network Security IP Range Scanner

A lightweight, beginner-friendly web application designed for educational network host discovery and security lab exercises. Built with **Python**, **Flask**, **HTML5**, **CSS3**, and **Vanilla JavaScript**.

---

## 📌 Table of Contents

1. [Project Overview](#-project-overview)
2. [Problem Statement](#-problem-statement)
3. [Objectives](#-objectives)
4. [Features Implemented](#-features-implemented)
5. [Technologies & Libraries Used](#-technologies--libraries-used)
6. [Project Folder Structure](#-project-folder-structure)
7. [Installation & Setup](#-installation--setup)
8. [How to Run the Application](#-how-to-run-the-application)
9. [How the Code Works](#-how-the-code-works)
10. [Testing & Verification](#-testing--verification)
11. [Screenshots](#-screenshots)
12. [Security Considerations & Limitations](#-security-considerations--limitations)
13. [Future Improvements](#-future-improvements)
14. [Responsible-Use Disclaimer](#-responsible-use-disclaimer)

---

## 🌐 Project Overview

The **Network Security IP Range Scanner** is an educational, browser-based reconnaissance tool designed to demonstrate fundamental network discovery techniques in authorized lab environments.

In computer networking and defensive cybersecurity, **host discovery** (commonly known as *ping sweeping*) is the primary step used by network administrators and security auditors to map active systems across a subnet. This tool provides an intuitive, interactive dashboard that probes a user-specified IPv4 address range or CIDR subnet, reports device responsiveness in real time, measures round-trip latency, and visualizes network health metrics.

---

## ❗ Problem Statement

When learning networking and cybersecurity:
1. **The "Black Box" Problem**: Beginners often rely on automated tools like Nmap without understanding how lower-level protocols (such as ICMP Echo Requests and Replies) operate or how operating systems handle network probes.
2. **The Loopback Misconception**: Students frequently test scanners against local addresses (such as `127.0.0.1`–`127.0.0.5`) and assume all five IP addresses correspond to distinct machines, unaware that the local OS kernel intercepts and answers for the entire `127.0.0.0/8` loopback block.
3. **Firewall Ambiguity**: When an address fails to reply to a ping, students often mistakenly assume the machine is powered off, overlooking that host firewalls (like Windows Defender Firewall) routinely drop unsolicited ICMP requests by default.

This project addresses these gaps by offering a transparent, local, and educational scanner that clearly distinguishes between **ACTIVE** replies and **NO RESPONSE** states while providing informative context on loopback routing and firewall behavior.

---

## 🎯 Objectives

- **Educational Clarity**: Demystify network host discovery through clean, readable code and clear status definitions.
- **Strict Input Validation**: Enforce rigorous IPv4 syntax verification, range boundaries, and safe host ceilings to prevent network disruption.
- **Accurate Status Representation**: Distinguish between confirmed active hosts (`ACTIVE`) and non-responsive targets (`NO RESPONSE`) without making false assumptions about host power state.
- **Real-Time Visual Feedback**: Use asynchronous Server-Sent Events (SSE) to display scan progress, live latency, and dynamic summary cards.
- **Safe & Ethical Architecture**: Ensure zero stealth, exploitation, or bypass capabilities, keeping the tool strictly defensive and educational.

---

## ✨ Features Implemented

### 1. Dual Input Modes
- **IP Range Mode**: Specify a custom start and end IPv4 address (e.g., `192.168.1.1` to `192.168.1.10`).
- **CIDR Subnet Mode**: Enter standard Classless Inter-Domain Routing notation (e.g., `192.168.1.0/28`).

### 2. Comprehensive Input Validation & Safety Bounds
- Validates IPv4 syntax using Python's built-in `ipaddress` library.
- Ensures Start IP is less than or equal to End IP.
- Enforces a safety ceiling of **254 hosts per scan** (`MAX_HOSTS_PER_SCAN = 254`) to prevent local denial of service or network congestion.
- Sanitizes input errors and presents clear, user-friendly error banners without exposing technical stack traces.

### 3. Safe Cross-Platform Host Discovery Engine
- Uses operating system-level ICMP Echo Requests with bounded timeouts (default: 800 ms).
- **Windows**: `ping -n 1 -w 800 <ip>`
- **Linux / macOS**: `ping -c 1 -W 1 <ip>`
- Subprocess arguments are passed as parameterized lists (avoiding `shell=True`) to prevent command injection vulnerabilities.
- Accurately parses Windows ping output to differentiate legitimate host replies from router-generated "Destination host unreachable" messages.

### 4. Real-Time Streaming & Live Progress
- Integrates **Server-Sent Events (SSE)** via `/api/scan/stream`.
- Displays real-time progress text (`Scanning host 3 of 10...`) and a dynamic CSS progress bar.
- Streams individual host results directly into the table as each probe completes, without waiting for the entire batch to finish.

### 5. Clear Status Classification
- **ACTIVE**: Host returned an ICMP Echo Reply within the timeout; round-trip latency (e.g., `< 1 ms`, `12 ms`) is displayed.
- **NO RESPONSE**: Probe timed out or was dropped. Educational notes explain that this may be caused by a host firewall or an offline device.
- **ERROR**: Network interface failure or probe execution issue.

### 6. Interactive Summary & Results Management
- **Summary Cards**: Instantly displays Target Range, Total Scanned, Active count, No Response count, and Errors.
- **Clear Results**: A dedicated button instantly halts active scans, wipes table data, resets metrics, and returns the UI to its initial state.
- **Quick-Fill Presets**: Convenient buttons for single-host testing (`127.0.0.1`), local subnet ranges (`192.168.1.1`–`192.168.1.5`), and CIDR subnets (`192.168.1.0/28`).

### 7. Educational UI & Loopback Guidance
- Displays a dedicated notice explaining why `127.0.0.x` addresses are loopback addresses and advises testing authorized local subnets to see both active and non-responsive hosts.
- Responsive dark-mode cybersecurity theme with accessible typography and clean status badges.

---

## 🛠️ Technologies & Libraries Used

### Backend
- **Python 3.10+** (Core programming language)
- **Flask (v3.1.x)**: Lightweight WSGI web framework handling routing, request parsing, and template rendering.
- **Python Standard Library**:
  - `ipaddress`: Parses, validates, and calculates IPv4 ranges and CIDR subnets.
  - `subprocess`: Executes native OS ping commands safely with strict argument lists.
  - `concurrent.futures.ThreadPoolExecutor`: Provides bounded multi-threading (up to 15 concurrent workers) for responsive scans.
  - `platform`: Detects the host operating system to supply the appropriate ping syntax.
  - `re`: Extracts round-trip latency values from ping standard output.
  - `json`: Serializes streaming payloads for Server-Sent Events and REST responses.
  - `unittest`: Implements the automated test suite.

### Frontend
- **HTML5**: Semantic document structure with accessible form controls and ARIA attributes.
- **CSS3**: Custom cybersecurity dark theme (deep slate palette, monospace IP typography, CSS grid and flexbox, animated progress indicators).
- **Vanilla JavaScript**: Intercepts form submissions, manages the `EventSource` API for real-time SSE streaming, and handles UI resets without third-party JS libraries.

---

## 📁 Project Folder Structure

```
network-security-ip-range-scanner/
│
├── app.py                  # Flask application: routes, validation, and multithreaded discovery engine
├── requirements.txt        # Project dependencies (Flask>=3.0.0)
├── README.md               # Comprehensive project documentation
│
├── static/
│   └── style.css           # Custom cybersecurity dark-theme stylesheet
│
├── templates/
│   └── index.html          # Front-end dashboard template with inline SSE controller
│
└── tests/
    └── test_scanner.py     # Automated unit and integration test suite (12 test cases)
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.10 or higher installed on your system.
- `pip` (Python package installer) available.

### Step 1: Open Terminal / PowerShell
Navigate to the project root directory:
```powershell
cd "c:\Users\ABHILASH\OneDrive\Documents\IP range Scanner"
```

### Step 2: Create a Virtual Environment (Recommended)
Creating an isolated environment keeps dependencies clean:
```powershell
# On Windows:
python -m venv venv
.\venv\Scripts\Activate.ps1

# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
Install Flask from the `requirements.txt` file:
```powershell
pip install -r requirements.txt
```

---

## 🚀 How to Run the Application

1. Start the Flask server:
   ```powershell
   python app.py
   ```
2. The terminal will display the startup banner:
   ```
   ============================================================
    Network Security IP Range Scanner
    Educational and Authorized Testing Only
    Running at: http://127.0.0.1:5000
   ============================================================
    * Serving Flask app 'app'
    * Debug mode: off
    * Running on http://127.0.0.1:5000
   ```
3. Open any modern web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 🔍 How the Code Works

### Architecture Flow

```
[ Web Browser ]
      │
      ├── 1. Submit Range / CIDR (AJAX or EventSource)
      ▼
[ Flask App (app.py) ]
      │
      ├── 2. validate_and_generate_ips() ─── Validates IPv4 & ensures <= 254 hosts
      │
      ├── 3. ThreadPoolExecutor (max_workers=15)
      │         │
      │         ├── Worker 1: ping_host("192.168.1.1") ──> subprocess.run(["ping", ...])
      │         ├── Worker 2: ping_host("192.168.1.2") ──> subprocess.run(["ping", ...])
      │         └── Worker N: ping_host(...)
      │
      ├── 4. Server-Sent Events (SSE) Stream (/api/scan/stream)
      ▼
[ Client-side JavaScript ]
      │
      └── 5. Updates Progress Bar, appends rows to Table, updates Summary Cards
```

### Key Components

1. **Input Validation (`validate_and_generate_ips`)**:
   - In **Range Mode**, converts both Start and End strings to `ipaddress.IPv4Address` instances. Verifies that `int(start) <= int(end)` and ensures the host count does not exceed 254.
   - In **CIDR Mode**, parses the string using `ipaddress.IPv4Network(cidr, strict=False)`. Automatically skips broadcast and network IDs on standard subnets while correctly handling `/31` and `/32` networks.

2. **Probe Execution (`ping_host`)**:
   - Detects the operating system using `platform.system()`.
   - Executes the native ping command via `subprocess.run()` with a strict 800 ms timeout.
   - **Windows Reply Verification**: On Windows, pinging an unresponsive host on a local subnet often returns exit code 0 because the local gateway sends an ICMP Host Unreachable reply (`Reply from 192.168.1.1: Destination host unreachable`). The function verifies that:
     - The output contains `reply from <target_ip>`
     - The output contains payload indicators (`bytes=` or `ttl=`)
     - The output does *not* contain `unreachable`, `timed out`, or `failure`

3. **Concurrency & Real-Time Streaming (`execute_scan` & `api_scan_stream`)**:
   - Probes are distributed across a `ThreadPoolExecutor` bounded to 15 workers. This allows scanning 20–50 hosts in seconds without overloading the network stack.
   - The `/api/scan/stream` endpoint streams chunked HTTP data formatted as `event: progress` for each completed host, concluding with `event: complete` delivering final metrics.

4. **Front-End DOM Controller (`index.html`)**:
   - An event listener catches the form submission, prevents page reload, initializes an `EventSource`, dynamically constructs table rows with styled badges, and updates summary cards.
   - A non-JavaScript fallback (`POST /scan`) is also built into the backend to render results server-side if JavaScript is disabled.

---

## 🧪 Testing & Verification

An automated test suite is provided in `tests/test_scanner.py`, containing **12 unit and integration tests** covering input validation, error handling, probe accuracy, and route availability.

### Running the Test Suite
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### Test Cases Covered

| Test Name | Description | Status |
|---|---|:---:|
| `test_a_valid_ip_range` | Verifies sequential generation of addresses from a valid range | Passed |
| `test_b_invalid_ip_address` | Verifies rejection of invalid octets (e.g., `192.168.1.abc`, `999.1.1.1`) | Passed |
| `test_c_empty_input` | Verifies clear error handling for blank fields | Passed |
| `test_d_start_greater_than_end` | Rejects inverted ranges (e.g., `192.168.1.50` to `192.168.1.10`) | Passed |
| `test_e_excessively_large_range` | Rejects scan requests exceeding the 254-host limit | Passed |
| `test_f_valid_and_invalid_cidr` | Verifies `/29` expansion (6 usable hosts) and malformed CIDR rejection | Passed |
| `test_localhost_probe` | Tests actual ICMP probe on `127.0.0.1` and confirms `ACTIVE` status | Passed |
| `test_compute_summary` | Verifies calculation of Active, No Response, and Error totals | Passed |
| `test_home_page_renders_warning` | Confirms the home route renders the legal warning and loopback notice | Passed |
| `test_api_scan_localhost_range` | Tests the JSON POST endpoint on `127.0.0.1` | Passed |
| `test_api_scan_invalid_range` | Confirms invalid ranges return HTTP 400 with no stack traces | Passed |
| `test_sse_stream_scan_localhost` | Verifies the Server-Sent Events stream yields progress and completion | Passed |

---

## 📷 Screenshots

> *Below are UI representations of the application. Replace the placeholders with actual screenshots from your lab environment when showcasing on GitHub.*

### 1. Main Dashboard & Configuration
<img width="1877" height="952" alt="image" src="https://github.com/user-attachments/assets/2ddd221a-2bd3-4004-a071-bed887279676" />
<img width="1883" height="947" alt="image" src="https://github.com/user-attachments/assets/9c1d983d-46a4-458e-a8e0-d847ce7da34d" />
<img width="1881" height="925" alt="image" src="https://github.com/user-attachments/assets/8c7c6a1e-1bb3-49af-a866-e2b46734c80d" />


### 2. Live Scan in Progress
<img width="1885" height="953" alt="image" src="https://github.com/user-attachments/assets/ee403658-db70-4bca-af64-410760578189" />


### 3. Scan Results & Summary Metrics
<img width="1883" height="945" alt="image" src="https://github.com/user-attachments/assets/011c336f-3947-4659-88bf-cbc3ffdd7219" />
<img width="1878" height="887" alt="image" src="https://github.com/user-attachments/assets/66317e07-c0ba-43f5-906e-8aaf7b1fb6a5" />

---

## 🔒 Security Considerations & Limitations

### Built-in Security Controls
- **Safe Command Invocation**: Commands are invoked using Python list arguments (`["ping", "-n", "1", ip]`), entirely avoiding shell interpolation (`shell=False`) to prevent command injection.
- **Resource Protection**: The 254-host limit and 15-worker concurrency ceiling prevent CPU exhaustion, socket starvation, and accidental broadcast storms.
- **Information Disclosure Prevention**: Internal application errors are captured gracefully; raw Python tracebacks are never exposed to the web client.

### Technical Limitations
- **ICMP Packet Filtering**: Modern firewalls (such as Windows Defender Firewall) routinely drop inbound ICMP Echo Requests. An active host with an enabled firewall will be reported as **`NO RESPONSE`**.
- **Loopback Behavior**: Probing `127.0.0.x` ranges will always report every address as `ACTIVE` because the local OS kernel answers for the entire loopback subnet. A physical or virtual network interface must be targeted to observe non-responsive addresses.
- **No Port Scanning / Fingerprinting**: By intentional educational design, this application does not perform TCP port scanning, banner grabbing, OS detection, or service enumeration.

---

## 🔮 Future Improvements

- [ ] **Optional TCP Connect Check**: Provide an optional fallback probe that tests common benign ports (e.g., 80, 443) when ICMP is blocked by a firewall.
- [ ] **Reverse DNS Resolution**: Display associated hostnames alongside IP addresses using Python's `socket.gethostbyaddr`.
- [ ] **Export Functionality**: Enable users to download scan results as CSV or JSON reports for lab assignments.
- [ ] **IPv6 Support**: Add support for scanning authorized local IPv6 subnets (`/120` or `/124`).
- [ ] **Theme Toggle**: Include a toggle between Dark and Light mode for different presentation settings.

---

## ⚖️ Responsible-Use Disclaimer

> **FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY**  
> This software is created solely for learning and authorized laboratory exercises. **Do not** scan networks or systems without explicit, prior authorization from the network owner. Scanning unauthorized systems may violate computer misuse laws, institutional policies, and terms of service. The author accepts no liability for misuse or damage caused by this software.
