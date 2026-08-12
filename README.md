# ⚡️ Zeus Scanner

Zeus Scanner is a clean Cloudflare IP scanner integrated with a real Xray core.

This scanner tests Cloudflare edge IPs using TLS/SNI, evaluates the best candidates with an actual Xray core using a provided configuration, and performs a real speed test from within the tunnel.

---

## 🚀 Installation & Usage

### 💻 Windows (Recommended)
**Requirement:** Python 3 must be installed on the system.

1. Download the project as a ZIP file from [GitHub](https://github.com/panel-zeus/IP-scanner/archive/refs/heads/main.zip) and extract it.
2. Open a Command Prompt or PowerShell in the extracted folder and run:
   ```cmd
   python server.py
   ```
3. The scanner interface will be available at `http://127.0.0.1:8000/`.

*(Note: The required Xray core is already included in the `bin` directory for Windows users, so no additional configuration is needed. If you choose to remove it, the basic IP scanner will still function, but the Xray verification and speed test features will be disabled.)*

### 📱 Android (Termux) & Linux
An automated one-line installer is provided for Linux and Termux environments. It automatically handles dependencies, downloads the appropriate Xray core based on the CPU architecture, and configures the environment.

Run the following command:
```bash
curl -fsSL https://raw.githubusercontent.com/panel-zeus/IP-scanner/main/install.sh | bash
```
Once the installation is complete, start the scanner by running:
```bash
zeus
```
The browser will automatically open `http://127.0.0.1:8000/`.

---

## 🧠 How It Works

### 1. Discovery
A TLS connection is initiated to each IP on selected ports, sending the specific panel SNI.

### 2. HTTP Verification
The response must contain the `cf-ray` or `Server: cloudflare` headers.
Statuses like `403`, `409`, or `429` indicate that the IP is reachable but access is refused; therefore, the IP is discarded.

### 3. Funnel Screening
For large lists (up to 1000 IPs), a rapid initial scan is performed. Only the best candidates are subsequently subjected to multiple precise tests to maintain both speed and accuracy.

### 4. Precise Measurement
Tests are repeated multiple times. Median ping, jitter, and packet loss are calculated independently, alongside TCP and TLS handshake durations.

### 5. Real Xray Testing
For the top-ranking IPs, a real tunnel is established using the provided configuration, and a `generate_204` request is made from within the tunnel. A valid response confirms that the IP successfully routes the configuration.

### 6. Real Speed Test
When the "Speed Test" option is enabled, throughput is measured from within the tunnel using `speed.cloudflare.com`, providing accurate real-world metrics rather than a raw socket test.

**Key detail regarding Xray Testing:**
In the generated test configuration, only the `address` is replaced with the candidate IP; `serverName` and `Host` remain untouched. This ensures all parameters remain constant while only the routing edge changes.

---

## 📂 Project Structure

| File | Description |
|---|---|
| `install.sh` | Automated one-line installer for Termux / Linux |
| `index.html` | User interface |
| `server.py` | Main scanning core and API server |
| `xray.py` | Xray core management, config parsing, tunneling, and speed tests |
| `test_core.py` | Unit tests for verifying logic and preventing bugs |

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ZEUS_PORT` | `8000` | Port used for the web interface |
| `XRAY_BIN` | `./bin/xray` | Path to the Xray core executable |
| `ZEUS_DIR` | `~/zeus-scanner` | Installation directory (Linux/Termux) |
| `ZEUS_XRAY_TAG` | `latest` | Xray release version to download |

---


# 💰 Donate & Support

<p align="center">Built with ❤️</p>

<p align="center"><a href="https://donatonion.ir-netlify.workers.dev"><b>https://donatonion.ir-netlify.workers.dev</b></a></p>

<p align="center">Thank you for your support in keeping this open-source project alive and actively developed! 🙏</p>

---
