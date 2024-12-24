PIA Port Forwarding Script

Overview: This script facilitates Private Internet Access (PIA) VPN users in establishing a WireGuard VPN connection with port forwarding capabilities. It automates server selection, connection setup, and port maintenance, ensuring reliable connectivity. The script now supports external configuration via an .ini file, enhancing flexibility and usability.

Features:

- Establishes a WireGuard VPN connection to PIA servers.
- Automatically configures port forwarding using PIA's API.
- Supports Dedicated IP (DIP) and region-based server selection modes.
- Reads configuration from an external piaplus_config.ini file.
- Periodically refreshes port binding in the background to maintain connectivity.
- Lists all available PIA servers that support WireGuard and port forwarding.
- Pings and selects the best VPN server based on latency.
- Automatically disables IPv6 for enhanced privacy.
- Configures Transmission to use the forwarded port.
- Provides comprehensive logging for debugging.

Prerequisites:

- Python 3.6+ installed on the system (tested with Python 3.11.2).
- Required Python dependencies:
  - requests
  - urllib3
- Access to a Private Internet Access (PIA) account with WireGuard and port forwarding support.
- System commands installed:
  - wg, wg-quick, sysctl, tee, ping, awk, xargs
- Root privileges to manage WireGuard interfaces and configure system settings.

Setup Instructions:

1. Clone this repository to your system.

2. Place the piaplus.py script and ca.rsa.4096.crt certificate file in the same directory.

3. Create a configuration file named piaplus_config.ini in the same directory with the following sections and keys:

  [PIA]
  DIP = true
  DIP_TOKEN = your_dip_token
  PIA_USERNAME = your_username
  PIA_PASSWORD = your_password
  PIA_REGION = region_id
  
  [General]
  TRANSMISSION_ENABLED = true
  AUTODISCONNECT = true
  
  [Network]
  MAX_SERVERS_FAILED_ATTEMPTS = 3
  SERVERS_REQUESTS_COUNT = 5
  RPC_CERT_FILE = ca.rsa.4096.crt
  
  [Logging]
  DEFAULT_LOG_LEVEL = INFO

4. Install the required Python dependencies:
  pip install requests urllib3

5. Run the script with:
  sudo python3 piaplus.py

Usage:

- Run in foreground mode to establish a new connection and configure port forwarding:
  sudo python3 piaplus.py
  
- List all available PIA servers supporting WireGuard and port forwarding:
  python3 piaplus.py --list-servers

Logging:

- The script logs its activity to piaplus.log for easy troubleshooting.
- Logs include detailed information about server selection, API interactions, and connection status.

Additional Notes:

- Ensure the script runs with root privileges to manage WireGuard interfaces.
- To stop the VPN connection, use:
  sudo wg-quick down pia
- Keep your PIA credentials and tokens secure.
  
Support: For issues or enhancements, please submit a GitHub issue in this repository or contact the developer.

Disclaimer: This script is provided as-is without warranty. Use it at your own risk.
