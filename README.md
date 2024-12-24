PIA Port Forwarding Script

Overview: This script is designed for Private Internet Access (PIA) VPN users who need to establish a WireGuard VPN connection with port forwarding capabilities. It automates the process of configuring and maintaining port forwarding, ensuring reliable connectivity, and integrates with tools like Transmission.

Features:

Establishes a WireGuard VPN connection to PIA servers.
Automatically configures port forwarding using PIA’s API.
Supports Dedicated IP (DIP) and region-based server selection modes.
Periodically refreshes port bindings in the background to maintain connectivity.
Selects the best VPN server based on latency using ICMP ping.
Automatically disables IPv6 for enhanced privacy.
Configures Transmission to use the forwarded port (optional).
Logs all activity and errors for easy debugging.
Reads configuration from an external ini file for flexibility.
Prerequisites:

Python 3.6+ installed (tested with Python 3.11.2).
Required Python Dependencies: requests, urllib3.
System Requirements:
Access to a Private Internet Access (PIA) account with WireGuard and port forwarding support.
The following system commands installed: wg, wg-quick, sysctl, tee, ping, awk, xargs.
Root Privileges required to manage WireGuard interfaces and configure system settings.
Setup Instructions:

Clone this repository to your system: git clone https://github.com/egoleos/piaplus.git
Install the required Python dependencies: pip install requests urllib3.
Edit the piaplus_config.ini file:
Set your PIA credentials (PIA_USERNAME, PIA_PASSWORD).
Specify your desired server region in PIA_REGION.
Optionally, provide a DIP_TOKEN for Dedicated IP support.
Run the script with: sudo python3 piaplus.py.
Usage: Run in foreground mode to establish a new connection and configure port forwarding: sudo python3 piaplus.py.

To run in background mode and maintain port bindings periodically, use the --background flag.

To display all available PIA servers that support WireGuard and port forwarding, use: python3 piaplus.py --list-servers.

Logging: All script activity is logged to piaplus.log for easy troubleshooting. Logs include detailed information about server selection, API interactions, and connection status.

Additional Notes:

The script must run with root privileges to manage WireGuard interfaces.
To stop the VPN connection, use: sudo wg-quick down pia.
Ensure your PIA credentials and tokens remain private for security purposes.
Support: For issues or enhancements, submit a GitHub issue in this repository or contact the developer.

Disclaimer: This script is provided "as-is" without any warranties. Use it at your own risk.
