#!/usr/bin/env python3
import argparse, base64, json, os, re, socket, ssl, subprocess, sys, time, types, urllib.parse, configparser, logging, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from requests.adapters import HTTPAdapter
from socket import error as SocketError, timeout as SocketTimeout
from typing import Dict, List, Optional, Tuple
from urllib3 import PoolManager
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import connection as urllib3_connection

# ====================== Load and Read Configuration ======================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "piaplus_config.ini")
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

DIP = config.getboolean('PIA', 'DIP')
DIP_TOKEN = config.get('PIA', 'DIP_TOKEN')
PIA_USERNAME = config.get('PIA', 'PIA_USERNAME')
PIA_PASSWORD = config.get('PIA', 'PIA_PASSWORD')
PIA_REGION = config.get('PIA', 'PIA_REGION')

TRANSMISSION_ENABLED = config.getboolean('General', 'TRANSMISSION_ENABLED')
AUTODISCONNECT = config.getboolean('General', 'AUTODISCONNECT')

MAX_FAILED_ATTEMPTS = config.getint('Network', 'MAX_SERVERS_FAILED_ATTEMPTS')
REQUESTS_COUNT = config.getint('Network', 'SERVERS_REQUESTS_COUNT')
RPC_CERT_FILE = config.get('Network', 'RPC_CERT_FILE')

DEFAULT_LOG_LEVEL = config.get('Logging', 'DEFAULT_LOG_LEVEL')

SERVERS_DB_FILE = os.path.join(SCRIPT_DIR, "piaplus_db.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "piaplus.log")
PID_FILE = "/var/run/piaplus.pid"

# ====================== Logging Configuration ======================
def configure_logging(level: str) -> logging.Logger:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s [%(levelname)s]: %(message)s',
        handlers=[
            logging.StreamHandler(),
            RotatingFileHandler(LOG_FILE, maxBytes=10**6, backupCount=5)
        ]
    )
    return logging.getLogger(__name__)

logger = configure_logging(DEFAULT_LOG_LEVEL)
session = requests.Session()

# ====================== Classes for Forced IP HTTPS ======================
class ForcedIpHttpsConnection(HTTPSConnection):
    def __init__(self, *args, dest_ip: Optional[str] = None, server_hostname: Optional[str] = None, **kwargs):
        self.dest_ip = dest_ip
        self.server_hostname = server_hostname
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        try:
            logger.debug(f"Establishing HTTPS connection to {self.dest_ip or self.host} with SNI {self.server_hostname}")
            self.sock = self._new_conn()
            self.sock.settimeout(self.timeout)
            self.ssl_context = ssl.create_default_context()
            if self.server_hostname:
                self.sock = self.ssl_context.wrap_socket(self.sock, server_hostname=self.server_hostname)
            else:
                self.sock = self.ssl_context.wrap_socket(self.sock)
            self._validate_conn()
            logger.debug("HTTPS connection established successfully.")
        except Exception as e:
            logger.error(f"Failed to establish forced HTTPS connection: {e}")
            raise e

class ForcedIpHttpsConnectionPool(HTTPSConnectionPool):
    def __init__(self, host: str, port: int, dest_ip: str, server_hostname: str, **kwargs):
        super().__init__(host, port, **kwargs)
        self.dest_ip = dest_ip
        self.server_hostname = server_hostname

    def _new_conn(self) -> HTTPSConnection:
        conn = super()._new_conn()
        conn.dest_ip = self.dest_ip
        conn.server_hostname = self.server_hostname
        return conn

class ForcedIpHttpsPoolManager(PoolManager):
    def __init__(self, num_pools: int, maxsize: int, block: bool, dest_ip: str, server_hostname: str, **kwargs):
        super().__init__(num_pools=num_pools, maxsize=maxsize, block=block, **kwargs)
        self.dest_ip = dest_ip
        self.server_hostname = server_hostname

    def _new_pool(self, scheme: str, host: str, port: int, request_context=None) -> HTTPSConnectionPool:
        assert scheme == 'https'
        return ForcedIpHttpsConnectionPool(
            host, 
            port, 
            dest_ip=self.dest_ip, 
            server_hostname=self.server_hostname, 
            **self.connection_pool_kw
        )

class ForcedIpHttpsAdapter(HTTPAdapter):
    def __init__(self, dest_ip: str, server_hostname: str, *args, **kwargs):
        self.dest_ip = dest_ip
        self.server_hostname = server_hostname
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs):
        self.poolmanager = ForcedIpHttpsPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            dest_ip=self.dest_ip,
            server_hostname=self.server_hostname,
            **pool_kwargs
        )

# ====================== Root Check Function ======================
def ensure_root():
    if os.geteuid() != 0:
        logger.info("Script is not running as root, attempting to relaunch with sudo...")
        try:
            subprocess.check_call(["sudo", sys.executable] + sys.argv)
        except subprocess.CalledProcessError as e:
            logger.info(f"Failed to relaunch with sudo: {e}")
            sys.exit(1)
        sys.exit(0)

# ====================== Utility and DB Functions ======================
def exit_with_error(message: str) -> None:
    logger.error(message)
    teardown_wireguard_interface('pia')
    sys.exit(1)

def json_to_namespace(s: str) -> types.SimpleNamespace:
    return json.loads(s, object_hook=lambda d: types.SimpleNamespace(**d))

def execute_command(cmd: List[str], check: bool = False, capture_output: bool = True,
                    input_data: Optional[str] = None, **kwargs) -> Optional[str]:
    logger.debug(f"Executing command: {' '.join(cmd)}")
    try:
        res = subprocess.run(
            cmd,
            check=check,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            text=True,
            input=input_data,
            **kwargs
        )
        if capture_output and res.stdout:
            logger.debug(f"Command output: {res.stdout.strip()}")
        return res.stdout.strip() if capture_output and res.stdout else None
    except FileNotFoundError:
        exit_with_error(f'Command not found: {cmd[0]}')
    except subprocess.CalledProcessError as e:
        logger.error(f'Command "{" ".join(cmd)}" failed with code {e.returncode}: {e.stderr}')
        exit_with_error(f'Command "{" ".join(cmd)}" failed with return code {e.returncode}: {e.stderr}')
    return None

def load_servers_db() -> Dict[str, List[Dict[str, any]]]:
    logger.debug("Loading servers DB from file...")
    if os.path.exists(SERVERS_DB_FILE):
        with open(SERVERS_DB_FILE, 'r') as f:
            return json.load(f)
    logger.debug("No existing DB found, returning empty dict.")
    return {}

def save_servers_db(db: Dict[str, List[Dict[str, any]]]) -> None:
    logger.debug("Saving servers DB to file...")
    with open(SERVERS_DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)
    logger.debug("Servers DB saved successfully.")

# ====================== Integrity and Security Checks ======================
def verify_rpc_cert_file() -> None:
    cert_path = os.path.join(SCRIPT_DIR, RPC_CERT_FILE)
    logger.debug(f"Verifying RPC certificate file at {cert_path}...")
    if not os.path.exists(cert_path):
        exit_with_error(f"RPC certificate file not found: {cert_path}")
    with open(cert_path, 'r') as f:
        content = f.read()
        if '-----BEGIN CERTIFICATE-----' not in content or '-----END CERTIFICATE-----' not in content:
            exit_with_error("Invalid RPC certificate file: missing PEM headers")
    logger.debug("RPC certificate file verified successfully.")

# ====================== VPN, WireGuard, and Network Functions ======================
def verify_dependencies() -> None:
    logger.info("Verifying required commands for the script...")
    required_cmds = ['wg', 'wg-quick', 'sysctl', 'tee', 'ping', 'awk', 'xargs']
    if TRANSMISSION_ENABLED:
        required_cmds.append('transmission-remote')
    for cmd in required_cmds:
        if execute_command(['which', cmd], check=False, capture_output=True) is None:
            exit_with_error(f'Required command "{cmd}" is not installed.')
    logger.info("All required commands are present.")

def disable_ipv6() -> None:
    logger.info("Disabling IPv6 system-wide...")
    cmd = ['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1']
    try:
        output = execute_command(cmd, check=False, capture_output=True)
        if output:
            logger.debug(f'sysctl output: {output}')
        logger.info('IPv6 is now disabled.')
    except Exception as e:
        logger.error(f'Failed to disable IPv6: {str(e)}')
        exit_with_error(f'Failed to disable IPv6: {str(e)}')

def teardown_wireguard_interface(interface_name: str) -> None:
    logger.debug(f"Tearing down WireGuard interface: {interface_name}")
    try:
        execute_command(['wg-quick', 'down', interface_name], check=True, capture_output=True)
        logger.info(f'WireGuard interface "{interface_name}" removed successfully.')
    except subprocess.CalledProcessError as e:
        logger.error(f'Failed to remove WireGuard interface "{interface_name}": {e.stderr}')
    except Exception as e:
        logger.error(f'Unexpected error removing WireGuard interface "{interface_name}": {e}')

def verify_public_ip(expected_ip: str) -> bool:
    logger.debug("Checking public IP via ipify...")
    try:
        actual_ip = session.get('https://api64.ipify.org?format=json', timeout=10).json()['ip']
    except requests.RequestException as e:
        logger.error(f'Failed to get public IP: {e}')
        exit_with_error(f'Failed to get public IP: {e}')
    logger.debug(f"Public IP is {actual_ip}, expected {expected_ip}.")
    if actual_ip == expected_ip:
        logger.info(f'Success: public IP matches VPN server IP: {expected_ip}')
        return True
    logger.error(f'Error: public IP {actual_ip} does not match VPN server IP {expected_ip}')
    return False

def establish_wireguard_connection(server: types.SimpleNamespace, token: str) -> None:
    logger.info(f"Establishing WireGuard connection to server {server.cn} ({server.ip})...")
    private_key = execute_command(['wg', 'genkey'])
    if private_key is None:
        exit_with_error('Failed to generate WireGuard private key.')
    public_key = execute_command(['wg', 'pubkey'], input_data=private_key + '\n')
    if public_key is None:
        exit_with_error('Failed to generate WireGuard public key.')
    logger.debug("Requesting addKey API call from PIA server...")
    res = make_api_call(server, 1337, 'addKey', pt=token, pubkey=public_key)
    if res.status != 'OK':
        logger.error(f"WireGuard addKey API call returned status {res.status}")
        exit_with_error('WireGuard addKey API call failed.')
    logger.debug("addKey API call successful.")

    transmission_cmds = ""
    if TRANSMISSION_ENABLED:
        logger.debug("TRANSMISSION_ENABLED is True, adding PostUp/PostDown commands for Transmission.")
        transmission_cmds = (
            "PostUp = transmission-remote -l | "
            "awk '$1 ~ /^[0-9]+$/ && $2 != \"100%\" {print $1}' | "
            "xargs -r -I{} transmission-remote -t {} --start\n"
            "PostDown = transmission-remote -t all --stop && "
            "if [ -f /var/run/piaplus.pid ]; then kill $(cat /var/run/piaplus.pid) && rm /var/run/piaplus.pid; fi\n"
        )

    pia_conf = f"""# generated by piaplus.py

[Interface]
Address = {res.peer_ip}
PrivateKey = {private_key}
{transmission_cmds}[Peer]
PersistentKeepalive = 25
PublicKey = {res.server_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {res.server_ip}:{res.server_port}
"""

    logger.debug("Creating /etc/wireguard/pia.conf with the new WireGuard configuration...")
    execute_command(['mkdir', '-p', '/etc/wireguard'], check=False, capture_output=True)
    execute_command(['tee', '/etc/wireguard/pia.conf'], input_data=pia_conf + '\n')

    logger.info("Bringing up wg-quick with pia.conf...")
    output_up = execute_command(['wg-quick', 'up', 'pia'], capture_output=True)
    if output_up:
        logger.debug(f'wg-quick up output: {output_up}')

    logger.debug("Verifying if the public IP now matches the VPN server IP...")
    if not verify_public_ip(res.server_ip):
        execute_command(['wg-quick', 'down', 'pia'], check=False, capture_output=True)
        exit_with_error('Error: different public IP than VPN server')
    logger.info("WireGuard connection established and public IP verified successfully.")

def reestablish_wireguard_connection(server: types.SimpleNamespace, token: str) -> None:
    logger.info(f"Re-establishing WireGuard connection to {server.cn} ({server.ip})...")
    establish_wireguard_connection(server, token)

# ====================== PIA Server API Calls ======================
def make_api_call(server: types.SimpleNamespace, port: int, path: str, **kwargs) -> types.SimpleNamespace:
    logger.debug(f"Making API call to {server.ip}:{port}/{path} with kwargs={kwargs}...")
    protocol = 'https'
    adapter = ForcedIpHttpsAdapter(dest_ip=server.ip, server_hostname=server.cn)
    session.mount(f'{protocol}://{server.ip}:{port}', adapter)
    query = urllib.parse.urlencode(kwargs)
    cert_path = os.path.join(SCRIPT_DIR, RPC_CERT_FILE)

    try:
        response = session.get(
            f'{protocol}://{server.ip}:{port}/{path}?{query}',
            headers={'Host': server.cn},
            verify=cert_path,
            timeout=10
        )
        response.raise_for_status()
        logger.debug(f"API call to {path} succeeded with status code {response.status_code}.")
    except requests.RequestException as e:
        logger.error(f"API call to {path} failed: {e}")
        exit_with_error(f"API call to {path} failed: {e}")

    return json_to_namespace(response.text)

def obtain_gateway_token(username: str, password: str) -> str:
    logger.info("Requesting gateway token from PIA (gtoken/generateToken)...")
    auth = requests.auth.HTTPBasicAuth(username, password)
    try:
        res = session.get('https://privateinternetaccess.com/gtoken/generateToken', auth=auth, timeout=10).json()
    except requests.RequestException as e:
        logger.error(f'Failed to get gateway token: {e}')
        exit_with_error(f'Failed to get gateway token: {e}')
    if res.get('status') != 'OK':
        logger.error(f"Unexpected response while obtaining gateway token: {repr(res)}")
        exit_with_error(f"Failed to get gateway token: {repr(res)}")
    logger.debug("Gateway token obtained successfully.")
    return res['token']

def obtain_pia_token_for_dip(username: str, password: str) -> str:
    logger.info("Requesting PIA token for Dedicated IP (DIP)...")
    url = 'https://www.privateinternetaccess.com/api/client/v2/token'
    headers = {"Content-Type": "application/json"}
    data = {"username": username, "password": password}
    try:
        r = session.post(url, headers=headers, json=data, timeout=10)
        r.raise_for_status()
        res = r.json()
        if 'token' not in res:
            logger.error('No token field found in DIP response.')
            exit_with_error('No token in response for DIP.')
    except requests.RequestException as e:
        logger.error(f'Failed to get PIA token for DIP: {e}')
        exit_with_error(f'Failed to get PIA token for DIP: {e}')
    logger.debug("PIA token for DIP obtained successfully.")
    return res['token']

def fetch_dip_server_details(pia_token: str, dip_token: str) -> types.SimpleNamespace:
    logger.info("Fetching Dedicated IP server details...")
    url = 'https://www.privateinternetaccess.com/api/client/v2/dedicated_ip'
    headers = {"Authorization": f"Token {pia_token}", "Content-Type": "application/json"}
    data = {"tokens": [dip_token]}
    try:
        r = session.post(url, headers=headers, json=data, timeout=10)
        r.raise_for_status()
        res = r.json()
    except requests.RequestException as e:
        logger.error(f'Failed to get DIP server details: {e}')
        exit_with_error(f'Failed to get DIP server details: {e}')
    if not res or not res[0].get('status') == 'active':
        logger.error('Could not validate the dedicated IP token provided!')
        exit_with_error('Could not validate the dedicated IP token provided!')
    dip_address = res[0]["ip"]
    dip_hostname = res[0]["cn"]
    dip_id = res[0]["id"]
    pf_capable = "false" if dip_id.startswith("us_") else "true"
    logger.info(f"Dedicated IP server: {dip_hostname} ({dip_address}) PF capable: {pf_capable}")
    return types.SimpleNamespace(ip=dip_address, cn=dip_hostname)

# ====================== Background Support (Port Binding) ======================
def keep_port_bound(server: types.SimpleNamespace, token: str, payload_encoded: str, signature: str) -> None:
    logger.info("Starting port binding maintenance loop...")
    last_binding_time = time.time()
    while True:
        try:
            current_time = time.time()
            if current_time - last_binding_time >= 900:
                logger.debug("15 minutes passed, attempting to re-bind port...")
                if AUTODISCONNECT and TRANSMISSION_ENABLED:
                    logger.debug("Checking active torrents for auto-disconnect logic...")
                    torrents_output = execute_command(["transmission-remote", "-l"], check=False, capture_output=True)
                    active_torrents = 0
                    if torrents_output:
                        active_torrents = sum(
                            1 for line in torrents_output.splitlines()[1:-1]
                            if re.search(r'\b(downloading|up & down)\b', line.lower())
                        )
                    if active_torrents == 0:
                        logger.info("No active torrents found. Tearing down WireGuard interface and exiting.")
                        teardown_wireguard_interface('pia')
                        sys.exit(0)

                res_bind = make_api_call(server, 19999, 'bindPort', payload=payload_encoded, signature=signature)
                if res_bind.status == 'OK':
                    logger.debug("Port was bound successfully.")
                    last_binding_time = current_time
                else:
                    logger.error("Port binding failed.")
                    exit_with_error('Port binding failed.')
            time.sleep(60)
        except KeyboardInterrupt:
            logger.warning("Background process interrupted by user. Exiting.")
            exit_with_error('Background process interrupted by user. Exiting.')
        except Exception as e:
            logger.error(f"Unexpected error in background process: {e}")
            logger.info("Attempting to reestablish WireGuard connection...")
            try:
                reestablish_wireguard_connection(server, token)
            except Exception as reconnect_error:
                logger.error(f"Reconnection error: {reconnect_error}")
                exit_with_error('Reconnection failed.')

def run_background_process(server: types.SimpleNamespace, token: str, payload_encoded: str, signature: str) -> None:
    logger.info("Starting background process to maintain port forwarding binding...")
    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        '--background',
        '--server-ip', server.ip,
        '--server-cn', server.cn,
        '--token', token,
        '--payload', payload_encoded,
        '--signature', signature
    ]
    logger.debug(f"Spawning background process with command: {' '.join(cmd)}")
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setpgrp)
    with open(PID_FILE, 'w') as f:
        f.write(str(process.pid))
    logger.info(f"Background process started with PID {process.pid}. PID file created at {PID_FILE}.")

# ====================== Servers and Ping Functions ======================
def get_full_server_list() -> List[Dict[str, any]]:
    logger.info("Fetching full list of PIA servers...")
    url = "https://serverlist.piaservers.net/vpninfo/servers/v4"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()
        all_regions = []
        for line in lines:
            try:
                data = json.loads(line)
                all_regions.append(data)
            except json.JSONDecodeError:
                logger.debug("Skipped invalid JSON line in server list.")
        logger.debug("PIA server list retrieved successfully.")
        return all_regions
    except requests.RequestException as e:
        logger.error(f"Failed to fetch server list: {e}")
        exit_with_error(f"Failed to fetch server list: {e}")

def list_servers() -> None:
    logger.info("Listing all servers that support WireGuard & Port Forwarding...")
    all_regions = get_full_server_list()
    filtered_regions = sorted(
        [
            {"name": r.get("name", "Unknown"), "id": r.get("id", "unknown_id")}
            for data in all_regions
            for r in data.get("regions", [])
            if r.get("port_forward") and "wg" in r.get("servers", {})
        ],
        key=lambda x: x['name']
    )
    for region in filtered_regions:
        print(f"{region['name']} - '{region['id']}'")

def retrieve_and_update_servers(region_id: str) -> List[Dict[str, any]]:
    logger.info(f"Retrieving and updating servers for region ID={region_id}...")
    db = load_servers_db()
    old_servers = db.get(region_id, [])
    old_count = len(old_servers)
    all_regions = get_full_server_list()
    region_obj = None
    for data in all_regions:
        for region in data.get("regions", []):
            if region.get('id') == region_id:
                region_obj = region
                break
        if region_obj:
            break
    if not region_obj:
        logger.error(f"Region ID '{region_id}' not found in server list.")
        exit_with_error(f"Region ID '{region_id}' not found in server list.")

    wg_servers = region_obj.get('servers', {}).get('wg', [])
    new_servers_temp = [
        {'cn': srv.get('cn'), 'ip': srv.get('ip'), 'failed_attempts': 0}
        for srv in wg_servers if srv.get('cn') and srv.get('ip')
    ]

    logger.debug(f"Found {len(new_servers_temp)} WireGuard servers in region {region_id} from the upstream list.")
    combined = {(s['ip'], s['cn']): s for s in old_servers}
    combined.update({(ns['ip'], ns['cn']): ns for ns in new_servers_temp})
    new_servers_list = sorted(combined.values(), key=lambda s: s['cn'])[:50]
    new_count = len(new_servers_list)
    db[region_id] = new_servers_list
    save_servers_db(db)
    logger.info(f"Servers for region {region_id} updated. Old count={old_count}, new count={new_count}.")
    return new_servers_list

def ping_server(ip: str) -> Optional[float]:
    logger.debug(f"Pinging server {ip} with 5 ICMP packets...")
    try:
        result = subprocess.run(['ping', '-c', '5', '-W', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            match = re.search(r"(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)", result.stdout)
            if match:
                avg = float(match.group(2))
                logger.debug(f"Ping average time to {ip}: {avg} ms")
                return avg
        else:
            logger.debug(f"Ping to {ip} failed with return code {result.returncode}")
    except Exception as e:
        logger.error(f"Exception occurred while pinging {ip}: {e}")
    return None

def ping_servers_in_region(servers: List[Dict[str, any]]) -> Tuple[Dict[str, float], float, float, float]:
    logger.info(f"Pinging {len(servers)} servers concurrently...")
    ping_results: Dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=min(len(servers), 20)) as executor:
        futures = {executor.submit(ping_server, srv['ip']): srv['ip'] for srv in servers}
        for future in as_completed(futures):
            ip = futures[future]
            avg = future.result()
            if avg is not None:
                ping_results[ip] = avg

    if ping_results:
        all_pings = list(ping_results.values())
        min_ping = min(all_pings)
        avg_ping = sum(all_pings) / len(all_pings)
        max_ping = max(all_pings)
        logger.info(f"Ping results across region: min={min_ping:.2f} ms, avg={avg_ping:.2f} ms, max={max_ping:.2f} ms.")
    else:
        min_ping = avg_ping = max_ping = 0.0
        logger.warning("No successful ping results obtained.")
    return ping_results, min_ping, avg_ping, max_ping

def prune_failed_servers(region_id: str, ping_results: Dict[str, float]) -> List[Dict[str, any]]:
    logger.info(f"Pruning servers with too many failures for region {region_id}...")
    db = load_servers_db()
    servers = db.get(region_id, [])
    new_servers: List[Dict[str, any]] = []
    for srv in servers:
        ip = srv['ip']
        if ip not in ping_results:
            srv['failed_attempts'] = srv.get('failed_attempts', 0) + 1
            logger.debug(f"{ip} not in ping results, incremented failed_attempts to {srv['failed_attempts']}")
            if srv['failed_attempts'] < MAX_FAILED_ATTEMPTS:
                new_servers.append(srv)
        else:
            srv['failed_attempts'] = 0
            new_servers.append(srv)

    servers_with_ping = sorted(
        [(s, ping_results[s['ip']]) for s in new_servers if s['ip'] in ping_results],
        key=lambda x: x[1]
    )[:50]
    new_servers = [s[0] for s in servers_with_ping]
    db[region_id] = new_servers
    save_servers_db(db)
    logger.info(f"Pruning complete. {len(new_servers)} servers remain for region {region_id}.")
    return new_servers

def select_best_server(region_id: str, ping_results: Dict[str, float]) -> Dict[str, any]:
    logger.info(f"Selecting best (lowest latency) server in region {region_id}...")
    db = load_servers_db()
    servers = db.get(region_id, [])
    servers_with_ping = [(srv, ping_results[srv['ip']]) for srv in servers if srv['ip'] in ping_results]
    if not servers_with_ping:
        logger.error(f"No servers available with ping results for region {region_id}.")
        exit_with_error(f"No servers available with ping results for region {region_id}.")
    best_server, best_ping = min(servers_with_ping, key=lambda x: x[1])
    logger.info(f"Best server for region {region_id}: {best_server['cn']} ({best_server['ip']}), ping={best_ping:.2f} ms.")
    return best_server

# ====================== Main Logic (main) ======================
def main() -> None:
    parser = argparse.ArgumentParser(description="PIA Port Forwarding Script")
    parser.add_argument('--background', action='store_true', help='Run in background mode for binding port maintenance')
    parser.add_argument('--server-ip', type=str, help='Server IP address')
    parser.add_argument('--server-cn', type=str, help='Server Common Name')
    parser.add_argument('--token', type=str, help='Authentication token')
    parser.add_argument('--payload', type=str, help='Encoded payload')
    parser.add_argument('--signature', type=str, help='Signature')
    parser.add_argument('--list-servers', action='store_true', help='List all servers by country supporting port forwarding')
    parser.add_argument('--log-level', type=str, default=DEFAULT_LOG_LEVEL,
                        help='Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)')
    args = parser.parse_args()

    global logger
    logger = configure_logging(args.log_level)

    if not args.background:
        logger.debug("Checking if the pia interface is up. If so, removing it...")
        try:
            interface_status = execute_command(['wg', 'show', 'pia'])
            if interface_status is not None and interface_status.strip():
                logger.info("Found existing pia interface.")
                teardown_wireguard_interface('pia')
        except Exception as e:
            logger.warning(f"Could not check or remove interface pia: {e}")

    try:
        if args.background:
            logger.info('Script running in background mode for periodic port binding maintenance...')
            required_args = [args.server_ip, args.server_cn, args.token, args.payload, args.signature]
            if not all(required_args):
                logger.error('Background mode requires: server-ip, server-cn, token, payload, signature.')
                exit_with_error('Background mode argument validation failed.')
            server = types.SimpleNamespace(ip=args.server_ip, cn=args.server_cn)
            keep_port_bound(server, args.token, args.payload, args.signature)

        else:
            logger.info('Script running in foreground mode. Will connect to VPN and set up port forwarding now...')

            ensure_root()
            verify_dependencies()
            verify_rpc_cert_file()
            disable_ipv6()

            if DIP and DIP_TOKEN:
                logger.info('DIP mode enabled. Obtaining PIA DIP token...')
                pia_token = obtain_pia_token_for_dip(PIA_USERNAME, PIA_PASSWORD)
                logger.info('Obtained PIA DIP token successfully. Fetching DIP server details...')
                server = fetch_dip_server_details(pia_token, DIP_TOKEN)
                logger.info('Obtained DIP server details successfully.')

                ping_result = ping_server(server.ip)
                if ping_result is not None:
                    logger.info(f"Ping to Dedicated IP server {server.cn} ({server.ip}): {ping_result:.2f} ms")
                else:
                    logger.warning(f"Could not ping Dedicated IP server {server.cn} ({server.ip})")

                gw_token = obtain_gateway_token(PIA_USERNAME, PIA_PASSWORD)
                logger.info('Gateway token obtained successfully.')
                token = gw_token
            else:
                logger.info('DIP mode not enabled. Proceeding with regular region-based connection...')
                token = obtain_gateway_token(PIA_USERNAME, PIA_PASSWORD)
                logger.info('Gateway token obtained successfully.')
                servers_list = retrieve_and_update_servers(PIA_REGION)
                ping_results, min_ping, avg_ping, max_ping = ping_servers_in_region(servers_list)
                prune_failed_servers(PIA_REGION, ping_results)
                logger.info(f"Completed pinging {len(servers_list)} servers in region {PIA_REGION}.")
                best_server = select_best_server(PIA_REGION, ping_results)
                server = types.SimpleNamespace(ip=best_server['ip'], cn=best_server['cn'])

            establish_wireguard_connection(server, token)
            try:
                logger.info('Requesting port forwarding signature from PIA API on port 19999...')
                res = make_api_call(server, 19999, 'getSignature', token=token)
                if res.status != 'OK':
                    logger.error('Failed to getSignature from PIA API.')
                    exit_with_error('Port forwarding: failed to getSignature')

                payload_encoded = res.payload
                signature = res.signature
                payload_decoded = json_to_namespace(base64.b64decode(payload_encoded).decode('utf8'))
                logger.info(f'Success: Obtained forwarded port: {payload_decoded.port}, valid until {payload_decoded.expires_at}')

                if TRANSMISSION_ENABLED:
                    logger.info(f"Setting Transmission to use new forwarded port: {payload_decoded.port}")
                    execute_command(["transmission-remote", "--port", str(payload_decoded.port)], check=True, capture_output=True)

                run_background_process(server, token, payload_encoded, signature)

            except Exception as e:
                logger.error(f'Unexpected error occurred while setting up port forwarding: {e}', exc_info=True)
                exit_with_error('Script encountered an unexpected error.')

    except Exception as main_exception:
        logger.error(f'Unexpected exception in main: {main_exception}', exc_info=True)
        exit_with_error('An unrecoverable error occurred in main.')

    logger.info('PIA Port Forwarding Script execution completed successfully.')

if __name__ == '__main__':
    main()
