#!/usr/bin/env python3
import argparse, base64, json, os, re, socket, subprocess, sys, time, types, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from socket import error as SocketError, timeout as SocketTimeout
from typing import Dict, List, Optional, Tuple

import requests, logging
from logging.handlers import RotatingFileHandler
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager, connection
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import connection as urllib3_connection

# Configuration Constants
TRANSMISSION_ENABLED: bool = True
AUTODISCONNECT: bool = True
DIP: bool = True
DIP_TOKEN: str = 'zzz'
PIA_USERNAME: str = 'xxx'
PIA_PASSWORD: str = 'yyy'
PIA_REGION: str = 'www'
'''
AU Adelaide - 'au_adelaide-pf', AU Brisbane - 'au_brisbane-pf', AU Melbourne - 'aus_melbourne', AU Perth - 'aus_perth', AU Sydney - 'aus', Albania - 'al', Algeria - 'dz', Andorra - 'ad', Argentina - 'ar', Armenia - 'yerevan', Australia Streaming Optimized - 'au_australia-so', Austria - 'austria', Bahamas - 'bahamas', Bangladesh - 'bangladesh', Belgium - 'belgium', Bolivia - 'bo_bolivia-pf', Bosnia and Herzegovina - 'ba', Brazil - 'br', Bulgaria - 'sofia', CA Montreal - 'ca', CA Ontario - 'ca_ontario', CA Ontario Streaming Optimized - 'ca_ontario-so', CA Toronto - 'ca_toronto', CA Vancouver - 'ca_vancouver', Cambodia - 'cambodia', Chile - 'santiago', China - 'china', Colombia - 'bogota', Costa Rica - 'sanjose', Croatia - 'zagreb', Cyprus - 'cyprus', Czech Republic - 'czech', DE Berlin - 'de_berlin', DE Frankfurt - 'de-frankfurt', DE Germany Streaming Optimized - 'de_germany-so', DK Copenhagen - 'denmark', DK Streaming Optimized - 'denmark_2', ES Madrid - 'spain', ES Valencia - 'es-valencia', Ecuador - 'ec_ecuador-pf', Egypt - 'egypt', Estonia - 'ee', FI Helsinki - 'fi', FI Streaming Optimized - 'fi_2', France - 'france', Georgia - 'georgia', Greece - 'gr', Greenland - 'greenland', Guatemala - 'gt_guatemala-pf', Hong Kong - 'hk', Hungary - 'hungary', IT Milano - 'italy', IT Streaming Optimized - 'italy_2', Iceland - 'is', India - 'in', Indonesia - 'jakarta', Ireland - 'ireland', Isle of Man - 'man', Israel - 'israel', JP Streaming Optimized - 'japan_2', JP Tokyo - 'japan', Kazakhstan - 'kazakhstan', Latvia - 'lv', Liechtenstein - 'liechtenstein', Lithuania - 'lt', Luxembourg - 'lu', Macao - 'macau', Malaysia - 'kualalumpur', Malta - 'malta', Mexico - 'mexico', Moldova - 'md', Monaco - 'monaco', Mongolia - 'mongolia', Montenegro - 'montenegro', Morocco - 'morocco', NL Netherlands Streaming Optimized - 'nl_netherlands-so', Nepal - 'np_nepal-pf', Netherlands - 'nl_amsterdam', New Zealand - 'nz', North Macedonia - 'mk', Norway - 'no', Panama - 'panama', Peru - 'pe_peru-pf', Philippines - 'philippines', Poland - 'poland', Portugal - 'pt', Qatar - 'qatar', Romania - 'ro', SE Stockholm - 'sweden', SE Streaming Optimized - 'sweden_2', Saudi Arabia - 'saudiarabia', Serbia - 'rs', Singapore - 'sg', Slovakia - 'sk', Slovenia - 'slovenia', South Africa - 'za', South Korea - 'kr_south_korea-pf', Sri Lanka - 'srilanka', Switzerland - 'swiss', Taiwan - 'taiwan', Turkey - 'tr', UK London - 'uk', UK Manchester - 'uk_manchester', UK Southampton - 'uk_southampton', UK Streaming Optimized - 'uk_2', Ukraine - 'ua', United Arab Emirates - 'ae', Uruguay - 'uy_uruguay-pf', Venezuela - 'venezuela', Vietnam - 'vietnam'
'''
MAX_FAILED_ATTEMPTS: int = 3
REQUESTS_COUNT: int = 5
RPC_CERT_FILE: str = 'ca.rsa.4096.crt'
PORT: int = 19999

SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))
SERVERS_DB_FILE: str = os.path.join(SCRIPT_DIR, "piaplus_db.json")
LOG_FILE: str = os.path.join(SCRIPT_DIR, "piaplus.log")
PID_FILE: str = "/var/run/piaplus.pid"

DEFAULT_LOG_LEVEL: str = 'INFO'

# ====================== Setup Logging ======================

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

logger: logging.Logger = configure_logging(DEFAULT_LOG_LEVEL)
session: requests.Session = requests.Session()

# ====================== Classes for Forced IP HTTPS ======================

class ForcedIpHttpsConnection(HTTPSConnection):
    def __init__(self, *args, dest_ip: Optional[str] = None, server_hostname: Optional[str] = None, **kwargs):
        self.dest_ip = dest_ip
        self.server_hostname = server_hostname
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        try:
            self.sock = self._new_conn()
            self.sock.settimeout(self.timeout)
            self.ssl_context = ssl.create_default_context()
            self.sock = self.ssl_context.wrap_socket(self.sock, server_hostname=self.server_hostname)
            self._validate_conn()
        except Exception as e:
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
        return ForcedIpHttpsConnectionPool(host, port, dest_ip=self.dest_ip, server_hostname=self.server_hostname, **self.connection_pool_kw)

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

# ====================== Utility Functions ======================

def exit_with_error(message: str) -> None:
    logger.error(message)
    if check_wireguard_interface('pia'):
        teardown_wireguard_interface('pia')
    sys.exit(1)

def json_to_namespace(s: str) -> types.SimpleNamespace:
    return json.loads(s, object_hook=lambda d: types.SimpleNamespace(**d))

def execute_command(cmd: List[str], check: bool = False, capture_output: bool = True, input_data: Optional[str] = None, **kwargs) -> Optional[str]:
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
        return res.stdout.strip() if capture_output and res.stdout else None
    except FileNotFoundError:
        exit_with_error(f'Command not found: {cmd[0]}')
    except subprocess.CalledProcessError as e:
        exit_with_error(f'Command "{" ".join(cmd)}" failed with return code {e.returncode}: {e.stderr}')
    return None

def load_servers_db() -> Dict[str, List[Dict[str, any]]]:
    if os.path.exists(SERVERS_DB_FILE):
        with open(SERVERS_DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_servers_db(db: Dict[str, List[Dict[str, any]]]) -> None:
    with open(SERVERS_DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

# ====================== Security and Integrity Checks ======================

def verify_rpc_cert_file() -> None:
    logger.debug("Verifying integrity of the RPC certificate file...")
    cert_path = os.path.join(SCRIPT_DIR, RPC_CERT_FILE)
    if not os.path.exists(cert_path):
        exit_with_error(f"RPC certificate file not found: {cert_path}")
    with open(cert_path, 'r') as f:
        content = f.read()
        if '-----BEGIN CERTIFICATE-----' not in content or '-----END CERTIFICATE-----' not in content:
            exit_with_error("Invalid RPC certificate file: missing PEM headers")
    logger.debug("RPC certificate file integrity verified.")

# ====================== Network & VPN Functions ======================

def obtain_gateway_token(username: str, password: str) -> str:
    logger.debug("Obtaining PIA gateway token...")
    auth = requests.auth.HTTPBasicAuth(username, password)
    try:
        res = session.get('https://privateinternetaccess.com/gtoken/generateToken', auth=auth, timeout=10).json()
    except requests.RequestException as e:
        exit_with_error(f'Failed to get gateway token: {e}')
    if res.get('status') != 'OK':
        exit_with_error(f"Failed to get gateway token: {repr(res)}")
    logger.debug("Successfully obtained PIA gateway token.")
    return res['token']

def obtain_pia_token_for_dip(username: str, password: str) -> str:
    logger.debug("Obtaining PIA token for DIP...")
    url = 'https://www.privateinternetaccess.com/api/client/v2/token'
    headers = {"Content-Type": "application/json"}
    data = {"username": username, "password": password}
    try:
        r = session.post(url, headers=headers, json=data, timeout=10)
        r.raise_for_status()
        res = r.json()
        if 'token' not in res:
            exit_with_error('No token in response for DIP.')
    except requests.RequestException as e:
        exit_with_error(f'Failed to get PIA token for DIP: {e}')
    logger.debug("Successfully obtained PIA DIP token.")
    return res['token']

def fetch_dip_server_details(pia_token: str, dip_token: str) -> types.SimpleNamespace:
    logger.debug("Fetching Dedicated IP server details...")
    url = 'https://www.privateinternetaccess.com/api/client/v2/dedicated_ip'
    headers = {
        "Authorization": f"Token {pia_token}",
        "Content-Type": "application/json"
    }
    data = {"tokens": [dip_token]}
    try:
        r = session.post(url, headers=headers, json=data, timeout=10)
        r.raise_for_status()
        res = r.json()
    except requests.RequestException as e:
        exit_with_error(f'Failed to get DIP server details: {e}')

    if not res or not res[0].get('status') == 'active':
        exit_with_error('Could not validate the dedicated IP token provided!')

    dip_address = res[0]["ip"]
    dip_hostname = res[0]["cn"]
    dip_id = res[0]["id"]
    pf_capable = "false" if dip_id.startswith("us_") else "true"
    logger.info(f"Dedicated IP server: {dip_hostname} ({dip_address}) PF capable: {pf_capable}")
    return types.SimpleNamespace(ip=dip_address, cn=dip_hostname)

def verify_dependencies() -> None:
    logger.debug("Verifying required dependencies...")
    required_commands = ['wg', 'wg-quick', 'sysctl', 'tee', 'ping', 'awk', 'xargs'] + (['transmission-remote'] if TRANSMISSION_ENABLED else [])
    for cmd in required_commands:
        if execute_command(['which', cmd], check=False) is None:
            exit_with_error(f'Required command "{cmd}" is not installed.')
    logger.debug("All required dependencies are available.")

def disable_ipv6() -> None:
    logger.debug("Disabling IPv6 system-wide...")
    cmd = ['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1']
    try:
        output = execute_command(cmd, check=False, capture_output=True)
        if output:
            logger.debug(f'sysctl output: {output}')
        logger.info('IPv6 is now disabled.')
    except Exception as e:
        exit_with_error(f'Failed to disable IPv6: {str(e)}')

def check_wireguard_interface(interface_name: str) -> bool:
    logger.debug(f"Checking if WireGuard interface '{interface_name}' exists...")
    try:
        result = execute_command(['wg', 'show', interface_name], check=False, capture_output=True)
        exists = result is not None
        logger.debug(f"WireGuard interface '{interface_name}' exists: {exists}")
        return exists
    except Exception as e:
        logger.debug(f"Error checking interface '{interface_name}': {e}")
        return False

def teardown_wireguard_interface(interface_name: str) -> None:
    logger.debug(f"Tearing down WireGuard interface '{interface_name}'...")
    try:
        execute_command(['wg-quick', 'down', interface_name], check=True, capture_output=True)
        logger.info(f'WireGuard interface "{interface_name}" removed successfully.')
    except Exception as e:
        logger.error(f'Failed to remove WireGuard interface "{interface_name}": {e}')

def reestablish_wireguard_connection(server: types.SimpleNamespace, token: str) -> None:
    logger.info("Re-establishing WireGuard connection...")
    establish_wireguard_connection(server, token)
    logger.info('Reconnected to WireGuard successfully.')

def verify_public_ip(expected_ip: str) -> bool:
    logger.debug("Verifying that current public IP matches the VPN server's IP...")
    try:
        actual_ip = session.get('https://api64.ipify.org?format=json', timeout=10).json()['ip']
    except requests.RequestException as e:
        exit_with_error(f'Failed to get public IP: {e}')
    if actual_ip == expected_ip:
        logger.info(f'Success: public IP matches VPN server IP: {expected_ip}')
        return True
    else:
        logger.error(f'Error: public IP {actual_ip} does not match VPN server IP {expected_ip}')
        return False

def establish_wireguard_connection(server: types.SimpleNamespace, token: str) -> None:
    logger.info("Establishing WireGuard connection to VPN server...")
    private_key = execute_command(['wg', 'genkey'])
    if private_key is None:
        exit_with_error('Failed to generate WireGuard private key.')
    public_key = execute_command(['wg', 'pubkey'], input_data=private_key + '\n')
    if public_key is None:
        exit_with_error('Failed to generate WireGuard public key.')
    logger.debug("Registering new WireGuard key with PIA server...")
    res = make_api_call(server, 1337, 'addKey', pt=token, pubkey=public_key)
    if res.status != 'OK':
        exit_with_error('WireGuard addKey API call failed.')
    if check_wireguard_interface('pia'):
        logger.info('Disabling old WireGuard connection before establishing a new one...')
        output_down = execute_command(['wg-quick', 'down', 'pia'], check=False, capture_output=True)
        if output_down:
            logger.debug(f'wg-quick down output: {output_down}')
    logger.debug("Constructing WireGuard configuration file...")
    transmission_commands = ""
    if TRANSMISSION_ENABLED:
        transmission_commands = (
            "PostUp = transmission-remote -l | awk '$1 ~ /^[0-9]+$/ && $2 != \"100%\" {print $1}' | xargs -r -I{} transmission-remote -t {} --start\n"
            "PostDown = transmission-remote -t all --stop && if [ -f /var/run/piaplus.pid ]; then kill $(cat /var/run/piaplus.pid) && rm /var/run/piaplus.pid; fi\n"
        )
    pia_conf = f"""\
# generated by piaplus.py

[Interface]
Address = {res.peer_ip}
PrivateKey = {private_key}
{transmission_commands}

[Peer]
PersistentKeepalive = 25
PublicKey = {res.server_key}

AllowedIPs = 0.0.0.0/0

Endpoint = {res.server_ip}:{res.server_port}
"""
    logger.info('Writing WireGuard config to /etc/wireguard/pia.conf')
    execute_command(['mkdir', '-p', '/etc/wireguard'], check=False, capture_output=True)
    execute_command(['tee', '/etc/wireguard/pia.conf'], input_data=pia_conf + '\n')
    logger.info('Bringing up the new WireGuard interface...')
    output_up = execute_command(['wg-quick', 'up', 'pia'], capture_output=True)
    if output_up:
        logger.debug(f'wg-quick up output: {output_up}')
    if not verify_public_ip(res.server_ip):
        logger.info('Disabling newly brought up WireGuard connection due to IP mismatch...')
        execute_command(['wg-quick', 'down', 'pia'], check=False, capture_output=True)
        exit_with_error('Error: different public IP than VPN server')
    logger.info('WireGuard interface "pia" is up and running.')
    logger.info('To disconnect from the VPN, run: sudo wg-quick down pia')

# ====================== API and Server Functions ======================

def make_api_call(server: types.SimpleNamespace, port: int, path: str, **kwargs) -> types.SimpleNamespace:
    logger.debug(f"Making API call to server {server.cn}:{port}/{path} with {kwargs}...")
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
    except requests.RequestException as e:
        exit_with_error(f"API call to {path} failed: {e}")
    return json_to_namespace(response.text)

# ====================== Background Process Handling ======================

def keep_port_bound(server: types.SimpleNamespace, token: str, payload_encoded: str, signature: str) -> None:
    logger.info('Running in background mode. Periodically refreshing port binding...')
    last_binding_time: float = time.time()
    while True:
        try:
            if not check_wireguard_interface('pia'):
                exit_with_error('WireGuard interface "pia" not found. Terminating background process.')

            current_time: float = time.time()
            if current_time - last_binding_time >= 900:
                if AUTODISCONNECT and TRANSMISSION_ENABLED:
                    torrents_output = execute_command(["transmission-remote", "-l"], check=False, capture_output=True)
                    active_torrents: int = sum(1 for line in torrents_output.splitlines()[1:-1]
                                              if re.search(r'\b(downloading|up & down)\b', line.lower())) if torrents_output else 0
                    logger.info(f'Torrents currently active: {active_torrents}')
                    if active_torrents == 0:
                        logger.info('All torrents have completed downloading successfully. Removing WireGuard interface "pia" and terminating.')
                        teardown_wireguard_interface('pia')
                        sys.exit(0)
                logger.debug("Refreshing port binding with PIA server...")
                res_bind = make_api_call(server, PORT, 'bindPort', payload=payload_encoded, signature=signature)
                if res_bind.status == 'OK':
                    logger.info("Port binding refreshed successfully. Will check again in 15 minutes.")
                    last_binding_time = current_time
                else:
                    logger.error('Port binding refresh failed. Removing WireGuard interface "pia" and terminating.')
                    exit_with_error('Port binding failed.')
            time.sleep(60)
        except KeyboardInterrupt:
            exit_with_error('Background process interrupted by user. Exiting.')
        except Exception as e:
            logger.error(f'Unexpected error in background process: {e}')
            logger.info('Attempting to reconnect WireGuard interface...')
            try:
                reestablish_wireguard_connection(server, token)
            except Exception as reconnect_error:
                logger.error(f'Reconnection error: {reconnect_error}')
                exit_with_error('Reconnection failed.')

def run_background_process(server: types.SimpleNamespace, token: str, payload_encoded: str, signature: str) -> None:
    logger.info('Launching a background process to maintain port forwarding over time...')
    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        '--background',
        '--server-ip', server.ip,
        '--server-cn', server.cn,
        '--port', str(PORT),
        '--token', token,
        '--payload', payload_encoded,
        '--signature', signature
    ]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setpgrp
    )
    with open(PID_FILE, 'w') as f:
        f.write(str(process.pid))
    logger.info('Background process launched successfully to maintain port forwarding.')

# ====================== Servers and Ping Functions ======================

def get_full_server_list() -> types.SimpleNamespace:
    logger.debug("Fetching the full PIA server list...")
    try:
        res = session.get('https://serverlist.piaservers.net/vpninfo/servers/v4', timeout=10)
        res.raise_for_status()
        full_server_list = json_to_namespace(res.text.split('\n')[0])
        full_server_list.regions = [r for r in full_server_list.regions if getattr(r, 'port_forward', False)]
    except Exception as e:
        exit_with_error(f"Failed to get full server list: {e}")
    logger.debug("Full server list obtained and filtered by port_forward capability.")
    return full_server_list

def retrieve_and_update_servers(region_id: str) -> List[Dict[str, any]]:
    logger.info(f"Retrieving and updating server list for region: {region_id}")
    db = load_servers_db()
    old_servers = db.get(region_id, [])
    old_count = len(old_servers)
    new_servers_temp: List[Dict[str, any]] = []
    with ThreadPoolExecutor(max_workers=REQUESTS_COUNT) as executor:
        futures = [executor.submit(get_full_server_list) for _ in range(REQUESTS_COUNT)]
        for future in as_completed(futures):
            sl = future.result()
            region_obj = next((r for r in sl.regions if r.id == region_id), None)
            if region_obj:
                wg_servers = getattr(region_obj.servers, 'wg', [])
                new_servers_temp.extend([{'cn': srv.cn, 'ip': srv.ip, 'failed_attempts': 0} for srv in wg_servers])
    combined = {(s['ip'], s['cn']): s for s in old_servers}
    combined.update({(ns['ip'], ns['cn']): ns for ns in new_servers_temp})
    new_servers_list = sorted(combined.values(), key=lambda s: s['cn'])[:50]
    new_count = len(new_servers_list)
    added = new_count - old_count
    logger.info(f"Previously known servers: {old_count}. After fetching {REQUESTS_COUNT} times, added {added} new servers. Total now: {new_count}.")
    db[region_id] = new_servers_list
    save_servers_db(db)
    return new_servers_list

def ping_server(ip: str) -> Optional[float]:
    logger.debug(f"Pinging server at IP: {ip}...")
    try:
        result = subprocess.run(
            ['ping', '-c', '10', '-W', '1', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            match = re.search(r"(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)", result.stdout)
            if match:
                avg = float(match.group(2))
                logger.debug(f"Ping successful for {ip}: avg={avg} ms")
                return avg
        logger.debug(f"Ping failed or no match for {ip}.")
    except Exception as e:
        logger.debug(f"Ping error for {ip}: {e}")
    return None

def ping_servers_in_region(servers: List[Dict[str, any]]) -> Tuple[Dict[str, float], float, float, float]:
    logger.info(f"Pinging all servers in region. Total servers to ping: {len(servers)}")
    ping_results: Dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=len(servers)) as executor:
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
    else:
        min_ping = avg_ping = max_ping = 0.0
    logger.info(f"Ping results: {len(ping_results)} servers responded. Min: {min_ping:.2f} ms, Avg: {avg_ping:.2f} ms, Max: {max_ping:.2f} ms")
    return ping_results, min_ping, avg_ping, max_ping

def prune_failed_servers(region_id: str, ping_results: Dict[str, float]) -> List[Dict[str, any]]:
    logger.info(f"Pruning servers in {region_id} that did not respond to ping...")
    db = load_servers_db()
    servers = db.get(region_id, [])
    new_servers: List[Dict[str, any]] = []
    removed_count: int = 0
    for srv in servers:
        ip = srv['ip']
        if ip not in ping_results:
            srv['failed_attempts'] = srv.get('failed_attempts', 0) + 1
            if srv['failed_attempts'] < MAX_FAILED_ATTEMPTS:
                new_servers.append(srv)
            else:
                removed_count += 1
        else:
            srv['failed_attempts'] = 0
            new_servers.append(srv)
    if removed_count > 0:
        logger.info(f"Removed {removed_count} servers due to exceeding {MAX_FAILED_ATTEMPTS} failed attempts.")
    servers_with_ping = sorted(
        [(s, ping_results[s['ip']]) for s in new_servers if s['ip'] in ping_results],
        key=lambda x: x[1]
    )[:50]
    new_servers = [s[0] for s in servers_with_ping]
    db[region_id] = new_servers
    save_servers_db(db)
    return new_servers

def select_best_server(region_id: str, ping_results: Dict[str, float]) -> Dict[str, any]:
    logger.info(f"Selecting the best server in region {region_id} based on ping results...")
    db = load_servers_db()
    servers = db.get(region_id, [])
    servers_with_ping = [(srv, ping_results[srv['ip']]) for srv in servers if srv['ip'] in ping_results]
    
    if not servers_with_ping:
        exit_with_error(f"No servers available with ping results for region {region_id}.")
    
    best_server, best_ping = min(servers_with_ping, key=lambda x: x[1])
    logger.info(f"Best server selected: {best_server['cn']} ({best_server['ip']}) with lowest ping: {best_ping:.2f} ms.")
    
    return best_server

# ====================== Main Logic ======================

def main() -> None:
    parser = argparse.ArgumentParser(description="PIA Port Forwarding Script")
    parser.add_argument('--background', action='store_true', help='Run in background mode for binding port maintenance')
    parser.add_argument('--server-ip', type=str, help='Server IP address')
    parser.add_argument('--server-cn', type=str, help='Server Common Name')
    parser.add_argument('--port', type=int, help='Port number')
    parser.add_argument('--token', type=str, help='Authentication token')
    parser.add_argument('--payload', type=str, help='Encoded payload')
    parser.add_argument('--signature', type=str, help='Signature')
    parser.add_argument('--log-level', type=str, default=DEFAULT_LOG_LEVEL, help='Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)')
    args = parser.parse_args()

    global logger
    logger = configure_logging(args.log_level)
    logger.info('Starting PIA Port Forwarding Script...')

    if not args.background and os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = f.read().strip()
            if pid.isdigit():
                os.kill(int(pid), 9)
        except Exception:
            pass
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

    verify_rpc_cert_file()
    try:
        if args.background:
            logger.info('Script running in background mode for periodic port binding maintenance...')
            required_args = [args.server_ip, args.server_cn, args.port, args.token, args.payload, args.signature]
            if not all(required_args):
                logger.error('Background mode requires all arguments: server-ip, server-cn, port, token, payload, signature.')
                exit_with_error('Background mode argument validation failed.')
            server = types.SimpleNamespace(ip=args.server_ip, cn=args.server_cn)
            keep_port_bound(server, args.token, args.payload, args.signature)
        else:
            logger.info('Script running in foreground mode. Will connect to VPN and set up port forwarding now...')
            if os.getuid() != 0:
                logger.error('Script must be run as root.')
                exit_with_error('You must run this script as root.')
            verify_dependencies()
            disable_ipv6()

            logger.debug(f"DIP={DIP}, DIP_TOKEN={DIP_TOKEN}")

            if DIP and DIP_TOKEN:
                logger.info('DIP mode enabled. Obtaining PIA DIP token...')
                pia_token = obtain_pia_token_for_dip(PIA_USERNAME, PIA_PASSWORD)
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
                logger.info('DIP mode not enabled. Proceeding with regular region-based connection.')
                token = obtain_gateway_token(PIA_USERNAME, PIA_PASSWORD)
                servers_list = retrieve_and_update_servers(PIA_REGION)
                ping_results, min_ping, avg_ping, max_ping = ping_servers_in_region(servers_list)
                prune_failed_servers(PIA_REGION, ping_results)
                logger.info(f"Completed pinging {len(servers_list)} servers in region {PIA_REGION}.")
                best_server = select_best_server(PIA_REGION, ping_results)
                server = types.SimpleNamespace(ip=best_server['ip'], cn=best_server['cn'])

            establish_wireguard_connection(server, token)
            try:
                logger.info('Requesting port forwarding signature from PIA API...')
                res = make_api_call(server, PORT, 'getSignature', token=token)
                if res.status != 'OK':
                    logger.error('Failed to getSignature from PIA API.')
                    exit_with_error('Port forwarding: failed to getSignature')
                payload_encoded: str = res.payload
                signature: str = res.signature
                payload_decoded = json_to_namespace(base64.b64decode(payload_encoded).decode('utf8'))
                logger.info(f'Success: Obtained forwarded port: {payload_decoded.port}, valid until {payload_decoded.expires_at}')
                if TRANSMISSION_ENABLED:
                    logger.info(f"Setting Transmission to use new port: {payload_decoded.port}")
                    execute_command(["transmission-remote", "--port", str(payload_decoded.port)], check=True, capture_output=True)
                run_background_process(server, token, payload_encoded, signature)
            except Exception as e:
                logger.error(f'Unexpected error occurred while setting up port forwarding: {e}')
                exit_with_error('Script encountered an unexpected error.')
    except Exception as main_exception:
        logger.error(f'Unexpected exception in main: {main_exception}', exc_info=True)
        exit_with_error('An unrecoverable error occurred in main.')
    logger.info('PIA Port Forwarding Script execution completed successfully.')

if __name__ == '__main__':
    main()