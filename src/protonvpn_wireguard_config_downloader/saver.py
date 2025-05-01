from abc import ABC, abstractmethod
import json
from pathlib import Path
from collections import defaultdict

from proton.vpn.connection.vpnconfiguration import (  # pyright: ignore[reportMissingTypeStubs]
    WireguardConfig,
)
from proton.vpn.core.connection import (  # pyright: ignore[reportMissingTypeStubs]
    VPNServer,
)
from proton.vpn.session import VPNSession  # pyright: ignore[reportMissingTypeStubs]

from protonvpn_wireguard_config_downloader import logger


class VPNServerSaver(ABC):
    """Abstract base class for saving VPN server."""

    @abstractmethod
    def save(self, session: VPNSession, vpn_server: VPNServer):
        """Save the given VPN server."""


class StdoutSaver(VPNServerSaver):
    """Writes VPN data to stdout."""

    def save(
        self,
        session: VPNSession,  # noqa: ARG002
        vpn_server: VPNServer,
    ):
        print(f"{vpn_server.server_name}-{vpn_server.label}.conf")  # noqa: T201


class FileSaver(VPNServerSaver):
    def __init__(self, dest_dir: Path):
        self.dest_dir = dest_dir

    def save(self, session: VPNSession, vpn_server: VPNServer):
        """Save the Wireguard config for the the VPN server to filesystem."""
        logger.debug(
            f"Saving configuration file for VPN server: {vpn_server.server_name}"
        )
        config = WireguardConfig(
            vpn_server, session.vpn_account.vpn_credentials, None, use_certificate=True
        )
        dest_fpath = self.dest_dir / f"{vpn_server.server_name}-{vpn_server.label}.conf"
        dest_fpath.write_text(config.generate(), encoding="utf-8")
        logger.info(
            f"Saved configuration file for VPN server: {vpn_server.server_name},  "
            f"name: {dest_fpath.name}"
        )


class JSONSaver(VPNServerSaver):
    """Saves VPN servers grouped by country in a JSON file."""
    
    def __init__(self, dest_dir: Path, json_filename: str = "servers.json", country_filter: str = None):
        self.dest_dir = dest_dir
        self.json_path = dest_dir / json_filename
        self.servers_by_country = defaultdict(list)
        
        # Process country filter string into a list of lowercase country codes
        self.country_filters = []
        if country_filter:
            # Split by pipe or comma to support both formats: de|nl|us or de,nl,us
            self.country_filters = [c.strip().lower() for c in country_filter.replace('|', ',').split(',')]
        
    def save(self, session: VPNSession, vpn_server: VPNServer):
        """Add server to country-grouped JSON structure."""
        # Extract country code from server_name (e.g., "de-1" -> "de")
        country_code = vpn_server.server_name.split("-")[0]
        
        # Skip if country filters are specified and this country isn't in the list
        if self.country_filters and country_code not in self.country_filters:
            return
            
        logger.debug(
            f"Adding server {vpn_server.server_name} to JSON for country {country_code}"
        )
        
        # Generate the WireGuard config
        config = WireguardConfig(
            vpn_server, session.vpn_account.vpn_credentials, None, use_certificate=True
        )
        
        # Add server info to the country grouping
        server_data = {
            "name": vpn_server.server_name,
            "label": vpn_server.label,
            "domain": vpn_server.domain,
            "ip": vpn_server.server_ip,
            "config": config.generate(),
        }
        
        self.servers_by_country[country_code].append(server_data)
    
    def write_json(self):
        """Write the collected servers to a JSON file."""
        if not self.servers_by_country:
            logger.warning("No servers collected to save to JSON")
            return
            
        logger.debug(f"Writing {len(self.servers_by_country)} countries to JSON file")
        
        # Convert defaultdict to regular dict for JSON serialization
        servers_dict = dict(self.servers_by_country)
        
        # Write the JSON file
        self.json_path.write_text(
            json.dumps(servers_dict, indent=2), 
            encoding="utf-8"
        )
        
        logger.info(f"Saved server configurations to {self.json_path}")
