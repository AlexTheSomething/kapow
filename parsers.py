"""
parsers.py - Nmap XML Data Parser

Converts standard Nmap XML outputs into normalized JSON-serializable structures suitable for:
- AG Grid (tabular asset inventory)
- Cytoscape.js (network topology force-directed canvas)
"""

import ipaddress
import json
import logging
import re
from typing import Any, Dict, List, Optional, Union
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

# Try optional defusedxml for enhanced XML security
try:
    import defusedxml.ElementTree as DefusedET
    XML_PARSER = DefusedET
except ImportError:
    XML_PARSER = ET


def sanitize_and_heal_xml(text: str) -> str:
    """
    Sanitize and heal partial, truncated, or warning-laden Nmap XML output.
    """
    if not text:
        raise ValueError("Empty XML input provided.")

    # 1. Locate start of <nmaprun
    start_idx = text.find("<nmaprun")
    if start_idx == -1:
        if "<host" in text:
            text = '<nmaprun scanner="nmap">\n' + text
        else:
            raise ValueError("No <nmaprun> root tag found in XML content.")
    else:
        text = text[start_idx:]

    # 2. Strip external DOCTYPE / stylesheet declarations that trigger parse warnings
    text = re.sub(r'<!DOCTYPE [^>]+>', '', text)
    text = re.sub(r'<\?xml-stylesheet [^>]+>', '', text)

    # 3. Heal unclosed tags if truncated
    if "</nmaprun>" not in text:
        last_host_end = text.rfind("</host>")
        if last_host_end != -1:
            # Cut off any trailing partial host tag and append closing root
            text = text[:last_host_end + len("</host>")] + "\n</nmaprun>"
        else:
            text = text + "\n</nmaprun>"

    return text


def safe_parse_xml(xml_input: Union[str, bytes]) -> ET.Element:
    """
    Safely parse an Nmap XML string or bytes into an ElementTree Element with auto-healing.

    :param xml_input: Raw Nmap XML string or bytes content.
    :return: Root Element of the parsed XML.
    :raises ValueError: If XML parsing fails or input is empty/invalid.
    """
    if not xml_input:
        raise ValueError("Empty XML input provided.")

    if isinstance(xml_input, bytes):
        raw_str = xml_input.decode('utf-8', errors='ignore')
    else:
        raw_str = str(xml_input)

    healed_str = sanitize_and_heal_xml(raw_str)
    xml_bytes = healed_str.strip().encode('utf-8')

    try:
        root = XML_PARSER.fromstring(xml_bytes)
        if root.tag != 'nmaprun':
            raise ValueError(f"Invalid Nmap XML document. Root tag is '<{root.tag}>', expected '<nmaprun>'.")
        return root
    except ET.ParseError as pe:
        # Fallback: attempt deeper regex sanitization of invalid characters
        try:
            cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', healed_str)
            root = XML_PARSER.fromstring(cleaned.encode('utf-8'))
            return root
        except Exception:
            raise ValueError(f"Failed to parse Nmap XML content: {pe}") from pe


class NmapParser:
    """
    Nmap XML Data Parser and Converter for AG Grid and Cytoscape.js.
    """

    def __init__(self, xml_input: Union[str, bytes]):
        """
        Initialize the parser with raw XML content.
        """
        self.root = safe_parse_xml(xml_input)

    def parse(self) -> Dict[str, Any]:
        """
        Parse full Nmap XML into a normalized Python dictionary structure.
        """
        metadata = self._parse_metadata()
        summary = self._parse_runstats()
        hosts = [self._parse_host(h) for h in self.root.findall('host')]

        return {
            "metadata": metadata,
            "summary": summary,
            "hosts": hosts,
        }

    def _parse_metadata(self) -> Dict[str, Any]:
        """Extract scan metadata from <nmaprun> attributes and child tags."""
        attrs = self.root.attrib
        scan_info_elems = self.root.findall('scaninfo')
        scan_types = [s.attrib.get('type') for s in scan_info_elems if s.attrib.get('type')]
        protocols = [s.attrib.get('protocol') for s in scan_info_elems if s.attrib.get('protocol')]

        return {
            "scanner": attrs.get('scanner', 'nmap'),
            "args": attrs.get('args', ''),
            "start_time": attrs.get('start', ''),
            "start_str": attrs.get('startstr', ''),
            "version": attrs.get('version', ''),
            "xml_version": attrs.get('xmloutputversion', ''),
            "scan_types": scan_types,
            "protocols": protocols,
        }

    def _parse_runstats(self) -> Dict[str, Any]:
        """Extract overall scan statistics from <runstats>."""
        runstats = self.root.find('runstats')
        if runstats is None:
            return {
                "finished_time": "",
                "elapsed": 0.0,
                "summary": "",
                "hosts_up": 0,
                "hosts_down": 0,
                "hosts_total": 0,
            }

        finished = runstats.find('finished')
        hosts_stat = runstats.find('hosts')

        finished_attrs = finished.attrib if finished is not None else {}
        hosts_attrs = hosts_stat.attrib if hosts_stat is not None else {}

        elapsed = 0.0
        try:
            elapsed = float(finished_attrs.get('elapsed', '0'))
        except (ValueError, TypeError):
            pass

        def _to_int(val: Optional[str]) -> int:
            try:
                return int(val) if val is not None else 0
            except ValueError:
                return 0

        return {
            "finished_time": finished_attrs.get('timestr', ''),
            "elapsed": elapsed,
            "summary": finished_attrs.get('summary', ''),
            "hosts_up": _to_int(hosts_attrs.get('up')),
            "hosts_down": _to_int(hosts_attrs.get('down')),
            "hosts_total": _to_int(hosts_attrs.get('total')),
        }

    def _parse_host(self, host_elem: ET.Element) -> Dict[str, Any]:
        """Extract complete details for a single host element."""
        # Status
        status_elem = host_elem.find('status')
        status = {
            "state": status_elem.attrib.get('state', 'unknown') if status_elem is not None else 'unknown',
            "reason": status_elem.attrib.get('reason', '') if status_elem is not None else '',
            "reason_ttl": status_elem.attrib.get('reason_ttl', '') if status_elem is not None else '',
        }

        # Addresses (IPv4, IPv6, MAC, Vendor)
        ipv4 = None
        ipv6 = None
        mac = None
        vendor = None

        for addr in host_elem.findall('address'):
            addr_type = addr.attrib.get('addrtype')
            addr_val = addr.attrib.get('addr')
            if addr_type == 'ipv4':
                ipv4 = addr_val
            elif addr_type == 'ipv6':
                ipv6 = addr_val
            elif addr_type == 'mac':
                mac = addr_val
                vendor = addr.attrib.get('vendor', vendor)

        ip = ipv4 or ipv6 or "0.0.0.0"

        # Hostnames
        hostnames = []
        primary_hostname = ""
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall('hostname'):
                name = hn.attrib.get('name', '')
                hn_type = hn.attrib.get('type', '')
                if name:
                    hostnames.append({"name": name, "type": hn_type})
                    if not primary_hostname:
                        primary_hostname = name

        # Ports & Services
        ports = []
        extraports = []
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for ep in ports_elem.findall('extraports'):
                extraports.append({
                    "state": ep.attrib.get('state', ''),
                    "count": int(ep.attrib.get('count', '0')) if ep.attrib.get('count', '').isdigit() else 0,
                })

            for p in ports_elem.findall('port'):
                ports.append(self._parse_port(p))

        # Operating System matches
        os_matches = []
        primary_os = "Unknown"
        primary_os_accuracy = 0
        os_elem = host_elem.find('os')
        if os_elem is not None:
            for match in os_elem.findall('osmatch'):
                m_name = match.attrib.get('name', '')
                try:
                    m_acc = int(match.attrib.get('accuracy', '0'))
                except ValueError:
                    m_acc = 0

                classes = []
                for cls in match.findall('osclass'):
                    classes.append({
                        "type": cls.attrib.get('type', ''),
                        "vendor": cls.attrib.get('vendor', ''),
                        "osfamily": cls.attrib.get('osfamily', ''),
                        "osgen": cls.attrib.get('osgen', ''),
                        "accuracy": cls.attrib.get('accuracy', ''),
                    })

                os_matches.append({
                    "name": m_name,
                    "accuracy": m_acc,
                    "classes": classes,
                })

                if m_acc > primary_os_accuracy:
                    primary_os = m_name
                    primary_os_accuracy = m_acc

        # Distance & Uptime
        distance = None
        dist_elem = host_elem.find('distance')
        if dist_elem is not None and dist_elem.attrib.get('value'):
            try:
                distance = int(dist_elem.attrib.get('value'))
            except ValueError:
                pass

        uptime = None
        uptime_elem = host_elem.find('uptime')
        if uptime_elem is not None:
            uptime = {
                "seconds": uptime_elem.attrib.get('seconds'),
                "lastboot": uptime_elem.attrib.get('lastboot'),
            }

        # Traceroute
        traceroute = []
        trace_elem = host_elem.find('trace')
        if trace_elem is not None:
            for hop in trace_elem.findall('hop'):
                try:
                    ttl = int(hop.attrib.get('ttl', '0'))
                except ValueError:
                    ttl = 0
                traceroute.append({
                    "ttl": ttl,
                    "ip": hop.attrib.get('ipaddr', ''),
                    "rtt": hop.attrib.get('rtt', ''),
                    "host": hop.attrib.get('host', ''),
                })

        return {
            "ip": ip,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "mac": mac,
            "vendor": vendor or "",
            "status": status,
            "primary_hostname": primary_hostname,
            "hostnames": hostnames,
            "ports": ports,
            "extraports": extraports,
            "os_matches": os_matches,
            "primary_os": primary_os,
            "primary_os_accuracy": primary_os_accuracy,
            "distance": distance,
            "uptime": uptime,
            "traceroute": traceroute,
        }

    def _parse_port(self, port_elem: ET.Element) -> Dict[str, Any]:
        """Extract details for a single port element."""
        protocol = port_elem.attrib.get('protocol', 'tcp')
        try:
            portid = int(port_elem.attrib.get('portid', '0'))
        except ValueError:
            portid = 0

        state_elem = port_elem.find('state')
        state = state_elem.attrib.get('state', 'unknown') if state_elem is not None else 'unknown'
        state_reason = state_elem.attrib.get('reason', '') if state_elem is not None else ''

        service_elem = port_elem.find('service')
        service_info = {
            "name": "",
            "product": "",
            "version": "",
            "extrainfo": "",
            "hostname": "",
            "ostype": "",
            "devicetype": "",
            "cpe": [],
            "banner": "",
        }

        if service_elem is not None:
            s_attrs = service_elem.attrib
            service_info["name"] = s_attrs.get('name', '')
            service_info["product"] = s_attrs.get('product', '')
            service_info["version"] = s_attrs.get('version', '')
            service_info["extrainfo"] = s_attrs.get('extrainfo', '')
            service_info["hostname"] = s_attrs.get('hostname', '')
            service_info["ostype"] = s_attrs.get('ostype', '')
            service_info["devicetype"] = s_attrs.get('devicetype', '')

            # Extract CPEs
            for cpe in service_elem.findall('cpe'):
                if cpe.text:
                    service_info["cpe"].append(cpe.text.strip())

            # Construct banner representation
            banner_parts = []
            if service_info["product"]:
                banner_parts.append(service_info["product"])
            if service_info["version"]:
                banner_parts.append(service_info["version"])
            if service_info["extrainfo"]:
                banner_parts.append(f"({service_info['extrainfo']})")

            service_info["banner"] = " ".join(banner_parts) if banner_parts else service_info["name"]

        # Parse NSE scripts output
        scripts = []
        for script in port_elem.findall('script'):
            s_id = script.attrib.get('id', '')
            s_output = script.attrib.get('output', '')
            elems = {}
            for elem in script.findall('elem'):
                k = elem.attrib.get('key', '')
                if k and elem.text:
                    elems[k] = elem.text.strip()

            scripts.append({
                "id": s_id,
                "output": s_output,
                "elements": elems,
            })

        return {
            "portid": portid,
            "protocol": protocol,
            "state": state,
            "state_reason": state_reason,
            "service": service_info,
            "scripts": scripts,
        }


def parse_nmap_xml(xml_input: Union[str, bytes]) -> Dict[str, Any]:
    """
    Convenience function to parse Nmap XML into a normalized Python dictionary.
    """
    parser = NmapParser(xml_input)
    return parser.parse()


def to_ag_grid(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Converts normalized Nmap dictionary output into flat tabular records optimized for AG Grid.

    Each row represents a specific service/port found on a host. If a host has no open ports
    or ports scanned, a host summary row is included.
    """
    rows: List[Dict[str, Any]] = []

    hosts = parsed_data.get('hosts', [])
    for host in hosts:
        ip = host.get('ip', '0.0.0.0')
        ipv6 = host.get('ipv6', '')
        hostname = host.get('primary_hostname', '')
        mac = host.get('mac', '')
        vendor = host.get('vendor', '')
        status = host.get('status', {}).get('state', 'unknown')
        os_name = host.get('primary_os', 'Unknown')
        os_accuracy = host.get('primary_os_accuracy', 0)
        distance = host.get('distance')

        ports = host.get('ports', [])
        if not ports:
            # Add host-level entry if no ports were parsed
            rows.append({
                "id": f"host-{ip}-summary",
                "ip": ip,
                "ipv6": ipv6,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "status": status,
                "port": None,
                "protocol": None,
                "port_state": None,
                "service": "",
                "product": "",
                "version": "",
                "banner": "",
                "os_name": os_name,
                "os_accuracy": os_accuracy,
                "distance": distance,
                "scripts_summary": "",
                "scripts": [],
            })
            continue

        for p in ports:
            portid = p.get('portid')
            protocol = p.get('protocol', 'tcp')
            port_state = p.get('state', 'unknown')
            svc = p.get('service', {})
            scripts = p.get('scripts', [])

            scripts_summary_list = [f"[{s['id']}] {s['output'].strip()}" for s in scripts if s.get('id')]
            scripts_summary = " | ".join(scripts_summary_list)

            rows.append({
                "id": f"host-{ip}-port-{portid}-{protocol}",
                "ip": ip,
                "ipv6": ipv6,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "status": status,
                "port": portid,
                "protocol": protocol,
                "port_state": port_state,
                "service": svc.get('name', ''),
                "product": svc.get('product', ''),
                "version": svc.get('version', ''),
                "banner": svc.get('banner', ''),
                "os_name": os_name,
                "os_accuracy": os_accuracy,
                "distance": distance,
                "scripts_summary": scripts_summary,
                "scripts": scripts,
            })

    return rows


def to_cytoscape(
    parsed_data: Dict[str, Any],
    include_services: bool = True,
    group_by_subnet: bool = True,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Converts normalized Nmap data into Cytoscape.js compatible graph format.

    Returns a dictionary with 'nodes' and 'edges':
    {
      "nodes": [ {"data": { "id": "...", "label": "...", ... }}, ... ],
      "edges": [ {"data": { "id": "...", "source": "...", "target": "...", ... }}, ... ]
    }
    """
    nodes_map: Dict[str, Dict[str, Any]] = {}
    edges_map: Dict[str, Dict[str, Any]] = {}
    subnets_seen: set = set()

    hosts = parsed_data.get('hosts', [])

    for host in hosts:
        ip = host.get('ip', '0.0.0.0')
        hostname = host.get('primary_hostname', '')
        mac = host.get('mac', '')
        vendor = host.get('vendor', '')
        status = host.get('status', {}).get('state', 'unknown')
        os_name = host.get('primary_os', 'Unknown')
        ports = host.get('ports', [])
        open_ports_count = sum(1 for p in ports if p.get('state') == 'open')

        # Calculate subnet parent node if enabled
        parent_subnet_id = None
        if group_by_subnet and ip != "0.0.0.0":
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnet_str = str(net)
                    parent_subnet_id = f"subnet-{subnet_str.replace('/', '_')}"

                    if parent_subnet_id not in subnets_seen:
                        subnets_seen.add(parent_subnet_id)
                        nodes_map[parent_subnet_id] = {
                            "data": {
                                "id": parent_subnet_id,
                                "label": f"Subnet {subnet_str}",
                                "type": "subnet",
                                "cidr": subnet_str,
                            }
                        }
            except ValueError:
                pass

        # Host Node
        host_node_id = f"host-{ip}"
        label_parts = [ip]
        if hostname:
            label_parts.append(f"({hostname})")

        host_data: Dict[str, Any] = {
            "id": host_node_id,
            "label": "\n".join(label_parts),
            "type": "host",
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "status": status,
            "os": os_name,
            "open_ports_count": open_ports_count,
        }

        if parent_subnet_id:
            host_data["parent"] = parent_subnet_id

        nodes_map[host_node_id] = {"data": host_data}

        # Handle Traceroute Hops (Network topology edges)
        traceroute = host.get('traceroute', [])
        if traceroute:
            prev_hop_node_id = None
            for hop in traceroute:
                hop_ip = hop.get('ip')
                if not hop_ip:
                    continue

                hop_host_id = f"host-{hop_ip}"
                if hop_host_id not in nodes_map:
                    nodes_map[hop_host_id] = {
                        "data": {
                            "id": hop_host_id,
                            "label": f"{hop_ip}\n({hop.get('host') or 'Router'})",
                            "type": "router" if hop.get('ttl') == 1 else "hop",
                            "ip": hop_ip,
                            "hostname": hop.get('host', ''),
                            "status": "up",
                        }
                    }

                if prev_hop_node_id:
                    edge_id = f"edge-{prev_hop_node_id}-to-{hop_host_id}"
                    if edge_id not in edges_map:
                        edges_map[edge_id] = {
                            "data": {
                                "id": edge_id,
                                "source": prev_hop_node_id,
                                "target": hop_host_id,
                                "rtt": hop.get('rtt', ''),
                                "label": f"rtt: {hop.get('rtt', '')}ms" if hop.get('rtt') else "",
                            }
                        }
                prev_hop_node_id = hop_host_id

            # Connect last traceroute hop to the target host if different
            if prev_hop_node_id and prev_hop_node_id != host_node_id:
                edge_id = f"edge-{prev_hop_node_id}-to-{host_node_id}"
                if edge_id not in edges_map:
                    edges_map[edge_id] = {
                        "data": {
                            "id": edge_id,
                            "source": prev_hop_node_id,
                            "target": host_node_id,
                            "label": "direct",
                        }
                    }

        # Optional Service Nodes connected to Host
        if include_services:
            for p in ports:
                portid = p.get('portid')
                protocol = p.get('protocol', 'tcp')
                port_state = p.get('state', 'unknown')
                svc = p.get('service', {})
                svc_name = svc.get('name', 'unknown')

                service_node_id = f"service-{ip}-{portid}-{protocol}"
                nodes_map[service_node_id] = {
                    "data": {
                        "id": service_node_id,
                        "label": f"{portid}/{protocol}\n{svc_name}",
                        "type": "service",
                        "port": portid,
                        "protocol": protocol,
                        "state": port_state,
                        "service": svc_name,
                        "banner": svc.get('banner', ''),
                        "host_ip": ip,
                    }
                }

                edge_id = f"edge-{host_node_id}-to-{service_node_id}"
                edges_map[edge_id] = {
                    "data": {
                        "id": edge_id,
                        "source": host_node_id,
                        "target": service_node_id,
                        "label": f"{protocol}:{portid}",
                    }
                }

    return {
        "nodes": list(nodes_map.values()),
        "edges": list(edges_map.values()),
    }
