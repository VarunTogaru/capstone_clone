import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    hosts = []

    for host in root.findall("host"):
        addr_node = host.find("address")
        address = addr_node.attrib.get("addr") if addr_node is not None else None

        ports_out = []
        ports_node = host.find("ports")
        if ports_node is not None:
            for p in ports_node.findall("port"):
                portid = p.attrib.get("portid")
                proto = p.attrib.get("protocol")
                state = p.find("state").attrib.get("state")
                service_node = p.find("service")
                service = service_node.attrib.get("name") if service_node is not None else None
                ports_out.append({"port": portid, "proto": proto, "state": state, "service": service})

        hosts.append({"address": address, "ports": ports_out})

    return {"hosts": hosts}