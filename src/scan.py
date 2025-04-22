import nmap
import json

def scan_host(host, ports="1-1024"):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=host, arguments=f"-sV -p {ports} --script vulners --script-args vulners.showall=true")
    
    scan_data = {
        "scan_info": scanner.scaninfo(),
        "scan_stats": scanner.scanstats(),
        "hosts": {}
    }
    
    for host in scanner.all_hosts():
        scan_data["hosts"][host] = {
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "protocols": {}
        }
        for proto in scanner[host].all_protocols():
            scan_data["hosts"][host]["protocols"][proto] = {}
            ports = scanner[host][proto].keys()
            for port in ports:
                port_info = scanner[host][proto][port]
                vulners_data = port_info.get("script", {}).get("vulners", {})
                
                scan_data["hosts"][host]["protocols"][proto][port] = {
                    "state": port_info["state"],
                    "name": port_info["name"],
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "vulners": vulners_data
                }
    
    return json.dumps(scan_data)

