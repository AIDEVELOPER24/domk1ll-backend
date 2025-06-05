# features/basic_port_scan.py

import nmap

COMMON_PORTS = range(1, 1025)

# Risk levels based on common port threats
PORT_RISK_MAP = {
    21: "High", 22: "Medium", 23: "High", 25: "Medium",
    53: "Low", 80: "Medium", 110: "Medium", 139: "High",
    143: "Low", 443: "Low", 445: "High", 3389: "High"
}

def get_port_risk(port: int) -> str:
    return PORT_RISK_MAP.get(port, "Low")

def run_basic_port_scan(target: str) -> dict:
    nm = nmap.PortScanner()
    
    try:
        # Perform scan
        nm.scan(hosts=target, arguments="-p 1-1024 -T4")

        results = []
        for proto in nm[target].all_protocols():
            ports = nm[target][proto].keys()
            for port in sorted(ports):
                state = nm[target][proto][port]['state']
                if state == 'open':
                    service = nm[target][proto][port].get('name', 'unknown')
                    results.append({
                        "port": port,
                        "service": service,
                        "risk": get_port_risk(port)
                    })

        return {
            "status": "success",
            "target": target,
            "open_ports": results,
            "open_port_count": len(results)
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Scan failed: {str(e)}"
        }
