# features/service_version_detection.py

import nmap

def run_service_version_detection(target: str, ports: str = '1-1024') -> dict:
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=f'-sV --version-intensity 5 -p {ports} -T4')

        results = []
        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                for port in sorted(nm[target][proto].keys()):
                    port_data = nm[target][proto][port]
                    if port_data['state'] == 'open':
                        service = port_data.get('name', 'unknown')
                        product = port_data.get('product', '')
                        version = port_data.get('version', '')
                        extrainfo = port_data.get('extrainfo', '')

                        full_version = f"{product} {version} {extrainfo}".strip() or 'n/a'

                        results.append({
                            "port": port,
                            "service": service,
                            "version": full_version
                        })

        return {
            "status": "success",
            "target": target,
            "service_versions": results
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Service version scan failed: {str(e)}"
        }
