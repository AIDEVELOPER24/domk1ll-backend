# router/scan_router.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from features.basic_port_scan import run_basic_port_scan
from features.service_version_detection import run_service_version_detection
from features.os_detection import run_os_detection
from features.geoip_lookup import run_geoip_lookup
from features.vulnerability_scan import run_vulnerability_scan  # NEW

router = APIRouter()

class ScanRequest(BaseModel):
    target: str
    scan_types: list[str] = []

@router.post("/scan")
def perform_scan(request: ScanRequest):
    if not request.target:
        raise HTTPException(status_code=400, detail="Target is required.")
    if not request.scan_types:
        raise HTTPException(status_code=400, detail="No scan type selected.")

    result = {"status": "success", "target": request.target}
    open_ports_for_service_scan = []

    # Basic Port Scan
    if "basic_scan" in request.scan_types:
        basic = run_basic_port_scan(request.target)
        if basic["status"] == "error":
            raise HTTPException(status_code=500, detail=basic["message"])
        result["open_ports"] = basic["open_ports"]
        result["open_port_count"] = basic["open_port_count"]
        open_ports_for_service_scan = [str(p["port"]) for p in basic["open_ports"]]

    # Service Version Detection
    if "service_scan" in request.scan_types:
        ports_arg = (
            ",".join(open_ports_for_service_scan)
            if open_ports_for_service_scan else "1-1024"
        )
        svc = run_service_version_detection(request.target, ports_arg)
        if svc["status"] == "error":
            raise HTTPException(status_code=500, detail=svc["message"])
        result["service_versions"] = svc["service_versions"]

    # OS Detection
    if "os_detection" in request.scan_types:
        osr = run_os_detection(request.target)
        if osr["status"] == "error":
            raise HTTPException(status_code=500, detail=osr["message"])
        result["os_info"] = {
            "ttl": osr.get("ttl"),
            "os_guess": osr.get("os_guess")
        }

    # GeoIP Lookup
    if "geoip" in request.scan_types:
        geo = run_geoip_lookup(request.target)
        if geo["status"] == "error":
            raise HTTPException(status_code=500, detail=geo["message"])
        result["geoip_info"] = geo["geoip_data"]

    # Vulnerability Scan
    if "vuln_scan" in request.scan_types:
        vuln = run_vulnerability_scan(request.target)
        if "error" in vuln:
            raise HTTPException(status_code=500, detail=vuln["error"])
        # vulnerability_results is a list of port-based findings
        result["vulnerability_results"] = vuln.get("vulnerability_results", [])

    return result
