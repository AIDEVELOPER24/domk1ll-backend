import socket
import requests

def run_geoip_lookup(target: str) -> dict:
    try:
        # Convert domain to IP if needed
        try:
            ip_address = socket.gethostbyname(target)
        except Exception:
            return {"status": "error", "message": "Invalid domain or IP"}

        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,zip,lat,lon,org,as,query")
        data = response.json()

        if data["status"] != "success":
            return {"status": "error", "message": data.get("message", "GeoIP lookup failed")}

        return {
            "status": "success",
            "geoip_data": {
                "ip": data.get("query"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "org": data.get("org"),
                "as_info": data.get("as"),
            }
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}
