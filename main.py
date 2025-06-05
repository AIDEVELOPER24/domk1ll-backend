# main.py

from fastapi import FastAPI
from routers import scan_router

app = FastAPI(
    title="CyberSecurity Scanner API",
    description="Performs selected scans on target IPs or domains.",
    version="1.0.0"
)

app.include_router(scan_router.router, prefix="/api")

@app.get("/")
def root():
    return {"message": "CyberSecurity Scanner API is running."}
