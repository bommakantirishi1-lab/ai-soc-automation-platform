from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from database import init_db, get_all_alerts, insert_alert
from datetime import datetime

app = FastAPI(title="SOC SaaS Platform")

init_db()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    alerts = get_all_alerts()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "alerts": alerts
    })


@app.post("/run-detection")
def run_detection():
    # Demo insertion (replace with real engine later)
    insert_alert(
        source_ip="192.168.1.100",
        score=12,
        severity="Medium",
        assigned_to="Sai Rishi Kumar Bommakanti"
    )

    return {"status": "Detection executed"}