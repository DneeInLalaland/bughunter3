# main.py
import os
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse  # เพิ่มสำหรับ Task 3.5
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import requests 
import time 
# Import สำหรับ Email Alert
import smtplib
import requests
from tenacity import retry, stop_after_attempt, wait_fixed

# Import สำหรับ Task 3.5: PDF Report Generation
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import สำหรับ DB (Task 3.1)
from db_utils import start_new_scan_in_db, save_vulnerability, update_scan_status, get_results_from_db, update_scan_progress 

# -------------------- ส่วนที่ 1: CONFIGURATION --------------------

# --- A. Port Configuration (Task 3.3) ---
SCANNER_API_URL = os.getenv("SCANNER_API_URL", "http://scanner:5001") + "/scan/all"
ML_API_URL = os.getenv("ML_API_URL", "http://ml:5000") + "/predict"   

# *** B. Email Configuration (Task 3.4) ***
EMAIL_SENDER = "projectfinal.i02bug@gmail.com"        # <-- **** อีเมลผู้ส่ง ****
EMAIL_PASSWORD = "uuyx ixmk gnya zlpg"        # <-- **** รหัสผ่านสำหรับแอป 16 หลัก ****
EMAIL_RECEIVER = "dnee5515@gmail.com" # <-- อีเมลผู้รับแจ้งเตือน
SMTP_SERVER = "smtp.gmail.com"              
SMTP_PORT = 587                             

app = FastAPI(title="AI-Powered Vulnerability Scanner Backend (P3)")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------- ส่วนที่ 2: FUNCTIONS --------------------

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def call_scanner_api(url: str):
    """เรียกใช้ Scanner API (Person 1) พร้อม Retry 3 ครั้ง"""
    try:
        print(f"[SCANNER] Calling Scanner API: {SCANNER_API_URL}")
        response = requests.post(
            SCANNER_API_URL,
            json={"url": url}, 
            timeout=60 
        ) 
        response.raise_for_status()
        result = response.json()
        print(f"[SCANNER] Response received: {result.keys() if isinstance(result, dict) else type(result)}")
        return result
    except Exception as e:
        print(f"[SCANNER] ERROR: {e}")
        return {"vulnerabilities": []}

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def call_ml_api(vuln_data: dict):
    """เรียกใช้ ML API (Person 2) พร้อม Retry 3 ครั้ง"""
    response = requests.post(
        ML_API_URL, 
        json=vuln_data,
        timeout=30
    )
    response.raise_for_status() 
    return response.json()

# --- Task 3.4: Email Alert Function ---
def send_email_notification(subject: str, body: str):
    """
    ส่งอีเมลแจ้งเตือนผ่าน SMTP (Gmail ต้องใช้ App Password)
    """
    SENDER_DISPLAY_NAME = "Bughunter" 
    
    msg = MIMEMultipart()
    msg['From'] = f"{SENDER_DISPLAY_NAME} <{EMAIL_SENDER}>"
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls() 
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, text)
        server.quit()
        print(f"[ALERT SUCCESS] Email notification sent: {subject[:50]}...")
    except Exception as e:
        print(f"[ALERT ERROR] Failed to send email notification: {e}")
        pass


# --- Task 3.5: PDF Report Generation Function ---
def generate_pdf_report(scan_id: int, results: dict):
    """
    Task 3.5: สร้างไฟล์ PDF Report
    สร้าง PDF report สรุปผลการ scan
    """
    # สร้าง folder reports ถ้ายังไม่มี
    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    report_filename = os.path.join(report_dir, f"report_scan_{scan_id}.pdf")
    
    # สร้าง PDF
    c = canvas.Canvas(report_filename, pagesize=letter)
    width, height = letter
    
    # === 1. Title Section ===
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width/2, height - 50, "AI-Powered Vulnerability Scan Report")
    
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(width/2, height - 75, "BugHunter Security Scanner")
    
    # === 2. Scan Details ===
    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 120, "Scan Information")
    c.line(72, height - 125, 540, height - 125)
    
    c.setFont("Helvetica", 11)
    y = height - 145
    
    # ดึงข้อมูลจาก results (ป้องกัน None)
    target_url = results.get('target_url', 'N/A')
    status = results.get('status', 'unknown')
    vulnerabilities = results.get('vulnerabilities', [])
    total_vulns = len(vulnerabilities)
    
    # จัดรูปแบบเวลา (FIX: ป้องกัน TypeError เมื่อเวลาเป็น None)
    start_time_obj = results.get('start_time')
    end_time_obj = results.get('end_time')
    
    if isinstance(start_time_obj, datetime):
        start_time_str = start_time_obj.strftime("%Y-%m-%d %H:%M:%S")
    elif start_time_obj:
        start_time_str = str(start_time_obj)
    else:
        start_time_str = 'N/A'
    
    if isinstance(end_time_obj, datetime):
        end_time_str = end_time_obj.strftime("%Y-%m-%d %H:%M:%S")
    elif end_time_obj:
        end_time_str = str(end_time_obj)
    else:
        end_time_str = 'N/A'
    
    # เขียนข้อมูล Scan
    c.drawString(72, y, f"Scan ID: {scan_id}")
    y -= 18
    c.drawString(72, y, f"Target URL: {target_url}")
    y -= 18
    c.drawString(72, y, f"Status: {status.upper()}")
    y -= 18
    c.drawString(72, y, f"Start Time: {start_time_str}")
    y -= 18
    c.drawString(72, y, f"End Time: {end_time_str}")
    y -= 35
    
    # === 3. Summary Statistics ===
    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, y, "Vulnerability Summary")
    c.line(72, y - 5, 540, y - 5)
    y -= 25
    
    # นับ severity
    critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
    high_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')
    medium_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'medium')
    low_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'low')
    
    c.setFont("Helvetica", 11)
    c.drawString(72, y, f"Total Vulnerabilities Found: {total_vulns}")
    y -= 18
    
    # แสดง severity breakdown พร้อมสี
    c.setFillColorRGB(0.8, 0, 0)  # Red
    c.drawString(72, y, f"Critical: {critical_count}")
    
    c.setFillColorRGB(1, 0.5, 0)  # Orange
    c.drawString(172, y, f"High: {high_count}")
    
    c.setFillColorRGB(1, 0.8, 0)  # Yellow
    c.drawString(272, y, f"Medium: {medium_count}")
    
    c.setFillColorRGB(0, 0.6, 0)  # Green
    c.drawString(372, y, f"Low: {low_count}")
    
    c.setFillColorRGB(0, 0, 0)  # Reset to black
    y -= 40
    
    # === 4. Detailed Vulnerabilities ===
    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, y, "Detailed Findings")
    c.line(72, y - 5, 540, y - 5)
    y -= 25
    
    c.setFont("Helvetica", 10)
    
    # เรียง vulnerabilities ตาม severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_vulns = sorted(
        vulnerabilities, 
        key=lambda v: severity_order.get(v.get('severity', 'low').lower(), 4)
    )
    
    # แสดงแค่ 15 vulnerabilities แรก (ป้องกันล้นหน้า)
    for i, vuln in enumerate(sorted_vulns[:15], 1):
        # เช็คว่าต้องขึ้นหน้าใหม่ไหม
        if y < 100:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 50
        
        vuln_type = vuln.get('type', 'Unknown')
        severity = vuln.get('severity', 'N/A')
        cvss = vuln.get('cvss_score', 'N/A')
        ai_score = vuln.get('ai_risk_score', 'N/A')
        affected_url = vuln.get('url', vuln.get('affected_url', 'N/A'))
        description = vuln.get('description', 'No description')[:80]  # ตัดให้สั้น
        
        # สีตาม severity
        if severity.lower() == 'critical':
            c.setFillColorRGB(0.8, 0, 0)
        elif severity.lower() == 'high':
            c.setFillColorRGB(1, 0.5, 0)
        elif severity.lower() == 'medium':
            c.setFillColorRGB(0.8, 0.6, 0)
        else:
            c.setFillColorRGB(0, 0.5, 0)
        
        c.setFont("Helvetica-Bold", 10)
        c.drawString(72, y, f"{i}. [{severity.upper()}] {vuln_type}")
        c.setFillColorRGB(0, 0, 0)
        
        y -= 15
        c.setFont("Helvetica", 9)
        c.drawString(90, y, f"CVSS: {cvss} | AI Risk: {ai_score} | URL: {str(affected_url)[:50]}")
        y -= 12
        c.drawString(90, y, f"Description: {description}")
        y -= 20
    
    # แสดงว่ามี vuln เพิ่มเติม
    if len(vulnerabilities) > 15:
        c.setFont("Helvetica-Oblique", 10)
        c.drawString(72, y, f"... and {len(vulnerabilities) - 15} more vulnerabilities")
        y -= 25
    
    # === 5. Footer ===
    c.setFont("Helvetica", 8)
    c.drawString(72, 40, f"Report generated by BugHunter on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(72, 28, "AI-Powered Vulnerability Scanner - KMUTT Project")
    
    # Save PDF
    c.save()
    print(f"[REPORT] PDF Report generated: {report_filename}")
    
    return report_filename


def save_vulnerability(scan_id: int, vuln: dict):
    """Save vulnerability to database"""
    import psycopg2
    
    try:
        conn = psycopg2.connect(
            dbname="vulnerability_scanner",
            user="scanuser",
            password="scanpass123",
            host="postgres",
            port="5432"
        )
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO vulnerabilities 
            (scan_id, type, severity, cvss_score, ai_risk_score, description, affected_url)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            scan_id,
            vuln.get('type', 'Unknown'),
            vuln.get('severity', 'Low'),
            vuln.get('cvss_score', 0.0),
            vuln.get('ai_risk_score', 0.0),
            vuln.get('description', ''),
            vuln.get('url', '')
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        print(f"[DB] Saved vulnerability: {vuln.get('type')}")
        
    except Exception as e:
        print(f"[DB] Error saving vulnerability: {e}")

def run_full_scan(scan_id: int, url: str, client_email: str = ""):
    """
    ฟังก์ชันหลักที่รันใน Background เพื่อประสานงาน Scanner และ ML Model (P1 & P2)
    """
    scan_start_time = datetime.now()  # บันทึกเวลาเริ่ม
    
    try:
        print(f"[ORCHESTRATOR] Starting scan for ID: {scan_id}, URL: {url}")
        
        # 1. CALL Scanner API (P1) - Integration
        update_scan_progress(scan_id, 15, "Scanning target website...")
        scanner_results = call_scanner_api(url)
        # Extract vulnerabilities from nested structure
        all_vulns = []
        results = scanner_results.get('results', {})
        for scan_type, data in results.items():
            vulns = data.get('vulnerabilities', data.get('issues', []))
            for v in vulns:
                v['scan_type'] = scan_type
                all_vulns.append(v)

        vulnerabilities = all_vulns

        # 2. LOOP และ CALL ML API (P2)
        total_vulns = len(vulnerabilities)
        update_scan_progress(scan_id, 40, f"Found {total_vulns} vulnerabilities, analyzing...")
        
        for idx, vuln in enumerate(vulnerabilities):
            # คำนวณ progress: 40% -> 85% (แบ่งตามจำนวน vulnerabilities)
            if total_vulns > 0:
                progress_per_vuln = 45.0 / total_vulns  # 45% สำหรับ loop (40-85)
                current_progress = 40 + int((idx + 1) * progress_per_vuln)
                update_scan_progress(scan_id, current_progress, f"Analyzing vulnerability {idx + 1}/{total_vulns}...")
            
            # แปลงข้อมูลให้ตรงกับ ML format
            print(f"[DEBUG] Processing vulnerability: {vuln.get('type', 'Unknown')}")
            # Helper functions สำหรับแปลงค่า
            def encode_severity(severity):
                mapping = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
                return mapping.get(severity, 1)
            
            def encode_attack_vector(vector):
                mapping = {"Network": 1, "Adjacent": 2, "Local": 3, "Physical": 4}
                return mapping.get(vector, 1)
            
            def encode_privileges(priv):
                mapping = {"None": 2, "Low": 1, "High": 0}
                return mapping.get(priv, 1)
            
            # ดึงค่าจาก vulnerability
            cvss_score = float(vuln.get("cvss_score", 5.0))
            severity = vuln.get("severity", "Medium")
            
            # สร้าง ML payload ที่มีครบ 13 fields
            ml_input = {
                "cvss_base_score": cvss_score,
                "exploitability_score": float(vuln.get("exploitability_score", cvss_score * 0.4)),
                "impact_score": float(vuln.get("impact_score", cvss_score * 0.6)),
                "cvss_severity_encoded": encode_severity(severity),
                "attack_vector_encoded": encode_attack_vector(vuln.get("attack_vector", "Network")),
                "attack_complexity_encoded": 0 if vuln.get("attack_complexity", "Low") == "Low" else 1,
                "privileges_required_encoded": encode_privileges(vuln.get("privileges_required", "None")),
                "user_interaction_encoded": 0 if vuln.get("user_interaction", "None") == "None" else 1,
                "cvss_combined": cvss_score,
                "attack_ease_score": float(vuln.get("exploitability_score", cvss_score * 0.4)) * 0.7,
                "public_exposure": 1 if vuln.get("has_public_exploit", False) else 0,
                "age_factor": 0.5,
                "severity_score": encode_severity(severity)
            }
            
            print(f"[ML INPUT] Sending to ML: {ml_input}")
            # 👆 จบส่วนที่เพิ่ม
            
            # 2.1 เรียก ML API (ส่ง ml_input แทน vuln)
            ai_result = call_ml_api(ml_input)
            
            print(f"[ML RESULT] Got result: {ai_result}")
            
            # 2.2 นำคะแนน AI มาเพิ่ม
            # แปลง risk_level เป็นตัวเลข 0-10
            risk_level = ai_result.get('risk_level', 'Medium')
            risk_mapping = {"Low": 3.0, "Medium": 5.0, "High": 7.5, "Critical": 9.5}
            vuln['ai_risk_score'] = risk_mapping.get(risk_level, 5.0)
            
            # 3. Save to Database (Task 3.1)
            save_vulnerability(scan_id, vuln)
            
            # 4. Task 3.4: Critical Alert Logic
            if vuln.get('ai_risk_score', 0.0) >= 9.0:
                alert_subject = f"🚨 CRITICAL VULN: {vuln.get('type')}"
                alert_body = f"พบช่องโหว่ Critical ที่ URL: {url}\nAI Risk Score: {vuln.get('ai_risk_score')}"
                send_email_notification(alert_subject, alert_body) # ส่งหา Admin

        # --- Task 3.5: สร้าง PDF Report อัตโนมัติหลัง scan เสร็จ ---
        scan_end_time = datetime.now()
        results_for_report = {
            'target_url': url,
            'status': 'completed',
            'start_time': scan_start_time,
            'end_time': scan_end_time,
            'vulnerabilities': vulnerabilities
        }
        update_scan_progress(scan_id, 90, "Generating PDF report...")
        generate_pdf_report(scan_id, results_for_report)

        # --- ขั้นตอนสุดท้ายหลังสแกนเสร็จ ---
        update_scan_progress(scan_id, 100, "Scan completed!")
        update_scan_status(scan_id, 'completed') # บันทึกสถานะสำเร็จ
        print(f"[ORCHESTRATOR] Scan ID {scan_id} COMPLETED and Report ready for {client_email}.")
    except Exception as e:
        print(f"[ORCHESTRATOR] EXCEPTION: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()

        # 6. Task 4.1: Error Handling (เมื่อ Retry ล้มเหลวครบ 3 ครั้ง)
        print(f"[ORCHESTRATOR] FATAL ERROR for Scan ID {scan_id}: {e}")
        update_scan_status(scan_id, 'failed')
        
        error_subject = f"❌ SCAN FAILED: ID {scan_id} - {url}"
        error_body = f"Scan failed with error: {str(e)}"
        send_email_notification(error_subject, error_body)


# -------------------- ส่วนที่ 3: ENDPOINTS API --------------------

class ScanRequest(BaseModel):
    target_url: str

@app.post("/scan")
async def start_scan(
    url: str = Query(..., description="The URL to scan"), 
    background_tasks: BackgroundTasks = None
):
    """
    🚀 Start a new vulnerability scan.
    """
    scan_id = start_new_scan_in_db(url)
    
    if scan_id is None:
        raise HTTPException(status_code=500, detail="Failed to initialize scan (Database error).")
        
    background_tasks.add_task(run_full_scan, scan_id, url)
    
    return {
        "id": scan_id,
        "message": "Scan initiated. Check status_url for results.",
        "status_url": f"/scan/{scan_id}"
    }

@app.post("/api/scan")
async def start_scan_api(
    url: str = Query(..., description="The URL to scan"), 
    background_tasks: BackgroundTasks = None
):
    """🚀 Start a new vulnerability scan (API version)"""
    return await start_scan(url, background_tasks)

@app.post("/api/scans")
async def start_scan_api_json(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """🚀 Start a new vulnerability scan (JSON body version)"""
    scan_id = start_new_scan_in_db(request.target_url)
    
    if scan_id is None:
        raise HTTPException(status_code=500, detail="Failed to initialize scan (Database error).")
        
    background_tasks.add_task(run_full_scan, scan_id, request.target_url)
    
    return {
        "id": scan_id,
        "message": "Scan initiated. Check status_url for results.",
        "status_url": f"/scan/{scan_id}"
    }

@app.get("/scan/{scan_id}")
async def get_scan_results(scan_id: int):
    """
    📊 Retrieve the results or current status of a specific scan ID.
    """
    results = get_results_from_db(scan_id) 
    
    if results is None:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found.")
        
    return results

# --- Task 3.5: PDF Report Download Endpoint ---
@app.get("/api/reports/{scan_id}")
async def get_report(scan_id: int):
    """
    📄 Generate and download PDF report for a scan
    """
    # ดึงข้อมูล scan จาก database
    results = get_results_from_db(scan_id)
    
    if results is None:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found")
    
    # สร้าง PDF
    report_path = generate_pdf_report(scan_id, results)
    
    # ส่งไฟล์กลับ
    return FileResponse(
        path=report_path,
        filename=f"vulnerability_report_scan_{scan_id}.pdf",
        media_type="application/pdf"
    )

# เพิ่ม Health Check Endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "scanner_api": SCANNER_API_URL,
        "ml_api": ML_API_URL
    }

# เพิ่ม Get All Scans (สำหรับ Frontend)
@app.get("/api/scans")
async def get_all_scans(skip: int = 0, limit: int = 10):
    """Get list of all scans"""
    import psycopg2
    from psycopg2.extras import RealDictCursor
    
    try:
        conn = psycopg2.connect(
            dbname="vulnerability_scanner",
            user="scanuser",
            password="scanpass123",
            host="postgres",
            port="5432"
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM scans ORDER BY scan_date DESC LIMIT %s OFFSET %s", (limit, skip))
        scans = cur.fetchall()
        cur.close()
        conn.close()
        # Add id field for frontend compatibility
        for scan in scans:
            scan["id"] = scan["scan_id"]
        return scans
    except Exception as e:
        print(f"Error fetching scans: {e}")
        return []

@app.get("/api/scans/{scan_id}")
async def get_scan_by_id(scan_id: int):
    """Get scan details by ID"""
    import psycopg2
    from psycopg2.extras import RealDictCursor
    
    try:
        conn = psycopg2.connect(
            dbname="vulnerability_scanner",
            user="scanuser",
            password="scanpass123",
            host="postgres",
            port="5432"
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
        scan = cur.fetchone()
        
        if scan:
            # ดึง vulnerabilities ด้วย
            cur.execute("SELECT * FROM vulnerabilities WHERE scan_id = %s", (scan_id,))
            vulnerabilities = cur.fetchall()
            scan["vulnerabilities"] = vulnerabilities
            scan["id"] = scan["scan_id"]
            scan["progress"] = scan.get("progress", 0)
            scan["status_message"] = scan.get("status_message", "")
        
        cur.close()
        conn.close()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return scan
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "BugHunter API",
        "docs": "/docs",
        "health": "/health",
        "reports": "/api/reports/{scan_id}"  # เพิ่ม endpoint ใหม่
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# --- API สำหรับ Reset Dashboard ---
@app.delete("/api/reset")
def reset_all_data():
    """ลบข้อมูล scan ทั้งหมดเพื่อ reset dashboard"""
    try:
        from db_utils import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ลบข้อมูลทั้งหมด
        cursor.execute("DELETE FROM vulnerabilities")
        cursor.execute("DELETE FROM scans")
        conn.commit()
        
        cursor.close()
        conn.close()
        
        print("[RESET] All data deleted successfully!")
        return {"message": "All scan data has been reset successfully", "status": "success"}
    except Exception as e:
        print(f"[RESET ERROR] {e}")
        raise HTTPException(status_code=500, detail=str(e))
