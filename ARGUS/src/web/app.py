"""
Web Interface for ARGUS Security Tool
Flask-based web dashboard with deep intelligence display
"""

from flask import Flask, render_template_string, request, jsonify, redirect, url_for, flash
import json
from datetime import datetime
import os
from pathlib import Path

def create_app(argus):
    """Create Flask application"""
    app = Flask(__name__)
    app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'argus-panoptes-secret-key')

    # --- Rate Limiting (from security config) ---
    _sec_cfg = argus.config_manager.get('security', {})
    _rl_cfg = _sec_cfg.get('rate_limiting', {})
    _rl_enabled = _rl_cfg.get('enabled', True)
    _rl_max_rpm = _rl_cfg.get('max_requests_per_minute', 60)
    _rl_buckets = {}  # ip -> (count, window_start)

    @app.before_request
    def _rate_limit():
        if not _rl_enabled:
            return None
        import time as _t
        ip = request.remote_addr or '0.0.0.0'
        now = _t.time()
        count, window = _rl_buckets.get(ip, (0, now))
        if now - window > 60:
            _rl_buckets[ip] = (1, now)
            return None
        if count >= _rl_max_rpm:
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
        _rl_buckets[ip] = (count + 1, window)
        return None

    @app.after_request
    def _security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com"
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

    @app.route('/')
    def index():
        return render_template_string(INDEX_HTML)

    # Keys that must NEVER appear in API responses (loaded once at startup)
    _secret_values = set()
    for _env_key in ('ARGUS_VIRUSTOTAL_KEY', 'ARGUS_ABUSEIPDB_KEY',
                     'ARGUS_OTX_KEY', 'ARGUS_IPINFO_TOKEN', 'FLASK_SECRET_KEY'):
        _v = os.environ.get(_env_key, '')
        if _v and len(_v) > 6:
            _secret_values.add(_v)

    def _sanitize_response(obj, secrets=_secret_values):
        """Recursively scrub any secret values from a response dict."""
        if isinstance(obj, dict):
            return {k: _sanitize_response(v, secrets) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_sanitize_response(i, secrets) for i in obj]
        if isinstance(obj, str):
            for s in secrets:
                if s in obj:
                    obj = obj.replace(s, '***REDACTED***')
            return obj
        return obj

    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        try:
            force = data.get('force', False)
            deep_fetch = data.get('deep_fetch', False)
            result = argus.scan_url(data['url'], force=bool(force),
                                    deep_fetch=bool(deep_fetch))
            # Close sessions after scan to prevent CloseWait TCP pile-up
            try:
                argus.url_detector.close_sessions()
            except Exception:
                pass
            return jsonify(_sanitize_response(result))
        except Exception as e:
            return jsonify({'error': str(_sanitize_response(str(e)))}), 500

    @app.route('/api/history')
    def api_history():
        try:
            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)
            history = argus.scan_cache.get_history(limit=limit, offset=offset)
            return jsonify({'history': history, 'total': argus.scan_cache.get_history_count()})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/history/export')
    def api_history_export():
        try:
            data = argus.scan_cache.export_json()
            return app.response_class(data, mimetype='application/json',
                                      headers={'Content-Disposition': 'attachment; filename=argus_scan_history.json'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/history/clear', methods=['POST'])
    def api_history_clear():
        try:
            argus.scan_cache.clear()
            return jsonify({'status': 'cleared'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/batch_scan', methods=['POST'])
    def api_batch_scan():
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({'error': 'URLs list is required'}), 400
        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs must be a list'}), 400
        try:
            deep_fetch = data.get('deep_fetch', False)
            results = argus.scan_urls(urls, deep_fetch=bool(deep_fetch))
            return jsonify({'results': results})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/encrypt', methods=['POST'])
    def api_encrypt():
        data = request.get_json()
        if not data or 'data' not in data:
            return jsonify({'error': 'Data is required'}), 400
        try:
            encrypted = argus.encrypt_data(data['data'])
            return jsonify({'encrypted': encrypted})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/decrypt', methods=['POST'])
    def api_decrypt():
        data = request.get_json()
        if not data or 'encrypted_data' not in data:
            return jsonify({'error': 'Encrypted data is required'}), 400
        try:
            decrypted = argus.decrypt_data(data['encrypted_data'])
            return jsonify({'decrypted': decrypted})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


    @app.route('/api/sandbox', methods=['GET'])
    def api_sandbox_status():
        try:
            detector = argus.url_detector
            return jsonify({'sandbox': detector.sandbox.is_active})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/sandbox', methods=['POST'])
    def api_sandbox_toggle():
        try:
            data = request.get_json() or {}
            detector = argus.url_detector
            new_state = data.get('enabled', not detector.sandbox.is_active)
            detector.sandbox.toggle(bool(new_state))
            return jsonify({'sandbox': detector.sandbox.is_active})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/dashboard')
    def dashboard():
        return redirect(url_for('index'))

    @app.route('/encrypt')
    def encrypt_page():
        return render_template_string(ENCRYPT_HTML)

    @app.route('/decrypt')
    def decrypt_page():
        return render_template_string(DECRYPT_HTML)

    @app.route('/settings')
    def settings():
        config = argus.config_manager.config
        return render_template_string(SETTINGS_HTML, config=config)

    @app.errorhandler(404)
    def not_found(error):
        return render_template_string(ERROR_404_HTML), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template_string(ERROR_500_HTML), 500

    return app


# ---------------------------------------------------------------------------
# CSS shared across all pages
# ---------------------------------------------------------------------------
ARGUS_CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#08080e;color:#d0d0d8;line-height:1.65;font-size:15px}
a{color:#8b9cf7;text-decoration:none}a:hover{color:#bac4ff}

.header{background:linear-gradient(135deg,#12102a 0%,#0a0a1e 100%);border-bottom:1px solid #1c1c30;padding:14px 0;position:sticky;top:0;z-index:100}
.header-inner{max-width:1100px;margin:0 auto;padding:0 28px;display:flex;align-items:center;justify-content:space-between}
.logo{font-size:1.4em;font-weight:700;color:#fff;display:flex;align-items:center;gap:10px;letter-spacing:.5px}
.logo-icon{font-size:1.3em}
.nav{display:flex;gap:4px}
.nav a{color:#777;padding:8px 18px;border-radius:8px;font-size:.88em;transition:all .2s;font-weight:500}
.nav a:hover,.nav a.active{color:#fff;background:rgba(139,156,247,.12)}

.container{max-width:1100px;margin:0 auto;padding:28px}

.card{background:#0f0f18;border:1px solid #1c1c2e;border-radius:14px;padding:28px;margin-bottom:24px}
.card h2{color:#fff;font-size:1.25em;margin-bottom:14px;display:flex;align-items:center;gap:10px;font-weight:600}
.card h3{color:#bbb;font-size:1em;margin-bottom:14px;font-weight:600}

.intel-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px}
.intel-full{grid-column:1/-1}
@media(max-width:900px){.intel-grid{grid-template-columns:1fr}}

.intel-section{background:#0b0b14;border:1px solid #1a1a2c;border-radius:12px;overflow:hidden}
.intel-header{padding:16px 22px;background:#101020;cursor:pointer;display:flex;justify-content:space-between;align-items:center;user-select:none;border-bottom:1px solid #1a1a2c;transition:background .15s}
.intel-header:hover{background:#14142a}
.intel-header h4{color:#8b9cf7;font-size:.92em;font-weight:600;display:flex;align-items:center;gap:10px}
.intel-header .ico{font-size:1.1em;opacity:.7}
.intel-header .toggle{color:#444;transition:transform .2s;font-size:.7em}
.intel-header.open .toggle{transform:rotate(180deg)}
.intel-body{padding:18px 22px;display:none;max-height:600px;overflow-y:auto}
.intel-body.open{display:block}

.data-table{width:100%;border-collapse:collapse;font-size:.87em}
.data-table tr:nth-child(even) td{background:rgba(255,255,255,.01)}
.data-table td{padding:8px 12px;border-bottom:1px solid #151520;vertical-align:top}
.data-table td:first-child{color:#6a6a80;white-space:nowrap;width:190px;font-weight:500}
.data-table td:last-child{color:#c8c8d4;word-break:break-word}

.threat-badge{display:inline-block;padding:6px 18px;border-radius:20px;font-weight:700;font-size:.82em;text-transform:uppercase;letter-spacing:.8px}
.threat-SAFE{background:#0d2818;color:#4ade80;border:1px solid #166534}
.threat-LOW{background:#1a2300;color:#a3e635;border:1px solid #3f6212}
.threat-SUSPICIOUS{background:#2a1f00;color:#fbbf24;border:1px solid #92400e}
.threat-MALICIOUS{background:#2a0a0a;color:#f87171;border:1px solid #991b1b}
.threat-CRITICAL{background:#3b0000;color:#ff4444;border:1px solid #dc2626;animation:pulse 2s infinite}
.threat-UNKNOWN{background:#1a1a1a;color:#888;border:1px solid #333}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.7}}

.score-bar{height:10px;background:#151520;border-radius:5px;margin:10px 0;overflow:hidden}
.score-fill{height:100%;border-radius:5px;transition:width .6s ease}

.reason-list{list-style:none}
.reason-list li{padding:10px 16px;margin:6px 0;background:#0d0d18;border-left:3px solid #8b9cf7;border-radius:0 8px 8px 0;font-size:.88em;color:#b8b8c8}

.scan-input{width:100%;padding:16px 20px;border-radius:12px;border:1px solid #252538;background:#0b0b14;color:#fff;font-size:1em;outline:none;transition:border .2s}
.scan-input:focus{border-color:#8b9cf7;box-shadow:0 0 0 3px rgba(139,156,247,.1)}
.scan-row{display:flex;gap:14px;margin:18px 0}
.btn{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;padding:16px 32px;border-radius:12px;cursor:pointer;font-size:.95em;font-weight:600;transition:all .2s;white-space:nowrap}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(102,126,234,.3)}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none}

.spinner{display:inline-block;width:18px;height:18px;border:2px solid #333;border-top-color:#8b9cf7;border-radius:50%;animation:spin .6s linear infinite;margin-right:8px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}

.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:18px 0}
.stat-box{background:#0b0b14;border:1px solid #1a1a2c;border-radius:12px;padding:18px;text-align:center}
.stat-value{font-size:1.6em;font-weight:700;color:#8b9cf7}
.stat-label{font-size:.78em;color:#555;margin-top:6px;text-transform:uppercase;letter-spacing:.5px}

.tag{display:inline-block;padding:3px 10px;border-radius:5px;font-size:.75em;margin:2px;background:#181828;color:#8b9cf7;font-weight:500}
.tag-warn{background:#2a1f00;color:#fbbf24}
.tag-danger{background:#2a0a0a;color:#f87171}
.tag-ok{background:#0d2818;color:#4ade80}

::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#08080e}::-webkit-scrollbar-thumb{background:#252538;border-radius:3px}

/* Sandbox toggle */
.sandbox-toggle{display:flex;align-items:center;gap:8px;font-size:.82em;color:#888}
.sandbox-toggle label{cursor:pointer;display:flex;align-items:center;gap:6px}
.sandbox-switch{position:relative;width:38px;height:20px;display:inline-block}
.sandbox-switch input{opacity:0;width:0;height:0}
.sandbox-slider{position:absolute;inset:0;background:#252538;border-radius:20px;transition:.25s;cursor:pointer}
.sandbox-slider::before{content:'';position:absolute;height:14px;width:14px;left:3px;bottom:3px;background:#555;border-radius:50%;transition:.25s}
.sandbox-switch input:checked+.sandbox-slider{background:#764ba2}
.sandbox-switch input:checked+.sandbox-slider::before{transform:translateX(18px);background:#fff}
.sandbox-badge{padding:2px 8px;border-radius:4px;font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.sandbox-on{background:#2d1a4e;color:#c084fc;border:1px solid #7c3aed}
.sandbox-off{background:#1a1a2c;color:#555;border:1px solid #252538}

/* Vertical redirect timeline */
.timeline{position:relative;padding:0;margin:16px 0 16px 20px}
.timeline::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:#1c1c30}
.tl-hop{position:relative;padding:0 0 20px 28px;font-size:.87em}
.tl-hop:last-child{padding-bottom:0}
.tl-hop::before{content:'';position:absolute;left:-5px;top:6px;width:12px;height:12px;border-radius:50%;border:2px solid #252538;background:#0f0f18;z-index:1}
.tl-hop.tl-start::before{background:#8b9cf7;border-color:#667eea}
.tl-hop.tl-end::before{width:14px;height:14px;left:-6px;top:5px}
.tl-hop.tl-safe::before{background:#4ade80;border-color:#166534}
.tl-hop.tl-warn::before{background:#fbbf24;border-color:#92400e}
.tl-hop.tl-danger::before{background:#f87171;border-color:#991b1b}
.tl-url{color:#aaa;word-break:break-all}
.tl-meta{display:flex;gap:8px;align-items:center;margin-top:4px;flex-wrap:wrap}

/* Safety card */
.safety-card{border-radius:14px;padding:22px 28px;margin:20px 0;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.safety-card.safe{background:linear-gradient(135deg,#0a2618 0%,#0d1f14 100%);border:1px solid #166534}
.safety-card.warning{background:linear-gradient(135deg,#2a1f00 0%,#1f1a00 100%);border:1px solid #92400e}
.safety-card.danger{background:linear-gradient(135deg,#2a0a0a 0%,#1f0808 100%);border:1px solid #991b1b}
.safety-card.unknown{background:#0f0f18;border:1px solid #252538}
.safety-icon{font-size:2.2em;line-height:1}
.safety-info{flex:1}
.safety-info h3{margin:0 0 4px;font-size:1.05em}
.safety-info p{margin:0;font-size:.85em;color:#888}
.safety-score{text-align:right;min-width:80px}
.safety-score .score-num{font-size:1.8em;font-weight:800}
.safety-score .score-label{font-size:.7em;text-transform:uppercase;letter-spacing:.5px;color:#666}

.mini-table{width:100%;font-size:.82em;border-collapse:collapse;margin:10px 0}
.mini-table th{text-align:left;padding:8px 10px;background:#101020;color:#555;font-weight:600;border-bottom:1px solid #1a1a2c;text-transform:uppercase;font-size:.78em;letter-spacing:.3px}
.mini-table td{padding:7px 10px;border-bottom:1px solid #111118;color:#aaa;word-break:break-all}

.chain-hop{display:flex;align-items:center;gap:12px;padding:10px 14px;margin:5px 0;background:#0d0d18;border-radius:8px;font-size:.87em}
.chain-hop .hop-num{background:#181828;color:#8b9cf7;padding:3px 10px;border-radius:5px;font-weight:700;min-width:32px;text-align:center}
.chain-hop .hop-status{padding:3px 10px;border-radius:5px;font-weight:600;font-size:.8em}
.status-2xx{background:#0d2818;color:#4ade80}
.status-3xx{background:#1a1a00;color:#fbbf24}
.status-4xx{background:#2a0a0a;color:#f87171}
.status-5xx{background:#3b0000;color:#ff4444}

.section-label{font-size:.7em;color:#444;text-transform:uppercase;letter-spacing:1px;margin-top:28px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #151520}

/* History panel */
.history-item{display:flex;justify-content:space-between;align-items:center;padding:7px 8px;margin:2px 0;background:#0a0a14;border-radius:6px;cursor:pointer;transition:background .15s;gap:8px}
.history-item:hover{background:#12121e}

/* Animations */
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.85}}
@keyframes fadeOut{0%{opacity:1}70%{opacity:1}100%{opacity:0}}

/* Responsive: stack history below on small screens */
@media(max-width:900px){
    .container>div[style*="display:flex"]{flex-direction:column!important}
    .container>div[style*="display:flex"]>div[style*="width:280px"]{width:100%!important;position:static!important}
}
"""

# ---------------------------------------------------------------------------
# JavaScript for the scan page
# ---------------------------------------------------------------------------
ARGUS_JS = r"""
let scanInProgress = false;

// ── Sandbox toggle ──
function initSandbox(){
    fetch('/api/sandbox').then(r=>r.json()).then(d=>{
        const cb=document.getElementById('sandboxCb');
        const badge=document.getElementById('sandboxBadge');
        if(cb)cb.checked=d.sandbox;
        if(badge){badge.textContent=d.sandbox?'SANDBOX':'LIVE';badge.className='sandbox-badge '+(d.sandbox?'sandbox-on':'sandbox-off');}
    }).catch(()=>{});
}
function toggleSandbox(){
    const cb=document.getElementById('sandboxCb');
    const wanted=cb.checked;
    cb.disabled=true;
    fetch('/api/sandbox',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:wanted})})
    .then(r=>r.json()).then(d=>{
        cb.checked=d.sandbox;
        const badge=document.getElementById('sandboxBadge');
        if(badge){badge.textContent=d.sandbox?'SANDBOX':'LIVE';badge.className='sandbox-badge '+(d.sandbox?'sandbox-on':'sandbox-off');}
    }).catch(()=>{cb.checked=!wanted;})
    .finally(()=>{cb.disabled=false;});
}

// ── Scan ──
function scanUrl(forceRescan) {
    const input = document.getElementById('urlInput');
    let url = input.value.trim();
    if (!url) { input.focus(); return; }
    if (url && !url.includes('://') && !url.startsWith('data:')) url = 'http://' + url;
    input.value = url;
    if (scanInProgress) return;
    scanInProgress = true;
    const btn = document.getElementById('scanBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Scanning...';
    document.getElementById('scanResult').innerHTML = '<div style="text-align:center;padding:40px;color:#555"><span class="spinner" style="display:inline-block;margin-right:10px"></span>Gathering intelligence...</div>';
    fetch('/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url, force: !!forceRescan})})
    .then(r=>r.json()).then(data=>{
        if(data.error){showError(data.error);}
        else{renderFullResult(data);loadHistory();}
    })
    .catch(err=>showError(err.toString()))
    .finally(()=>{scanInProgress=false;btn.disabled=false;btn.innerHTML='Scan URL';});
}
function showError(msg){document.getElementById('scanResult').innerHTML=`<div class="card" style="border-color:#991b1b"><h3 style="color:#f87171">Error</h3><p>${msg}</p></div>`;}

// ── Copy to clipboard ──
let _lastScanResult = null;
function copyText(text){navigator.clipboard.writeText(text).then(()=>{const t=document.createElement('div');t.textContent='Copied!';t.style.cssText='position:fixed;top:20px;right:20px;background:#4ade80;color:#000;padding:8px 18px;border-radius:8px;font-size:.85em;z-index:9999';document.body.appendChild(t);setTimeout(()=>t.remove(),1500);});}
function copyLastJSON(){if(_lastScanResult)copyText(JSON.stringify(_lastScanResult,null,2));}

// ── Scan History ──
function loadHistory(){
    fetch('/api/history?limit=20').then(r=>r.json()).then(d=>{
        const el=document.getElementById('historyPanel');
        if(!el||!d.history||!d.history.length){if(el)el.innerHTML='<p style="color:#333;font-size:.8em;padding:8px">No scans yet</p>';return;}
        let h='<div style="display:flex;justify-content:space-between;align-items:center;padding:0 4px 8px"><span style="color:#555;font-size:.75em">'+d.total+' scans</span><div><button onclick="exportHistory()" style="background:none;border:1px solid #333;color:#888;padding:2px 8px;border-radius:4px;font-size:.7em;cursor:pointer;margin-right:4px" title="Export JSON">Export</button><button onclick="clearHistory()" style="background:none;border:1px solid #333;color:#555;padding:2px 8px;border-radius:4px;font-size:.7em;cursor:pointer" title="Clear">Clear</button></div></div>';
        d.history.forEach(s=>{
            const tc={SAFE:'#4ade80',LOW:'#a3e635',SUSPICIOUS:'#fbbf24',MALICIOUS:'#f87171',CRITICAL:'#ff4444',UNKNOWN:'#666'};
            const c=tc[s.threat_level]||'#666';
            const domain=s.domain||s.url||'';
            const ts=s.timestamp?new Date(s.timestamp).toLocaleTimeString():'';
            h+=`<div class="history-item" onclick="document.getElementById('urlInput').value='${esc(s.url)}';scanUrl();" title="${esc(s.url)}">
                <div style="display:flex;align-items:center;gap:6px;min-width:0">
                    <span style="width:8px;height:8px;border-radius:50%;background:${c};flex-shrink:0"></span>
                    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.78em;color:#aaa">${esc(domain)}</span>
                </div>
                <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
                    ${s.blocked?'<span style="color:#f87171;font-size:.65em">BLOCKED</span>':''}
                    <span style="color:${c};font-size:.7em;font-weight:600">${s.threat_level}</span>
                    <span style="color:#333;font-size:.65em">${ts}</span>
                </div>
            </div>`;
        });
        el.innerHTML=h;
    }).catch(()=>{});
}
function exportHistory(){window.open('/api/history/export','_blank');}
function clearHistory(){if(confirm('Clear all scan history?'))fetch('/api/history/clear',{method:'POST'}).then(()=>loadHistory());}

// ── Main render ──
function renderFullResult(r) {
    _lastScanResult = r;
    const el = document.getElementById('scanResult');
    const I = r.intel || {};
    let h = '';

    // Sandbox indicator
    if (I.sandbox_active) {
        h += `<div style="background:#2d1a4e;border:1px solid #7c3aed;border-radius:10px;padding:10px 18px;margin-bottom:16px;display:flex;align-items:center;gap:10px">
            <span style="font-size:1.2em">&#9881;</span>
            <span style="color:#c084fc;font-weight:600;font-size:.88em">SANDBOX MODE — All data is simulated. No real network requests were made.</span></div>`;
    }

    // Safety Guard BLOCKED banner
    if (r.blocked && r.safety_block) {
        const sb = r.safety_block;
        h += `<div style="background:linear-gradient(135deg,#1a0a2e 0%,#0f0520 100%);border:2px solid #7c3aed;border-radius:14px;padding:22px 28px;margin-bottom:20px">
            <div style="display:flex;align-items:center;gap:16px">
                <span style="font-size:2.2em">&#128737;</span>
                <div><h2 style="color:#a78bfa;margin:0 0 6px;font-size:1.1em">SAFETY GUARD — SCAN BLOCKED</h2>
                <p style="color:#8b5cf6;margin:0 0 4px;font-size:.9em">${esc(sb.reason)}</p>
                <p style="color:#555;margin:0;font-size:.8em;word-break:break-all">${esc(sb.url||r.url)}</p></div>
            </div></div>`;
        el.innerHTML = h; return;
    }

    // Killswitch BLOCKED banner
    if (r.blocked && r.killswitch) {
        const ks = r.killswitch;
        h += `<div style="background:linear-gradient(135deg,#3b0000 0%,#1f0000 100%);border:2px solid #dc2626;border-radius:14px;padding:22px 28px;margin-bottom:20px;animation:pulse 1.5s infinite">
            <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
                <span style="font-size:2.4em">&#9940;</span>
                <div style="flex:1">
                    <h2 style="color:#ff4444;margin:0 0 6px;font-size:1.2em;letter-spacing:.5px">KILLSWITCH ACTIVATED — URL BLOCKED</h2>
                    <p style="color:#f87171;margin:0 0 8px;font-size:.92em">${esc(ks.reason||'Malicious destination detected')}</p>
                    <p style="color:#991b1b;margin:0;font-size:.82em;word-break:break-all">Blocked URL: ${esc(ks.url||r.url)}</p>
                    <p style="color:#991b1b;margin:4px 0 0;font-size:.82em">Domain: <strong>${esc(ks.domain||'')}</strong> &nbsp; Risk Score: <strong style="color:#ff4444">${ks.risk_score||100}</strong></p>
                </div>
                <div style="text-align:center;min-width:80px">
                    <div style="font-size:2.2em;font-weight:900;color:#ff4444">${ks.risk_score||100}</div>
                    <div style="font-size:.65em;color:#991b1b;text-transform:uppercase;letter-spacing:1px">BLOCKED</div>
                </div>
            </div>
            <div style="margin-top:14px;padding-top:12px;border-top:1px solid #450a0a;color:#7f1d1d;font-size:.78em">
                No further analysis was performed. The scan was terminated immediately to protect the system.
            </div>
        </div>`;
        // For blocked URLs, show minimal info and return early
        el.innerHTML = h;
        return;
    }

    // ── Threat Summary ──
    const cacheTag = r.from_cache ? '<span class="tag" style="background:#1e1b4b;color:#818cf8;margin-left:8px">CACHED</span>' : '';
    h += `<div class="card" style="border-left:4px solid ${tc(r.threat_level)}">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px">
            <div><h2 style="margin-bottom:6px">Scan Complete ${cacheTag}</h2>
                <p style="color:#555;font-size:.85em;word-break:break-all">${r.url} <button onclick="copyText('${r.url.replace(/'/g,"\\'")}')" style="background:none;border:1px solid #333;color:#666;padding:1px 6px;border-radius:4px;font-size:.75em;cursor:pointer;margin-left:4px" title="Copy URL">&#128203;</button></p></div>
            <div style="text-align:right">
                <span class="threat-badge threat-${r.threat_level}">${r.threat_level}</span>
                <div style="margin-top:8px;color:#555;font-size:.85em">Score: <strong style="color:#fff">${r.threat_score}</strong></div></div>
        </div>
        <div class="score-bar" style="margin-top:14px"><div class="score-fill" style="width:${Math.min(r.threat_score*5,100)}%;background:${tc(r.threat_level)}"></div></div>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
            <button onclick="scanUrl(true)" style="background:#1e1b4b;border:1px solid #333;color:#818cf8;padding:4px 12px;border-radius:6px;font-size:.78em;cursor:pointer">Force Re-scan</button>
            <button onclick="copyLastJSON()" style="background:#0a0a0a;border:1px solid #333;color:#666;padding:4px 12px;border-radius:6px;font-size:.78em;cursor:pointer">Copy JSON</button>
        </div>
    </div>`;

    // ── Safety Card (final destination) ──
    h += renderSafetyCard(I);

    // ── Redirect Timeline ──
    h += renderTimeline(I);

    // ── Quick Stats ──
    h += `<div class="stats-grid">
        ${sb('Domain',r.domain||'N/A')}${sb('Scan Time',r.timestamp?new Date(r.timestamp).toLocaleString():'N/A')}
        ${sb('Threat Score',r.threat_score)}${sb('Findings',(r.reasons||[]).length)}
    </div>`;

    // ── Findings ──
    if (r.reasons && r.reasons.length) {
        h += `<div class="card"><h3>Findings &amp; Risk Indicators</h3><ul class="reason-list">`;
        r.reasons.forEach(x=>{h+=`<li>${esc(x)}</li>`;});
        h += `</ul></div>`;
    }

    // ── Intel Grid ──
    h += `<div class="intel-grid">`;

    // GeoIP
    if (I.geoip && !I.geoip.error) {
        const g = I.geoip;
        h += sec('geo','Location &amp; Network','',`
            ${dr('IP Address',g.ip)}${dr('Country',g.country?(g.country+' ('+g.country_code+')'):'N/A')}
            ${dr('Region',g.region)}${dr('City',g.city)}${dr('ZIP',g.zip)}
            ${dr('Coordinates',g.latitude&&g.longitude?g.latitude+', '+g.longitude:'N/A')}
            ${dr('Timezone',g.timezone)}${dr('ISP',g.isp)}${dr('Organization',g.org)}
            ${dr('AS Number',g.as_number)}${dr('AS Name',g.as_name)}${dr('Reverse DNS',g.reverse_dns)}
            ${dr('Proxy/VPN',ft(g.is_proxy))}${dr('Hosting',ft(g.is_hosting))}${dr('Mobile',ft(g.is_mobile))}
        `,true);
    } else { h+=sec('geo','Location &amp; Network','',errRow(I.geoip)); }

    // WHOIS
    if (I.whois && !I.whois.error) {
        const w = I.whois;
        h += sec('whois','WHOIS / Registration','',`
            ${dr('Registrar',w.registrar)}${dr('Organization',w.registrant_org)}${dr('Name',w.registrant_name)}
            ${dr('Email',Array.isArray(w.registrant_email)?w.registrant_email.join(', '):w.registrant_email)}
            ${dr('Country',w.registrant_country)}${dr('State',w.registrant_state)}${dr('City',w.registrant_city)}
            ${dr('Created',w.creation_date)}${dr('Expires',w.expiration_date)}${dr('Updated',w.updated_date)}
            ${dr('Domain Age',w.domain_age_days?w.domain_age_days+' days'+(w.newly_registered?' <span class="tag tag-danger">NEW</span>':w.young_domain?' <span class="tag tag-warn">YOUNG</span>':''):'N/A')}
            ${dr('Name Servers',Array.isArray(w.name_servers)?w.name_servers.join('<br>'):w.name_servers)}
            ${dr('Status',Array.isArray(w.status)?w.status.join('<br>'):w.status)}
            ${dr('DNSSEC',w.dnssec)}
        `,true);
    } else { h+=sec('whois','WHOIS / Registration','',errRow(I.whois),true); }

    // SSL Certificate
    if (I.ssl && !I.ssl.error) {
        const s = I.ssl;
        let expiryTag = '';
        if (s.expired) expiryTag = ' <span class="tag tag-danger">EXPIRED</span>';
        else if (s.expiring_soon) expiryTag = ' <span class="tag tag-warn">EXPIRING SOON</span>';
        h += sec('ssl','SSL / TLS Certificate','intel-full',`
            ${dr('Subject',s.subject?Object.entries(s.subject).map(([k,v])=>k+'='+v).join(', '):'N/A')}
            ${dr('Issuer',s.issuer?Object.entries(s.issuer).map(([k,v])=>k+'='+v).join(', '):'N/A')}
            ${dr('Valid From',s.not_before)}${dr('Valid Until',(s.not_after||'')+expiryTag)}
            ${dr('Days Until Expiry',s.days_until_expiry!=null?s.days_until_expiry:'N/A')}
            ${dr('TLS Version',s.tls_version)}${dr('Signature Algorithm',s.signature_algorithm)}
            ${dr('Serial Number',s.serial_number)}${dr('Version',s.version)}
            ${s.subject_alt_names&&s.subject_alt_names.length?dr('SANs',s.subject_alt_names.map(x=>'<span class="tag">'+x.value+'</span>').join(' ')):''}
            ${s.key_usage&&s.key_usage.length?dr('Key Usage',s.key_usage.map(x=>'<span class="tag">'+x+'</span>').join(' ')):''}
            ${s.ocsp&&s.ocsp.length?dr('OCSP',s.ocsp.join('<br>')):''}
            ${s.ca_issuers&&s.ca_issuers.length?dr('CA Issuers',s.ca_issuers.join('<br>')):''}
            ${s.crl&&s.crl.length?dr('CRL',s.crl.join('<br>')):''}
        `,true);
    } else { h+=sec('ssl','SSL / TLS Certificate','intel-full',errRow(I.ssl),true); }

    // DNS Records
    if (I.dns && !I.dns.error) {
        const d = I.dns; let dh = '';
        ['A','AAAA','CNAME','MX','NS','TXT','CAA','SOA'].forEach(t=>{
            if(!d[t])return;
            let v='';
            if(t==='MX'&&Array.isArray(d[t]))v=d[t].map(m=>m.priority+' '+m.exchange).join('<br>');
            else if(t==='SOA'&&typeof d[t]==='object')v=Object.entries(d[t]).map(([k,v])=>k+': '+v).join('<br>');
            else if(Array.isArray(d[t]))v=d[t].join('<br>');
            else v=String(d[t]);
            dh+=dr(t,v);
        });
        if(d.spf&&d.spf.length)dh+=dr('SPF',d.spf.join('<br>'));
        if(d.dmarc&&d.dmarc.length)dh+=dr('DMARC',d.dmarc.join('<br>'));
        dh+=dr('DNSSEC',d.has_dnssec?'<span class="tag tag-ok">YES</span>':'<span class="tag tag-warn">NO</span>');
        h+=sec('dns','DNS Records','',dh,true);
    } else { h+=sec('dns','DNS Records','',errRow(I.dns),true); }

    // HTTP Response
    if (I.http && !I.http.error) {
        const p = I.http;
        let ph = `${dr('Status',p.status_code)}${dr('Server',p.server)}${dr('Powered By',p.powered_by)}
            ${dr('Content Type',p.content_type)}${dr('Response Time',p.response_time_ms+' ms')}
            ${dr('Final URL',p.final_url)}${dr('Security Score',p.security_header_score)}`;
        if(p.technologies&&p.technologies.length)ph+=dr('Technologies',p.technologies.map(t=>'<span class="tag">'+t+'</span>').join(' '));
        h+=sec('http','HTTP Response','',ph,true);
    } else {h+=sec('http','HTTP Response','',errRow(I.http),true);}

    // Security Headers
    if (I.http && I.http.security_headers) {
        let sh='<table class="mini-table"><tr><th>Header</th><th>Status</th></tr>';
        Object.entries(I.http.security_headers).forEach(([k,v])=>{
            const c=v==='MISSING'?'tag-danger':'tag-ok';
            sh+=`<tr><td>${k}</td><td><span class="tag ${c}">${v==='MISSING'?'MISSING':v.substring(0,100)}</span></td></tr>`;
        });
        sh+='</table>';
        h+=sec('secheaders','Security Headers Audit','intel-full',sh);
    }

    // Cookies
    if (I.http && I.http.cookies && I.http.cookies.length) {
        let ch='<table class="mini-table"><tr><th>Name</th><th>Domain</th><th>Secure</th><th>HttpOnly</th></tr>';
        I.http.cookies.forEach(c=>{
            ch+=`<tr><td>${esc(c.name)}</td><td>${esc(c.domain)}</td>
                <td><span class="tag ${c.secure?'tag-ok':'tag-warn'}">${c.secure?'Yes':'No'}</span></td>
                <td><span class="tag ${c.httponly?'tag-ok':'tag-warn'}">${c.httponly?'Yes':'No'}</span></td></tr>`;
        });
        ch+='</table>';
        h+=sec('cookies','Cookies ('+I.http.cookies.length+')','intel-full',ch);
    }

    // Content Analysis
    if (I.content_analysis && !I.content_analysis.error) {
        const ca = I.content_analysis;
        let caH = '';
        if (ca.page_title) caH += dr('Page Title', esc(ca.page_title));
        if (ca.forms) {
            caH += dr('Forms Found', ca.forms.count);
            if (ca.forms.credential_harvesting) caH += dr('Credential Harvesting', '<span class="tag tag-danger">DETECTED</span>');
            if (ca.forms.cross_domain_action) caH += dr('Cross-Domain Form', '<span class="tag tag-warn">YES</span>');
            if (ca.forms.details && ca.forms.details.length) {
                ca.forms.details.forEach((f,i) => {
                    let fTags = '';
                    if (f.has_password_field) fTags += '<span class="tag tag-danger">PASSWORD</span> ';
                    if (f.cross_domain) fTags += '<span class="tag tag-warn">EXTERNAL</span> ';
                    if (f.warning) fTags += '<span class="tag tag-danger">'+f.warning+'</span> ';
                    if (f.sensitive_fields && f.sensitive_fields.length) fTags += f.sensitive_fields.map(s=>'<span class="tag tag-danger">'+s+'</span>').join(' ');
                    caH += dr('Form #'+(i+1), esc(f.method)+' '+esc(f.action||'(self)')+ ' — '+f.input_count+' inputs '+fTags);
                });
            }
        }
        if (ca.iframes) {
            caH += dr('Iframes', ca.iframes.count + (ca.iframes.suspicious_count > 0 ? ' <span class="tag tag-warn">'+ca.iframes.suspicious_count+' suspicious</span>' : ''));
        }
        if (ca.external_scripts) {
            caH += dr('External Scripts', ca.external_scripts.external_count + ' of ' + ca.external_scripts.total_scripts + ' total');
        }
        if (ca.external_links) {
            caH += dr('External Links', ca.external_links.external_link_count + ' to ' + ca.external_links.unique_external_domains + ' domains');
            if (ca.external_links.top_external_domains && ca.external_links.top_external_domains.length) {
                caH += dr('Top External', ca.external_links.top_external_domains.slice(0,5).map(d=>'<span class="tag">'+esc(d.domain)+' ('+d.count+')</span>').join(' '));
            }
        }
        if (ca.obfuscation && ca.obfuscation.detected) {
            caH += dr('JS Obfuscation', '<span class="tag tag-danger">DETECTED</span> — '+ca.obfuscation.pattern_count+' patterns');
        }
        if (ca.hidden_elements && ca.hidden_elements.count > 0) {
            const hc = ca.hidden_elements.count;
            caH += dr('Hidden Elements', hc + (hc > 10 ? ' <span class="tag tag-warn">EXCESSIVE</span>' : ''));
        }
        if (ca.data_exfil_indicators && ca.data_exfil_indicators.detected) {
            caH += dr('Data Exfil', '<span class="tag tag-danger">'+ca.data_exfil_indicators.count+' indicator(s)</span>');
        }
        if (ca.risk_indicators && ca.risk_indicators.length) {
            caH += '</table><ul class="reason-list" style="margin-top:8px">';
            ca.risk_indicators.forEach(r => { caH += '<li>'+esc(r)+'</li>'; });
            caH += '</ul><table class="data-table">';
        }
        if (ca.meta_tags && Object.keys(ca.meta_tags).length) {
            let metaH = '</table><table class="mini-table"><tr><th>Meta Tag</th><th>Content</th></tr>';
            Object.entries(ca.meta_tags).slice(0,15).forEach(([k,v]) => { metaH += '<tr><td>'+esc(k)+'</td><td>'+esc(v.substring(0,150))+'</td></tr>'; });
            metaH += '</table><table class="data-table">';
            caH += metaH;
        }
        h += sec('content','Content Analysis','intel-full',caH);
    } else { h+=sec('content','Content Analysis','intel-full',errRow(I.content_analysis)); }

    // Domain Analysis
    if (I.domain_analysis && !I.domain_analysis.error) {
        const da = I.domain_analysis;
        let daH = '';
        if (da.typosquatting) {
            const ts = da.typosquatting;
            if (ts.is_typosquat) {
                daH += dr('Typosquatting', '<span class="tag tag-danger">DETECTED</span> — target: '+esc(ts.target_brand)+' (distance: '+ts.distance+')');
            } else {
                daH += dr('Typosquatting', '<span class="tag tag-ok">Not detected</span>');
            }
            if (ts.homoglyph_detected) {
                daH += dr('Homoglyph Attack', '<span class="tag tag-danger">DETECTED</span> — targeting '+esc(ts.homoglyph_target));
            }
        }
        if (da.whois_privacy) {
            const wp = da.whois_privacy;
            daH += dr('WHOIS Privacy', wp.is_private ? '<span class="tag tag-warn">PROTECTED</span> — '+esc(wp.reason||'') : '<span class="tag tag-ok">Public</span>');
        }
        if (da.registrar_risk) {
            const rr = da.registrar_risk;
            if (rr.registrar) {
                let rTag = rr.is_risky ? '<span class="tag tag-warn">RISKY</span>' : rr.is_reputable ? '<span class="tag tag-ok">REPUTABLE</span>' : '<span class="tag">NEUTRAL</span>';
                daH += dr('Registrar', esc(rr.registrar) + ' ' + rTag);
            }
        }
        if (da.domain_patterns) {
            const dp = da.domain_patterns;
            daH += dr('Domain Length', dp.domain_length + ' chars' + (dp.is_long ? ' <span class="tag tag-warn">LONG</span>' : ''));
            if (dp.excessive_hyphens) daH += dr('Hyphens', dp.hyphen_count + ' <span class="tag tag-warn">EXCESSIVE</span>');
            if (dp.random_looking) daH += dr('Pattern', '<span class="tag tag-danger">RANDOMLY GENERATED (DGA)</span>');
            if (dp.brand_in_subdomain) daH += dr('Brand in Subdomain', '<span class="tag tag-danger">'+esc(dp.brand_in_subdomain)+'</span>');
        }
        if (da.risk_indicators && da.risk_indicators.length) {
            daH += '</table><ul class="reason-list" style="margin-top:8px">';
            da.risk_indicators.forEach(r => { daH += '<li>'+esc(r)+'</li>'; });
            daH += '</ul><table class="data-table">';
        }
        h += sec('domain-analysis','Domain Analysis','',daH);
    } else { h+=sec('domain-analysis','Domain Analysis','',errRow(I.domain_analysis)); }

    // IP WHOIS
    if (I.ip_whois && !I.ip_whois.error) {
        const iw=I.ip_whois;
        h+=sec('ipwhois','IP Network Ownership','',`
            ${dr('ASN',iw.asn)}${dr('ASN CIDR',iw.asn_cidr)}${dr('ASN Country',iw.asn_country)}
            ${dr('Description',iw.asn_description)}${dr('Registry',iw.asn_registry)}
            ${dr('Network',iw.network_name)}${dr('CIDR',iw.network_cidr)}
            ${dr('Range',(iw.network_start||'')+' - '+(iw.network_end||''))}
        `);
    } else { h+=sec('ipwhois','IP Network Ownership','',errRow(I.ip_whois)); }

    // Reverse DNS
    if (I.reverse_dns && !I.reverse_dns.error) {
        h+=sec('rdns','Reverse DNS','',`${dr('IP',I.reverse_dns.ip)}${dr('Hostname',I.reverse_dns.hostname||'No PTR record')}`);
    } else { h+=sec('rdns','Reverse DNS','',errRow(I.reverse_dns)); }

    // URL Parameters
    if (I.url_params) {
        const up=I.url_params;
        if (up.total_params > 0) {
            let uh=`<p style="margin-bottom:10px;color:#555">${up.total_params} parameters found</p>`;
            if(up.tracking_params&&up.tracking_params.length)uh+=`<p style="margin:6px 0">Tracking: ${up.tracking_params.map(t=>'<span class="tag tag-warn">'+t+'</span>').join(' ')}</p>`;
            if(up.sensitive_params&&up.sensitive_params.length)uh+=`<p style="margin:6px 0">Sensitive: ${up.sensitive_params.map(t=>'<span class="tag tag-danger">'+t+'</span>').join(' ')}</p>`;
            if(up.params){
                uh+='<table class="mini-table" style="margin-top:12px"><tr><th>Parameter</th><th>Value</th></tr>';
                Object.entries(up.params).forEach(([k,v])=>{uh+=`<tr><td>${esc(k)}</td><td>${esc(String(v).substring(0,200))}</td></tr>`;});
                uh+='</table>';
            }
            h+=sec('params','URL Parameters','intel-full',uh);
        } else {
            h+=sec('params','URL Parameters','intel-full',`${dr('Parameters','<span class="tag tag-ok">None — clean URL</span>')}${dr('Tracking',ft(up.has_tracking))}${dr('Sensitive',ft(up.has_sensitive))}`);
        }
    } else {
        h+=sec('params','URL Parameters','intel-full',dr('Parameters','<span style="color:#555">No parameter data</span>'));
    }

    // Resolved IPs
    if (I.resolved_ips && I.resolved_ips.length) {
        h+=sec('ips','Resolved IPs','',I.resolved_ips.map(ip=>'<span class="tag">'+ip+'</span>').join(' '));
    }

    // ── Multi-Source Threat Intelligence ──
    if (I.threat_intel && !I.threat_intel.error) {
        const ti = I.threat_intel;
        const res = ti.results || {};

        // Summary card
        let verdictCls = ti.verdict==='malicious'?'tag-danger':ti.verdict==='suspicious'?'tag-warn':ti.verdict==='low_risk'?'tag-warn':'tag-ok';
        let tiSummary = `<p style="margin-bottom:12px">Verdict: <span class="tag ${verdictCls}" style="font-size:.9em;padding:4px 14px">${(ti.verdict||'clean').toUpperCase()}</span> &nbsp; Score: <strong style="color:#fff">${ti.threat_score||0}</strong> &nbsp; Sources: ${(ti.sources_available||[]).length}/${(ti.sources_queried||[]).length}</p>`;
        if (ti.threat_reasons && ti.threat_reasons.length) {
            tiSummary += '<ul class="reason-list" style="margin-top:8px">';
            ti.threat_reasons.forEach(r=>{tiSummary+=`<li>${esc(r)}</li>`;});
            tiSummary += '</ul>';
        }
        h+=sec('ti-summary','Threat Intel Summary','intel-full',tiSummary,true);

        // VirusTotal
        const vt = res.virustotal;
        if (vt && vt.available && !vt.scan_submitted) {
            let vtH = `${dr('Detection Ratio',vt.detection_ratio)}${dr('Reputation',vt.reputation)}${dr('Times Submitted',vt.times_submitted)}${dr('Title',vt.title)}`;
            if (vt.categories && Object.keys(vt.categories).length) vtH+=dr('Categories',Object.entries(vt.categories).map(([k,v])=>'<span class="tag">'+v+'</span>').join(' '));
            if (vt.tags && vt.tags.length) vtH+=dr('Tags',vt.tags.map(t=>'<span class="tag">'+t+'</span>').join(' '));
            if (vt.detections && vt.detections.length) {
                vtH+='</table><h4 style="color:#f87171;margin:10px 0 6px;font-size:.85em">Detections</h4><table class="mini-table"><tr><th>Engine</th><th>Category</th><th>Result</th></tr>';
                vt.detections.forEach(d=>{vtH+=`<tr><td>${esc(d.engine)}</td><td><span class="tag tag-danger">${d.category}</span></td><td>${esc(d.result)}</td></tr>`;});
                vtH+='</table><table class="data-table">';
            }
            h+=sec('ti-vt','VirusTotal','',vtH);
        } else if (vt && vt.scan_submitted) {
            h+=sec('ti-vt','VirusTotal','',`<p style="color:#8b9cf7">${esc(vt.info||'Scan submitted')}</p>`);
        } else if (vt && vt.error) {
            h+=sec('ti-vt','VirusTotal','',`<p style="color:#555">${esc(vt.error)}</p>`);
        }

        // AbuseIPDB
        const adb = res.abuseipdb;
        if (adb && adb.available) {
            let aH = `${dr('IP',adb.ip)}${dr('Abuse Confidence',adb.abuse_confidence_score+'%')}${dr('Total Reports',adb.total_reports)}${dr('ISP',adb.isp)}${dr('Usage Type',adb.usage_type)}${dr('Country',adb.country_code)}${dr('Tor Exit',ft(adb.is_tor))}${dr('Last Reported',adb.last_reported_at)}`;
            h+=sec('ti-adb','AbuseIPDB','',aH);
        } else if (adb && adb.error) {
            h+=sec('ti-adb','AbuseIPDB','',`<p style="color:#555">${esc(adb.error)}</p>`);
        }

        // AlienVault OTX
        const otx = res.alienvault_otx;
        if (otx && otx.available) {
            let oH = `${dr('Pulse Count',otx.pulse_count)}`;
            if (otx.pulses && otx.pulses.length) {
                oH+='</table><table class="mini-table"><tr><th>Pulse</th><th>Tags</th><th>Adversary</th></tr>';
                otx.pulses.forEach(p=>{oH+=`<tr><td>${esc(p.name)}</td><td>${(p.tags||[]).map(t=>'<span class="tag">'+t+'</span>').join(' ')}</td><td>${esc(p.adversary)}</td></tr>`;});
                oH+='</table><table class="data-table">';
            }
            h+=sec('ti-otx','AlienVault OTX','',oH);
        } else if (otx && otx.error) {
            h+=sec('ti-otx','AlienVault OTX','',`<p style="color:#555">${esc(otx.error)}</p>`);
        }

        // IPinfo
        const ipi = res.ipinfo;
        if (ipi && ipi.available) {
            let ipH = `${dr('IP',ipi.ip)}${dr('ASN',ipi.asn)}${dr('AS Name',ipi.as_name)}${dr('AS Domain',ipi.as_domain)}${dr('Country',ipi.country?(ipi.country+' ('+ipi.country_code+')'):'N/A')}${dr('Continent',ipi.continent?(ipi.continent+' ('+ipi.continent_code+')'):'N/A')}`;
            h+=sec('ti-ipi','IPinfo.io','',ipH);
        } else if (ipi && ipi.error) {
            h+=sec('ti-ipi','IPinfo.io','',`<p style="color:#555">${esc(ipi.error)}</p>`);
        }
    } else {
        h+=sec('ti-summary','Threat Intel Summary','intel-full',errRow(I.threat_intel),true);
    }

    h += `</div>`; // close intel-grid

    // Raw JSON
    h += sec('raw','Raw JSON Data','',`<pre style="background:#06060a;padding:14px;border-radius:8px;overflow-x:auto;font-size:.73em;color:#555;max-height:400px">${esc(JSON.stringify(r,null,2))}</pre>`);

    el.innerHTML = h;
}

// ── Safety Card renderer ──
function renderSafetyCard(I) {
    const fd = I.final_destination;
    if (!fd) return '';
    const colorMap = {green:'safe',yellow:'warning',red:'danger',gray:'unknown'};
    const iconMap = {green:'&#9989;',yellow:'&#9888;',red:'&#9940;',gray:'&#10067;'};
    const labelMap = {SAFE:'Destination is Safe',WARNING:'Caution Advised',DANGEROUS:'Blocked — Malicious Destination',UNKNOWN:'Reputation Unknown'};
    const scoreColorMap = {green:'#4ade80',yellow:'#fbbf24',red:'#f87171',gray:'#666'};
    const cls = colorMap[fd.color]||'unknown';
    const icon = iconMap[fd.color]||'&#10067;';
    const label = labelMap[fd.verdict]||fd.verdict;
    const sc = fd.risk_score!=null?fd.risk_score:'?';
    const scColor = scoreColorMap[fd.color]||'#666';
    let extra = '';
    if (fd.in_blacklist) extra = '<span class="tag tag-danger" style="margin-top:6px;display:inline-block">BLACKLISTED DOMAIN</span>';
    if (fd.sandbox) extra += ' <span class="tag" style="background:#2d1a4e;color:#c084fc;margin-top:6px">SIMULATED</span>';
    return `<div class="safety-card ${cls}">
        <div class="safety-icon">${icon}</div>
        <div class="safety-info">
            <h3 style="color:${scColor}">${label}</h3>
            <p style="word-break:break-all">${esc(fd.url||'')}</p>
            ${extra}
        </div>
        <div class="safety-score">
            <div class="score-num" style="color:${scColor}">${sc}</div>
            <div class="score-label">Risk Score</div>
        </div>
    </div>`;
}

// ── Redirect Timeline renderer ──
function renderTimeline(I) {
    const rc = I.redirect_chain;
    if (!rc || rc.error || !rc.chain || !rc.chain.length) return '';
    const fd = I.final_destination || {};
    const hops = rc.chain;
    const total = hops.length;
    let h = `<div class="card"><h3 style="margin-bottom:4px">Redirect Chain</h3>
        <p style="color:#555;font-size:.82em;margin-bottom:8px">${total} hop${total!==1?'s':''} &mdash; Final: <span style="color:#8b9cf7">${esc(rc.final_url||'')}</span></p>
        <div class="timeline">`;
    hops.forEach((hop, idx) => {
        const isFirst = idx === 0;
        const isLast = idx === total - 1;
        let cls = 'tl-hop';
        if (isFirst) cls += ' tl-start';
        if (isLast) {
            cls += ' tl-end';
            const c = fd.color || 'gray';
            if (c==='green') cls += ' tl-safe';
            else if (c==='yellow') cls += ' tl-warn';
            else if (c==='red') cls += ' tl-danger';
        }
        const sc = hop.status_code || 0;
        const scCls = sc>=500?'status-5xx':sc>=400?'status-4xx':sc>=300?'status-3xx':'status-2xx';
        h += `<div class="${cls}">
            <div class="tl-url">${esc(hop.url||'')}</div>
            <div class="tl-meta">
                <span class="hop-status ${scCls}">${sc||'?'}</span>
                <span class="tag">${isFirst?'START':isLast?'FINAL':'HOP '+(idx+1)}</span>
                ${hop.server?'<span style="color:#444;font-size:.8em">'+esc(hop.server)+'</span>':''}
                ${hop.note?'<span class="tag tag-danger">'+esc(hop.note)+'</span>':''}
            </div>
        </div>`;
    });
    h += `</div></div>`;
    return h;
}

// ── Helpers ──
function tc(l){return{SAFE:'#4ade80',LOW:'#a3e635',SUSPICIOUS:'#fbbf24',MALICIOUS:'#f87171',CRITICAL:'#ff4444',UNKNOWN:'#666'}[l]||'#666';}
function sb(l,v){return`<div class="stat-box"><div class="stat-value" style="font-size:${String(v).length>20?'.82em':'1.5em'}">${v}</div><div class="stat-label">${l}</div></div>`;}
function dr(l,v){if(v===null||v===undefined||v===''||v==='None'||v==='null')v='<span style="color:#333">-</span>';return`<tr><td>${l}</td><td>${v}</td></tr>`;}
function sec(id,title,extra,content,open){return`<div class="intel-section ${extra||''}"><div class="intel-header${open?' open':''}" id="intel-${id}" onclick="toggleIntel(this)"><h4>${title}</h4><span class="toggle">&#9660;</span></div><div class="intel-body${open?' open':''}"><table class="data-table">${content}</table></div></div>`;}
function toggleIntel(el){el.classList.toggle('open');el.nextElementSibling.classList.toggle('open');}
function ft(v){if(v===true)return'<span class="tag tag-warn">Yes</span>';if(v===false)return'<span class="tag tag-ok">No</span>';return'<span class="tag">-</span>';}
function errRow(obj){if(!obj)return dr('Status','<span style="color:#555">No data available</span>');if(obj.error)return dr('Error','<span style="color:#f87171">'+esc(obj.error)+'</span>');return dr('Status','<span style="color:#555">No data</span>');}
function esc(s){if(!s)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML;}
function encryptData(){const d=document.getElementById('encryptInput').value;if(!d)return;fetch('/api/encrypt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:d})}).then(r=>r.json()).then(r=>{document.getElementById('encryptResult').innerHTML='<h3>Encrypted</h3><textarea class="scan-input" rows="3" readonly>'+esc(r.encrypted)+'</textarea>';}).catch(e=>alert(e));}
function decryptData(){const d=document.getElementById('decryptInput').value;if(!d)return;fetch('/api/decrypt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({encrypted_data:d})}).then(r=>r.json()).then(r=>{document.getElementById('decryptResult').innerHTML='<h3>Decrypted</h3><textarea class="scan-input" rows="3" readonly>'+esc(r.decrypted)+'</textarea>';}).catch(e=>alert(e));}
document.addEventListener('DOMContentLoaded',()=>{
    const i=document.getElementById('urlInput');
    if(i)i.addEventListener('keydown',e=>{if(e.key==='Enter')scanUrl();});
    initSandbox();
    loadHistory();
});
"""

# ---------------------------------------------------------------------------
# Page header/footer wrappers
# ---------------------------------------------------------------------------
def _page(title_suffix, nav_active, body_content):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ARGUS - {title_suffix}</title>
<style>{ARGUS_CSS}</style>
</head>
<body>
<div class="header"><div class="header-inner">
    <div class="logo"><span class="logo-icon">&#x25C8;</span> ARGUS <span id="sandboxBadge" class="sandbox-badge sandbox-off">LIVE</span></div>
    <div class="nav">
        <a href="/" class="{'active' if nav_active=='home' else ''}">Scanner</a>
        <a href="/dashboard" class="{'active' if nav_active=='dashboard' else ''}">Dashboard</a>
        <a href="/encrypt" class="{'active' if nav_active=='encrypt' else ''}">Encrypt</a>
        <a href="/decrypt" class="{'active' if nav_active=='decrypt' else ''}">Decrypt</a>
        <div class="sandbox-toggle">
            <label><span class="sandbox-switch"><input type="checkbox" id="sandboxCb" onchange="toggleSandbox()"><span class="sandbox-slider"></span></span> Sandbox</label>
        </div>
    </div>
</div></div>
<div class="container">{body_content}</div>
<script>{ARGUS_JS}</script>
</body></html>"""

# ---------------------------------------------------------------------------
# HTML Pages
# ---------------------------------------------------------------------------
INDEX_HTML = _page('The All-Seeing Eye', 'home', """
<div style="display:flex;gap:20px;align-items:flex-start">
<div style="flex:1;min-width:0">
    <div class="card">
        <h2>&#x25C8; ARGUS Deep URL Intelligence Scanner</h2>
        <p style="color:#666;margin-bottom:8px;">Enter any URL to perform a full OSINT scan: WHOIS, DNS, GeoIP, SSL, HTTP headers, redirect chain, content analysis, typosquatting detection, and multi-source threat intelligence.</p>
        <div class="scan-row">
            <input type="text" id="urlInput" class="scan-input" placeholder="https://example.com/path?param=value" autofocus>
            <button id="scanBtn" class="btn" onclick="scanUrl()">Scan URL</button>
        </div>
    </div>
    <div id="scanResult"></div>
</div>
<div style="width:280px;flex-shrink:0;position:sticky;top:20px">
    <div class="card" style="padding:14px">
        <h4 style="margin:0 0 10px;color:#888;font-size:.82em;letter-spacing:.5px">SCAN HISTORY</h4>
        <div id="historyPanel" style="max-height:70vh;overflow-y:auto"><p style="color:#333;font-size:.8em">No scans yet</p></div>
    </div>
</div>
</div>
""")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ARGUS - Dashboard</title>
<style>""" + ARGUS_CSS + """</style>
</head>
<body>
<div class="header"><div class="header-inner">
    <div class="logo"><span class="logo-icon">&#x25C8;</span> ARGUS</div>
    <div class="nav">
        <a href="/">Scanner</a>
        <a href="/dashboard" class="active">Dashboard</a>
        <a href="/encrypt">Encrypt</a>
        <a href="/decrypt">Decrypt</a>
    </div>
</div></div>
<div class="container">
    <div class="card">
        <h2>Security Dashboard</h2>
        <div class="stats-grid">
            <div class="stat-box"><div class="stat-value">{{ summary.total_events }}</div><div class="stat-label">Total Events</div></div>
            <div class="stat-box"><div class="stat-value">{{ summary.severity_counts.get('HIGH', 0) + summary.severity_counts.get('CRITICAL', 0) }}</div><div class="stat-label">High Priority</div></div>
            <div class="stat-box"><div class="stat-value">{{ summary.session_id[:8] }}</div><div class="stat-label">Session ID</div></div>
        </div>
    </div>
    <div class="card">
        <h3>Recent Suspicious Activities</h3>
        {% for activity in suspicious[:20] %}
        <div style="padding:10px 14px;margin:6px 0;background:#0c0c14;border-left:3px solid #f87171;border-radius:0 6px 6px 0;font-size:0.85em;">
            <strong>{{ activity.event_type }}</strong> <span style="color:#666;">{{ activity.timestamp }}</span><br>
            {{ activity.source }} &#8594; {{ activity.target }}
        </div>
        {% endfor %}
    </div>
</div>
</body></html>"""

ENCRYPT_HTML = _page('Encrypt', 'encrypt', """
<div class="card">
    <h2>AES-256 Encryption</h2>
    <p style="color:#666;margin-bottom:12px;">Encrypt sensitive data using AES-256 with PBKDF2 key derivation.</p>
    <textarea id="encryptInput" class="scan-input" rows="5" placeholder="Enter data to encrypt..."></textarea>
    <button class="btn" style="margin-top:12px;" onclick="encryptData()">Encrypt</button>
    <div id="encryptResult" style="margin-top:16px;"></div>
</div>
""")

DECRYPT_HTML = _page('Decrypt', 'decrypt', """
<div class="card">
    <h2>AES-256 Decryption</h2>
    <p style="color:#666;margin-bottom:12px;">Decrypt data that was encrypted with ARGUS.</p>
    <textarea id="decryptInput" class="scan-input" rows="5" placeholder="Paste encrypted data..."></textarea>
    <button class="btn" style="margin-top:12px;" onclick="decryptData()">Decrypt</button>
    <div id="decryptResult" style="margin-top:16px;"></div>
</div>
""")

SETTINGS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ARGUS - Settings</title>
<style>""" + ARGUS_CSS + """</style>
</head>
<body>
<div class="header"><div class="header-inner">
    <div class="logo"><span class="logo-icon">&#x25C8;</span> ARGUS</div>
    <div class="nav">
        <a href="/">Scanner</a>
        <a href="/dashboard">Dashboard</a>
        <a href="/encrypt">Encrypt</a>
        <a href="/decrypt">Decrypt</a>
    </div>
</div></div>
<div class="container">
    <div class="card"><h2>Configuration</h2>
    <pre style="background:#0c0c14;padding:16px;border-radius:8px;font-size:0.85em;color:#8b9cf7;overflow-x:auto;">{{ config | tojson(indent=2) }}</pre>
    </div>
</div>
</body></html>"""

ERROR_404_HTML = _page('Not Found', '', """
<div class="card"><h2>404 - Page Not Found</h2><p>The requested page does not exist.</p><a href="/" class="btn" style="margin-top:12px;display:inline-block;">Back to Scanner</a></div>
""")

ERROR_500_HTML = _page('Server Error', '', """
<div class="card"><h2>500 - Server Error</h2><p>An internal error occurred.</p><a href="/" class="btn" style="margin-top:12px;display:inline-block;">Back to Scanner</a></div>
""")
