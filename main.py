#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proxy Cron Manager (UI simples) — sem campos de proxy no formulário
- Login com proteção de brute-force e rate-limit leve
- Dashboard lista proxies disponíveis (Webshare API) de múltiplas API keys
- Jobs: Nome, URL, Intervalo (padrão 180s)
- Runner: retries até HTTP 200 alternando proxies (usa 'padrão' primeiro)
- Ao obter 200, salva o proxy vencedor como padrão
- Persistência em UM arquivo: data.json (tasks, logs, proxies, settings)
- Secrets (login, sessão, Webshare, keep-alive) vêm de variáveis de ambiente

NOVO:
- Suporte a DUAS API keys da Webshare (WEBSHARE_API_KEY_1 e WEBSHARE_API_KEY_2)
- Mostra na UI de qual conta/key veio cada proxy
- Se detectar "Bandwidth limit reached" (HTTP 402), pula o restante daquela key/conta
"""

import os
import json
import time
import uuid
import threading
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from functools import wraps

import requests
from flask import (
    Flask, request, redirect, url_for, render_template_string,
    flash, get_flashed_messages, session, abort
)
from werkzeug.security import check_password_hash, generate_password_hash
from concurrent.futures import ThreadPoolExecutor

# ======================
# CONFIG (via ambiente)
# ======================

ADMIN_USER = os.environ.get("ADMIN_USER")
ADMIN_PASSWORD_PLAIN = os.environ.get("ADMIN_PASSWORD")
SESSION_SECRET = os.environ.get("SESSION_SECRET")

# Suporte novo: 2 chaves. Compatível com legado (WEBSHARE_API_KEY)
WEBSHARE_API_KEY_1 = os.environ.get("WEBSHARE_API_KEY_1") or os.environ.get("WEBSHARE_API_KEY")
WEBSHARE_API_KEY_2 = os.environ.get("WEBSHARE_API_KEY_2")

WEBSHARE_ACCOUNTS = []
if WEBSHARE_API_KEY_1:
    WEBSHARE_ACCOUNTS.append({"label": "webshare-1", "token": WEBSHARE_API_KEY_1})
if WEBSHARE_API_KEY_2:
    WEBSHARE_ACCOUNTS.append({"label": "webshare-2", "token": WEBSHARE_API_KEY_2})

raw = os.environ.get("KEEPALIVE_URLS", "")
KEEPALIVE_URLS = [u.strip() for u in raw.split(",") if u.strip()]

_missing_env = [
    name for name, val in [
        ("ADMIN_USER", ADMIN_USER),
        ("ADMIN_PASSWORD", ADMIN_PASSWORD_PLAIN),
        ("SESSION_SECRET", SESSION_SECRET),
    ]
    if not val
]
if not WEBSHARE_ACCOUNTS:
    _missing_env.append("WEBSHARE_API_KEY_1 (ou WEBSHARE_API_KEY) / WEBSHARE_API_KEY_2")
if not KEEPALIVE_URLS:
    _missing_env.append("KEEPALIVE_URLS")

if _missing_env:
    raise RuntimeError(
        "Variáveis de ambiente obrigatórias ausentes: "
        + ", ".join(_missing_env)
    )

ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD_PLAIN)

# Job fixo de keep-alive (intervalo padrão)
KEEPALIVE_INTERVAL = int(os.environ.get("KEEPALIVE_INTERVAL", 60))

# ————————————————
# constantes de execução
DEFAULT_INTERVAL = 180
DEFAULT_TIMEOUT = 15
MAX_WORKERS = 20
CHECK_INTERVAL = 1
SAVER_DELAY = 2
MAX_RETRIES_PER_RUN = 8
RETRIES_PER_PROXY = 2
# ————————————————

# anti brute-force / rate-limit
MAX_LOGIN_FAILS = 5
LOCKOUT_MINUTES = 15
GLOBAL_RATE_WINDOW_SEC = 60
GLOBAL_MAX_REQ_PER_IP = 120
LOGIN_RATE_MAX_PER_IP = 10

# Webshare
WEBSHARE_URL = "https://proxy.webshare.io/api/v2/proxy/list/"

DATA_FILE = "data.json"


# ======================
# App & Estados
# ======================

app = Flask(__name__)
app.secret_key = SESSION_SECRET

SAVE_LOCK = threading.Lock()
SCHED_LOCK = threading.Lock()
POOL_LOCK = threading.Lock()

# Estrutura única em memória (persistida em data.json)
data = {
    "tasks": {},       # id -> {id,name,url,interval,timeout,enabled,last_status,last_error,last_run,next_run}
    "logs": [],        # lista de entradas
    "settings": {      # configurações
        "default_proxy_id": None,
        "user_agent": "ProxyCron/1.0"
    },
    "proxies": []      # lista (Webshare múltiplas contas)
}

_tasks_dirty = False
_logs_dirty = False
_settings_dirty = False
_proxies_dirty = False

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Rate-limit simples em memória
ip_hits = defaultdict(lambda: deque())
login_hits = defaultdict(lambda: deque())
fail_by_ip = defaultdict(lambda: deque())
fail_by_user = defaultdict(lambda: deque())
ip_lockouts = {}
user_lockouts = {}


# ======================
# Utils
# ======================

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def proxy_unique_key(p):
    # Unifica por endpoint + credenciais + origem da conta (importante para duas keys)
    return (
        p.get("proxy_address"),
        p.get("port"),
        p.get("username"),
        p.get("password"),
        p.get("account_label"),
    )

def proxy_display_id(p):
    # ID estável local caso Webshare não retorne id
    wid = p.get("id")
    if wid:
        return str(wid)
    base = f"{p.get('proxy_address')}:{p.get('port')}"
    acct = p.get("account_label", "unknown")
    return f"{acct}|{base}"

def merge_proxies(existing, extras):
    """
    Unifica por endpoint+credenciais+account_label.
    Preserva dados novos quando houver conflito.
    """
    merged = {}
    for src in (existing, extras):
        for p in src:
            k = proxy_unique_key(p)
            if k in merged:
                merged[k].update({kk: vv for kk, vv in p.items() if vv is not None})
            else:
                merged[k] = dict(p)
    out = list(merged.values())
    # ordenação estável para UI
    out.sort(key=lambda p: (
        p.get("account_label", ""),
        str(p.get("country_code", "")),
        str(p.get("city_name", "")),
        str(p.get("proxy_address", "")),
        str(p.get("port", "")),
    ))
    return out

def normalize_webshare_proxy(p, account_label):
    q = dict(p)
    q["source"] = "webshare"
    q["account_label"] = account_label
    q["provider_key"] = account_label
    q["id"] = q.get("id") or proxy_display_id({**q, "account_label": account_label})
    return q

def fetch_webshare_list_for_account(account):
    r = requests.get(
        WEBSHARE_URL,
        headers={"Authorization": f"Token {account['token']}"},
        params={"mode": "direct", "page_size": 50},
        timeout=30
    )
    r.raise_for_status()
    js = r.json()
    rows = js.get("results", [])
    return [normalize_webshare_proxy(p, account["label"]) for p in rows]

def fetch_all_webshare_lists():
    """
    Busca proxies de todas as keys configuradas.
    Não aborta geral se uma falhar.
    """
    all_proxies = []
    errors = []
    for account in WEBSHARE_ACCOUNTS:
        try:
            rows = fetch_webshare_list_for_account(account)
            all_proxies.extend(rows)
        except Exception as e:
            errors.append(f"{account['label']}: {e}")
    return all_proxies, errors

def load_all():
    global data
    if not os.path.exists(DATA_FILE):
        data["proxies"] = []
        save_all(force=True)
        return
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            data["tasks"] = loaded.get("tasks", {})
            data["logs"] = loaded.get("logs", [])
            data["settings"] = loaded.get("settings", {"default_proxy_id": None, "user_agent": "ProxyCron/1.0"})
            data["proxies"] = loaded.get("proxies", [])
    except Exception:
        data["proxies"] = []
        save_all(force=True)

def save_all(force=False):
    global _tasks_dirty, _logs_dirty, _settings_dirty, _proxies_dirty
    if not (force or _tasks_dirty or _logs_dirty or _settings_dirty or _proxies_dirty):
        return
    with SAVE_LOCK:
        snapshot = {
            "tasks": data["tasks"],
            "logs": data["logs"],
            "settings": data["settings"],
            "proxies": data["proxies"]
        }
        atomic_write(DATA_FILE, snapshot)
        _tasks_dirty = _logs_dirty = _settings_dirty = _proxies_dirty = False
        print("[saver] data.json atualizado")

def mark_dirty(section):
    global _tasks_dirty, _logs_dirty, _settings_dirty, _proxies_dirty
    if section == "tasks":
        _tasks_dirty = True
    elif section == "logs":
        _logs_dirty = True
    elif section == "settings":
        _settings_dirty = True
    elif section == "proxies":
        _proxies_dirty = True

def ensure_next_run_all():
    for t in data["tasks"].values():
        if not t.get("next_run"):
            t["next_run"] = now_iso()
    mark_dirty("tasks")

def hits_prune(q: deque, window_s: int):
    cutoff = time.time() - window_s
    while q and q[0] < cutoff:
        q.popleft()

def client_ip():
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "0.0.0.0").split(",")[0].strip()

def rate_limit_check(is_login=False):
    ip = client_ip()
    now = time.time()
    if ip in ip_lockouts and ip_lockouts[ip] > now:
        abort(429, "IP temporariamente bloqueado")
    q = login_hits[ip] if is_login else ip_hits[ip]
    hits_prune(q, GLOBAL_RATE_WINDOW_SEC)
    q.append(now)
    lim = LOGIN_RATE_MAX_PER_IP if is_login else GLOBAL_MAX_REQ_PER_IP
    if len(q) > lim:
        abort(429, "Muitas requisições, tente novamente em instantes")

def register_login_failure(ip, username):
    now = time.time()
    fq_ip = fail_by_ip[ip]
    fq_user = fail_by_user[username]
    hits_prune(fq_ip, LOCKOUT_MINUTES * 60)
    hits_prune(fq_user, LOCKOUT_MINUTES * 60)
    fq_ip.append(now)
    fq_user.append(now)
    if len(fq_ip) >= MAX_LOGIN_FAILS:
        ip_lockouts[ip] = now + LOCKOUT_MINUTES * 60
    if len(fq_user) >= MAX_LOGIN_FAILS:
        user_lockouts[username] = now + LOCKOUT_MINUTES * 60

def login_blocked(ip, username):
    now = time.time()
    return (ip in ip_lockouts and ip_lockouts[ip] > now) or (username in user_lockouts and user_lockouts[username] > now)

def is_authenticated():
    return session.get("auth_user") == ADMIN_USER

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def build_proxy_url(p):
    u = p.get("username") or ""
    w = p.get("password") or ""
    host = p.get("proxy_address")
    port = p.get("port")
    creds = f"{u}:{w}@" if (u or w) else ""
    return f"http://{creds}{host}:{port}"

def proxies_for_requests(p):
    url = build_proxy_url(p)
    return {"http": url, "https": url}

def append_log(entry):
    with SCHED_LOCK:
        data["logs"].append(entry)
        if len(data["logs"]) > 5000:
            data["logs"] = data["logs"][-5000:]
    mark_dirty("logs")

def rotate_default_proxy(proxy_id):
    data["settings"]["default_proxy_id"] = proxy_id
    mark_dirty("settings")

def pick_attempt_order():
    """
    Ordem: padrão -> demais.
    Repetição por proxy.
    """
    with POOL_LOCK:
        proxies = list(data["proxies"])
    default_id = data["settings"].get("default_proxy_id")

    ordered = []
    if default_id:
        ordered.extend([p for p in proxies if str(p.get("id")) == str(default_id)])
        ordered.extend([p for p in proxies if str(p.get("id")) != str(default_id)])
    else:
        ordered = proxies

    expanded = []
    for p in ordered:
        for _ in range(RETRIES_PER_PROXY):
            expanded.append(p)
    return expanded

def is_bandwidth_exhausted_response(resp):
    """
    Detecta bloqueio de banda de proxy (ex.: Webshare).
    """
    if resp is None:
        return False
    if resp.status_code != 402:
        return False
    try:
        body = (resp.text or "")[:300].lower()
    except Exception:
        body = ""
    return "bandwidth limit reached" in body or "upgrade to continue using the proxy" in body

def short_resp_body(resp, n=160):
    try:
        return (resp.text or "")[:n].replace("\n", " ").strip()
    except Exception:
        return ""

def run_http_with_failover(url, timeout_s, user_agent):
    tried = []
    errors = []
    headers = {"User-Agent": user_agent}

    # Se uma key estourar banda, pulamos todas proxies dessa key nessa execução
    exhausted_accounts = set()

    plan = pick_attempt_order()
    plan = plan[:MAX_RETRIES_PER_RUN] if MAX_RETRIES_PER_RUN > 0 else plan

    for i, p in enumerate(plan, start=1):
        account_label = p.get("account_label", "unknown")
        if account_label in exhausted_accounts:
            errors.append(f"try#{i} skip={account_label} bandwidth_exhausted")
            continue

        tag = f"{p.get('proxy_address')}:{p.get('port')}[{account_label}]"
        tried.append(tag)

        try:
            resp = requests.get(
                url,
                headers=headers,
                proxies=proxies_for_requests(p),
                timeout=timeout_s
            )

            if resp.status_code == 200:
                return {
                    "status": 200,
                    "body_snippet": resp.text[:500],
                    "tried": tried,
                    "winner_account": account_label
                }, p

            if is_bandwidth_exhausted_response(resp):
                exhausted_accounts.add(account_label)
                errors.append(
                    f"try#{i} status=402 bandwidth_exhausted account={account_label} "
                    f"body={short_resp_body(resp)}"
                )
                continue

            errors.append(
                f"try#{i} status={resp.status_code} account={account_label} body={short_resp_body(resp)}"
            )

        except Exception as e:
            errors.append(f"try#{i} err={str(e)[:140]} account={account_label}")

    # última carta: sem proxy
    try:
        resp = requests.get(url, headers=headers, timeout=timeout_s)
        if resp.status_code == 200:
            return {
                "status": 200,
                "body_snippet": resp.text[:500],
                "tried": tried,
                "note": "sem proxy"
            }, None
        errors.append(f"direct status={resp.status_code} body={short_resp_body(resp)}")
    except Exception as e:
        errors.append(f"direct err={str(e)[:140]}")

    return {"error": "; ".join(errors), "tried": tried}, None

def run_task(tid, is_test=False):
    with SCHED_LOCK:
        t = data["tasks"].get(tid)
        if not t:
            return {"error": "task not found"}

    url = t.get("url")
    timeout = int(t.get("timeout", DEFAULT_TIMEOUT))
    ua = data["settings"].get("user_agent", "ProxyCron/1.0")

    start = time.time()
    result, good_proxy = run_http_with_failover(url, timeout, ua)
    elapsed = round(time.time() - start, 3)
    ts = now_iso()

    with SCHED_LOCK:
        if tid in data["tasks"]:
            if result.get("status") == 200:
                data["tasks"][tid]["last_status"] = 200
                data["tasks"][tid]["last_error"] = None
                if good_proxy:
                    rotate_default_proxy(str(good_proxy.get("id") or proxy_display_id(good_proxy)))
            else:
                data["tasks"][tid]["last_status"] = None
                data["tasks"][tid]["last_error"] = result.get("error")
            data["tasks"][tid]["last_run"] = ts
            if not is_test:
                interval = max(1, int(data["tasks"][tid].get("interval", DEFAULT_INTERVAL)))
                nr = datetime.now(timezone.utc) + timedelta(seconds=interval)
                data["tasks"][tid]["next_run"] = nr.isoformat()
    mark_dirty("tasks")

    append_log({
        "task_id": tid,
        "task_name": t.get("name") or tid,
        "url": url,
        "is_test": bool(is_test),
        "result": dict(result, **{"duration_s": elapsed}),
        "at": ts
    })
    return result

def scheduler_loop():
    print("[scheduler] iniciado")
    while True:
        try:
            now_ts = datetime.now(timezone.utc).timestamp()
            due = []
            with SCHED_LOCK:
                for tid, t in list(data["tasks"].items()):
                    if not t.get("enabled", True):
                        continue
                    nxt = t.get("next_run") or now_iso()
                    try:
                        nxt_ts = datetime.fromisoformat(nxt).timestamp()
                    except Exception:
                        nxt_ts = now_ts
                    if nxt_ts <= now_ts:
                        due.append(tid)
                        interval = max(1, int(t.get("interval", DEFAULT_INTERVAL)))
                        nr = datetime.now(timezone.utc) + timedelta(seconds=interval)
                        t["next_run"] = nr.isoformat()
                        mark_dirty("tasks")
            for tid in due:
                try:
                    executor.submit(run_task, tid, False)
                except Exception as e:
                    append_log({"at": now_iso(), "error": f"executor submit error: {e}"})
        except Exception as e:
            append_log({"at": now_iso(), "error": f"scheduler error: {e}"})
        time.sleep(CHECK_INTERVAL)

def saver_loop():
    last = 0.0
    while True:
        time.sleep(0.5)
        if time.time() - last >= SAVER_DELAY:
            save_all()
            last = time.time()


# ======================
# Boot helpers
# ======================

def refresh_proxies_from_all_accounts():
    """
    Atualiza proxies via todas as keys e mescla com o pool atual.
    """
    rows, errs = fetch_all_webshare_lists()
    if rows:
        with POOL_LOCK:
            data["proxies"] = merge_proxies(data["proxies"], rows)
        mark_dirty("proxies")
    return rows, errs

def ensure_bootstrap_items():
    """
    - Atualiza as proxies (best-effort, Webshare de 1..N keys)
    - Garante job de keep-alive para cada URL
    """
    try:
        rows, errs = refresh_proxies_from_all_accounts()
        print(f"[boot] proxies carregadas: {len(rows)}")
        if errs:
            print("[boot] falhas em algumas keys:", " | ".join(errs))
    except Exception as e:
        print(f"[boot] falha ao atualizar proxies: {e}")

    with SCHED_LOCK:
        for url in KEEPALIVE_URLS:
            existing = next((t for t in data["tasks"].values() if t.get("url") == url), None)
            if existing:
                existing["interval"] = KEEPALIVE_INTERVAL
                existing["enabled"] = True
                existing.setdefault("name", f"Keepalive {url}")
                existing.setdefault("timeout", DEFAULT_TIMEOUT)
                existing.setdefault("next_run", now_iso())
            else:
                tid = str(uuid.uuid4())
                data["tasks"][tid] = {
                    "id": tid,
                    "name": f"Keepalive {url}",
                    "url": url,
                    "interval": KEEPALIVE_INTERVAL,
                    "timeout": DEFAULT_TIMEOUT,
                    "enabled": True,
                    "last_status": None,
                    "last_error": None,
                    "last_run": None,
                    "next_run": now_iso(),
                }
        mark_dirty("tasks")


# ======================
# Templates
# ======================

BASE = """
<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Proxy Cron</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('index') }}">Proxy Cron</a>
        <div class="d-flex">
          {% if session.get('auth_user') %}
            <a class="btn btn-outline-light me-2" href="{{ url_for('index') }}">Dashboard</a>
            <a class="btn btn-outline-light me-2" href="{{ url_for('show_logs') }}">Logs</a>
            <a class="btn btn-outline-warning me-2" href="{{ url_for('refresh_proxies') }}">Atualizar Proxies</a>
            <a class="btn btn-outline-danger" href="{{ url_for('logout') }}">Sair</a>
          {% else %}
            <a class="btn btn-outline-light" href="{{ url_for('login') }}">Login</a>
          {% endif %}
        </div>
      </div>
    </nav>
    <div class="container">
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          {% for m in messages %}
          <div class="alert alert-info">{{ m }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      {{ body|safe }}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

INDEX = """
<div class="d-flex justify-content-between align-items-center mb-3">
  <h2>Jobs</h2>
  <div>
    <a href="{{ url_for('create') }}" class="btn btn-primary">+ Criar job</a>
  </div>
</div>

<table class="table table-striped table-bordered">
  <thead>
    <tr>
      <th>Nome</th>
      <th>URL</th>
      <th>Intervalo (s)</th>
      <th>Último Status</th>
      <th>Próxima Execução</th>
      <th>Ações</th>
    </tr>
  </thead>
  <tbody>
    {% for tid, t in tasks.items() %}
    <tr>
      <td>{{ t.get('name') or tid }}</td>
      <td style="max-width:320px;word-wrap:break-word">{{ t.get('url') }}</td>
      <td>{{ t.get('interval') }}</td>
      <td>
        {% if t.get('last_status') %}
          <span class="badge bg-success">{{ t.get('last_status') }}</span>
        {% elif t.get('last_error') %}
          <span class="badge bg-danger">ERR</span>
          <div style="font-size:.8em">{{ t.get('last_error')[:120] }}</div>
        {% else %}-{% endif %}
        <div style="font-size:.75em;color:#666">{{ t.get('last_run') }}</div>
      </td>
      <td>{{ t.get('next_run') }}</td>
      <td>
        <form style="display:inline" method="post" action="{{ url_for('test', tid=tid) }}">
          <button class="btn btn-sm btn-outline-primary">Test</button>
        </form>
        <a class="btn btn-sm btn-warning" href="{{ url_for('edit', tid=tid) }}">Editar</a>
        <form style="display:inline" method="post" action="{{ url_for('toggle', tid=tid) }}">
          {% if t.get('enabled', True) %}
            <button class="btn btn-sm btn-secondary">Desativar</button>
          {% else %}
            <button class="btn btn-sm btn-success">Ativar</button>
          {% endif %}
        </form>
        <form style="display:inline" method="post" action="{{ url_for('delete', tid=tid) }}" onsubmit="return confirm('Deletar?')">
          <button class="btn btn-sm btn-danger">Deletar</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<hr class="my-4">

<h3>Proxies disponíveis</h3>
<p class="text-muted">
  Lista puxada da Webshare (múltiplas API keys). A execução usa a proxy padrão e faz failover.
  Se uma conta retornar 402 (Bandwidth limit reached), o runner pula as demais proxies daquela conta nessa execução.
</p>

<table class="table table-sm table-bordered">
  <thead>
    <tr>
      <th>Padrão?</th>
      <th>ID</th>
      <th>Conta/Key</th>
      <th>Host:Port</th>
      <th>User</th>
      <th>País/Cidade</th>
      <th>Fonte</th>
      <th>Ação</th>
    </tr>
  </thead>
  <tbody>
    {% for p in proxies %}
      {% set is_default = (p.get('id')|string == default_id|string) %}
      <tr class="{{ 'table-success' if is_default else '' }}">
        <td>{{ '✅' if is_default else '' }}</td>
        <td style="font-size:.85em">{{ p.get('id') }}</td>
        <td><span class="badge bg-secondary">{{ p.get('account_label','-') }}</span></td>
        <td>{{ p.get('proxy_address') }}:{{ p.get('port') }}</td>
        <td>{{ p.get('username') }}</td>
        <td>{{ p.get('country_code','') }}/{{ p.get('city_name','') }}</td>
        <td>{{ p.get('source','') }}</td>
        <td>
          <form method="post" action="{{ url_for('set_default_proxy', proxy_id=p.get('id')) }}">
            <button class="btn btn-sm btn-outline-primary">Tornar padrão</button>
          </form>
        </td>
      </tr>
    {% endfor %}
  </tbody>
</table>
"""

FORM = f"""
<h3>{{{{ title }}}}</h3>
<form method="post">
  <div class="mb-3">
    <label class="form-label">Nome (opcional)</label>
    <input class="form-control" name="name" value="{{{{ t.get('name','') }}}}">
  </div>
  <div class="mb-3">
    <label class="form-label">URL alvo</label>
    <input class="form-control" name="url" required value="{{{{ t.get('url','') }}}}">
  </div>
  <div class="row">
    <div class="col-md-4 mb-3">
      <label class="form-label">Intervalo (segundos)</label>
      <input class="form-control" type="number" name="interval" value="{{{{ t.get('interval',{DEFAULT_INTERVAL}) }}}}">
      <div class="form-text">Padrão: {DEFAULT_INTERVAL}s</div>
    </div>
    <div class="col-md-4 mb-3">
      <label class="form-label">Timeout (segundos)</label>
      <input class="form-control" type="number" name="timeout" value="{{{{ t.get('timeout',{DEFAULT_TIMEOUT}) }}}}">
    </div>
    <div class="col-md-4 mb-3">
      <label class="form-label">Ativado</label><br>
      <input class="form-check-input" type="checkbox" name="enabled" id="enabled" {{{{ 'checked' if t.get('enabled', True) else '' }}}}>
      <label class="form-check-label" for="enabled">Sim</label>
    </div>
  </div>

  <button class="btn btn-primary" type="submit">Salvar</button>
  <a class="btn btn-secondary" href="{{{{ url_for('index') }}}}">Cancelar</a>
</form>
"""

LOGS = """
<h3>Logs</h3>
<p><a class="btn btn-sm btn-outline-secondary" href="{{ url_for('index') }}">Voltar</a></p>
<table class="table table-sm table-bordered">
  <thead><tr><th>When (UTC)</th><th>Task</th><th>URL</th><th>Teste?</th><th>Resultado</th></tr></thead>
  <tbody>
    {% for ent in logs|reverse %}
      <tr>
        <td style="width:170px">{{ ent.get('at') }}</td>
        <td>{{ ent.get('task_name') or ent.get('task_id') }}</td>
        <td style="max-width:320px;word-wrap:break-word">{{ ent.get('url') }}</td>
        <td>{{ '✅' if ent.get('is_test') else '' }}</td>
        <td>
          {% if ent.get('result') %}
            {% if ent.result.status %}
              <span class="badge bg-success">{{ ent.result.status }}</span>
              <div style="font-size:.85em">{{ ent.result.duration_s }}s</div>
              {% if ent.result.winner_account %}
                <div style="font-size:.85em;color:#444">Conta vencedora: <b>{{ ent.result.winner_account }}</b></div>
              {% endif %}
              <pre style="white-space:pre-wrap">{{ ent.result.body_snippet }}</pre>
            {% elif ent.result.error %}
              <span class="badge bg-danger">ERR</span>
              <div style="font-size:.85em">{{ ent.result.duration_s }}s</div>
              <pre style="white-space:pre-wrap">{{ ent.result.error }}</pre>
              {% if ent.result.tried %}
                <div style="font-size:.85em;color:#666">Tried: {{ ent.result.tried|join(', ') }}</div>
              {% endif %}
            {% else %}
              <pre style="white-space:pre-wrap">{{ ent.result }}</pre>
            {% endif %}
          {% else %}
            {{ ent }}
          {% endif %}
        </td>
      </tr>
    {% endfor %}
  </tbody>
</table>
"""

LOGIN = """
<div class="row justify-content-center">
  <div class="col-md-5">
    <h3>Login</h3>
    <form method="post" autocomplete="off">
      <div class="mb-3">
        <label class="form-label">Usuário</label>
        <input class="form-control" name="username" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Senha</label>
        <input class="form-control" type="password" name="password" required>
      </div>
      <button class="btn btn-primary" type="submit">Entrar</button>
    </form>
    <p class="text-muted mt-3" style="font-size:.9em">Falhas demais bloqueiam temporariamente.</p>
  </div>
</div>
"""


# ======================
# Rotas
# ======================

@app.before_request
def _apply_rate_limits():
    path = request.path.rstrip("/")
    if path.startswith("/static"):
        return
    rate_limit_check(is_login=(path == "/login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        body = render_template_string(LOGIN)
        return render_template_string(BASE, body=body, get_flashed_messages=get_flashed_messages)

    ip = client_ip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if login_blocked(ip, username):
        time.sleep(1.0)
        flash("Acesso temporariamente bloqueado. Tente mais tarde.")
        return redirect(url_for("login"))

    ok = (username == ADMIN_USER) and check_password_hash(ADMIN_PASSWORD_HASH, password)
    if not ok:
        register_login_failure(ip, username)
        time.sleep(0.7)
        flash("Usuário ou senha inválidos")
        return redirect(url_for("login"))

    session.clear()
    session["auth_user"] = ADMIN_USER
    fail_by_ip[ip].clear()
    fail_by_user[username].clear()
    ip_lockouts.pop(ip, None)
    user_lockouts.pop(username, None)
    return redirect(request.args.get("next") or url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão encerrada")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    with SCHED_LOCK, POOL_LOCK:
        tasks_local = dict(data["tasks"])
        proxies_local = list(data["proxies"])
        default_id = data["settings"].get("default_proxy_id")
    body = render_template_string(INDEX, tasks=tasks_local, proxies=proxies_local, default_id=default_id)
    return render_template_string(BASE, body=body, get_flashed_messages=get_flashed_messages)

@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        tid = str(uuid.uuid4())
        t = {
            "id": tid,
            "name": request.form.get("name", "").strip(),
            "url": request.form.get("url", "").strip(),
            "interval": max(1, int(request.form.get("interval", DEFAULT_INTERVAL) or DEFAULT_INTERVAL)),
            "timeout": max(1, int(request.form.get("timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)),
            "enabled": True if request.form.get("enabled") else False,
            "last_status": None,
            "last_error": None,
            "last_run": None,
            "next_run": now_iso()
        }
        with SCHED_LOCK:
            data["tasks"][tid] = t
        mark_dirty("tasks")
        flash("Job criado")
        return redirect(url_for("index"))

    body = render_template_string(FORM, title="Criar job", t={})
    return render_template_string(BASE, body=body, get_flashed_messages=get_flashed_messages)

@app.route("/edit/<tid>", methods=["GET", "POST"])
@login_required
def edit(tid):
    with SCHED_LOCK:
        t = data["tasks"].get(tid)
    if not t:
        flash("Job não encontrado")
        return redirect(url_for("index"))

    if request.method == "POST":
        with SCHED_LOCK:
            data["tasks"][tid]["name"] = request.form.get("name", "").strip()
            data["tasks"][tid]["url"] = request.form.get("url", "").strip()
            data["tasks"][tid]["interval"] = max(1, int(request.form.get("interval", DEFAULT_INTERVAL) or DEFAULT_INTERVAL))
            data["tasks"][tid]["timeout"] = max(1, int(request.form.get("timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT))
            data["tasks"][tid]["enabled"] = True if request.form.get("enabled") else False
            data["tasks"][tid]["next_run"] = now_iso()
        mark_dirty("tasks")
        flash("Job atualizado")
        return redirect(url_for("index"))

    body = render_template_string(FORM, title="Editar job", t=t)
    return render_template_string(BASE, body=body, get_flashed_messages=get_flashed_messages)

@app.route("/toggle/<tid>", methods=["POST"])
@login_required
def toggle(tid):
    with SCHED_LOCK:
        if tid in data["tasks"]:
            data["tasks"][tid]["enabled"] = not data["tasks"][tid].get("enabled", True)
            if data["tasks"][tid]["enabled"]:
                data["tasks"][tid]["next_run"] = now_iso()
            mark_dirty("tasks")
            flash("Estado alterado")
        else:
            flash("Job não encontrado")
    return redirect(url_for("index"))

@app.route("/delete/<tid>", methods=["POST"])
@login_required
def delete(tid):
    with SCHED_LOCK:
        if tid in data["tasks"]:
            del data["tasks"][tid]
            mark_dirty("tasks")
            flash("Job deletado")
        else:
            flash("Job não encontrado")
    return redirect(url_for("index"))

@app.route("/test/<tid>", methods=["POST"])
@login_required
def test(tid):
    with SCHED_LOCK:
        if tid not in data["tasks"]:
            flash("Job não encontrado")
            return redirect(url_for("index"))
    executor.submit(run_task, tid, True)
    flash("Teste disparado (veja em Logs).")
    return redirect(url_for("show_logs"))

@app.route("/logs")
@login_required
def show_logs():
    with SCHED_LOCK:
        logs_local = list(data["logs"])
    body = render_template_string(LOGS, logs=logs_local)
    return render_template_string(BASE, body=body, get_flashed_messages=get_flashed_messages)

@app.route("/admin/refresh_proxies", methods=["GET", "POST"])
@login_required
def refresh_proxies():
    if request.method == "GET":
        body = """
        <h3>Atualizar Proxies (Webshare)</h3>
        <p>Busca via API em todas as API keys configuradas e mescla com a lista atual. Tudo salvo em <code>data.json</code>.</p>
        <form method="post">
          <button class="btn btn-primary">Atualizar agora</button>
          <a class="btn btn-secondary" href="{{ url_for('index') }}">Voltar</a>
        </form>
        """
        body = render_template_string(body)
        return render_template_string(BASE, body=body, get_flashed_messages=get_flashed_messages)

    try:
        rows, errs = refresh_proxies_from_all_accounts()
        msg = f"Proxylist atualizada. Novas/mescladas: {len(rows)}. Total salvo: {len(data['proxies'])}."
        if errs:
            msg += " Falhas parciais: " + " | ".join(errs)
        flash(msg)
    except Exception as e:
        flash(f"Erro ao atualizar proxies: {e}")
    return redirect(url_for("index"))

@app.route("/admin/set_default/<proxy_id>", methods=["POST"])
@login_required
def set_default_proxy(proxy_id):
    with POOL_LOCK:
        if any(str(p.get("id")) == str(proxy_id) for p in data["proxies"]):
            rotate_default_proxy(str(proxy_id))
            flash(f"Padrão definido: {proxy_id}")
        else:
            flash("Proxy não encontrada")
    return redirect(url_for("index"))

# alias amigável
app.add_url_rule("/set_default/<proxy_id>", view_func=set_default_proxy, methods=["POST"])


# ======================
# Boot
# ======================

def boot():
    load_all()
    ensure_bootstrap_items()
    ensure_next_run_all()

if __name__ == "__main__":
    boot()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    threading.Thread(target=saver_loop, daemon=True).start()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    port = int(os.getenv("PORT", 5000))
    print(f"App em http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
