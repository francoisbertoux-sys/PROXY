#!/usr/bin/env python3
"""
Proxy CORS — API Cecurity CFEC
-------------------------------
Relaie les appels de l'eForm Therefore vers Cecurity en gérant :
  - les headers CORS (autorise *.thereforeonline.com)
  - la session Cecurity côté serveur (JSESSIONID stocké en mémoire)

Démarrage :
    pip install flask requests
    python proxy_cecurity.py

Variables d'environnement :
    PORT            port d'écoute (défaut : 5000)
    ALLOWED_ORIGIN  suffixe d'origin autorisé (défaut : .thereforeonline.com)
"""

import os
import uuid
import time
import threading

import requests
from flask import Flask, request, Response

# ── Config ──────────────────────────────────────────────────────────────────
CECURITY_BASE    = 'https://partition-rcte.cecurity.com/jersey-cfec-openapi'
ALLOWED_SUFFIX   = os.environ.get('ALLOWED_ORIGIN', '.thereforeonline.com')
PORT             = int(os.environ.get('PORT', 5000))
SESSION_TTL      = 3600   # secondes avant qu'une session inactive soit purgée

app = Flask(__name__)

# ── Sessions : sid → { session: requests.Session, last_seen: timestamp } ───
_store = {}
_lock  = threading.Lock()

def get_or_create_session(sid):
    with _lock:
        if sid and sid in _store:
            _store[sid]['last_seen'] = time.time()
            return sid, _store[sid]['session']
        new_sid  = str(uuid.uuid4())
        _store[new_sid] = {'session': requests.Session(), 'last_seen': time.time()}
        return new_sid, _store[new_sid]['session']

def purge_old_sessions():
    """Supprime les sessions inactives depuis plus de SESSION_TTL secondes."""
    cutoff = time.time() - SESSION_TTL
    with _lock:
        to_delete = [k for k, v in _store.items() if v['last_seen'] < cutoff]
        for k in to_delete:
            del _store[k]

# ── CORS ────────────────────────────────────────────────────────────────────
def cors_headers(origin):
    return {
        'Access-Control-Allow-Origin':      origin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods':     'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers':     'Content-Type, Accept, X-SIV-Session',
        'Access-Control-Expose-Headers':    'X-SIV-Session',
    }

@app.after_request
def add_cors(resp):
    origin = request.headers.get('Origin', '')
    if origin.endswith(ALLOWED_SUFFIX):
        for k, v in cors_headers(origin).items():
            resp.headers[k] = v
    return resp

# ── Preflight OPTIONS ───────────────────────────────────────────────────────
@app.route('/proxy/<path:path>', methods=['OPTIONS'])
def preflight(path):
    return Response('', 204)

# ── Proxy principal ─────────────────────────────────────────────────────────
@app.route('/proxy/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    purge_old_sessions()

    sid, sess = get_or_create_session(request.headers.get('X-SIV-Session', ''))

    url    = f'{CECURITY_BASE}/{path}'
    params = request.args.to_dict()

    cecurity_resp = sess.request(
        method  = request.method,
        url     = url,
        params  = params,
        headers = {
            'Content-Type': 'application/json',
            'Accept':       'application/json',
        },
        data    = request.get_data(),
        timeout = 30,
        allow_redirects = True,
    )

    resp = Response(
        cecurity_resp.content,
        status       = cecurity_resp.status_code,
        content_type = cecurity_resp.headers.get('Content-Type', 'application/json'),
    )
    resp.headers['X-SIV-Session'] = sid
    return resp

# ── Entrée ──────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f'Proxy Cecurity démarré sur http://0.0.0.0:{PORT}')
    print(f'Origins autorisées : *{ALLOWED_SUFFIX}')
    app.run(host='0.0.0.0', port=PORT)
