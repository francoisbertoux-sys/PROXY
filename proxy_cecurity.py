#!/usr/bin/env python3
"""
Proxy CORS — API Cecurity CFEC
Relaie les appels navigateur vers Cecurity en gérant CORS et sessions. V9
"""

import os
import uuid
import time
import threading

import requests
from flask import Flask, request, Response, jsonify

CECURITY_BASE  = 'https://partition-rcte.cecurity.com/jersey-cfec-openapi'
ALLOWED_SUFFIX = os.environ.get('ALLOWED_ORIGIN', '.thereforeonline.com')
PORT           = int(os.environ.get('PORT', 5000))
SESSION_TTL    = 3600

app = Flask(__name__)

# ── Sessions côté serveur ────────────────────────────────────────────────────
_store = {}
_lock  = threading.Lock()

def get_or_create_session(sid):
    with _lock:
        if sid and sid in _store:
            _store[sid]['last_seen'] = time.time()
            return sid, _store[sid]['session']
        new_sid = str(uuid.uuid4())
        _store[new_sid] = {'session': requests.Session(), 'last_seen': time.time()}
        return new_sid, _store[new_sid]['session']

def purge_old_sessions():
    cutoff = time.time() - SESSION_TTL
    with _lock:
        for k in [k for k, v in _store.items() if v['last_seen'] < cutoff]:
            del _store[k]

# ── CORS helpers ─────────────────────────────────────────────────────────────
def get_cors_headers(origin):
    return {
        'Access-Control-Allow-Origin':      origin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods':     'GET, POST, DELETE, PATCH, PUT, OPTIONS',
        'Access-Control-Allow-Headers':     'Content-Type, Accept, X-SIV-Session, Authorization, X-TENANT-ID, X-TENANT-NAME',
        'Access-Control-Expose-Headers':    'X-SIV-Session',
    }

def is_allowed_origin(origin):
    return origin.endswith(ALLOWED_SUFFIX) if origin else False

@app.after_request
def add_cors(resp):
    origin = request.headers.get('Origin', '')
    if is_allowed_origin(origin):
        for k, v in get_cors_headers(origin).items():
            resp.headers[k] = v
    return resp

# ── Health check + debug ─────────────────────────────────────────────────────
@app.route('/ping')
def ping():
    return jsonify({'status': 'ok', 'sessions': len(_store)})

@app.route('/debug/<sid>')
def debug_session(sid):
    with _lock:
        if sid not in _store:
            return jsonify({'error': 'session not found'}), 404
        cookies = dict(_store[sid]['session'].cookies)
        return jsonify({'sid': sid, 'cookies': cookies})

# ── Preflight OPTIONS ─────────────────────────────────────────────────────────
@app.route('/proxy/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/proxy/<path:path>', methods=['OPTIONS'])
def preflight(path):
    origin = request.headers.get('Origin', '')
    resp   = Response('', 204)
    if is_allowed_origin(origin):
        for k, v in get_cors_headers(origin).items():
            resp.headers[k] = v
    return resp

# ── Proxy principal ───────────────────────────────────────────────────────────
@app.route('/proxy/', defaults={'path': ''}, methods=['GET', 'POST', 'DELETE', 'PATCH', 'PUT'])
@app.route('/proxy/<path:path>', methods=['GET', 'POST', 'DELETE', 'PATCH', 'PUT'])
def proxy(path):
    purge_old_sessions()
    sid, sess = get_or_create_session(request.headers.get('X-SIV-Session', ''))

    url    = f'{CECURITY_BASE}/{path}'
    params = request.args.to_dict()

    try:
        cecurity_resp = sess.request(
            method  = request.method,
            url     = url,
            params  = params,
            headers = {
                'Content-Type':  'application/json',
                'Accept':        request.headers.get('Accept', '*/*'),
                'X-TENANT-ID':   request.headers.get('X-TENANT-ID', ''),
                'X-TENANT-NAME': request.headers.get('X-TENANT-NAME', ''),
            },
            data    = request.get_data(),
            timeout = 30,
        )
    except requests.RequestException as e:
        resp = jsonify({'error': str(e)})
        resp.status_code = 502
        return resp

    resp = Response(
        cecurity_resp.content,
        status       = cecurity_resp.status_code,
        content_type = cecurity_resp.headers.get('Content-Type', 'application/json'),
    )
    resp.headers['X-SIV-Session'] = sid
    return resp

if __name__ == '__main__':
    print(f'Proxy démarré — port {PORT}')
    app.run(host='0.0.0.0', port=PORT)
