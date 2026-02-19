import http.server
import socketserver
import sqlite3
import json
import os
import urllib.parse
import uuid
import base64
import math
import hmac
import hashlib
import secrets
import time
from datetime import datetime
import socket
import webbrowser
import threading
from http.cookies import SimpleCookie

PORT = 8000
DB_FILE = "maintenance.db"
ATTACHMENTS_DB = "attachments.db"
AUTH_COOKIE_NAME = "huolto_auth"
AUTH_PBKDF2_ITERATIONS = 120000
AUTH_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
AUTH_CONFIG_KEY = "api_auth"
AUTH_LOGIN_MAX_FAILURES = 5
AUTH_LOGIN_PENALTY_SECONDS = 60
auth_sessions = {}
auth_sessions_lock = threading.Lock()
auth_login_failures = {}
auth_login_failures_lock = threading.Lock()
PLATE_SQL_EXPR = "REPLACE(REPLACE(REPLACE(UPPER(COALESCE(license_plate, '')), '-', ''), ' ', ''), '.', '')"

def read_config_value(key):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT value FROM config WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def get_auth_config():
    raw = read_config_value(AUTH_CONFIG_KEY)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}

def is_password_enabled():
    config = get_auth_config()
    return bool(config.get("hash") and config.get("salt"))

def build_password_hash(password, iterations=AUTH_PBKDF2_ITERATIONS):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {
        "hash": digest.hex(),
        "salt": salt.hex(),
        "iterations": int(iterations),
        "updated_at": datetime.now().isoformat(timespec="seconds")
    }

def verify_password(password, config):
    if not isinstance(config, dict):
        return False
    hash_hex = config.get("hash", "")
    salt_hex = config.get("salt", "")
    iterations = int(config.get("iterations", AUTH_PBKDF2_ITERATIONS))
    if not hash_hex or not salt_hex:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(hash_hex, digest.hex())

def cleanup_expired_sessions():
    now = int(time.time())
    with auth_sessions_lock:
        expired = [token for token, expires_at in auth_sessions.items() if expires_at <= now]
        for token in expired:
            del auth_sessions[token]

def get_client_identity(handler):
    try:
        return handler.client_address[0] or "unknown"
    except Exception:
        return "unknown"

def get_auth_penalty_seconds_remaining(client_id):
    now = int(time.time())
    with auth_login_failures_lock:
        entry = auth_login_failures.get(client_id)
        if not entry:
            return 0
        penalty_until = int(entry.get("penalty_until", 0))
        if penalty_until <= now:
            entry["penalty_until"] = 0
            return 0
        return penalty_until - now

def register_auth_failure(client_id):
    now = int(time.time())
    with auth_login_failures_lock:
        entry = auth_login_failures.get(client_id, {"fail_count": 0, "penalty_until": 0})
        fail_count = int(entry.get("fail_count", 0)) + 1
        penalty_until = int(entry.get("penalty_until", 0))
        if fail_count % AUTH_LOGIN_MAX_FAILURES == 0:
            penalty_until = now + AUTH_LOGIN_PENALTY_SECONDS
        entry["fail_count"] = fail_count
        entry["penalty_until"] = penalty_until
        auth_login_failures[client_id] = entry
        return max(0, penalty_until - now)

def reset_auth_failures(client_id):
    with auth_login_failures_lock:
        if client_id in auth_login_failures:
            del auth_login_failures[client_id]

def normalize_plate_lookup(value):
    return ''.join(ch for ch in str(value or '').upper() if ch.isalnum())

def normalize_single_line_text(value):
    return ' '.join(str(value or '').split())

def parse_report_data_blob(raw_data):
    try:
        parsed = json.loads(raw_data) if raw_data else {}
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}

def init_db():
    # Main DB
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  customer_name TEXT,
                  license_plate TEXT,
                  vin TEXT,
                  report_date TEXT,
                  data TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS config
                 (key TEXT PRIMARY KEY, value TEXT)''')
    
    # Default Maintenance Items
    c.execute("SELECT value FROM config WHERE key='maintenance_items'")
    if not c.fetchone():
        default_items = {
            "schema_version": 2,
            "groups": [
                {
                    "id": "group_dfdf234e-7872-456f-be64-9e9cede7244c",
                    "title": "Tehdyt huoltotyöt",
                    "items": [
                        {
                            "id": "item_c0e87515-bb88-433e-a2ad-7e459ce9b1f2",
                            "label": "Moottoriöljyn vaihto",
                            "subitems": [
                                "0W-30",
                                "0W-40",
                                "5W-30",
                                "5W-40",
                                "10W-40",
                                "15W-40"
                            ]
                        },
                        {
                            "id": "item_b3209975-4d41-4651-9c33-7e7a8187fcd3",
                            "label": "Öljynsuodattimen vaihto"
                        },
                        {
                            "id": "item_b8f08f5d-ad0b-4b25-91d8-79dcf41c1673",
                            "label": "Vaihteistoöljyn vaihto",
                            "subitems": [
                                "75W-80",
                                "75W-85",
                                "75W-90",
                                "75W-140",
                                "80W-90"
                            ]
                        },
                        {
                            "id": "item_2f814705-4379-4196-8abe-a8e1fe0c99f0",
                            "label": "Polttoainesuodattimen vaihto"
                        },
                        {
                            "id": "item_14665c07-c89d-4530-a2c8-91ed5be51759",
                            "label": "Jarrunesteen vaihto",
                            "subitems": [
                                "DOT 4",
                                "DOT 5.1"
                            ]
                        },
                        {
                            "id": "item_aa8159e8-2f7b-461b-b4d2-61a6acf9e586",
                            "label": "Sytytystulppien vaihto"
                        },
                        {
                            "id": "item_db81c50a-957d-4614-9067-83f99c1a542a",
                            "label": "Moottorin ilmansuodattimen vaihto"
                        },
                        {
                            "id": "item_ac20f43b-9287-4ba1-af7b-d81f74827916",
                            "label": "Raitisilmansuodattimen vaihto",
                            "subitems": [
                                "Aktiivihiili",
                                "Tarvikelaatu",
                                "Alkuperäislaatu"
                            ]
                        },
                        {
                            "id": "item_a22bf85c-6f05-4d76-84b7-89371a963dc8",
                            "label": "Apulaitehihnan vaihto"
                        },
                        {
                            "id": "item_06372f53-9541-4c6c-ae66-bd4296493a7d",
                            "label": "Saranoiden rasvaus"
                        }
                    ]
                },
                {
                    "id": "group_eb0505f2-f1a0-4d2f-8000-eb9613db5ce1",
                    "title": "JARRUJÄRJESTELMÄ",
                    "items": [
                        {
                            "id": "item_87a1c06e-84a6-4f3a-92d1-8a196e7e3421",
                            "label": "Jarrupalojen kulutuspinnan tarkastus"
                        },
                        {
                            "id": "item_c8d01e59-45a6-43cc-b7ac-30313a343df2",
                            "label": "Jarrulevyn kunnon tarkastus"
                        },
                        {
                            "id": "item_b3e0d100-ca9b-4f81-b30a-ab676cce6a2c",
                            "label": "Käsijarrun toiminnan tarkastus"
                        },
                        {
                            "id": "item_c2fde5cb-feb6-4b55-83a3-48c57f56f224",
                            "label": "Jarruletkujen ja -putkien tarkastus"
                        }
                    ]
                },
                {
                    "id": "group_5765522b-fb19-4e38-a9aa-9122cbe3bf78",
                    "title": "NESTEET",
                    "items": [
                        {
                            "id": "item_29eae5e6-be60-4c6e-b711-e65283dc3326",
                            "label": "Öljyjen ja nesteiden määrän tarkastus"
                        },
                        {
                            "id": "item_7eecf4e0-954c-41b6-8a4b-f6636ad7c177",
                            "label": "Tuulilasinpesunesteen tarkastus ja täyttö",
                            "subitems": [
                                "-25°C",
                                "-18°C",
                                "-10°C",
                                "Kesälaatu"
                            ]
                        },
                        {
                            "id": "item_5358a2ed-1642-4d68-833d-f650d3e7411e",
                            "label": "Ohjaustehostinnesteen tarkastus"
                        },
                        {
                            "id": "item_e88bcd60-e325-4a8d-80df-c25b193c8270",
                            "label": "Jäähdytysnesteen tarkastus"
                        }
                    ]
                },
                {
                    "id": "group_d7b66a4e-4af4-4ee1-a112-c26fab53be73",
                    "title": "RENKAAT JA PYÖRÄT",
                    "items": [
                        {
                            "id": "item_3ec52c95-2e94-42b9-9ddf-ce519f573267",
                            "label": "Renkaiden kunnon tarkastus"
                        },
                        {
                            "id": "item_84dd7768-900e-4d6b-829b-8d78c283fff0",
                            "label": "Renkaiden ilmanpaineen tarkistus"
                        },
                        {
                            "id": "item_3749b1b5-491a-476b-b5b1-568c0d939a80",
                            "label": "Vararenkaan kunnon tarkastus"
                        }
                    ]
                },
                {
                    "id": "group_1a1eb362-0ca7-42c9-b47b-8ce21dceb731",
                    "title": "VALOT JA SÄHKÖLAITTEET",
                    "items": [
                        {
                            "id": "item_6d241fc9-81ba-45f8-a8cf-69a22a4ea2fe",
                            "label": "Ulkovalojen tarkastus"
                        },
                        {
                            "id": "item_f595e72d-acd7-48ca-98e6-10c55d02bbc5",
                            "label": "Sisävalojen tarkastus"
                        },
                        {
                            "id": "item_530c829d-bcc6-4a47-bce4-923ecaa2532d",
                            "label": "Akun kunnon tarkistus"
                        },
                        {
                            "id": "item_b2c9e95d-2601-4938-808b-070d3e013894",
                            "label": "Laturin ja hihnan tarkastus"
                        }
                    ]
                },
                {
                    "id": "group_68cb8201-f0d1-4a83-9e10-b49cafa04e66",
                    "title": "ALUSTA JA JOUSITUS",
                    "items": [
                        {
                            "id": "item_d1d49ff1-ccc6-4278-b7f4-a14a62b085d5",
                            "label": "Iskunvaimentimien ja jousituksen tarkastus"
                        },
                        {
                            "id": "item_2a6fc917-12f8-4e1a-ad6a-1d196791bb33",
                            "label": "Ohjauslaitteiston tarkastus"
                        },
                        {
                            "id": "item_d4447a16-839e-4e19-a4ec-150b3f4d2298",
                            "label": "Vetokoukun ja pohjan tarkastus"
                        }
                    ]
                }
            ]
        }
        c.execute("INSERT INTO config (key, value) VALUES (?, ?)", ('maintenance_items', json.dumps(default_items)))

    # Default Shop Settings
    c.execute("SELECT value FROM config WHERE key='shop_settings'")
    if not c.fetchone():
        default_settings = {
            "company_text": "Korjaamo Oy\nOsoite 1\n00100 Helsinki\nY-tunnus: 123456-7",
            "hide_na_in_print": True,
            "accent_color": "#009eb8",
            "status_labels": {
                "done": "Suoritettu",
                "not_done": "Ei tehty",
                "na": "Ei sisälly"
            }
        }
        c.execute("INSERT INTO config (key, value) VALUES (?, ?)", ('shop_settings', json.dumps(default_settings)))
    
    conn.commit()
    conn.close()

    # Attachments DB
    conn_att = sqlite3.connect(ATTACHMENTS_DB)
    c_att = conn_att.cursor()
    c_att.execute('''CREATE TABLE IF NOT EXISTS images
                     (uuid TEXT PRIMARY KEY, mime_type TEXT, blob_data BLOB)''')
    conn_att.commit()
    conn_att.close()

class MaintenanceRequestHandler(http.server.SimpleHTTPRequestHandler):
    def send_json(self, status_code, payload, extra_headers=None):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        if extra_headers:
            for header_name, header_value in extra_headers:
                self.send_header(header_name, header_value)
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def read_json_body(self):
        content_length = int(self.headers.get('Content-Length', '0') or 0)
        if content_length <= 0:
            return {}
        post_data = self.rfile.read(content_length)
        if not post_data:
            return {}
        return json.loads(post_data.decode('utf-8'))

    def get_auth_cookie_token(self):
        cookie_header = self.headers.get('Cookie', '')
        if not cookie_header:
            return None
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            morsel = cookie.get(AUTH_COOKIE_NAME)
            return morsel.value if morsel else None
        except Exception:
            return None

    def is_request_authenticated(self):
        if not is_password_enabled():
            return True

        cleanup_expired_sessions()
        token = self.get_auth_cookie_token()
        if not token:
            return False

        now = int(time.time())
        with auth_sessions_lock:
            expires_at = auth_sessions.get(token, 0)
            if expires_at > now:
                return True
            if token in auth_sessions:
                del auth_sessions[token]
        return False

    def send_forbidden_auth_required(self):
        self.send_json(403, {'error': 'forbidden', 'auth_required': True})

    def handle_auth_status(self):
        password_required = is_password_enabled()
        self.send_json(200, {
            'password_enabled': password_required,
            'authenticated': self.is_request_authenticated() if password_required else True
        })

    def handle_auth_login(self):
        try:
            data = self.read_json_body()
        except Exception:
            self.send_json(400, {'error': 'invalid_json'})
            return

        client_id = get_client_identity(self)
        penalty_remaining = get_auth_penalty_seconds_remaining(client_id)
        if penalty_remaining > 0:
            self.send_json(429, {
                'status': 'rate_limited',
                'auth_required': True,
                'retry_after': penalty_remaining
            })
            return

        password = data.get('password', '')
        if not isinstance(password, str):
            password = ''

        auth_config = get_auth_config()
        if not (auth_config.get('hash') and auth_config.get('salt')):
            self.send_json(200, {'status': 'not_required', 'password_enabled': False})
            return

        if not verify_password(password, auth_config):
            penalty_after_failure = register_auth_failure(client_id)
            if penalty_after_failure > 0:
                self.send_json(429, {
                    'status': 'rate_limited',
                    'auth_required': True,
                    'retry_after': penalty_after_failure
                })
                return
            self.send_json(403, {'status': 'invalid_password', 'auth_required': True})
            return

        reset_auth_failures(client_id)
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + AUTH_SESSION_TTL_SECONDS
        with auth_sessions_lock:
            auth_sessions[token] = expires_at

        cookie_value = (
            f"{AUTH_COOKIE_NAME}={token}; Path=/; Max-Age={AUTH_SESSION_TTL_SECONDS}; "
            "HttpOnly; SameSite=Lax"
        )
        self.send_json(200, {'status': 'ok', 'password_enabled': True}, extra_headers=[('Set-Cookie', cookie_value)])

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        if path.startswith('/api/'):
            if path == '/api/auth_status':
                self.handle_auth_status()
                return

            if not self.is_request_authenticated():
                self.send_forbidden_auth_required()
                return

            # Special handling for binary image data
            if path == '/api/attachment':
                self.serve_attachment(query)
                return

            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            response_data = {}

            try:
                if path == '/api/config':
                    c.execute("SELECT key, value FROM config")
                    rows = c.fetchall()
                    for row in rows:
                        if row['key'] == AUTH_CONFIG_KEY:
                            continue
                        response_data[row['key']] = json.loads(row['value'])
                    response_data['security'] = {'password_enabled': is_password_enabled()}
                
                elif path == '/api/reports':
                    search_q = query.get('q', [''])[0]
                    page = int(query.get('page', [1])[0])
                    limit = int(query.get('limit', [30])[0])
                    offset = (page - 1) * limit

                    # Base SQL
                    sql_base = "FROM reports WHERE 1=1"
                    params = []

                    if search_q:
                        terms = [term for term in search_q.split() if term]
                        for term in terms:
                            wildcard = f"%{term}%"
                            sql_base += """ AND (
                                customer_name LIKE ?
                                OR REPLACE(UPPER(license_plate), '-', '') LIKE REPLACE(UPPER(?), '-', '')
                                OR vin LIKE ?
                                OR COALESCE(json_extract(data, '$.vehicle_model'), '') LIKE ?
                            )"""
                            params.extend([wildcard, wildcard, wildcard, wildcard])
                    
                    # Get Total Count
                    c.execute(f"SELECT COUNT(*) {sql_base}", params)
                    total_count = c.fetchone()[0]

                    # Get Data
                    sql = f"SELECT id, customer_name, license_plate, vin, report_date, data, created_at {sql_base} ORDER BY created_at DESC LIMIT ? OFFSET ?"
                    params.extend([limit, offset])
                    
                    c.execute(sql, params)
                    rows = c.fetchall()
                    
                    response_data = {
                        'items': [dict(row) for row in rows],
                        'total': total_count,
                        'page': page,
                        'limit': limit,
                        'pages': math.ceil(total_count / limit)
                    }

                elif path == '/api/report_suggestions':
                    field = (query.get('field', [''])[0] or '').strip().lower()
                    raw_q = query.get('q', [''])[0]
                    normalized_q = normalize_single_line_text(raw_q)
                    try:
                        limit = int(query.get('limit', [8])[0])
                    except (TypeError, ValueError):
                        limit = 8
                    limit = max(1, min(limit, 20))

                    if len(normalized_q) < 2:
                        response_data = {'items': []}
                    elif field == 'customer':
                        terms = [term for term in normalized_q.split(' ') if term]
                        sql_base = "FROM reports WHERE 1=1"
                        params = []
                        for term in terms:
                            sql_base += " AND REPLACE(REPLACE(customer_name, char(10), ' '), char(13), ' ') LIKE ?"
                            params.append(f"%{term}%")
                        c.execute(
                            f'''SELECT customer_name, license_plate, report_date
                                {sql_base}
                                ORDER BY created_at DESC, id DESC
                                LIMIT ?''',
                            (*params, max(limit * 6, limit))
                        )
                        rows = c.fetchall()
                        seen_customers = set()
                        items = []
                        for row in rows:
                            customer_name = row['customer_name'] or ''
                            customer_key = normalize_single_line_text(customer_name).casefold()
                            if not customer_key or customer_key in seen_customers:
                                continue
                            seen_customers.add(customer_key)
                            items.append({
                                'customer_name': customer_name,
                                'license_plate': row['license_plate'] or '',
                                'report_date': row['report_date'] or ''
                            })
                            if len(items) >= limit:
                                break
                        response_data = {'items': items}
                    elif field in ('plate', 'license_plate'):
                        plate_key = normalize_plate_lookup(normalized_q)
                        if len(plate_key) < 2:
                            response_data = {'items': []}
                        else:
                            wildcard = f"%{plate_key}%"
                            c.execute(
                                f'''SELECT customer_name, license_plate, report_date, data
                                    FROM reports
                                    WHERE {PLATE_SQL_EXPR} LIKE ?
                                    ORDER BY created_at DESC, id DESC
                                    LIMIT ?''',
                                (wildcard, max(limit * 8, limit))
                            )
                            rows = c.fetchall()
                            seen_plates = set()
                            items = []
                            for row in rows:
                                license_plate = row['license_plate'] or ''
                                normalized_plate = normalize_plate_lookup(license_plate)
                                if not normalized_plate or normalized_plate in seen_plates:
                                    continue
                                seen_plates.add(normalized_plate)
                                payload = parse_report_data_blob(row['data'])
                                items.append({
                                    'license_plate': license_plate,
                                    'customer_name': row['customer_name'] or '',
                                    'report_date': row['report_date'] or '',
                                    'mileage': str(payload.get('mileage', '') or '').strip()
                                })
                                if len(items) >= limit:
                                    break
                            response_data = {'items': items}
                    else:
                        response_data = {'items': []}
                
                elif path == '/api/reports_by_date':
                    start_date = (query.get('start', [''])[0] or '').strip()
                    end_date = (query.get('end', [''])[0] or '').strip()

                    try:
                        if start_date:
                            datetime.strptime(start_date, '%Y-%m-%d')
                        if end_date:
                            datetime.strptime(end_date, '%Y-%m-%d')
                    except ValueError:
                        start_date = ''
                        end_date = ''

                    if start_date and end_date:
                        if start_date > end_date:
                            start_date, end_date = end_date, start_date
                        c.execute(
                            '''SELECT id, customer_name, license_plate, report_date, created_at
                               FROM reports
                               WHERE report_date >= ? AND report_date <= ?
                               ORDER BY report_date ASC, created_at DESC, id DESC''',
                            (start_date, end_date)
                        )
                        rows = c.fetchall()
                    else:
                        rows = []

                    response_data = {
                        'items': [dict(row) for row in rows],
                        'start': start_date,
                        'end': end_date
                    }

                elif path == '/api/report':
                    report_id = query.get('id', [None])[0]
                    if report_id:
                        c.execute("SELECT * FROM reports WHERE id=?", (report_id,))
                        row = c.fetchone()
                        if row:
                            data_blob = json.loads(row['data'])
                            # Remove legacy company_info so it doesn't overwrite global settings
                            data_blob.pop('company_info', None) 
                            data_blob['id'] = row['id']
                            response_data = data_blob
                
                elif path == '/api/lookup_vehicle':
                    plate = query.get('plate', [''])[0]
                    plate_key = normalize_plate_lookup(plate)
                    if plate_key:
                        c.execute(
                            f'''SELECT vin, data
                                FROM reports
                                WHERE {PLATE_SQL_EXPR} = ?
                                ORDER BY COALESCE(report_date, '') DESC, created_at DESC, id DESC
                                LIMIT 1''',
                            (plate_key,)
                        )
                        row = c.fetchone()
                        if row:
                            full_data = parse_report_data_blob(row['data'])
                            response_data = {
                                'vin': row['vin'],
                                'vehicle_model': full_data.get('vehicle_model', ''),
                                'engine_code': full_data.get('engine_code', ''),
                                'registered_date': full_data.get('registered_date', ''),
                                'previous_mileage': str(full_data.get('mileage', '') or '').strip()
                            }

                self.send_json(200, response_data)
            except Exception as e:
                print(f"Error: {e}")
                self.send_json(500, {'error': str(e)})
            finally:
                conn.close()
            return

        return super().do_GET()

    def serve_attachment(self, query):
        img_id = query.get('id', [None])[0]
        if not img_id:
            self.send_error(404)
            return
        
        try:
            conn = sqlite3.connect(ATTACHMENTS_DB)
            c = conn.cursor()
            c.execute("SELECT mime_type, blob_data FROM images WHERE uuid=?", (img_id,))
            row = c.fetchone()
            conn.close()

            if row:
                self.send_response(200)
                self.send_header('Content-type', row[0])
                self.end_headers()
                self.wfile.write(row[1])
            else:
                self.send_error(404)
        except Exception as e:
            print(f"Attachment Error: {e}")
            self.send_error(500)

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if not path.startswith('/api/'):
            self.send_error(404)
            return

        if path == '/api/auth':
            self.handle_auth_login()
            return

        if not self.is_request_authenticated():
            self.send_forbidden_auth_required()
            return

        try:
            data = self.read_json_body()
        except Exception:
            self.send_json(400, {'error': 'invalid_json'})
            return

        try:
            response_data = {}
            
            if path == '/api/upload_attachment':
                image_b64 = data.get('image', '').split(',')[-1] 
                mime_type = data.get('mime', 'application/octet-stream')
                custom_id = data.get('custom_id', None)
                
                img_bytes = base64.b64decode(image_b64)
                img_uuid = custom_id if custom_id else str(uuid.uuid4())

                conn_att = sqlite3.connect(ATTACHMENTS_DB)
                c_att = conn_att.cursor()
                c_att.execute("INSERT OR REPLACE INTO images (uuid, mime_type, blob_data) VALUES (?, ?, ?)", 
                              (img_uuid, mime_type, img_bytes))
                conn_att.commit()
                conn_att.close()
                
                response_data = {'status': 'uploaded', 'uuid': img_uuid}
            
            elif path == '/api/delete_attachment':
                target_id = data.get('id')
                if target_id:
                    conn_att = sqlite3.connect(ATTACHMENTS_DB)
                    c_att = conn_att.cursor()
                    c_att.execute("DELETE FROM images WHERE uuid=?", (target_id,))
                    conn_att.commit()
                    c_att.execute("VACUUM")
                    conn_att.close()
                    response_data = {'status': 'deleted', 'uuid': target_id}
                else:
                    response_data = {'status': 'error', 'message': 'No id provided'}

            elif path == '/api/delete_reports':
                # Bulk Delete Reports & Full GC for dangling attachments
                ids = data.get('ids', [])
                if ids:
                    # 1. Delete reports from Main DB
                    conn = sqlite3.connect(DB_FILE)
                    # row_factory needed to parse data properly
                    conn.row_factory = sqlite3.Row
                    c = conn.cursor()
                    
                    placeholders = ','.join('?' * len(ids))
                    c.execute(f"DELETE FROM reports WHERE id IN ({placeholders})", ids)
                    conn.commit()
                    
                    # 2. Garbage Collection: Scan ALL remaining reports for active attachments
                    active_attachments = set()
                    c.execute("SELECT data FROM reports")
                    rows = c.fetchall()
                    for row in rows:
                        try:
                            rpt = json.loads(row['data'])
                            if 'attachments' in rpt and isinstance(rpt['attachments'], list):
                                active_attachments.update(rpt['attachments'])
                        except Exception:
                            pass
                    
                    # Compact Main DB
                    c.execute("VACUUM")
                    conn.close()

                    # 3. Prune Attachments DB: Remove any image NOT in active_attachments
                    conn_att = sqlite3.connect(ATTACHMENTS_DB)
                    c_att = conn_att.cursor()
                    
                    # Get all image UUIDs
                    c_att.execute("SELECT uuid FROM images")
                    all_images = {row[0] for row in c_att.fetchall()}
                    
                    # Protected IDs (like company logo)
                    protected = {'company_logo'}
                    
                    # Calculate garbage
                    to_delete = all_images - active_attachments - protected
                    
                    if to_delete:
                        to_delete_list = list(to_delete)
                        # Batch delete in chunks (SQLite limit safety)
                        chunk_size = 500
                        for i in range(0, len(to_delete_list), chunk_size):
                            chunk = to_delete_list[i:i+chunk_size]
                            att_placeholders = ','.join('?' * len(chunk))
                            c_att.execute(f"DELETE FROM images WHERE uuid IN ({att_placeholders})", chunk)
                        
                        conn_att.commit()
                        c_att.execute("VACUUM")
                    
                    conn_att.close()
                    
                    response_data = {'status': 'deleted', 'count': len(ids), 'cleaned_attachments': len(to_delete)}
                else:
                    response_data = {'status': 'error', 'message': 'No ids provided'}

            else:
                # Operations on Main DB
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()

                if path == '/api/save_report':
                    # Clean company_info if it was accidentally sent, so it doesn't get saved
                    data.pop('company_info', None)
                    
                    customer = data.get('customer_name', '')
                    plate = data.get('license_plate', '')
                    vin = data.get('vin', '')
                    date = data.get('report_date', datetime.now().strftime('%Y-%m-%d'))
                    json_dump = json.dumps(data)
                    
                    if 'id' in data and data['id']:
                        c.execute('''UPDATE reports SET customer_name=?, license_plate=?, vin=?, report_date=?, data=? 
                                     WHERE id=?''', (customer, plate, vin, date, json_dump, data['id']))
                        response_data = {'status': 'updated', 'id': data['id']}
                    else:
                        c.execute('''INSERT INTO reports (customer_name, license_plate, vin, report_date, data) 
                                     VALUES (?, ?, ?, ?, ?)''', (customer, plate, vin, date, json_dump))
                        response_data = {'status': 'created', 'id': c.lastrowid}
                
                elif path == '/api/save_config':
                    if 'maintenance_items' in data:
                        c.execute("UPDATE config SET value=? WHERE key='maintenance_items'", (json.dumps(data['maintenance_items']),))
                    if 'maintenance_sets' in data:
                        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ('maintenance_sets', json.dumps(data['maintenance_sets'])))
                    if 'shop_settings' in data:
                        c.execute("UPDATE config SET value=? WHERE key='shop_settings'", (json.dumps(data['shop_settings']),))
                    security = data.get('security')
                    if isinstance(security, dict) and 'password' in security:
                        raw_password = security.get('password')
                        if isinstance(raw_password, str):
                            password = raw_password.strip()
                            if password:
                                c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (AUTH_CONFIG_KEY, json.dumps(build_password_hash(password))))
                            else:
                                c.execute("DELETE FROM config WHERE key=?", (AUTH_CONFIG_KEY,))
                                with auth_sessions_lock:
                                    auth_sessions.clear()
                            with auth_login_failures_lock:
                                auth_login_failures.clear()
                    response_data = {'status': 'config_updated'}

                conn.commit()
                conn.close()

            self.send_json(200, response_data)
        except Exception as e:
            print(f"DB Error: {e}")
            self.send_json(500, {'error': str(e)})
        return

def get_local_ipv4_addresses():
    ips = set()

    # 1) Hostname -> IP:t (toimii usein, ei aina)
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass

    # 2) “UDP” -> ensisijainen lähiverkon IP (ei lähetä dataa)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            ips.add(ip)
    except Exception:
        pass

    return sorted(ips)

if __name__ == "__main__":
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        init_db()
        print("")
        print("------------------------------------------------")
        print("| Huoltorapsa v1.2 -palvelin | Makkesoft 2026  |")
        print("------------------------------------------------")
        print("")
        print("Palvelin käynnistyy, voit pienentää tämän ikkunan.")
        print("Palvelimen voi lopettaa joko painamalla Ctrl+C tai ikkunan ylänurkan ruksista.")
        print(" ")
        print("Avaa selaimessa jokin näistä osoitteista:")
        print(f"  http://localhost:{PORT}/")
        for ip in get_local_ipv4_addresses():
            print(f"  http://{ip}:{PORT}/")
        print(" ")
        print("Toimintaloki ilmestyy alle:")

        # Avaa selain automaattisesti 1.5 sekunnin kuluttua
        def open_browser():
            webbrowser.open(f'http://localhost:{PORT}/')
        
        threading.Timer(1.5, open_browser).start()

        with socketserver.TCPServer(("", PORT), MaintenanceRequestHandler) as httpd:
            httpd.serve_forever()

    except Exception as e:
        print("\n!!!!!!!!!!!!!! VIRHE !!!!!!!!!!!!!!")
        print(f"Virhe käynnistyksessä: {e}")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
        input("Paina Enter sulkeaksesi ikkunan...")
