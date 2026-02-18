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
auth_sessions = {}
auth_sessions_lock = threading.Lock()

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
            "groups": [
                {
                    "title": "Tehdyt huoltotyöt",
                    "items": ["Moottoriöljyn vaihto", "Öljynsuodattimen vaihto", "Polttoainesuodattimen vaihto", "Jarrunesteen vaihto", "Sytytystulppien vaihto", "Moottorin ilmansuodattimen vaihto", "Raitisilmansuodattimen vaihto", "Saranoiden rasvaus"]
                },
                {
                    "title": "JARRUJÄRJESTELMÄ",
                    "items": ["Jarrupalojen kulutuspinnan tarkastus", "Jarrulevyn kunnon tarkastus", "Käsijarrun toiminnan tarkastus", "Jarruletkujen ja -putkien tarkastus"]
                },
                {
                    "title": "NESTEET",
                    "items": ["Öljyjen ja nesteiden määrän tarkastus", "Tuulilasinpesunesteen tarkastus ja täyttö", "Ohjaustehostinnesteen tarkastus", "Jäähdytysnesteen tarkastus"]
                },
                {
                    "title": "RENKAAT JA PYÖRÄT",
                    "items": ["Renkaiden kunnon tarkastus", "Renkaiden ilmanpaineen tarkistus", "Vararenkaan kunnon tarkastus"]
                },
                {
                    "title": "VALOT JA SÄHKÖLAITTEET",
                    "items": ["Ulkovalojen tarkastus", "Sisävalojen tarkastus", "Akun kunnon tarkistus", "Laturin ja hihnan tarkastus"]
                },
                {
                    "title": "ALUSTA JA JOUSITUS",
                    "items": ["Iskunvaimentimien ja jousituksen tarkastus", "Ohjauslaitteiston tarkastus", "Vetokoukun ja pohjan tarkastus"]
                }
            ]
        }
        c.execute("INSERT INTO config (key, value) VALUES (?, ?)", ('maintenance_items', json.dumps(default_items)))

    # Default Shop Settings
    c.execute("SELECT value FROM config WHERE key='shop_settings'")
    if not c.fetchone():
        default_settings = {
            "company_text": "Autokorjaamo Oy\nKorjaamokuja 1\n00100 Helsinki\nY-tunnus: 123456-7",
            "hide_na_in_print": False,
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

        password = data.get('password', '')
        if not isinstance(password, str):
            password = ''

        auth_config = get_auth_config()
        if not (auth_config.get('hash') and auth_config.get('salt')):
            self.send_json(200, {'status': 'not_required', 'password_enabled': False})
            return

        if not verify_password(password, auth_config):
            self.send_json(403, {'status': 'invalid_password', 'auth_required': True})
            return

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
                        wildcard = f"%{search_q}%"
                        sql_base += " AND (customer_name LIKE ? OR license_plate LIKE ? OR vin LIKE ? OR data LIKE ?)"
                        params = [wildcard, wildcard, wildcard, wildcard]
                    
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
                    if plate:
                        c.execute("SELECT vin, data FROM reports WHERE license_plate LIKE ? ORDER BY created_at DESC LIMIT 1", (plate,))
                        row = c.fetchone()
                        if row:
                            full_data = json.loads(row['data'])
                            response_data = {
                                'vin': row['vin'],
                                'vehicle_model': full_data.get('vehicle_model', ''),
                                'engine_code': full_data.get('engine_code', ''),
                                'registered_date': full_data.get('registered_date', '')
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
