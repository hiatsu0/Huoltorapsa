import http.server
import socketserver
import sqlite3
import json
import os
import urllib.parse
import uuid
import base64
import math
from datetime import datetime
import socket
import webbrowser
import threading

PORT = 8000
DB_FILE = "maintenance.db"
ATTACHMENTS_DB = "attachments.db"

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
            "accent_color": "#009eb8"
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
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        if path.startswith('/api/'):
            # Special handling for binary image data
            if path == '/api/attachment':
                self.serve_attachment(query)
                return

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            response_data = {}

            try:
                if path == '/api/config':
                    c.execute("SELECT key, value FROM config")
                    rows = c.fetchall()
                    for row in rows:
                        response_data[row['key']] = json.loads(row['value'])
                
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

                self.wfile.write(json.dumps(response_data).encode())
            except Exception as e:
                print(f"Error: {e}")
                self.wfile.write(json.dumps({'error': str(e)}).encode())
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
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))
        
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path.startswith('/api/'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

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
                            except:
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
                        response_data = {'status': 'config_updated'}

                    conn.commit()
                    conn.close()

                self.wfile.write(json.dumps(response_data).encode())
            except Exception as e:
                print(f"DB Error: {e}")
                self.wfile.write(json.dumps({'error': str(e)}).encode())
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
