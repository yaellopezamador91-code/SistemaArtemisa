from __future__ import annotations
import html, io, secrets, hashlib, sqlite3, string, urllib.parse, zipfile
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.sax.saxutils import escape
from http.cookies import SimpleCookie
ROOT=Path(__file__).resolve().parent
DB=ROOT/'atemisa.db'
SESSIONS={}
HOST='127.0.0.1'; PORT=8000

def connect():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def initialize():
 with connect() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','reception')),salt TEXT NOT NULL,pwhash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY,name TEXT NOT NULL,age INTEGER NOT NULL,phone TEXT NOT NULL,emergency_name TEXT NOT NULL,emergency_phone TEXT NOT NULL,qr TEXT UNIQUE NOT NULL,status TEXT NOT NULL DEFAULT 'Activo',due TEXT,class_credits INTEGER NOT NULL DEFAULT 0,birth_date TEXT,payment_mode TEXT NOT NULL DEFAULT 'Mensualidad',scholarship_pct INTEGER NOT NULL DEFAULT 0,schedule TEXT NOT NULL DEFAULT '',training_days TEXT NOT NULL DEFAULT '',created TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,student_id INTEGER NOT NULL REFERENCES students(id),cents INTEGER NOT NULL,concept TEXT NOT NULL,paid TEXT NOT NULL,cashier INTEGER NOT NULL REFERENCES users(id),receipt TEXT UNIQUE NOT NULL,base_cents INTEGER NOT NULL DEFAULT 0,discount_pct INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY,student_id INTEGER NOT NULL REFERENCES students(id),checked TEXT NOT NULL,method TEXT NOT NULL,receiver INTEGER NOT NULL REFERENCES users(id),allowed INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),csrf TEXT NOT NULL,expires TEXT NOT NULL,last_seen TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS prices(mode TEXT PRIMARY KEY,cents INTEGER NOT NULL DEFAULT 0);
  CREATE INDEX IF NOT EXISTS ix_payday ON payments(paid); CREATE INDEX IF NOT EXISTS ix_attday ON attendance(checked);''')
  for migration in ("ALTER TABLE students ADD COLUMN class_credits INTEGER NOT NULL DEFAULT 0","ALTER TABLE students ADD COLUMN birth_date TEXT","ALTER TABLE students ADD COLUMN payment_mode TEXT NOT NULL DEFAULT 'Mensualidad'","ALTER TABLE students ADD COLUMN scholarship_pct INTEGER NOT NULL DEFAULT 0","ALTER TABLE students ADD COLUMN schedule TEXT NOT NULL DEFAULT ''","ALTER TABLE students ADD COLUMN training_days TEXT NOT NULL DEFAULT ''","ALTER TABLE payments ADD COLUMN base_cents INTEGER NOT NULL DEFAULT 0","ALTER TABLE payments ADD COLUMN discount_pct INTEGER NOT NULL DEFAULT 0"):
   try: c.execute(migration)
   except sqlite3.OperationalError: pass
  for mode in ('Mensualidad','Clase individual','Fin de semana','Clase personalizada'):
   c.execute('INSERT OR IGNORE INTO prices(mode,cents) VALUES(?,?)',(mode,30000 if mode=='Clase personalizada' else 0))
def now(): return datetime.now().astimezone()
def stamp(): return now().isoformat(timespec='seconds')
def age_from_birth(value):
 if not value: return None
 born=date.fromisoformat(value); today=date.today()
 return today.year-born.year-((today.month,today.day)<(born.month,born.day))
def esc(x): return html.escape(str(x if x is not None else ''),quote=True)
def money(c): return '$'+format(c/100,',.2f')
def hashpass(p,salt=None):
 salt=salt or secrets.token_bytes(16); return salt.hex(),hashlib.pbkdf2_hmac('sha256',p.encode(),salt,240000).hex()
def validpass(p,s,d): return secrets.compare_digest(hashpass(p,bytes.fromhex(s))[1],d)
def access(s):
 if s['status'] in ('Baja','Congelado/Suspendido'): return 'Acceso denegado','red'
 if s['status']=='Becado': return 'Permitido · becado','green'
 if not s['due']: return 'Sin fecha · acceso restringido','red'
 due=date.fromisoformat(s['due']); today=date.today()
 if today<=due: return ('Próximo a vencer','amber') if (due-today).days<=7 else ('Vigente','green')
 days=(today-due).days
 if days<=4: return f'Tolerancia · día {days}','amber'
 return 'Vencido · acceso restringido','red'

TRAINING_DAYS={'MWF':{0,2,4},'TTS':{1,3,5},'WEEKEND':{5,6}}
TRAINING_LABELS={'MWF':'Lunes, miércoles y viernes','TTS':'Martes, jueves y sábado','WEEKEND':'Fines de semana (sábado y domingo)'}
def training_day_allowed(s,day):
 if s['payment_mode'] not in ('Mensualidad','Fin de semana'): return True
 return s['training_days'] in TRAINING_DAYS and day in TRAINING_DAYS[s['training_days']]
def parse_money(x):
 n=round(float(x.replace('$','').replace(',',''))*100)
 if n<=0: raise ValueError('El monto debe ser mayor a cero.')
 return n

def qr_matrix(payload):
 bts=payload.encode()
 if len(bts)>17: raise ValueError('Identificador QR demasiado largo')
 bits=[0,1,0,0]+[(len(bts)>>i)&1 for i in range(7,-1,-1)]
 for b in bts: bits.extend((b>>i)&1 for i in range(7,-1,-1))
 bits.extend([0]*min(4,152-len(bits)))
 while len(bits)%8: bits.append(0)
 words=[]
 for i in range(0,len(bits),8):
  v=0
  for bit in bits[i:i+8]: v=(v<<1)|bit
  words.append(v)
 pads=[236,17]; pi=0
 while len(words)<19: words.append(pads[pi%2]); pi+=1
 def mul(x,y):
  z=0
  for _ in range(8):
   if y&1: z^=x
   y>>=1; x<<=1
   if x&256: x^=0x11D
  return z
 exp=[0]*512; x=1
 for i in range(255): exp[i]=x; x=mul(x,2)
 for i in range(255,512): exp[i]=exp[i-255]
 gen=[1]
 for i in range(7):
  nxt=[0]*(len(gen)+1)
  for j,v in enumerate(gen): nxt[j]^=v; nxt[j+1]^=mul(v,exp[i])
  gen=nxt
 rem=[0]*7
 for v in words:
  factor=v^rem[0]; rem=rem[1:]+[0]
  for j,g in enumerate(gen[1:]): rem[j]^=mul(g,factor)
 data=[]
 for v in words+rem: data.extend((v>>i)&1 for i in range(7,-1,-1))
 n=21; m=[[None]*n for _ in range(n)]
 def finder(r0,c0):
  for dr in range(-1,8):
   for dc in range(-1,8):
    r,c=r0+dr,c0+dc
    if 0<=r<n and 0<=c<n:
     on=0<=dr<=6 and 0<=dc<=6 and (dr in (0,6) or dc in (0,6) or (2<=dr<=4 and 2<=dc<=4))
     m[r][c]=int(on)
 finder(0,0); finder(0,14); finder(14,0)
 for i in range(8,13): m[6][i]=int(i%2==0); m[i][6]=int(i%2==0)
 d=8; v=d<<10
 for i in range(14,9,-1):
  if (v>>i)&1: v^=0x537<<(i-10)
 fmt=((d<<10)|(v&1023))^0x5412
 for i in range(6): m[i][8]=(fmt>>i)&1
 m[7][8]=(fmt>>6)&1; m[8][8]=(fmt>>7)&1; m[8][7]=(fmt>>8)&1
 for i in range(9,15): m[8][14-i]=(fmt>>i)&1
 for i in range(8): m[8][20-i]=(fmt>>i)&1
 for i in range(8,15): m[6+i][8]=(fmt>>i)&1
 m[13][8]=1; idx=0; col=20; up=True
 while col>0:
  if col==6: col-=1
  for r in (range(20,-1,-1) if up else range(21)):
   for c in (col,col-1):
    if m[r][c] is None:
     bit=data[idx] if idx<len(data) else 0; idx+=1; m[r][c]=bit^int((r+c)%2==0)
  up=not up; col-=2
 return m
def qr_svg(payload):
 m=qr_matrix(payload); paths=[]
 for r,row in enumerate(m):
  for c,v in enumerate(row):
   if v: paths.append(f'M{c},{r}h1v1h-1z')
 return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-4 -4 29 29" width="260" height="260"><rect x="-4" y="-4" width="29" height="29" fill="white"/><path fill="#111" d="'+''.join(paths)+'"/></svg>'

def xlsx(sheets):
 def col(n):
  out=''
  while n: n,r=divmod(n-1,26); out=chr(65+r)+out
  return out
 def worksheet(rows):
  xmlrows=[]
  for ri,row in enumerate(rows,1):
   cells=[]
   for ci,val in enumerate(row,1):
    cells.append(f'<c r="{col(ci)}{ri}" t="inlineStr"><is><t xml:space="preserve">{escape(str(val if val is not None else ""))}</t></is></c>')
   xmlrows.append(f'<row r="{ri}">'+''.join(cells)+'</row>')
  return '<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'+''.join(xmlrows)+'</sheetData></worksheet>'
 content_types='<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
 rels='<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
 sheet_tags=[]; workbook_rels=[]; files={}
 for index,(name,rows) in enumerate(sheets,1):
  content_types+=f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
  sheet_tags.append(f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>')
  workbook_rels.append(f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>')
  files[f'xl/worksheets/sheet{index}.xml']=worksheet(rows)
 content_types+='</Types>'
 rels+='</Relationships>'
 files.update({
  '[Content_Types].xml':content_types,
  '_rels/.rels':'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
  'xl/workbook.xml':'<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'+''.join(sheet_tags)+'</sheets></workbook>',
  'xl/_rels/workbook.xml.rels':rels
 })
 out=io.BytesIO()
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for name,value in files.items(): z.writestr(name,value)
 return out.getvalue()
class App(BaseHTTPRequestHandler):
 server_version='Atemisa/1.0'
 def log_message(self,fmt,*args): print(now().strftime('%H:%M:%S'),fmt%args)
 def cookies(self):
  c=SimpleCookie(); c.load(self.headers.get('Cookie','')); return {k:v.value for k,v in c.items()}
 def auth(self):
  sid=self.cookies().get('atemisa','')
  if not sid: return None
  token_hash=hashlib.sha256(sid.encode()).hexdigest()
  with connect() as c:
   record=c.execute('SELECT * FROM sessions WHERE token_hash=?',(token_hash,)).fetchone()
   if not record: return None
   if record['expires']<now().isoformat(timespec='seconds'):
    c.execute('DELETE FROM sessions WHERE token_hash=?',(token_hash,)); return None
   user=c.execute('SELECT * FROM users WHERE id=? AND active=1',(record['user_id'],)).fetchone()
   if not user:
    c.execute('DELETE FROM sessions WHERE token_hash=?',(token_hash,)); return None
   expiry=(now()+timedelta(days=30)).isoformat(timespec='seconds')
   c.execute('UPDATE sessions SET expires=?,last_seen=? WHERE token_hash=?',(expiry,stamp(),token_hash))
  return user,sid,record['csrf']
 def session_cookie(self,sid):
  secure='; Secure' if self.headers.get('X-Forwarded-Proto','').lower()=='https' else ''
  return f'atemisa={sid}; Max-Age=2592000; HttpOnly; SameSite=Lax; Path=/{secure}'
 def send(self,body,status=200,ctype='text/html; charset=utf-8',headers=None):
  data=body.encode() if isinstance(body,str) else body
  self.send_response(status); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY'); self.send_header('Referrer-Policy','same-origin'); self.send_header('Cache-Control','no-store')
  for k,v in (headers or {}).items(): self.send_header(k,v)
  self.end_headers(); self.wfile.write(data)
 def go(self,url='/',cookie=None):
  self.send_response(303); self.send_header('Location',url); self.send_header('Cache-Control','no-store')
  if cookie: self.send_header('Set-Cookie',cookie)
  self.end_headers()
 def form(self):
  size=min(int(self.headers.get('Content-Length','0')),100000); raw=self.rfile.read(size).decode('utf-8','replace')
  return {k:v[-1] for k,v in urllib.parse.parse_qs(raw,keep_blank_values=True).items()}
 def page(self,title,body,user=None):
  head=''
  if user:
   csrf=self.auth()[2]
   logo='<img class="brand-logo" src="/static/logo.png" alt="">' if (ROOT/'static/logo.png').exists() else ('<img class="brand-logo" src="/static/logo.svg" alt="">' if (ROOT/'static/logo.svg').exists() else '')
   head=f'<header class="top"><div class="brand">{logo} ARTEMISA <small>Muay Thai · Gestión y control de acceso</small></div><div>{esc(user["name"])} · {"Administrador" if user["role"]=="admin" else "Recepción"} <form style="display:inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="secondary">Salir</button></form></div></header>'
  icon='/static/logo.png' if (ROOT/'static/logo.png').exists() else ('/static/logo.svg' if (ROOT/'static/logo.svg').exists() else '')
  favicon=f'<link rel="icon" href="{icon}">' if icon else ''
  return f'<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · ARTEMISA</title><link rel="stylesheet" href="/static/app.css">{favicon}</head><body>{head}<main class="wrap">{body}</main></body></html>'
 def login(self,error=''):
  with connect() as c: n=c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']
  if n==0:
   body='<h1>Crear administrador</h1><p class="muted">Configura la cuenta inicial. Usa una contraseña de al menos 12 caracteres.</p><form class="form" method="post" action="/setup"><div class="full"><label>Nombre</label><input name="name" required maxlength="80"></div><div class="full"><label>Contraseña</label><input name="password" type="password" required minlength="12"></div><div class="full"><label>Confirmar contraseña</label><input name="confirm" type="password" required minlength="12"></div><button class="full">Crear administrador</button></form>'
  else:
   body='<h1>Iniciar sesión</h1><p class="muted">Acceso para administración y recepción.</p><form class="form" method="post" action="/login"><div class="full"><label>Nombre</label><input name="name" required autocomplete="username"></div><div class="full"><label>Tu contraseña o PIN personal</label><input name="password" type="password" required autocomplete="current-password"></div><button class="full">Entrar</button></form><p class="quiet">.</p>'
  if error: body=f'<div class="flash err">{esc(error)}</div>'+body
  logo='<img class="brand-logo" src="/static/logo.png" alt="">' if (ROOT/'static/logo.png').exists() else ('<img class="brand-logo" src="/static/logo.svg" alt="">' if (ROOT/'static/logo.svg').exists() else '')
  icon='/static/logo.png' if (ROOT/'static/logo.png').exists() else ('/static/logo.svg' if (ROOT/'static/logo.svg').exists() else '')
  favicon=f'<link rel="icon" href="{icon}">' if icon else ''
  return f'<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acceso · ARTEMISA</title><link rel="stylesheet" href="/static/app.css">{favicon}</head><body><main class="login"><div class="panel"><div class="login-brand">{logo} ARTEMISA MUAY THAI</div>{body}<p class="quiet">Sistema local · ARTEMISA Muay Thai</p></div></main></body></html>'
 def do_GET(self):
  route=urllib.parse.urlsplit(self.path); path=route.path; auth=self.auth()
  if path=='/static/app.css': return self.send((ROOT/'static/app.css').read_text(encoding='utf-8'),ctype='text/css; charset=utf-8')
  if path in ('/static/logo.png','/static/logo.svg'):
   logo_path=ROOT/'static'/Path(path).name
   if not logo_path.exists(): return self.send('No encontrado',404)
   return self.send(logo_path.read_bytes(),ctype='image/png' if logo_path.suffix=='.png' else 'image/svg+xml')
  if not auth: return self.send(self.login())
  user,sid,token=auth
  if path=='/': return self.dashboard(user,token,urllib.parse.parse_qs(route.query))
  if path=='/staff':
   if user['role']!='admin': return self.send('Acceso denegado',403)
   q=urllib.parse.parse_qs(route.query).get('id',[''])[0]
   with connect() as c: member=c.execute("SELECT id,name,active FROM users WHERE id=? AND role='reception'",(q,)).fetchone()
   if not member: return self.send('Cuenta no encontrada',404)
   return self.staff_editor(user,token,member)
  if path=='/student':
   q=urllib.parse.parse_qs(route.query).get('id',[''])[0]
   with connect() as c: student=c.execute('SELECT * FROM students WHERE id=?',(q,)).fetchone()
   if not student: return self.send('No encontrado',404)
   return self.student_editor(user,token,student)
  if path=='/qr':
   q=urllib.parse.parse_qs(route.query).get('id',[''])[0]
   with connect() as c: s=c.execute('SELECT * FROM students WHERE id=?',(q,)).fetchone()
   if not s: return self.send('No encontrado',404)
   label,cls=access(s); body=f'<div class="panel" style="text-align:center"><h1>{esc(s["name"])}</h1>{qr_svg("AT"+s["qr"])}<p>Escanea este código para registrar asistencia.</p><p><span class="badge {cls}">{esc(label)}</span></p><button class="no-print" onclick="window.print()">Imprimir QR</button> <a class="btn secondary no-print" href="/qr.svg?id={s["id"]}">Descargar QR (SVG)</a> <a class="btn secondary no-print" href="/#alumnos">Volver a alumnos</a></div>'
   body=body.replace('<a class="btn secondary no-print" href="/#alumnos">Volver a alumnos</a>',f'<a class="btn secondary no-print" href="/credential?id={s["id"]}">Credencial</a> <a class="btn secondary no-print" href="/#alumnos">Volver a alumnos</a>')
   return self.send(self.page('Código QR',body,user))
  if path=='/credential':
   q=urllib.parse.parse_qs(route.query).get('id',[''])[0]
   with connect() as c: s=c.execute('SELECT * FROM students WHERE id=?',(q,)).fetchone()
   if not s: return self.send('No encontrado',404)
   schedule=s['schedule'] or TRAINING_LABELS.get(s['training_days'],'Por definir')
   logo='<img class="credential-logo" src="/static/logo.png" alt="">' if (ROOT/'static/logo.png').exists() else ('<img class="credential-logo" src="/static/logo.svg" alt="">' if (ROOT/'static/logo.svg').exists() else '')
   body=f'<div class="credential-wrap"><article class="credential"><header class="credential-head">{logo}<div><strong>ARTEMISA</strong><small>MUAY THAI · CREDENCIAL</small></div></header><div class="credential-content"><div class="photo-slot"><span>FOTO<br>INFANTIL<br>2.5 × 3 cm</span></div><div class="credential-data"><h1>{esc(s["name"])}</h1><p><b>Horario</b><span>{esc(schedule)}</span></p><p><b>Tutor</b><span>{esc(s["emergency_name"])}</span></p><p><b>Contacto del tutor</b><span>{esc(s["emergency_phone"])}</span></p></div><div class="credential-qr">{qr_svg("AT"+s["qr"])}</div></div><footer>Identificación de alumno · Presentar al ingresar</footer></article><div class="actions no-print credential-actions"><button onclick="window.print()">Imprimir credencial</button><a class="btn secondary" href="/qr?id={s["id"]}">Volver al QR</a> <a class="btn secondary" href="/#alumnos">Volver al panel</a></div></div>'
   return self.send(self.page('Credencial',body,user))
  if path=='/qr.svg':
   q=urllib.parse.parse_qs(route.query).get('id',[''])[0]
   with connect() as c: s=c.execute('SELECT qr,name FROM students WHERE id=?',(q,)).fetchone()
   if not s: return self.send('No encontrado',404)
   svg=qr_svg('AT'+s['qr'])
   return self.send(svg,ctype='image/svg+xml; charset=utf-8',headers={'Content-Disposition':'attachment; filename="atemisa-qr.svg"'})
  if path=='/receipt':
   q=urllib.parse.parse_qs(route.query).get('id',[''])[0]
   with connect() as c: p=c.execute('SELECT p.*,s.name student,u.name AS cashier_name FROM payments p JOIN students s ON s.id=p.student_id JOIN users u ON u.id=p.cashier WHERE p.id=?',(q,)).fetchone()
   if not p: return self.send('Recibo no encontrado',404)
   discount_line=f'<dt>Precio base</dt><dd>{money(p["base_cents"])}</dd><dt>Beca aplicada</dt><dd>{p["discount_pct"]}%</dd>' if p['discount_pct'] else ''
   body=f'<article class="receipt"><img class="receipt-watermark" src="/static/logo.png" alt=""><p class="muted">ARTEMISA MUAY THAI</p><h1>Recibo de pago</h1><p>Folio <strong>{esc(p["receipt"])}</strong></p><hr><dl><dt>Alumno</dt><dd>{esc(p["student"])}</dd><dt>Concepto</dt><dd>{esc(p["concept"])}</dd>{discount_line}<dt>Total pagado</dt><dd>{money(p["cents"])} MXN</dd><dt>Fecha</dt><dd>{esc(datetime.fromisoformat(p["paid"]).strftime("%d/%m/%Y %H:%M"))}</dd><dt>Recibió</dt><dd>{esc(p["cashier_name"])}</dd></dl><p class="quiet">Comprobante del pago.</p><div class="actions no-print"><button onclick="window.print()">Imprimir / guardar PDF</button><a class="btn secondary" href="/">Volver</a></div></article>'
   return self.send(self.page('Recibo',body,user))
  if path=='/export.xlsx':
   if user['role']!='admin': return self.send('Acceso denegado',403)
   period=urllib.parse.parse_qs(route.query).get('period',['weekly'])[0]
   today=date.today()
   end=today.isoformat()
   if period=='weekly':
    start=(today-timedelta(days=today.weekday())).isoformat()
    label='semanal'
   elif period=='monthly':
    start=today.replace(day=1).isoformat()
    label='mensual'
   elif period=='all':
    start=None
    label='completo'
   else:
    return self.send('Periodo de reporte no válido',400)
   payments_where=' WHERE substr(p.paid,1,10)>=? AND substr(p.paid,1,10)<=?' if start else ''
   attendance_where=' WHERE substr(a.checked,1,10)>=? AND substr(a.checked,1,10)<=?' if start else ''
   params=(start,end) if start else ()
   with connect() as c:
    payments=c.execute('SELECT p.paid,p.receipt,s.name,p.concept,p.cents,p.base_cents,p.discount_pct,u.name cashier FROM payments p JOIN students s ON s.id=p.student_id JOIN users u ON u.id=p.cashier'+payments_where+' ORDER BY p.paid,p.id',params).fetchall()
    attendance=c.execute('SELECT a.checked,s.name,a.method,a.allowed,u.name receiver_name FROM attendance a JOIN students s ON s.id=a.student_id JOIN users u ON u.id=a.receiver'+attendance_where+' ORDER BY a.checked,a.id',params).fetchall()
   payment_rows=[['Fecha y hora','Folio','Alumno','Concepto','Monto pagado MXN','Precio base MXN','Descuento %','Recepcionista']]
   for r in payments:
    base=r['base_cents'] or r['cents']
    payment_rows.append([datetime.fromisoformat(r['paid']).strftime('%d/%m/%Y %H:%M'),r['receipt'],r['name'],r['concept'],f'{r["cents"]/100:.2f}',f'{base/100:.2f}',r['discount_pct'],r['cashier']])
   attendance_rows=[['Fecha y hora','Alumno','Método','Resultado','Registró']]
   for r in attendance:
    attendance_rows.append([datetime.fromisoformat(r['checked']).strftime('%d/%m/%Y %H:%M'),r['name'],r['method'],'Permitido' if r['allowed'] else 'Denegado',r['receiver_name']])
   data=xlsx([('Asistencias',attendance_rows),('Pagos',payment_rows)])
   return self.send(data,ctype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',headers={'Content-Disposition':f'attachment; filename="atemisa-reporte-{label}.xlsx"'})
  return self.send('No encontrado',404)
 def student_editor(self,user,csrf,student):
  modes=('Mensualidad','Clase individual','Fin de semana')
  mode_options=''.join('<option '+('selected' if student['payment_mode']==m else '')+'>'+esc(m)+'</option>' for m in modes)
  regular=('Activo','Pago pendiente','Congelado/Suspendido','Baja')
  status_values=regular+('Becado',) if user['role']=='admin' or student['status']=='Becado' else regular
  status_options=''.join('<option '+('selected' if student['status']==st else '')+'>'+esc(st)+'</option>' for st in status_values)
  scholarship=''
  if user['role']=='admin': scholarship=f'<div><label>Porcentaje de beca (0 a 100%)</label><input name="scholarship_pct" type="number" min="0" max="100" value="{student["scholarship_pct"]}"></div>'
  elif student['status']=='Becado': scholarship='<p class="quiet">La beca y su porcentaje solo los puede cambiar el administrador.</p>'
  birth=student['birth_date'] or ''; schedule=student['schedule'] or ''
  day_options='<option value="">Selecciona días</option>'+''.join(f'<option value="{key}" {"selected" if student["training_days"]==key else ""}>{TRAINING_LABELS[key]}</option>' for key in ('MWF','TTS'))
  body=f'<div class="panel"><h1 class="title">Editar alumno</h1><p class="muted">Actualiza datos de contacto, modalidad de pago y estado.</p><form class="form" method="post" action="/student/edit"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{student["id"]}"><div><label>Nombre completo</label><input name="name" required value="{esc(student["name"])}"></div><div><label>Fecha de nacimiento</label><input name="birth_date" type="date" required value="{esc(birth)}"></div><div><label>Celular</label><input name="phone" required value="{esc(student["phone"])}"></div><div><label>Contacto de emergencia</label><input name="emergency_name" required value="{esc(student["emergency_name"])}"></div><div><label>Teléfono de emergencia</label><input name="emergency_phone" required value="{esc(student["emergency_phone"])}"></div><div><label>Modalidad de pago</label><select id="edit-payment-mode" name="payment_mode">{mode_options}</select></div><div id="edit-training-days-wrap" class="full" {"" if student["payment_mode"]=="Mensualidad" else "hidden"}><label>Días permitidos de entrenamiento</label><select id="edit-training-days" name="training_days">{day_options}</select><small>Solo aplica a mensualidad.</small></div><div><label>Fecha límite de pago</label><input name="due" type="date" value="{esc(student["due"] or "")}"></div><div><label>Estado</label><select name="status">{status_options}</select></div>{scholarship}<div class="full actions"><button>Guardar cambios</button><a class="btn secondary" href="/#alumnos">Cancelar</a></div></form></div>'
  body+='<script>document.addEventListener("DOMContentLoaded",()=>{const m=document.getElementById("edit-payment-mode"),d=document.getElementById("edit-training-days"),w=document.getElementById("edit-training-days-wrap");function sync(){if(!m||!d)return;const monthly=m.value==="Mensualidad";if(w)w.hidden=!monthly;d.required=monthly;if(!monthly)d.value="";}m?.addEventListener("change",sync);sync();});</script>'
  return self.send(self.page('Editar alumno',body,user))
 def staff_editor(self,user,csrf,staff):
  body=f'<div class="panel"><h1 class="title">Editar cuenta de recepción</h1><p class="muted">Actualiza el nombre, la contraseña o el estado de acceso. Si dejas la contraseña vacía, se conserva la actual.</p><form class="form" method="post" action="/staff/edit"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{staff["id"]}"><div class="full"><label>Nombre de recepcionista</label><input name="name" maxlength="80" required value="{esc(staff["name"])}"></div><div class="full"><label>Nueva contraseña (mínimo 12 caracteres; opcional)</label><input name="new_password" type="password" minlength="12" autocomplete="new-password"></div><div class="full"><label>Estado de cuenta</label><select name="active"><option value="1" {"selected" if staff["active"] else ""}>Activa</option><option value="0" {"selected" if not staff["active"] else ""}>Desactivada</option></select></div><div class="full actions"><button>Guardar cuenta</button><a class="btn secondary" href="/#personal">Cancelar</a></div></form></div>'
  return self.send(self.page('Editar recepción',body,user))
 def dashboard(self,user,csrf,query):
  today=date.today().isoformat(); start=(date.today()-timedelta(days=date.today().weekday())).isoformat()
  with connect() as c:
   count=c.execute("SELECT COUNT(*) n FROM students WHERE status!='Baja'").fetchone()['n']
   income=c.execute('SELECT COALESCE(SUM(cents),0) n FROM payments WHERE substr(paid,1,10)=?',(today,)).fetchone()['n']
   weekly=c.execute('SELECT COALESCE(SUM(cents),0) n FROM payments WHERE substr(paid,1,10)>=?',(start,)).fetchone()['n']
   attends=c.execute('SELECT COUNT(*) n FROM attendance WHERE substr(checked,1,10)=? AND allowed=1',(today,)).fetchone()['n']
   students=c.execute('SELECT * FROM students ORDER BY name COLLATE NOCASE').fetchall()
   pays=c.execute('SELECT p.id,p.paid,p.cents,p.concept,p.receipt,s.name AS student,u.name AS received_by FROM payments p JOIN students s ON s.id=p.student_id JOIN users u ON u.id=p.cashier ORDER BY p.id DESC LIMIT 15').fetchall()
   ats=c.execute('SELECT a.id,a.student_id,a.checked,a.allowed,s.name AS student,u.name AS receiver_name FROM attendance a JOIN students s ON s.id=a.student_id JOIN users u ON u.id=a.receiver WHERE substr(a.checked,1,10)=? ORDER BY a.id DESC LIMIT 20',(today,)).fetchall()
   staff=c.execute("SELECT id,name,active FROM users WHERE role='reception' ORDER BY name COLLATE NOCASE").fetchall() if user['role']=='admin' else []
   prices={r['mode']:r['cents'] for r in c.execute('SELECT mode,cents FROM prices').fetchall()}
  q=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query); message=q.get('msg',[''])[0]; error=q.get('err',[''])[0]
  admin_metrics=f'<div class="grid"><div class="card"><div class="muted">Alumnos activos</div><div class="metric">{count}</div></div><div class="card"><div class="muted">Cobros de hoy</div><div class="metric">{money(income)}</div></div><div class="card"><div class="muted">Asistencias de hoy</div><div class="metric">{attends}</div></div><div class="card"><div class="muted">Ingresos de esta semana</div><div class="metric">{money(weekly)}</div></div></div>' if user['role']=='admin' else ''
  body=f'<h1 class="title">Panel de control</h1>{admin_metrics}'
  if message: body+=f'<div class="flash">{esc(message)}</div>'
  if error: body+=f'<div class="flash err">{esc(error)}</div>'
  attendance_options="".join(f'<option value="{esc(s["name"])}" label="{esc(s["phone"])}">' + f'<option value="{esc(s["phone"])}" label="{esc(s["name"])}">' for s in students if s["status"]!="Baja")
  body+=f'<section id="entrada" data-view="entrada" class="panel"><h2 class="title">Registrar asistencia</h2><form class="actions" method="post" action="/attendance"><input type="hidden" name="csrf" value="{csrf}"><input name="student_key" list="alumnos-sugeridos" placeholder="Escribe nombre o celular, o escanea QR" autocomplete="off" required><datalist id="alumnos-sugeridos">{attendance_options}</datalist><button>Registrar entrada</button></form><p class="quiet">El lector QR USB debe funcionar como teclado. El sistema aplica cuatro días de tolerancia después del vencimiento.</p></section>'
  opts=''.join(f'<option value="{s["id"]}" data-mode="{esc(s["payment_mode"])}" data-scholarship="{s["scholarship_pct"] if s["status"]=='Becado' else 0}">{esc(s["name"])} · {esc(s["phone"])}</option>' for s in students if s['status']!='Baja')
  body+=f'<section id="alumnos" data-view="alumnos" class="section"><div class="panel"><h2 class="title">Alta de alumno</h2><form id="student-form" class="form" method="post" action="/students"><input type="hidden" name="csrf" value="{csrf}"><div><label>Nombre completo</label><input name="name" maxlength="120" required></div><div><label>Fecha de nacimiento</label><input name="birth_date" type="date" required><label>Modalidad de pago</label><select id="student-payment-mode" name="payment_mode" required><option>Mensualidad</option><option>Clase individual</option><option>Fin de semana</option></select></div><div id="student-training-days-wrap"><label>Días permitidos de entrenamiento</label><select id="student-training-days" name="training_days"><option value="">Selecciona días</option><option value="MWF">Lunes, miércoles y viernes</option><option value="TTS">Martes, jueves y sábado</option></select></div><div><label>Celular</label><input name="phone" required></div><div><label>Fecha límite de pago</label><input name="due" type="date"></div><div><label>Contacto de emergencia</label><input name="emergency_name" required></div><div><label>Teléfono de emergencia</label><input name="emergency_phone" required></div><button class="full">Guardar alumno</button></form></div></section><section id="cobro" data-view="cobro" class="section"><div class="panel"><h2 class="title">Registrar cobro</h2><form class="form" method="post" action="/payments"><input type="hidden" name="csrf" value="{csrf}"><div class="full"><label>Alumno</label><select name="student_id" required><option value="">Seleccionar</option>{opts}</select></div><div><label>Monto base del cobro (MXN)</label><input id="payment-amount" name="amount" type="number" min="0.01" step="0.01" value="{prices.get('Mensualidad',0)/100 if prices.get('Mensualidad',0) else ''}" required></div><div><label>Concepto</label><select id="payment-concept" name="concept"><option data-rate="{prices.get('Mensualidad',0)/100}">Mensualidad</option><option data-rate="{prices.get('Clase individual',0)/100}">Clase individual</option><option data-rate="{prices.get('Fin de semana',0)/100}">Fin de semana</option><option data-rate="{prices.get('Clase personalizada',30000)/100}">Clase personalizada</option><option data-rate="0">Otro</option></select></div><p class="quiet full">La tarifa se precarga según el concepto y puede editarse. La mensualidad extiende 30 días y emite recibo.</p><div class="full"><label>Confirma tu contraseña para registrar el cobro</label><input type="password" name="confirm_password" autocomplete="current-password" required></div><div id="payment-summary" class="payment-summary full" aria-live="polite"><p id="payment-empty" class="payment-empty">Selecciona un alumno para calcular su total.</p><div id="payment-breakdown" hidden><div class="payment-row"><span>Tarifa base</span><strong id="payment-base">$0.00</strong></div><div id="payment-discount-row" class="payment-row"><span id="payment-discount-label">Beca aplicada</span><strong id="payment-discount">− $0.00</strong></div><div class="payment-due"><span>Total a cobrar</span><strong id="payment-total">$0.00 MXN</strong></div><p id="payment-note" class="payment-note">La beca se aplica automáticamente a mensualidades.</p></div></div><button class="full">Guardar cobro</button></form></div></section>'
  body+="""<script>document.addEventListener("DOMContentLoaded",()=>{const trainingMode=document.getElementById("student-payment-mode")||document.getElementById("edit-payment-mode"),trainingDays=document.getElementById("student-training-days")||document.getElementById("edit-training-days"),trainingWrap=document.getElementById("student-training-days-wrap")||document.getElementById("edit-training-days-wrap");function syncTrainingDays(){if(!trainingMode||!trainingDays)return;const monthly=trainingMode.value==="Mensualidad";trainingDays.required=monthly;if(trainingWrap)trainingWrap.hidden=!monthly;if(!monthly)trainingDays.value="";}trainingMode?.addEventListener("change",syncTrainingDays);syncTrainingDays();const concept=document.getElementById("payment-concept"),amount=document.getElementById("payment-amount"),student=document.querySelector('[name="student_id"]'),empty=document.getElementById("payment-empty"),breakdown=document.getElementById("payment-breakdown"),baseOut=document.getElementById("payment-base"),discountLabel=document.getElementById("payment-discount-label"),discountOut=document.getElementById("payment-discount"),discountRow=document.getElementById("payment-discount-row"),totalOut=document.getElementById("payment-total"),note=document.getElementById("payment-note");const money=cents=>"$"+(cents/100).toLocaleString("es-MX",{minimumFractionDigits:2,maximumFractionDigits:2});function update(){if(!concept||!amount||!student||!empty||!breakdown)return;const opt=student.selectedOptions[0];if(!opt||!opt.value){empty.hidden=false;breakdown.hidden=true;return;}empty.hidden=true;breakdown.hidden=false;const pct=concept.value==="Mensualidad"?Number(opt.dataset.scholarship||0):0,baseCents=Math.max(0,Math.round(Number(amount.value||0)*100)),totalCents=Math.round(baseCents*(100-pct)/100),discountCents=baseCents-totalCents;baseOut.textContent=money(baseCents);const hasScholarship=Number(opt.dataset.scholarship||0)>0,appliesScholarship=hasScholarship&&concept.value==="Mensualidad";if(discountRow)discountRow.hidden=!appliesScholarship;if(note){note.hidden=!hasScholarship;note.textContent=appliesScholarship?`Se descontó automáticamente el ${pct}% a esta mensualidad.`:"La beca se aplica únicamente a mensualidades.";}discountLabel.textContent=`Beca aplicada (${pct}%)`;discountOut.textContent="− "+money(discountCents);totalOut.textContent=money(totalCents)+" MXN";}function applyStudentRate(){const opt=student.selectedOptions[0];if(!opt||!opt.value)return;const match=[...concept.options].find(o=>o.textContent.trim()===opt.dataset.mode);if(match){concept.value=match.value;const rate=Number(match.dataset.rate);if(rate>0)amount.value=rate;}}student?.addEventListener("change",()=>{applyStudentRate();update();});concept?.addEventListener("change",()=>{const rate=Number(concept.selectedOptions[0].dataset.rate);if(rate>0)amount.value=rate;update();});amount?.addEventListener("input",update);update();const views=[...document.querySelectorAll("[data-view]")],links=[...document.querySelectorAll("[data-view-target]")];function show(key){views.forEach(v=>v.hidden=v.dataset.view!==key);links.forEach(a=>a.classList.toggle("active",a.dataset.viewTarget===key));}links.forEach(a=>a.addEventListener("click",e=>{e.preventDefault();const key=a.dataset.viewTarget;history.replaceState(null,"","#"+key);show(key);}));const initial=location.hash.slice(1);show(views.some(v=>v.dataset.view===initial)?initial:"entrada");});</script>"""
  if user['role']=='admin':
   body+=f'<section id="precios" data-view="precios" class="section panel"><h2 class="title">Tarifas editables</h2><p class="muted">Configura los importes sugeridos. Recepción puede ajustar el monto al registrar cada cobro.</p><form class="form" method="post" action="/prices"><input type="hidden" name="csrf" value="{csrf}"><div><label>Mensualidad (MXN)</label><input type="number" name="monthly" min="0" step="0.01" value="{prices.get("Mensualidad",0)/100 or ""}"></div><div><label>Clase individual (MXN)</label><input type="number" name="class_price" min="0" step="0.01" value="{prices.get("Clase individual",0)/100 or ""}"></div><div><label>Fin de semana (MXN)</label><input type="number" name="weekend" min="0" step="0.01" value="{prices.get("Fin de semana",0)/100 or ""}"></div><div><label>Clase personalizada (MXN)</label><input type="number" name="personal_class" min="0" step="0.01" value="{prices.get("Clase personalizada",30000)/100}"></div><button class="full">Guardar tarifas</button></form></section>'

  body+='<section id="lista-alumnos" data-view="alumnos" class="section panel"><h2 class="title">Alumnos y vigencia</h2><div class="scroll"><table><thead><tr><th>Alumno</th><th>Contacto</th><th>Vigencia</th><th>Acceso</th><th>QR / estado</th></tr></thead><tbody>'
  if students:
   for s in students:
    label,kind=access(s); status=''
    body+='<tr><td><strong>'+esc(s['name'])+'</strong><br><span class="muted">'+str(age_from_birth(s['birth_date']) if s['birth_date'] else s['age'])+' años · '+esc(s['payment_mode'])+' · '+esc(s['status'])+' · pases: '+str(s['class_credits'])+'</span></td><td>'+esc(s['phone'])+'<br><span class="muted">Emergencia: '+esc(s['emergency_name'])+' · '+esc(s['emergency_phone'])+'</span></td><td>'+esc(s['due'] or 'Sin fecha')+'</td><td><span class="badge '+kind+'">'+esc(label)+'</span></td><td><div class="actions"><a href="/qr?id='+str(s['id'])+'">Ver QR</a> <a href="/credential?id='+str(s['id'])+'">Credencial</a> <a href="/student?id='+str(s['id'])+'">Editar alumno</a>'+'</div></td></tr>'
  else: body+='<tr><td colspan="5">Todavía no hay alumnos.</td></tr>'
  body+='</tbody></table></div></section>'
  if user['role']=='admin':
   people=''.join('<tr><td>'+esc(x['name'])+'</td><td>'+('Activa' if x['active'] else 'Desactivada')+'</td><td><a href="/staff?id='+str(x['id'])+'">Editar</a></td></tr>' for x in staff) or '<tr><td colspan="3">No hay cuentas de recepción.</td></tr>'
   body+=f'<section id="personal" data-view="personal" class="section cols"><div class="panel"><h2 class="title">Crear cuenta de recepción</h2><p class="muted">El administrador crea la cuenta y establece la contraseña inicial. La recepcionista usará siempre estas credenciales personales para entrar.</p><form class="form" method="post" action="/staff"><input type="hidden" name="csrf" value="{csrf}"><div class="full"><label>Nombre</label><input name="name" maxlength="80" required></div><div class="full"><label>Contraseña inicial (mínimo 12 caracteres)</label><input name="password" type="password" minlength="12" required autocomplete="new-password"></div><div class="full"><label>Confirmar contraseña</label><input name="confirm" type="password" minlength="12" required autocomplete="new-password"></div><button class="full">Crear cuenta</button></form></div><div class="panel"><h2 class="title">Cuentas de recepción</h2><table><thead><tr><th>Nombre</th><th>Estado</th><th></th></tr></thead><tbody>{people}</tbody></table></div></section><section id="reporte" data-view="reporte" class="section panel"><h2 class="title">Reportes</h2><p class="muted">Cada archivo contiene pestañas de asistencias y pagos para el periodo seleccionado.</p><div class="actions"><a class="btn" href="/export.xlsx?period=weekly">Descargar reporte semanal</a><a class="btn" href="/export.xlsx?period=monthly">Descargar reporte mensual</a><a class="btn secondary" href="/export.xlsx?period=all">Descargar historial completo</a></div></section>'
  if user['role']=='admin':
   body+='<section id="actividad" data-view="actividad" class="section cols"><div class="panel"><h2 class="title">Asistencia de hoy</h2><div class="scroll"><table><thead><tr><th>Hora</th><th>Alumno</th><th>Acceso</th><th>Registró</th></tr></thead><tbody>'
   body+=''.join(f'<tr><td>{datetime.fromisoformat(a["checked"]).strftime("%H:%M")}</td><td>{esc(a["student"])}</td><td>{"Permitido" if a["allowed"] else "Denegado"}</td><td>{esc(a["receiver_name"])}</td></tr>' for a in ats) or '<tr><td colspan="4">Sin registros.</td></tr>'
   body+='</tbody></table></div></div><div class="panel"><h2 class="title">Pagos recientes</h2><div class="scroll"><table><thead><tr><th>Fecha</th><th>Alumno / concepto</th><th>Monto</th><th>Recibió</th><th></th></tr></thead><tbody>'
   body+=''.join(f'<tr><td>{datetime.fromisoformat(p["paid"]).strftime("%d/%m %H:%M")}</td><td>{esc(p["student"])}<br>{esc(p["concept"])}</td><td>{money(p["cents"])}</td><td>{esc(p["received_by"])}</td><td><a href="/receipt?id={p["id"]}">Recibo</a></td></tr>' for p in pays) or '<tr><td colspan="5">Sin cobros.</td></tr>'
   body+=f'</tbody></table></div></div></section><p class="quiet">.</p>'
  sidenav='<aside class="sidebar"><details open><summary>Navegación</summary><nav><a href="#entrada" data-view-target="entrada">Registrar asistencia</a><a href="#alumnos" data-view-target="alumnos">Alumnos</a><a href="#cobro" data-view-target="cobro">Cobros</a>'
  if user['role']=='admin': sidenav+='<details class="admin-nav" open><summary>Administrador</summary><a href="#personal" data-view-target="personal">Cuentas de recepción</a><a href="#precios" data-view-target="precios">Tarifas</a><a href="#reporte" data-view-target="reporte">Reportes</a><a href="#actividad" data-view-target="actividad">Asistencias y actividad</a></details>'
  sidenav+='</nav></details></aside>'
  body='<div class="layout">'+sidenav+'<div class="main-content">'+body+'</div></div>'
  return self.send(self.page('Panel',body,user))
 def do_POST(self):
  path=urllib.parse.urlsplit(self.path).path; data=self.form(); auth=self.auth()
  if path=='/setup':
   with connect() as c: n=c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']
   name=data.get('name','').strip(); pw=data.get('password','')
   if n: return self.go('/login')
   if not name or len(pw)<12 or pw!=data.get('confirm'): return self.send(self.login('Contraseña inválida o no coincide.'))
   salt,digest=hashpass(pw)
   with connect() as c: c.execute('INSERT INTO users(name,role,salt,pwhash,created) VALUES(?,?,?,?,?)',(name,'admin',salt,digest,stamp()))
   return self.create_session(name,pw)
  if path=='/login':
   name=data.get('name','').strip(); pw=data.get('password','')
   with connect() as c: users=c.execute('SELECT * FROM users WHERE name=? COLLATE NOCASE AND active=1',(name,)).fetchall()
   for u in users:
    if validpass(pw,u['salt'],u['pwhash']):
     return self.create_session(name,pw)
   return self.send(self.login('Nombre o contraseña incorrectos.'))
  if not auth: return self.go('/')
  user,sid,csrf=auth
  if not secrets.compare_digest(data.get('csrf',''),csrf): return self.send('Solicitud inválida. Recarga la página.',403)
  if path=='/logout':
    token_hash=hashlib.sha256(sid.encode()).hexdigest()
    with connect() as c: c.execute('DELETE FROM sessions WHERE token_hash=?',(token_hash,))
    return self.go('/', 'atemisa=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')
  try:
   if path=='/students':
    name=data.get('name','').strip(); birth=data.get('birth_date','').strip(); phone=data.get('phone','').strip(); en=data.get('emergency_name','').strip(); ep=data.get('emergency_phone','').strip(); due=data.get('due','').strip() or None; mode=data.get('payment_mode','Mensualidad'); schedule=''; training_days=data.get('training_days','')
    if not name or not phone or not en or not ep or not birth: raise ValueError('Completa los datos obligatorios del alumno.')
    age=age_from_birth(birth)
    if age is None or age<0 or age>120 or date.fromisoformat(birth)>date.today(): raise ValueError('La fecha de nacimiento no es válida.')
    if mode not in ('Mensualidad','Clase individual','Fin de semana'): raise ValueError('Modalidad de pago no válida.')
    if mode=='Mensualidad' and training_days not in ('MWF','TTS'): raise ValueError('Para mensualidad, selecciona lunes-miércoles-viernes o martes-jueves-sábado.')
    if mode=='Fin de semana': training_days='WEEKEND'
    elif mode=='Clase individual': training_days=''
    if due: date.fromisoformat(due)
    qr=''.join(secrets.choice(string.digits) for _ in range(10))
    with connect() as c:
     c.execute('INSERT INTO students(name,age,phone,emergency_name,emergency_phone,qr,status,due,payment_mode,birth_date,schedule,training_days,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(name,age,phone,en,ep,qr,'Activo',due,mode,birth,schedule,training_days,stamp()))
     student_id=c.execute('SELECT last_insert_rowid()').fetchone()[0]
    return self.go('/qr?id='+str(student_id))
   if path=='/student/edit':
    student_id=int(data.get('id','0')); name=data.get('name','').strip(); birth=data.get('birth_date','').strip(); phone=data.get('phone','').strip(); en=data.get('emergency_name','').strip(); ep=data.get('emergency_phone','').strip(); due=data.get('due','').strip() or None; mode=data.get('payment_mode',''); schedule=''; training_days=data.get('training_days','')
    if not name or not birth or not phone or not en or not ep: raise ValueError('Completa los datos obligatorios del alumno.')
    age=age_from_birth(birth)
    if age is None or age<0 or age>120 or date.fromisoformat(birth)>date.today(): raise ValueError('La fecha de nacimiento no es válida.')
    if mode not in ('Mensualidad','Clase individual','Fin de semana'): raise ValueError('Modalidad de pago no válida.')
    if mode=='Mensualidad' and training_days not in ('MWF','TTS'): raise ValueError('Para mensualidad, selecciona lunes-miércoles-viernes o martes-jueves-sábado.')
    if mode=='Fin de semana': training_days='WEEKEND'
    elif mode=='Clase individual': training_days=''
    if due: date.fromisoformat(due)
    with connect() as c:
     old=c.execute('SELECT * FROM students WHERE id=?',(student_id,)).fetchone()
     if not old: raise ValueError('No se encontró el alumno.')
     status=old['status']; pct=old['scholarship_pct']
     if user['role']=='admin':
      status=data.get('status','Activo')
      if status not in ('Activo','Pago pendiente','Becado','Congelado/Suspendido','Baja'): raise ValueError('Estado no válido.')
      pct=int(data.get('scholarship_pct','0')) if status=='Becado' else 0
      if not 0<=pct<=100: raise ValueError('El porcentaje de beca debe estar entre 0 y 100.')
     elif status!='Becado':
      status=data.get('status','Activo')
      if status not in ('Activo','Pago pendiente','Congelado/Suspendido','Baja'): raise ValueError('Estado no permitido para recepción.')
     c.execute('UPDATE students SET name=?,age=?,birth_date=?,phone=?,emergency_name=?,emergency_phone=?,due=?,payment_mode=?,status=?,scholarship_pct=?,schedule=?,training_days=? WHERE id=?',(name,age,birth,phone,en,ep,due,mode,status,pct,schedule,training_days,student_id))
    return self.go('/?msg='+urllib.parse.quote('Datos del alumno actualizados.'))
   if path=='/payments':
    confirm_password=data.get('confirm_password','')
    if not validpass(confirm_password,user['salt'],user['pwhash']):
     return self.go('/?err='+urllib.parse.quote('Contraseña incorrecta. No se registró el cobro.')+'#cobro')
    sidstudent=int(data.get('student_id','0')); base_cents=parse_money(data.get('amount','0')); concept=data.get('concept','Mensualidad')
    with connect() as c:
     s=c.execute('SELECT * FROM students WHERE id=?',(sidstudent,)).fetchone()
     if not s: raise ValueError('Selecciona un alumno válido.')
     discount_pct=s['scholarship_pct'] if concept=='Mensualidad' and s['status']=='Becado' else 0
     cents=(base_cents*(100-discount_pct)+50)//100
     receipt='ATM-'+now().strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper()
     c.execute('INSERT INTO payments(student_id,cents,concept,paid,cashier,receipt,base_cents,discount_pct) VALUES(?,?,?,?,?,?,?,?)',(sidstudent,cents,concept,stamp(),user['id'],receipt,base_cents,discount_pct))
     if concept=='Mensualidad':
      base=date.fromisoformat(s['due']) if s['due'] and date.fromisoformat(s['due'])>date.today() else date.today()
      new_due=(base+timedelta(days=30)).isoformat()
      c.execute('UPDATE students SET due=? WHERE id=?',(new_due,sidstudent))
     elif concept in ('Clase individual','Fin de semana','Clase personalizada'):
      c.execute('UPDATE students SET class_credits=class_credits+1 WHERE id=?',(sidstudent,))
     pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
    return self.go('/receipt?id='+str(pid))
   if path=='/attendance':
    key=data.get('student_key','').strip(); qrkey=key[2:] if key.startswith('AT') else key
    with connect() as c: s=c.execute('SELECT * FROM students WHERE qr=? OR phone=? OR name LIKE ? COLLATE NOCASE ORDER BY id LIMIT 1',(qrkey,key,'%'+key+'%')).fetchone()
    if not s: return self.go('/?err='+urllib.parse.quote('No se encontró el alumno.'))
    label,kind=access(s); allowed=kind!='red'; method='QR' if key.startswith('AT') else 'Búsqueda manual'
    wrong_training_day=not training_day_allowed(s,date.today().weekday())
    if wrong_training_day:
     allowed=False; label='Día no permitido · '+TRAINING_LABELS.get(s['training_days'],'sin modalidad asignada'); kind='red'
    with connect() as c:
     if not allowed and not wrong_training_day and s['status'] not in ('Baja','Congelado/Suspendido') and s['class_credits']>0:
      c.execute('UPDATE students SET class_credits=class_credits-1 WHERE id=?',(s['id'],)); allowed=True; label='Acceso por pase pagado'; kind='green'
     c.execute('INSERT INTO attendance(student_id,checked,method,receiver,allowed) VALUES(?,?,?,?,?)',(s['id'],stamp(),method,user['id'],int(allowed)))
    if not allowed: return self.go('/?err='+urllib.parse.quote(f'Acceso denegado para {s["name"]}: {label}. Se guardó el intento.'))
    return self.go('/?msg='+urllib.parse.quote(f'Entrada registrada: {s["name"]} · {label}.'))
   if path=='/prices':
    if user['role']!='admin': return self.send('Acceso denegado',403)
    values={'Mensualidad':data.get('monthly','0'),'Clase individual':data.get('class_price','0'),'Fin de semana':data.get('weekend','0'),'Clase personalizada':data.get('personal_class','300')}
    with connect() as c:
     for mode,value in values.items():
      cents=round(float(value or '0')*100)
      if cents<0: raise ValueError('La tarifa no puede ser negativa.')
      c.execute('INSERT INTO prices(mode,cents) VALUES(?,?) ON CONFLICT(mode) DO UPDATE SET cents=excluded.cents',(mode,cents))
    return self.go('/?msg='+urllib.parse.quote('Tarifas actualizadas.'))
   if path=='/staff':
    if user['role']!='admin': return self.send('Acceso denegado',403)
    name=data.get('name','').strip(); password=data.get('password',''); confirm=data.get('confirm','')
    if not name or len(password)<12 or password!=confirm: raise ValueError('Escribe el nombre y confirma una contraseña de al menos 12 caracteres.')
    with connect() as c:
     if c.execute('SELECT 1 FROM users WHERE name=? COLLATE NOCASE',(name,)).fetchone(): raise ValueError('Ya existe una cuenta con ese nombre.')
     salt,digest=hashpass(password)
     c.execute('INSERT INTO users(name,role,salt,pwhash,created) VALUES(?,?,?,?,?)',(name,'reception',salt,digest,stamp()))
    return self.go('/?msg='+urllib.parse.quote('Cuenta de recepción creada.'))
   if path=='/staff/edit':
    if user['role']!='admin': return self.send('Acceso denegado',403)
    member_id=int(data.get('id','0')); name=data.get('name','').strip(); password=data.get('new_password',''); active=int(data.get('active','0'))
    if not name or active not in (0,1): raise ValueError('Revisa el nombre y el estado de la cuenta.')
    if password and len(password)<12: raise ValueError('La nueva contraseña debe tener al menos 12 caracteres.')
    with connect() as c:
     member=c.execute("SELECT * FROM users WHERE id=? AND role='reception'",(member_id,)).fetchone()
     if not member: raise ValueError('No se encontró la cuenta de recepción.')
     if c.execute('SELECT 1 FROM users WHERE name=? COLLATE NOCASE AND id<>?',(name,member_id)).fetchone(): raise ValueError('Ya existe otra cuenta con ese nombre.')
     c.execute('UPDATE users SET name=?,active=? WHERE id=?',(name,active,member_id))
     if password:
      salt,digest=hashpass(password)
      c.execute('UPDATE users SET salt=?,pwhash=? WHERE id=?',(salt,digest,member_id))
      c.execute('DELETE FROM sessions WHERE user_id=?',(member_id,))
     elif not active: c.execute('DELETE FROM sessions WHERE user_id=?',(member_id,))
    return self.go('/?msg='+urllib.parse.quote('Cuenta de recepción actualizada.'))
   if path=='/status':
    if user['role']!='admin': return self.send('Acceso denegado',403)
    state=data.get('status','')
    if state not in ('Activo','Pago pendiente','Becado','Congelado/Suspendido','Baja'): raise ValueError('Estado no válido.')
    with connect() as c: c.execute('UPDATE students SET status=? WHERE id=?',(state,int(data.get('id','0'))))
    return self.go('/?msg='+urllib.parse.quote('Estado actualizado.'))
  except (ValueError,sqlite3.IntegrityError) as e:
   return self.go('/?err='+urllib.parse.quote(str(e) or 'No se pudo guardar el registro.'))
  return self.send('No encontrado',404)
 def create_session(self,name,pw):
  with connect() as c: users=c.execute('SELECT * FROM users WHERE name=? COLLATE NOCASE AND active=1',(name,)).fetchall()
  u=next((x for x in users if validpass(pw,x['salt'],x['pwhash'])),None)
  if not u: return self.send(self.login('No se pudo iniciar la sesión.'))
  sid=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); digest=hashlib.sha256(sid.encode()).hexdigest(); expires=(now()+timedelta(days=30)).isoformat(timespec='seconds')
  with connect() as c: c.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires,last_seen) VALUES(?,?,?,?,?)',(digest,u['id'],csrf,expires,stamp()))
  return self.go('/',self.session_cookie(sid))

def main():
 initialize(); print('Sistema ARTEMISA disponible localmente: http://127.0.0.1:8000'); print('ñam ñam ñam'); ThreadingHTTPServer((HOST,PORT),App).serve_forever()
if __name__=='__main__': main()


