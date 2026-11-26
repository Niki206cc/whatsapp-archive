import os, sqlite3, secrets, html, time
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from contextlib import closing
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import urlencode, urlsplit, parse_qs
from urllib.request import Request as URLRequest, build_opener, HTTPRedirectHandler
from pathlib import Path
import re, uuid, logging
from starlette.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, RedirectResponse, Response
import json, hashlib, threading, shutil

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
auth = HTTPBasic()
password = os.environ["ARCHIVE_PASSWORD"]
secret = os.environ["WEBHOOK_SECRET"]
if min(len(password), len(secret)) < 16:
    raise RuntimeError("Credentials must be at least 16 characters")

def db():
    c = sqlite3.connect("/data/archive.sqlite", timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, received INTEGER, kind TEXT, chat TEXT, body TEXT)")
    with c:
        cols = {row[1] for row in c.execute("PRAGMA table_info(events)")}
        if "direction" not in cols:
            c.execute("ALTER TABLE events ADD COLUMN direction TEXT")
        for name, typ in (("media_file","TEXT"),("media_type","TEXT"),("media_name","TEXT"),("media_size","INTEGER"),("media_error","TEXT")):
            if name not in cols:
                c.execute("ALTER TABLE events ADD COLUMN "+name+" "+typ)
        c.execute("CREATE INDEX IF NOT EXISTS events_chat ON events(chat,id)")
        for name in ("message_id","revoked"):
            if name not in cols:
                c.execute("ALTER TABLE events ADD COLUMN "+name+" TEXT")
        c.execute("CREATE TABLE IF NOT EXISTS contacts (chat TEXT PRIMARY KEY, name TEXT, photo BLOB, mime TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS contact_refresh (chat TEXT PRIMARY KEY, attempted INTEGER)")
    return c

def authorized(c: HTTPBasicCredentials = Depends(auth)):
    if not (secrets.compare_digest(c.username.encode(), b"admin") and secrets.compare_digest(c.password.encode(), password.encode())):
        raise HTTPException(401, headers={"WWW-Authenticate":"Basic"})

MEDIA = Path("/data/media")
MEDIA.mkdir(exist_ok=True)
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def save_media(p):
    if not p.get("hasMedia"):
        return (None, None, None, None, None)
    m = p.get("media") or {}
    target = MEDIA / uuid.uuid4().hex
    try:
        u = urlsplit(m.get("url") or "")
        if not re.fullmatch(r"/api/files/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", u.path) or ".." in u.path:
            raise ValueError("URL allegato non valido")
        key = os.environ.get("WAHA_API_KEY")
        if not key:
            raise ValueError("WAHA_API_KEY mancante")
        req = URLRequest("http://waha:3000"+u.path, headers={"X-Api-Key":key})
        size = 0
        with build_opener(NoRedirect()).open(req, timeout=30) as response, target.open("wb") as f:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 100*1024*1024:
                    raise ValueError("Limite 100 MiB")
                f.write(chunk)
        return (target.name, str(m.get("mimetype") or "application/octet-stream"), str(m.get("filename") or u.path.rsplit("/",1)[-1]), size, None)
    except Exception as e:
        target.unlink(missing_ok=True)
        logging.warning("Media download failed: %s", type(e).__name__)
        return (None,None,None,None,"Allegato non acquisito")

@app.get("/media/{file_id}")
def media_file(file_id: str, download: bool = False, _: None = Depends(authorized)):
    if not re.fullmatch(r"[a-f0-9]{32}",file_id):
        raise HTTPException(404)
    with closing(db()) as c:
        row = c.execute("SELECT media_type,media_name FROM events WHERE media_file=?", (file_id,)).fetchone()
    if not row or not (MEDIA/file_id).is_file():
        raise HTTPException(404)
    safe = row[0].split(";")[0] in ("image/jpeg","image/png","image/webp","image/gif","video/mp4","audio/ogg","audio/mpeg","audio/mp4","audio/wav","video/webm")
    return FileResponse(MEDIA/file_id, media_type=row[0] if safe else "application/octet-stream", filename=row[1], content_disposition_type="inline" if safe and not download else "attachment", headers={"X-Content-Type-Options":"nosniff","Cache-Control":"no-store"})

@app.post("/webhook")
async def webhook(request: Request):
    if not secrets.compare_digest(request.headers.get("X-Archive-Secret","").encode(), secret.encode()):
        raise HTTPException(403)
    raw = await request.body()
    if len(raw) > 2_000_000:
        raise HTTPException(413)
    event = await request.json()
    if not isinstance(event, dict):
        raise HTTPException(400)
    kind = event.get("event")
    if kind not in ("message.any", "session.status", "message.revoked"):
        return {"ignored": True}
    p = event.get("payload") or {}
    if not isinstance(p, dict):
        raise HTTPException(400)
    chat = p.get("to") if p.get("fromMe") else p.get("from")
    key = (p.get("_data") or {}).get("key") or {}
    chat = key.get("remoteJidAlt") or key.get("remoteJid") or chat or p.get("from")
    chat = str(chat or "").replace("@s.whatsapp.net","@c.us")
    if kind == "message.revoked":
        before = p.get("before") or {}
        after = p.get("after") or {}
        mid = p.get("revokedMessageId") or before.get("id")
        matched = 0
        if isinstance(mid,str) and mid:
            with closing(db()) as c,c:
                rows = c.execute("SELECT id,message_id FROM events WHERE kind='message.any' AND message_id IS NOT NULL").fetchall()
                candidates = [rid for rid, stored in rows if stored == mid or (stored.split("_",3)[2] == mid if len(stored.split("_",3)) >= 3 else False)]
                if len(candidates)==1:
                    matched = c.execute("UPDATE events SET revoked=? WHERE id=?",(str(int(time.time())),candidates[0])).rowcount
        logging.warning("Revoke event: original_id_present=%s matched=%s",bool(mid),matched)
        return {"ok":True}
    attachment = await run_in_threadpool(save_media,p) if kind == "message.any" else (None,)*5
    body = p.get("body") if kind == "message.any" else p.get("status")
    with closing(db()) as c, c:
        push = (p.get("_data") or {}).get("pushName")
        if kind=="message.any" and not p.get("fromMe") and not chat.endswith("@g.us") and isinstance(push,str) and push:
            c.execute("INSERT OR IGNORE INTO contacts(chat,name) VALUES(?,?)",(chat,push[:200]))
        c.execute("INSERT INTO events(received,kind,chat,body,direction,media_file,media_type,media_name,media_size,media_error,message_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(int(time.time()),kind,str(chat or ""),str(body or ""), ("out" if p.get("fromMe") else "in") if kind == "message.any" else None, *attachment,str(p.get('id') or '')))
    if kind=="message.any":
        contact_wakeup.set()
    return {"ok": True}


def esc(v):
    return html.escape(str(v or ""), quote=True)


def csrf():
    return hashlib.sha256((secret+":local:"+password).encode()).hexdigest()

async def form_data(request):
    raw=await request.body()
    if len(raw)>100000:
        raise HTTPException(413)
    data=parse_qs(raw.decode(),keep_blank_values=True)
    if not secrets.compare_digest(data.get("token",[""])[0],csrf()):
        raise HTTPException(403)
    return data

@app.post("/delete")
async def delete_local(request: Request, _: None = Depends(authorized)):
    data=await form_data(request)
    chat=data.get("chat",[""])[0]
    ids=[int(x) for x in data.get("ids",[]) if x.isdecimal()][:300]
    whole=data.get("whole",[""])[0]=="1"
    if whole and chat:
        where,args="kind='message.any' AND chat=?",[chat]
    elif ids:
        where,args="kind='message.any' AND id IN ("+",".join("?" for _ in ids)+")",ids
    else:
        raise HTTPException(400)
    with closing(db()) as c,c:
        files=c.execute("SELECT media_file FROM events WHERE "+where,args).fetchall()
        c.execute("DELETE FROM events WHERE "+where,args)
        for (f,) in files:
            if f and re.fullmatch(r"[a-f0-9]{32}",f) and not c.execute("SELECT 1 FROM events WHERE media_file=?",(f,)).fetchone():
                (MEDIA/f).unlink(missing_ok=True)
    return RedirectResponse("/?"+urlencode({"chat":chat}) if chat and not whole else "/",303)

def waha_json(path,params):
    req=URLRequest("http://waha:3000"+path+"?"+urlencode(params),headers={"X-Api-Key":os.environ.get("WAHA_API_KEY","")})
    with build_opener(NoRedirect()).open(req,timeout=10) as res:
        return json.loads(res.read(4000000))

@app.post("/contacts/refresh")
async def refresh_contacts(request: Request, _: None = Depends(authorized)):
    await form_data(request)
    return await run_in_threadpool(sync_contacts)

def sync_contacts(force=True):
    with contact_lock:
        return sync_contacts_locked(force)

contact_lock=threading.Lock()
contact_wakeup=threading.Event()
contact_stop=threading.Event()

def contact_worker():
    while not contact_stop.is_set():
        try:
            sync_contacts(False)
        except Exception as e:
            logging.warning("Contact worker: %s",type(e).__name__)
        contact_wakeup.wait(30)
        contact_wakeup.clear()

@app.on_event("startup")
def start_contacts():
    with closing(db()):
        pass
    contact_stop.clear()
    threading.Thread(target=contact_worker,daemon=True).start()

@app.on_event("shutdown")
def stop_contacts():
    contact_stop.set()
    contact_wakeup.set()

def sync_contacts_locked(force):
    from urllib.parse import quote
    with closing(db()) as c:
        chats=[r[0] for r in c.execute("SELECT DISTINCT chat FROM events WHERE kind='message.any' AND chat<>''")]
    for chat in chats:
        if contact_stop.is_set():
            break
        with closing(db()) as c,c:
            last=c.execute("SELECT attempted FROM contact_refresh WHERE chat=?",(chat,)).fetchone()
            if not force and last and time.time()-last[0]<86400:
                continue
            c.execute("INSERT INTO contact_refresh(chat,attempted) VALUES(?,?) ON CONFLICT(chat) DO UPDATE SET attempted=excluded.attempted",(chat,int(time.time())))
        params={"session":"default","contactId":chat}
        try:
            obj=waha_json("/api/default/groups/"+quote(chat,safe=""),{}) if chat.endswith("@g.us") else waha_json("/api/contacts",params)
            name=obj.get("name") or obj.get("subject") or obj.get("pushname") or obj.get("pushName")
            if isinstance(name,str) and name:
                with closing(db()) as c,c:
                    c.execute("INSERT INTO contacts(chat,name) VALUES(?,?) ON CONFLICT(chat) DO UPDATE SET name=excluded.name",(chat,name[:200]))
        except Exception as e:
            logging.warning("Contact lookup: %s",type(e).__name__)
        try:
            obj=waha_json("/api/contacts/profile-picture",params)
            url=obj.get("profilePictureURL") or obj.get("url")
            u=urlsplit(url or "")
            if u.scheme!="https" or not u.hostname or not (u.hostname.endswith(".whatsapp.net") or u.hostname.endswith(".fbcdn.net")) or u.username or u.password or u.port not in (None,443):
                continue
            with build_opener(NoRedirect()).open(URLRequest(url),timeout=10) as res:
                mime=res.headers.get_content_type()
                photo=res.read(2000001)
            if mime in ("image/jpeg","image/png","image/webp") and len(photo)<=2000000:
                with closing(db()) as c,c:
                    c.execute("INSERT INTO contacts(chat,photo,mime) VALUES(?,?,?) ON CONFLICT(chat) DO UPDATE SET photo=excluded.photo,mime=excluded.mime",(chat,photo,mime))
        except Exception as e:
            logging.warning("Profile picture lookup: %s",type(e).__name__)
        time.sleep(0.5)
    return RedirectResponse("/",303)

@app.get("/avatar")
def avatar(chat: str, _: None = Depends(authorized)):
    with closing(db()) as c:
        row=c.execute("SELECT photo,mime FROM contacts WHERE chat=?",(chat,)).fetchone()
    if not row or not row[0]:
        raise HTTPException(404)
    return Response(row[0],media_type=row[1],headers={"X-Content-Type-Options":"nosniff","Cache-Control":"no-store"})

def controls(chat):
    hidden='<input type="hidden" name="token" value="'+csrf()+'"><input type="hidden" name="chat" value="'+esc(chat)+'">'
    confirm=' onsubmit="return confirm(&quot;Confermi la cancellazione locale?&quot;)"'
    return '<form id="delete-selected" method="post" action="/delete"'+confirm+'>'+hidden+'<button>Elimina selezionati</button></form>'+('<form method="post" action="/delete"'+confirm+'>'+hidden+'<input type="hidden" name="whole" value="1"><button>Elimina chat completa</button></form>' if chat else "")

def refresh_button():
    return '<form method="post" action="/contacts/refresh"><input type="hidden" name="token" value="'+csrf()+'"><button>Aggiorna contatti e foto</button></form>'


def size_label(n):
    for unit in ("B","KB","MB","GB","TB"):
        if n<1024 or unit=="TB":
            return f"{n:.2f} {unit}"
        n/=1024

def storage_summary():
    database=sum(p.stat().st_size for p in Path("/data").glob("archive.sqlite*") if p.is_file())
    media=sum(p.stat().st_size for p in MEDIA.iterdir() if p.is_file())
    return "DB: "+size_label(database)+" · Media: "+size_label(media)+" · Totale: "+size_label(database+media)

def page(title,body):
    return '<!doctype html><html lang="it"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>'+esc(title)+'</title><style>body{font:15px system-ui;margin:24px}table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid #ccc;text-align:left}button{padding:8px}img{max-width:90px;max-height:70px}</style><a href="/">Torna alle chat</a><h1>'+esc(title)+'</h1>'+body+'</html>'

@app.get("/storage",response_class=HTMLResponse)
def storage(category: str="", _: None=Depends(authorized)):
    with closing(db()) as c:
        rows=c.execute("SELECT e.id,e.media_file,e.media_name,e.media_type,e.chat,e.received,coalesce(k.name,e.chat) FROM events e LEFT JOIN contacts k ON k.chat=e.chat WHERE e.media_file IS NOT NULL ORDER BY e.media_size DESC").fetchall()
    items=[]
    totals={}
    for mid,f,name,mime,chat,stamp,label in rows:
        if not re.fullmatch(r"[a-f0-9]{32}",f):
            continue
        p=MEDIA/f
        exists=p.is_file()
        try:
            n=p.stat().st_size if exists else 0
        except FileNotFoundError:
            n,exists=0,False
        kind=(mime or "").split("/")[0]
        kind=kind if kind in ("image","video","audio") else "document"
        totals[kind]=totals.get(kind,0)+n
        if category and category!=kind:
            continue
        url="/media/"+f
        preview='<img loading="lazy" src="'+url+'">' if exists and kind=="image" else ""
        link='<a href="'+url+'?download=true">'+esc(name or f)+'</a>' if exists else esc(name or f)+" (file mancante)"
        items.append('<tr><td><input type="checkbox" name="ids" value="'+str(mid)+'"></td><td>'+preview+link+'<small> '+esc(f)+'</small></td><td>'+esc(label)+'</td><td>'+datetime.fromtimestamp(stamp,ZoneInfo("Europe/Rome")).strftime("%d/%m/%Y %H:%M")+'</td><td>'+size_label(n)+'</td></tr>')
    hidden='<input type="hidden" name="token" value="'+csrf()+'">'
    filters=' · '.join('<a href="/storage?category='+k+'">'+v+'</a>' for k,v in (("","Tutti"),("image","Foto"),("video","Video"),("audio","Audio"),("document","Documenti")))
    body='<p>'+esc(storage_summary())+' · Libero sul filesystem media: '+size_label(shutil.disk_usage(MEDIA).free)+'</p><p>'+esc(" · ".join(k+": "+size_label(v) for k,v in totals.items()))+'</p><p>Cartella Windows prevista: <code>C:\\WhatsAppArchive\\media</code> (solo dopo migrazione).</p><p>'+filters+'</p>'
    body+='<form method="post" action="/storage/delete" onsubmit="return confirm(&quot;Eliminare gli allegati selezionati?&quot;)">'+hidden+'<button>Elimina allegati selezionati</button><table><tr><th></th><th>File</th><th>Contatto</th><th>Data</th><th>Dimensione</th></tr>'+''.join(items)+'</table></form>'
    for action,label in (("cleanup","Rimuovi riferimenti ai file mancanti"),("vacuum","Ottimizza database")):
        body+='<form method="post" action="/storage/'+action+'">'+hidden+'<button>'+label+'</button></form>'
    return page("Gestione media",body)

@app.post("/storage/{action}")
async def storage_action(action: str,request: Request,_: None=Depends(authorized)):
    data=await form_data(request)
    return await run_in_threadpool(storage_action_sync,action,data)

def storage_action_sync(action,data):
    with closing(db()) as c:
        if action=="vacuum":
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            c.execute("VACUUM")
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        elif action in ("delete","cleanup"):
            ids=[int(x) for x in data.get("ids",[]) if x.isdecimal()][:1000]
            with c:
                rows=c.execute("SELECT id,media_file FROM events WHERE media_file IS NOT NULL").fetchall()
                for mid,f in rows:
                    if not re.fullmatch(r"[a-f0-9]{32}",f):
                        continue
                    p=MEDIA/f
                    if (action=="delete" and mid in ids) or (action=="cleanup" and not p.is_file()):
                        c.execute("UPDATE events SET media_file=NULL,media_size=NULL,media_error=? WHERE id=?",("Allegato rimosso dall archivio",mid))
                        if not c.execute("SELECT 1 FROM events WHERE media_file=?",(f,)).fetchone():
                            p.unlink(missing_ok=True)
        else:
            raise HTTPException(404)
    return RedirectResponse("/storage",303)


@app.get("/", response_class=HTMLResponse)
def dashboard(q: str = "", chat: str = "", contact_q: str = "", _: None = Depends(authorized)):
    with closing(db()) as c:
        chats = c.execute("SELECT chat, count(*), max(id) FROM events WHERE kind='message.any' GROUP BY chat ORDER BY max(id) DESC").fetchall()
        contacts = {r[0]:(r[1],r[2]) for r in c.execute("SELECT chat,name,photo IS NOT NULL FROM contacts")}
        total = c.execute("SELECT count(*) FROM events WHERE kind='message.any'").fetchone()[0]
        if not chat and not q and chats:
            chat = chats[0][0]
        rows = c.execute("SELECT received,chat,body,direction,media_file,media_type,media_name,media_error,id,revoked FROM events WHERE kind='message.any' AND (?='' OR chat=?) AND (body LIKE ? OR chat LIKE ?) ORDER BY id DESC LIMIT 300",(chat,chat,"%"+q+"%","%"+q+"%")).fetchall()
    def contact_label(name):
        return contacts.get(name,(None,False))[0] or name or "Sconosciuto"
    def contact_avatar(name):
        if contacts.get(name,(None,False))[1]:
            return '<img class="avatar" src="/avatar?'+esc(urlencode({"chat":name}))+'">'
        initials="".join(word[0].upper() for word in contact_label(name).split()[:2])
        return '<span class="avatar initials">'+esc(initials)+'</span>'
    def contact_number(name):
        return "+"+name.split("@")[0] if re.fullmatch(r"[0-9]+@c.us",name) else name
    links = "".join('<a class="contact '+('active' if name==chat else '')+'" href="/?'+esc(urlencode({"chat":name,"contact_q":contact_q}))+'">'+contact_avatar(name)+esc(contact_label(name))+'<small>'+esc(contact_number(name))+' · '+str(n)+' messaggi</small></a>' for name,n,_ in chats if not contact_q or contact_q.casefold() in (contact_label(name)+" "+contact_number(name)).casefold())
    contact_search='<form method="get"><input name="contact_q" placeholder="Cerca contatto" value="'+esc(contact_q)+'"><input type="hidden" name="chat" value="'+esc(chat)+'"><button>Cerca</button></form>'
    bubbles = ""
    for stamp,name,body,direction,mfile,mtype,mname,merror,mid,revoked in reversed(rows):
        date = datetime.fromtimestamp(stamp, ZoneInfo("Europe/Rome")).strftime("%d/%m/%Y %H:%M")
        cls = direction if direction in ("in","out") else "unknown"
        label = {"in":"Ricevuto","out":"Inviato","unknown":"Direzione non disponibile"}[cls]
        preview = ""
        if mfile and not (MEDIA/mfile).is_file():
            preview = "<p>Allegato rimosso o mancante</p>"
        elif mfile:
            url = "/media/"+esc(mfile)
            mime = (mtype or "").split(";")[0]
            if mime in ("image/jpeg","image/png","image/webp","image/gif"):
                preview = '<img loading="lazy" style="max-width:100%;max-height:360px" src="'+url+'">'
            elif mime in ("video/mp4","video/webm"):
                preview = '<video controls preload="none" style="max-width:100%" src="'+url+'"></video>'
            elif mime in ("audio/ogg","audio/mpeg","audio/mp4","audio/wav"):
                preview = '<audio controls preload="none" src="'+url+'"></audio>'
            preview += '<p><a href="'+url+'?download=true">Scarica '+esc(mname)+'</a></p>'
        elif merror:
            preview = '<p>'+esc(merror)+'</p>'
        bubbles += '<article class="bubble '+cls+'"><small>'+esc(contacts.get(name,(None,False))[0] or name)+' · '+label+'</small><div>'+esc(body or "[Messaggio senza testo]")+'</div>'+preview+'<small>'+date+'</small>'+('<p style="color:#c44">Messaggio revocato su WhatsApp · '+datetime.fromtimestamp(int(revoked),ZoneInfo("Europe/Rome")).strftime("%d/%m/%Y %H:%M")+'</p>' if revoked else '')+'<label><input type="checkbox" name="ids" value="'+str(mid)+'" form="delete-selected"> Seleziona</label></article>'
    return """<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WhatsApp Archive</title><style>
    *{box-sizing:border-box}body{margin:0;font:15px system-ui;background:#eef2ef;color:#17251e}header{padding:16px;background:#075e54;color:white}main{display:grid;grid-template-columns:minmax(180px,30%) 1fr;min-height:80vh}aside{background:white;border-right:1px solid #ccc;padding:12px;overflow-wrap:anywhere}.contact{display:block;padding:14px;color:inherit;text-decoration:none;border-bottom:1px solid #ddd}.avatar{width:38px;height:38px;border-radius:50%;object-fit:cover;float:left;margin-right:10px}.initials{display:grid;place-items:center;background:#d9eee6;color:#075e54;font-weight:bold}.contact{min-height:70px;overflow:hidden}.active{background:#d9eee6}small{display:block;opacity:.75;font-size:12px}section{padding:16px;min-width:0}.bubble{max-width:85%;width:fit-content;background:white;border-radius:12px;padding:12px;margin:10px 0;overflow-wrap:anywhere}.bubble div{white-space:pre-wrap;margin:6px 0}.out{margin-left:auto;background:#d9fdd3}.unknown{background:#e5e5e5}form{display:flex;gap:8px;flex-wrap:wrap}input,button{padding:10px;border:1px solid #aaa;border-radius:6px}a{color:inherit}@media(prefers-color-scheme:dark){body{background:#15221e;color:#eee}aside,.bubble{background:#263830}.out,.active{background:#285b48}.unknown{background:#424242}}@media(max-width:600px){main{grid-template-columns:1fr}aside{max-height:30vh;overflow:auto}}
    </style></head><body><header><strong>WhatsApp Archive v0.5</strong> · """+str(total)+""" messaggi <span style="float:right">"""+esc(storage_summary())+""" · <a href="/storage">Gestione media</a></span></header><main><aside><a href="/">Conversazioni</a> · <a href="/?q=%25">Tutte</a>"""+refresh_button()+contact_search+links+"""</aside><section><form><input type="hidden" name="chat" value=" """ .rstrip()+esc(chat)+'''"><input name="q" placeholder="Cerca nella conversazione" value="'''+esc(q)+'''"><button>Cerca</button><a href="/?q='''+esc(urlencode({"q":q})[2:])+'''">Ricerca globale</a></form><h2>'''+esc(contacts.get(chat,(None,False))[0] or chat or "Tutte le conversazioni")+'''</h2><p>Ultimi 300 risultati · aggiorna la pagina per nuovi messaggi</p>'''+controls(chat)+(bubbles or "<p>Nessun messaggio trovato.</p>")+'''</section></main></body></html>'''
