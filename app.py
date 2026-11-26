import os, sqlite3, secrets, html, time
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from contextlib import closing

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
    return c

def authorized(c: HTTPBasicCredentials = Depends(auth)):
    if not (secrets.compare_digest(c.username.encode(), b"admin") and secrets.compare_digest(c.password.encode(), password.encode())):
        raise HTTPException(401, headers={"WWW-Authenticate":"Basic"})

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
    if kind not in ("message.any", "session.status"):
        return {"ignored": True}
    p = event.get("payload") or {}
    if not isinstance(p, dict):
        raise HTTPException(400)
    chat = p.get("to") if p.get("fromMe") else p.get("from")
    body = p.get("body") if kind == "message.any" else p.get("status")
    with closing(db()) as c, c:
        c.execute("INSERT INTO events(received,kind,chat,body) VALUES(?,?,?,?)",(int(time.time()),kind,str(chat or ""),str(body or "")))
    return {"ok": True}

@app.get("/", response_class=HTMLResponse)
def dashboard(q: str = "", _: None = Depends(authorized)):
    with closing(db()) as c:
        rows = c.execute("SELECT datetime(received,'unixepoch'),kind,chat,body FROM events WHERE body LIKE ? OR chat LIKE ? ORDER BY id DESC LIMIT 200",("%"+q+"%","%"+q+"%")).fetchall()
    table = "".join("<tr>"+"".join("<td>"+html.escape(str(v or ""))+"</td>" for v in r)+"</tr>" for r in rows)
    return '<!doctype html><html lang="it"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>WhatsApp Archive</title><style>body{font:16px system-ui;margin:2rem;background:#f4f6f5;color:#17251e}table{border-collapse:collapse;width:100%;background:white}td,th{padding:12px;border-bottom:1px solid #ddd;text-align:left;overflow-wrap:anywhere}input,button{padding:10px}</style><h1>WhatsApp Archive</h1><p>Versione di test — ultimi 200 eventi, orari UTC</p><form><input name="q" placeholder="Cerca testo o contatto" value="'+html.escape(q,quote=True)+'"><button>Cerca</button></form><table><tr><th>Data</th><th>Evento</th><th>Chat</th><th>Testo</th></tr>'+table+'</table></html>'
