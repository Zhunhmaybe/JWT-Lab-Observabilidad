#cd ~/jwt-lab/main.py

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel
from jose import jwt, JWTError
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
import asyncio, queue, logging, datetime, json, os

# ─── Configuración Básica ───
app = FastAPI()
SECRET_KEY = "super_secreto_del_club"
ALGORITHM  = "HS256"

logging.basicConfig(filename="/home/utn-hacking/jwt-lab/requests.log", level=logging.INFO, format='%(message)s')
log_queue: queue.Queue = queue.Queue(maxsize=200)

def log_event(event: dict):
    logging.info(json.dumps(event))
    try: log_queue.put_nowait(event)
    except queue.Full:
        log_queue.get_nowait()
        log_queue.put_nowait(event)

# ─── Base de Datos (SQLite) ───
SQLALCHEMY_DATABASE_URL = "sqlite:////home/utn-hacking/jwt-lab/ctf_lab.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)

# Inicializar DB y usuarios por defecto
Base.metadata.create_all(bind=engine)
db = SessionLocal()
if not db.query(User).filter(User.username == "alumno1").first():
    db.add_all([
        User(username="alumno1", password="1234", role="user"),
        User(username="admin", password="admin123", role="admin")
    ])
    db.commit()
db.close()

# ─── Middleware de Observabilidad ───
@app.middleware("http")
async def observe_all(request: Request, call_next):
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    entry = {"ts": datetime.datetime.utcnow().isoformat(), "method": request.method, "path": str(request.url.path), "ip": request.client.host, "token_raw": token[:60] + "…" if len(token) > 60 else token, "token_decode": None, "attack_detected": None, "status": None}
    
    if token:
        try:
            unverified = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "none"], options={"verify_signature": False, "verify_exp": False})
            entry["token_decode"] = unverified
            header = jwt.get_unverified_header(token)
            if header.get("alg", "").lower() == "none":
                entry["attack_detected"] = "NONE_ALGORITHM_ATTACK"
        except Exception as e:
            entry["token_decode"] = f"ERROR: {e}"
            
    response = await call_next(request)
    entry["status"] = response.status_code
    
    # Ignorar logs de SSE para no saturar la pantalla
    if "/dashboard/stream" not in entry["path"]:
        log_event(entry)
    return response

def require_valid_token(request: Request):
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    if not token: raise HTTPException(401, "Token requerido")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg", "").lower() == "none": raise HTTPException(401, "Algoritmo 'none' no permitido")
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as e:
        raise HTTPException(401, f"Token inválido: {e}")

# ─── Modelos Pydantic ───
class LoginRequest(BaseModel):
    username: str
    password: str

# ─── Endpoints de la Aplicación ───
@app.post("/api/login")
def login(creds: LoginRequest):
    db = SessionLocal()
    user = db.query(User).filter(User.username == creds.username, User.password == creds.password).first()
    db.close()
    
    if not user: raise HTTPException(401, "Credenciales incorrectas")
    
    payload = {"sub": user.username, "role": user.role, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token, "user": {"username": user.username, "role": user.role}}

@app.get("/private")
def private_route(payload: dict = Depends(require_valid_token)): 
    return {"msg": "Acceso concedido a zona de usuarios", "user": payload}

@app.get("/admin")
def admin_route(payload: dict = Depends(require_valid_token)):
    if payload.get("role") != "admin": raise HTTPException(403, "Acceso denegado: Se requiere rol admin")
    return {"msg": "Panel de Administración Seguro", "secret_data": "Flag{Firma_Validada_Con_Exito}"}

@app.get("/admin-vulnerable")
def admin_vulnerable(request: Request):
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    if not token: raise HTTPException(401, "Token requerido")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"], options={"verify_signature": False, "verify_exp": False})
        if payload.get("role") != "admin": raise HTTPException(403, "Solo admins")
        return {"msg": "🚨 PANEL VULNERABLE COMPROMETIDO", "flag": "Flag{Tampering_Exitoso_Sin_Firma}"}
    except JWTError as e: raise HTTPException(401, f"Token inválido: {e}")

# ─── Endpoints del Dashboard ───
@app.get("/dashboard/stream")
async def stream_logs(request: Request):
    async def event_generator():
        while True:
            if await request.is_disconnected(): break
            try:
                event = log_queue.get_nowait()
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty: await asyncio.sleep(0.3)
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    with open("/home/utn-hacking/jwt-lab/dashboard.html") as f: return f.read()
