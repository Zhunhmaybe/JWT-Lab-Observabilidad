#~/jwt-lab/main.py

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import asyncio, queue, threading, logging, datetime, json

app = FastAPI()
SECRET_KEY = "super_secreto_del_club"
ALGORITHM  = "HS256"

# Logger estructurado
logging.basicConfig(
    filename="/home/utn-hacking/jwt-lab/requests.log",
    level=logging.INFO,
    format='%(message)s'
)

def log_event(event: dict):
    logging.info(json.dumps(event))

# ─── Middleware: registra CADA petición ───────────────────────
@app.middleware("http")
async def observe_all(request: Request, call_next):
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    entry = {
        "ts": datetime.datetime.utcnow().isoformat(),
        "method": request.method,
        "path": str(request.url.path),
        "ip": request.client.host,
        "token_raw": token[:60] + "…" if len(token) > 60 else token,
        "token_decode": None,
        "attack_detected": None,
        "status": None
    }

    # Intentar decodificar sin verificar (para ver qué trae)
    if token:
        try:
            # Decodifica SIN verificar firma — solo para observar el payload
            unverified = jwt.decode(
                token, SECRET_KEY,
                algorithms=[ALGORITHM, "none"],  # "none" para detectar el ataque
                options={"verify_signature": False, "verify_exp": False}
            )
            entry["token_decode"] = unverified

            # Detectar ataque None Algorithm
            header = jwt.get_unverified_header(token)
            if header.get("alg", "").lower() == "none":
                entry["attack_detected"] = "NONE_ALGORITHM_ATTACK"
        except Exception as e:
            entry["token_decode"] = f"ERROR: {e}"

    response = await call_next(request)
    entry["status"] = response.status_code
    log_event(entry)
    return response

# ─── Dependencia: validación estricta ─────────────────────────
def require_valid_token(request: Request):
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(401, "Token requerido")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg", "").lower() == "none":
            raise HTTPException(401, "Algoritmo 'none' no permitido")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(401, f"Token inválido: {e}")

# ─── Endpoints ────────────────────────────────────────────────
@app.get("/public")
def public_route():
    return {"msg": "Ruta pública — sin autenticación"}

@app.get("/private")
def private_route(payload: dict = Depends(require_valid_token)):
    return {"msg": "Acceso concedido", "user": payload}

@app.get("/admin")
def admin_route(payload: dict = Depends(require_valid_token)):
    if payload.get("role") != "admin":
        raise HTTPException(403, "Solo admins — intenta el ataque de payload tampering")
    return {"msg": "Panel de admin", "user": payload}

# ─── Generador de tokens (para el club) ───────────────────────
@app.post("/token/generate")
def generate_token(username: str, role: str = "user"):
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token, "payload": payload}

# Cola compartida entre el logger y el SSE stream
log_queue: queue.Queue = queue.Queue(maxsize=200)

def log_event(event: dict):
    logging.info(json.dumps(event))
    try:
        log_queue.put_nowait(event)
    except queue.Full:
        log_queue.get_nowait()
        log_queue.put_nowait(event)

# ─── Endpoint SSE ─────────────────────────────────────────────
@app.get("/dashboard/stream")
async def stream_logs(request: Request):
    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            try:
                event = log_queue.get_nowait()
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                await asyncio.sleep(0.3)
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

# ─── Servir el dashboard HTML ──────────────────────────────────
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    with open("/home/utn-hacking/jwt-lab/dashboard.html") as f:
        return f.read()