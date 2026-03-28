from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from dotenv import load_dotenv
from passlib.context import CryptContext
from apscheduler.schedulers.background import BackgroundScheduler
import os, uuid, random

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "").replace("postgres://", "postgresql://")
SECRET_ADMIN = os.getenv("SECRET_ADMIN", "admin123")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI(title="Servidor de Licencias - AsistenteIA")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class Usuario(Base):
    __tablename__ = "usuarios"
    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    nombre         = Column(String)
    correo         = Column(String, unique=True)
    password       = Column(String)
    plan           = Column(String, default="basico")
    referido_por   = Column(String, nullable=True)
    fecha_registro = Column(DateTime, default=datetime.utcnow)


class Licencia(Base):
    __tablename__ = "licencias"
    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id     = Column(String)
    clave          = Column(String, unique=True)
    estado         = Column(String, default="activa")
    plan           = Column(String, default="basico")
    fecha_vence    = Column(DateTime)
    es_prueba      = Column(Boolean, default=True)
    fecha_creacion = Column(DateTime, default=datetime.utcnow)


class ApiKeyPool(Base):
    __tablename__ = "api_keys_pool"
    id                 = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    correo_cuenta      = Column(String)
    api_key            = Column(String)
    usuarios_asignados = Column(Integer, default=0)
    requests_hoy       = Column(Integer, default=0)
    activa             = Column(Boolean, default=True)


class LogTokens(Base):
    __tablename__ = "log_tokens"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id    = Column(String)
    correo        = Column(String)
    tokens_usados = Column(Integer)
    key_usada     = Column(String)
    tarea         = Column(String)
    fecha         = Column(DateTime, default=datetime.utcnow)


class Cupon(Base):
    __tablename__ = "cupones"
    codigo        = Column(String, primary_key=True)
    descuento     = Column(Integer)
    usos_maximos  = Column(Integer, default=100)
    usos_actuales = Column(Integer, default=0)
    fecha_vence   = Column(DateTime)
    activo        = Column(Boolean, default=True)


class Pago(Base):
    __tablename__ = "pagos"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id  = Column(String)
    monto       = Column(Integer)
    cupon_usado = Column(String, nullable=True)
    fecha_pago  = Column(DateTime, default=datetime.utcnow)
    referencia  = Column(String, nullable=True)


Base.metadata.create_all(bind=engine)


# ---- Reset diario de API keys ----
def reset_requests_diarios():
    db = SessionLocal()
    try:
        db.query(ApiKeyPool).update({"requests_hoy": 0})
        db.commit()
        print(f"[{datetime.utcnow()}] Reset diario de requests completado.")
    finally:
        db.close()

scheduler = BackgroundScheduler()
scheduler.add_job(reset_requests_diarios, "cron", hour=0, minute=0)
scheduler.start()
# ----------------------------------


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verificar_admin(x_admin_secret: str = Header(...)):
    if x_admin_secret != SECRET_ADMIN:
        raise HTTPException(status_code=403, detail="No autorizado")


def obtener_key_disponible(db: Session):
    keys = db.query(ApiKeyPool).filter(
        ApiKeyPool.activa == True
    ).order_by(ApiKeyPool.requests_hoy.asc()).all()
    if not keys:
        return os.getenv("GROQ_API_KEY_BACKUP", "")
    key = keys[0]
    key.requests_hoy += 1
    db.commit()
    return key.api_key


@app.get("/")
def root():
    return {"status": "ok", "mensaje": "Servidor de licencias AsistenteIA"}


@app.post("/registro")
def registrar_usuario(datos: dict, db: Session = Depends(get_db)):
    if db.query(Usuario).filter(Usuario.correo == datos["correo"]).first():
        raise HTTPException(status_code=400, detail="Correo ya registrado")
    password_hash = pwd_context.hash(datos["password"])
    usuario = Usuario(
        nombre=datos["nombre"],
        correo=datos["correo"],
        password=password_hash,
        plan=datos.get("plan", "basico"),
        referido_por=datos.get("referido_por")
    )
    db.add(usuario)
    clave = str(uuid.uuid4()).replace("-", "").upper()[:16]
    licencia = Licencia(
        usuario_id=usuario.id,
        clave=clave,
        plan=datos.get("plan", "basico"),
        fecha_vence=datetime.utcnow() + timedelta(days=30),
        es_prueba=True
    )
    db.add(licencia)
    db.commit()
    return {
        "mensaje": "Usuario registrado exitosamente",
        "clave_licencia": clave,
        "prueba_gratis_dias": 30
    }


@app.get("/validar/{clave}")
def validar_licencia(clave: str, db: Session = Depends(get_db)):
    licencia = db.query(Licencia).filter(Licencia.clave == clave).first()
    if not licencia:
        return {"valida": False, "mensaje": "Licencia no encontrada"}
    if licencia.estado != "activa":
        return {"valida": False, "mensaje": "Licencia suspendida. Contacta soporte."}
    if licencia.fecha_vence < datetime.utcnow():
        licencia.estado = "vencida"
        db.commit()
        return {"valida": False, "mensaje": "Licencia vencida. Renueva en tudominio.com"}
    api_key = obtener_key_disponible(db)
    return {
        "valida": True,
        "plan": licencia.plan,
        "fecha_vence": licencia.fecha_vence.isoformat(),
        "api_key": api_key,
        "dias_restantes": (licencia.fecha_vence - datetime.utcnow()).days,
        "google_client_id":     os.getenv("GOOGLE_CLIENT_ID", ""),
        "google_client_secret": os.getenv("GOOGLE_CLIENT_SECRET", ""),
        "azure_client_id":      os.getenv("AZURE_CLIENT_ID", ""),
        "azure_tenant_id":      os.getenv("AZURE_TENANT_ID", ""),
    }


@app.post("/log/tokens")
def registrar_tokens(datos: dict, db: Session = Depends(get_db)):
    log = LogTokens(
        usuario_id=datos.get("usuario_id"),
        correo=datos.get("correo"),
        tokens_usados=datos.get("tokens_usados", 0),
        key_usada=datos.get("key_usada"),
        tarea=datos.get("tarea", "general")
    )
    db.add(log)
    db.commit()
    return {"ok": True}


@app.post("/cupon/validar")
def validar_cupon(datos: dict, db: Session = Depends(get_db)):
    cupon = db.query(Cupon).filter(Cupon.codigo == datos["codigo"].upper()).first()
    if not cupon or not cupon.activo:
        return {"valido": False, "mensaje": "Cupon no valido"}
    if cupon.fecha_vence < datetime.utcnow():
        return {"valido": False, "mensaje": "Cupon vencido"}
    if cupon.usos_actuales >= cupon.usos_maximos:
        return {"valido": False, "mensaje": "Cupon agotado"}
    return {"valido": True, "descuento": cupon.descuento}


@app.post("/pagos/wompi")
async def webhook_wompi(datos: dict, db: Session = Depends(get_db)):
    try:
        evento = datos.get("event", "")
        if evento != "transaction.updated":
            return {"ok": True}

        transaccion = datos.get("data", {}).get("transaction", {})
        estado = transaccion.get("status", "")

        if estado != "APPROVED":
            return {"ok": True}

        referencia = transaccion.get("reference", "")
        monto = transaccion.get("amount_in_cents", 0) // 100

        licencia = db.query(Licencia).filter(Licencia.clave == referencia).first()
        if not licencia:
            return {"ok": False, "mensaje": "Licencia no encontrada"}

        licencia.estado = "activa"
        licencia.fecha_vence = datetime.utcnow() + timedelta(days=30)
        licencia.es_prueba = False

        pago = Pago(
            usuario_id=licencia.usuario_id,
            monto=monto,
            referencia=referencia
        )
        db.add(pago)
        db.commit()

        return {"ok": True, "mensaje": f"Licencia {referencia} activada"}

    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/admin/usuarios", dependencies=[Depends(verificar_admin)])
def listar_usuarios(db: Session = Depends(get_db)):
    usuarios = db.query(Usuario).all()
    resultado = []
    for u in usuarios:
        licencia = db.query(Licencia).filter(Licencia.usuario_id == u.id).first()
        tokens_hoy = db.query(LogTokens).filter(
            LogTokens.usuario_id == u.id,
            LogTokens.fecha >= datetime.utcnow().replace(hour=0, minute=0)
        ).all()
        total_tokens = sum(t.tokens_usados for t in tokens_hoy)
        resultado.append({
            "id": u.id,
            "nombre": u.nombre,
            "correo": u.correo,
            "plan": u.plan,
            "licencia_estado": licencia.estado if licencia else "sin licencia",
            "licencia_vence": licencia.fecha_vence.isoformat() if licencia else None,
            "tokens_hoy": total_tokens,
            "fecha_registro": u.fecha_registro.isoformat()
        })
    return resultado


@app.post("/admin/suspender", dependencies=[Depends(verificar_admin)])
def suspender_licencia(datos: dict, db: Session = Depends(get_db)):
    licencia = db.query(Licencia).filter(Licencia.clave == datos["clave"]).first()
    if not licencia:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    licencia.estado = "suspendida"
    db.commit()
    return {"mensaje": f"Licencia {datos['clave']} suspendida"}


@app.post("/admin/activar", dependencies=[Depends(verificar_admin)])
def activar_licencia(datos: dict, db: Session = Depends(get_db)):
    licencia = db.query(Licencia).filter(Licencia.clave == datos["clave"]).first()
    if not licencia:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    licencia.estado = "activa"
    licencia.fecha_vence = datetime.utcnow() + timedelta(days=30)
    licencia.es_prueba = False
    db.commit()
    return {"mensaje": f"Licencia {datos['clave']} activada por 30 dias"}


@app.post("/admin/keys/agregar", dependencies=[Depends(verificar_admin)])
def agregar_key(datos: dict, db: Session = Depends(get_db)):
    key = ApiKeyPool(
        correo_cuenta=datos["correo"],
        api_key=datos["api_key"]
    )
    db.add(key)
    db.commit()
    return {"mensaje": "API key agregada al pool"}


@app.get("/admin/keys", dependencies=[Depends(verificar_admin)])
def listar_keys(db: Session = Depends(get_db)):
    keys = db.query(ApiKeyPool).all()
    return [{"id": k.id, "correo": k.correo_cuenta, "usuarios": k.usuarios_asignados,
             "requests_hoy": k.requests_hoy, "activa": k.activa} for k in keys]


@app.get("/admin/dashboard", dependencies=[Depends(verificar_admin)])
def dashboard(db: Session = Depends(get_db)):
    total_usuarios = db.query(Usuario).count()
    activas = db.query(Licencia).filter(Licencia.estado == "activa").count()
    suspendidas = db.query(Licencia).filter(Licencia.estado == "suspendida").count()
    tokens_hoy = db.query(LogTokens).filter(
        LogTokens.fecha >= datetime.utcnow().replace(hour=0, minute=0)
    ).all()
    total_tokens_hoy = sum(t.tokens_usados for t in tokens_hoy)
    top_usuarios = {}
    for t in tokens_hoy:
        top_usuarios[t.correo] = top_usuarios.get(t.correo, 0) + t.tokens_usados
    top_5 = sorted(top_usuarios.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "total_usuarios": total_usuarios,
        "licencias_activas": activas,
        "licencias_suspendidas": suspendidas,
        "tokens_consumidos_hoy": total_tokens_hoy,
        "top_usuarios_tokens": [{"correo": c, "tokens": t} for c, t in top_5]
    }


@app.post("/admin/cupon/crear", dependencies=[Depends(verificar_admin)])
def crear_cupon(datos: dict, db: Session = Depends(get_db)):
    cupon = Cupon(
        codigo=datos["codigo"].upper(),
        descuento=datos["descuento"],
        usos_maximos=datos.get("usos_maximos", 100),
        fecha_vence=datetime.utcnow() + timedelta(days=datos.get("dias_vigencia", 30))
    )
    db.add(cupon)
    db.commit()
    return {"mensaje": f"Cupon {cupon.codigo} creado con {cupon.descuento}% de descuento"}