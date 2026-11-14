"""API del sistema de soporte técnico multisede Trilce (versión 2).

Incluye: reporte del docente por QR, login con roles (técnico / administrador),
gestión de tickets para soporte, historial, indicadores y administración de usuarios.
"""
import hmac
import os
import secrets
from contextlib import contextmanager
from typing import Literal, Optional

import psycopg2
import psycopg2.extras
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

import seguridad

DATABASE_URL = os.environ.get("DATABASE_URL")
# En producción pon aquí las URLs de tus páginas, separadas por coma.
ORIGENES = os.environ.get("ALLOWED_ORIGINS", "*").split(",")

# ------------------------------------------------------------------
# Regla de prioridad PROVISIONAL (hasta confirmar la sección 5 del documento).
# Charter: la prioridad depende de si hay una clase activa; el objetivo de
# primera respuesta en clase activa es menor a 8 minutos.
# ------------------------------------------------------------------
PLAZO_EN_CLASE_MIN = 8
PLAZO_FUERA_CLASE_MIN = 60  # PROVISIONAL: definir con la Jefatura de TI

app = FastAPI(title="Soporte Trilce")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGENES,
    allow_methods=["*"],
    allow_headers=["*"],
)
bearer = HTTPBearer(auto_error=False)


@contextmanager
def conexion():
    """Abre una conexión a la base, confirma al salir y revierte si hubo error."""
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="Falta la variable DATABASE_URL")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def calcular_prioridad(tipo_falla_id: int, en_clase: bool):
    """Devuelve (prioridad, plazo_en_minutos). Regla provisional: ver arriba."""
    if en_clase:
        return "alta", PLAZO_EN_CLASE_MIN
    return "media", PLAZO_FUERA_CLASE_MIN


# ------------------------------------------------------------------
# Autenticación y roles
# ------------------------------------------------------------------
def secreto() -> str:
    valor = os.environ.get("SECRET_KEY")
    if not valor or len(valor) < 20:
        raise HTTPException(
            status_code=500, detail="Falta la variable SECRET_KEY (mínimo 20 caracteres)"
        )
    return valor


def autenticar(cur, cred: Optional[HTTPAuthorizationCredentials]):
    """Devuelve el usuario del token, verificando en la base que siga activo."""
    if cred is None:
        raise HTTPException(status_code=401, detail="Inicia sesión para continuar")
    datos = seguridad.leer_token(cred.credentials, secreto())
    if not datos:
        raise HTTPException(status_code=401, detail="Sesión inválida o vencida")
    cur.execute(
        """
        SELECT u.id, u.nombre, u.correo, u.rol, u.sede_id, u.activo, s.nombre AS sede
        FROM usuarios u LEFT JOIN sedes s ON s.id = u.sede_id
        WHERE u.id = %s
        """,
        (datos["uid"],),
    )
    usuario = cur.fetchone()
    if not usuario or not usuario["activo"]:
        raise HTTPException(status_code=401, detail="Usuario no disponible")
    return usuario


def exigir_admin(usuario):
    if usuario["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Solo el administrador puede hacer esto")


def filtro_sede(usuario):
    """None = ve todas las sedes (admin). Un técnico solo ve la suya."""
    if usuario["rol"] == "admin":
        return None
    if usuario["sede_id"] is None:
        raise HTTPException(status_code=403, detail="Tu usuario no tiene una sede asignada")
    return usuario["sede_id"]


def datos_publicos(usuario):
    return {
        "id": usuario["id"],
        "nombre": usuario["nombre"],
        "rol": usuario["rol"],
        "sede_id": usuario["sede_id"],
        "sede": usuario["sede"] or "Todas las sedes",
    }


# ------------------------------------------------------------------
# Salud
# ------------------------------------------------------------------
@app.get("/salud")
def salud():
    return {"estado": "ok"}


@app.get("/salud/db")
def salud_db():
    with conexion() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 AS ok")
        cur.fetchone()
    return {"base_de_datos": "ok"}


# ------------------------------------------------------------------
# Página del docente (sin login)
# ------------------------------------------------------------------
@app.get("/qr/{token}")
def leer_qr(token: str):
    """El docente escanea el QR: devuelve el equipo, su ubicación y las fallas comunes."""
    with conexion() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT e.id, e.nombre AS equipo, te.id AS tipo_equipo_id,
                   te.nombre AS tipo_equipo, a.nombre AS ambiente, a.piso,
                   s.nombre AS sede
            FROM equipos e
            JOIN tipos_equipo te ON te.id = e.tipo_equipo_id
            JOIN ambientes a ON a.id = e.ambiente_id
            JOIN sedes s ON s.id = e.sede_id
            WHERE e.token_qr = %s AND e.activo
            """,
            (token,),
        )
        equipo = cur.fetchone()
        if not equipo:
            raise HTTPException(status_code=404, detail="QR no válido")
        cur.execute(
            """
            SELECT id, descripcion, es_otro
            FROM tipos_falla
            WHERE tipo_equipo_id = %s AND activo
            ORDER BY orden, id
            """,
            (equipo["tipo_equipo_id"],),
        )
        fallas = cur.fetchall()
    return {"equipo": equipo, "fallas": fallas}


class TicketNuevo(BaseModel):
    token_qr: str
    tipo_falla_id: int
    en_clase: bool
    descripcion: Optional[str] = None
    contacto: Optional[str] = None


@app.post("/tickets", status_code=201)
def crear_ticket(datos: TicketNuevo):
    """El docente presiona 'Registrar problema'."""
    with conexion() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, sede_id, tipo_equipo_id
            FROM equipos WHERE token_qr = %s AND activo
            """,
            (datos.token_qr,),
        )
        equipo = cur.fetchone()
        if not equipo:
            raise HTTPException(status_code=404, detail="QR no válido")

        cur.execute(
            "SELECT id FROM tipos_falla WHERE id = %s AND tipo_equipo_id = %s AND activo",
            (datos.tipo_falla_id, equipo["tipo_equipo_id"]),
        )
        if not cur.fetchone():
            raise HTTPException(status_code=400, detail="Falla no válida para este equipo")

        prioridad, plazo_min = calcular_prioridad(datos.tipo_falla_id, datos.en_clase)
        token_seguimiento = secrets.token_urlsafe(16)

        cur.execute(
            """
            INSERT INTO tickets (sede_id, equipo_id, tipo_falla_id, descripcion,
                                 en_clase, contacto_docente, prioridad, token_seguimiento,
                                 plazo_atencion)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now() + make_interval(mins => %s))
            RETURNING id, estado, prioridad, token_seguimiento
            """,
            (
                equipo["sede_id"],
                equipo["id"],
                datos.tipo_falla_id,
                datos.descripcion,
                datos.en_clase,
                datos.contacto,
                prioridad,
                token_seguimiento,
                plazo_min,
            ),
        )
        ticket = cur.fetchone()

        cur.execute(
            """
            INSERT INTO ticket_historial (ticket_id, sede_id, estado_nuevo, nota)
            VALUES (%s, %s, 'nuevo', 'Ticket creado')
            """,
            (ticket["id"], equipo["sede_id"]),
        )
    return ticket


@app.get("/seguimiento/{token}")
def seguimiento(token: str):
    """Enlace de seguimiento: el docente ve en qué estado va su reporte."""
    with conexion() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.estado, t.prioridad, t.creado_en, t.atendido_en, t.resuelto_en,
                   e.nombre AS equipo, f.descripcion AS falla
            FROM tickets t
            JOIN equipos e ON e.id = t.equipo_id
            JOIN tipos_falla f ON f.id = t.tipo_falla_id
            WHERE t.token_seguimiento = %s
            """,
            (token,),
        )
        ticket = cur.fetchone()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    return ticket


# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------
class Login(BaseModel):
    correo: str
    password: str


@app.post("/auth/login")
def login(datos: Login):
    with conexion() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.nombre, u.rol, u.sede_id, u.password_hash, u.activo,
                   s.nombre AS sede
            FROM usuarios u LEFT JOIN sedes s ON s.id = u.sede_id
            WHERE lower(u.correo) = lower(%s)
            """,
            (datos.correo.strip(),),
        )
        usuario = cur.fetchone()
    hash_guardado = usuario["password_hash"] if usuario else ""
    correcto = seguridad.verificar_password(datos.password, hash_guardado)
    if not usuario or not usuario["activo"] or not correcto:
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")
    return {
        "token": seguridad.crear_token(usuario["id"], secreto()),
        "usuario": datos_publicos(usuario),
    }


@app.get("/auth/yo")
def quien_soy(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
    return datos_publicos(usuario)


# ------------------------------------------------------------------
# Página de soporte (requiere login)
# ------------------------------------------------------------------
SQL_TICKETS = """
SELECT t.id, t.estado, t.prioridad, t.en_clase, t.descripcion,
       t.creado_en, t.atendido_en, t.resuelto_en, t.plazo_atencion,
       e.nombre AS equipo, te.nombre AS tipo_equipo,
       a.nombre AS ambiente, a.piso, s.nombre AS sede,
       f.descripcion AS falla, u.nombre AS tecnico
FROM tickets t
JOIN equipos e ON e.id = t.equipo_id
JOIN tipos_equipo te ON te.id = e.tipo_equipo_id
JOIN ambientes a ON a.id = e.ambiente_id
JOIN sedes s ON s.id = t.sede_id
JOIN tipos_falla f ON f.id = t.tipo_falla_id
LEFT JOIN usuarios u ON u.id = t.tecnico_id
"""

ORDEN_ACTIVOS = """
ORDER BY (t.estado = 'resuelto'),
         CASE t.prioridad WHEN 'critica' THEN 0 WHEN 'alta' THEN 1
                          WHEN 'media' THEN 2 ELSE 3 END,
         t.plazo_atencion NULLS LAST, t.creado_en DESC
"""


@app.get("/soporte/tickets")
def listar_tickets(
    estado: Literal["activos", "resueltos", "todos"] = "activos",
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        condiciones, params = [], []
        if sede is not None:
            condiciones.append("t.sede_id = %s")
            params.append(sede)
        if estado == "activos":
            condiciones.append("t.estado <> 'resuelto'")
        elif estado == "resueltos":
            condiciones.append("t.estado = 'resuelto'")
        sql = SQL_TICKETS
        if condiciones:
            sql += " WHERE " + " AND ".join(condiciones)
        sql += " ORDER BY t.resuelto_en DESC" if estado == "resueltos" else ORDEN_ACTIVOS
        sql += " LIMIT 200"
        cur.execute(sql, params)
        tickets = cur.fetchall()
        cur.execute("SELECT now() AS ahora")
        ahora = cur.fetchone()["ahora"]
    return {"ahora": ahora, "tickets": tickets}


def obtener_ticket(cur, usuario, ticket_id: int, bloquear: bool = False):
    """Busca un ticket respetando la sede del usuario; 404 si no existe o no es suyo."""
    sede = filtro_sede(usuario)
    sql = "SELECT id, sede_id, estado FROM tickets WHERE id = %s"
    params = [ticket_id]
    if sede is not None:
        sql += " AND sede_id = %s"
        params.append(sede)
    if bloquear:
        sql += " FOR UPDATE"
    cur.execute(sql, params)
    ticket = cur.fetchone()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    return ticket


@app.post("/soporte/tickets/{ticket_id}/atender")
def atender_ticket(
    ticket_id: int, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    """Primera acción de atención: marca el ticket 'en atención' y registra la hora."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        ticket = obtener_ticket(cur, usuario, ticket_id, bloquear=True)
        if ticket["estado"] != "nuevo":
            raise HTTPException(status_code=409, detail="Este ticket ya fue tomado o resuelto")
        cur.execute(
            """
            UPDATE tickets
            SET estado = 'en_atencion', tecnico_id = %s, atendido_en = now()
            WHERE id = %s
            """,
            (usuario["id"], ticket_id),
        )
        cur.execute(
            """
            INSERT INTO ticket_historial
                (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
            VALUES (%s, %s, 'nuevo', 'en_atencion', %s, 'Ticket tomado por soporte')
            """,
            (ticket_id, ticket["sede_id"], usuario["id"]),
        )
    return {"id": ticket_id, "estado": "en_atencion"}


class Resolucion(BaseModel):
    nota: str = Field(max_length=500)


@app.post("/soporte/tickets/{ticket_id}/resolver")
def resolver_ticket(
    ticket_id: int,
    datos: Resolucion,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """Cierra el ticket registrando la intervención realizada."""
    nota = datos.nota.strip()
    if len(nota) < 3:
        raise HTTPException(status_code=400, detail="Describe brevemente qué se hizo")
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        ticket = obtener_ticket(cur, usuario, ticket_id, bloquear=True)
        if ticket["estado"] == "resuelto":
            raise HTTPException(status_code=409, detail="Este ticket ya está resuelto")
        cur.execute(
            """
            UPDATE tickets
            SET estado = 'resuelto', resuelto_en = now(),
                tecnico_id = COALESCE(tecnico_id, %s),
                atendido_en = COALESCE(atendido_en, now())
            WHERE id = %s
            """,
            (usuario["id"], ticket_id),
        )
        cur.execute(
            """
            INSERT INTO ticket_historial
                (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
            VALUES (%s, %s, %s, 'resuelto', %s, %s)
            """,
            (ticket_id, ticket["sede_id"], ticket["estado"], usuario["id"], nota),
        )
    return {"id": ticket_id, "estado": "resuelto"}


class CambioPrioridad(BaseModel):
    prioridad: str = Field(max_length=10)


@app.post("/soporte/tickets/{ticket_id}/prioridad")
def cambiar_prioridad(
    ticket_id: int,
    datos: CambioPrioridad,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """El técnico ajusta la urgencia del ticket (crítica, alta, media o baja)."""
    nueva = datos.prioridad.strip().lower()
    if nueva not in ("critica", "alta", "media", "baja"):
        raise HTTPException(status_code=400, detail="Prioridad no válida")
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        ticket = obtener_ticket(cur, usuario, ticket_id, bloquear=True)
        if ticket["estado"] == "resuelto":
            raise HTTPException(status_code=409, detail="Este ticket ya está resuelto")
        cur.execute("SELECT prioridad FROM tickets WHERE id = %s", (ticket_id,))
        anterior = cur.fetchone()["prioridad"]
        if anterior != nueva:
            cur.execute("UPDATE tickets SET prioridad = %s WHERE id = %s", (nueva, ticket_id))
            cur.execute(
                """
                INSERT INTO ticket_historial
                    (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (ticket_id, ticket["sede_id"], ticket["estado"], ticket["estado"],
                 usuario["id"], "Prioridad cambiada de " + anterior + " a " + nueva),
            )
    return {"id": ticket_id, "prioridad": nueva}


@app.get("/soporte/tickets/{ticket_id}/historial")
def historial_ticket(
    ticket_id: int, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        obtener_ticket(cur, usuario, ticket_id)
        cur.execute(
            """
            SELECT h.estado_anterior, h.estado_nuevo, h.nota, h.creado_en,
                   u.nombre AS usuario
            FROM ticket_historial h
            LEFT JOIN usuarios u ON u.id = h.usuario_id
            WHERE h.ticket_id = %s
            ORDER BY h.creado_en, h.id
            """,
            (ticket_id,),
        )
        eventos = cur.fetchall()
    return {"eventos": eventos}


@app.get("/soporte/indicadores")
def indicadores(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    """Indicadores de gestión: primera respuesta, MTTR, por sede y fallas recurrentes."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        filtro, params = "", []
        if sede is not None:
            filtro, params = "WHERE t.sede_id = %s", [sede]

        cur.execute(
            f"""
            SELECT
              (count(*) FILTER (WHERE t.estado <> 'resuelto'))::int AS abiertos,
              count(*)::int AS total,
              ((avg(extract(epoch FROM (t.atendido_en - t.creado_en)))
                 FILTER (WHERE t.atendido_en IS NOT NULL)) / 60)::float8
                 AS primera_respuesta_min,
              ((avg(extract(epoch FROM (t.resuelto_en - t.creado_en)))
                 FILTER (WHERE t.resuelto_en IS NOT NULL)) / 60)::float8 AS mttr_min,
              (count(*) FILTER (
                 WHERE t.en_clase AND COALESCE(t.atendido_en, now()) > t.plazo_atencion
              ))::int AS en_clase_fuera_de_plazo
            FROM tickets t {filtro}
            """,
            params,
        )
        resumen = cur.fetchone()

        cur.execute(
            f"""
            SELECT s.nombre AS sede, count(*)::int AS tickets
            FROM tickets t JOIN sedes s ON s.id = t.sede_id {filtro}
            GROUP BY s.nombre ORDER BY tickets DESC
            """,
            params,
        )
        por_sede = cur.fetchall()

        cur.execute(
            f"""
            SELECT e.nombre AS equipo, a.nombre AS ambiente, s.nombre AS sede,
                   count(*)::int AS fallas
            FROM tickets t
            JOIN equipos e ON e.id = t.equipo_id
            JOIN ambientes a ON a.id = e.ambiente_id
            JOIN sedes s ON s.id = t.sede_id
            {filtro}
            GROUP BY e.id, e.nombre, a.nombre, s.nombre
            HAVING count(*) >= 2
            ORDER BY fallas DESC
            LIMIT 5
            """,
            params,
        )
        recurrentes = cur.fetchall()
    return {**resumen, "por_sede": por_sede, "fallas_recurrentes": recurrentes}


# ------------------------------------------------------------------
# Administración de usuarios (solo administrador)
# ------------------------------------------------------------------
class PrimerAdmin(BaseModel):
    nombre: str = Field(min_length=2, max_length=100)
    correo: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=8, max_length=200)


@app.post("/setup/primer-admin", status_code=201)
def primer_admin(datos: PrimerAdmin, x_setup_key: Optional[str] = Header(default=None)):
    """Crea el primer administrador. Solo funciona si no hay usuarios y se envía SETUP_KEY."""
    clave = os.environ.get("SETUP_KEY")
    if not clave:
        raise HTTPException(status_code=404, detail="No disponible")
    if not x_setup_key or not hmac.compare_digest(x_setup_key.encode(), clave.encode()):
        raise HTTPException(status_code=403, detail="Clave de instalación incorrecta")
    with conexion() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*)::int AS n FROM usuarios")
        if cur.fetchone()["n"] > 0:
            raise HTTPException(status_code=409, detail="Ya existe al menos un usuario")
        cur.execute(
            """
            INSERT INTO usuarios (sede_id, nombre, correo, password_hash, rol)
            VALUES (NULL, %s, lower(%s), %s, 'admin')
            RETURNING id
            """,
            (datos.nombre.strip(), datos.correo.strip(), seguridad.hashear_password(datos.password)),
        )
        nuevo = cur.fetchone()
    return {"id": nuevo["id"], "rol": "admin"}


class UsuarioNuevo(BaseModel):
    nombre: str = Field(min_length=2, max_length=100)
    correo: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    rol: Literal["tecnico", "admin"]
    sede_id: Optional[int] = None


@app.post("/admin/usuarios", status_code=201)
def crear_usuario(
    datos: UsuarioNuevo, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    with conexion() as conn, conn.cursor() as cur:
        exigir_admin(autenticar(cur, cred))
        if datos.rol == "tecnico" and datos.sede_id is None:
            raise HTTPException(status_code=400, detail="Un técnico necesita una sede")
        if datos.sede_id is not None:
            cur.execute("SELECT 1 FROM sedes WHERE id = %s", (datos.sede_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=400, detail="La sede indicada no existe")
        cur.execute("SELECT 1 FROM usuarios WHERE lower(correo) = lower(%s)", (datos.correo.strip(),))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Ya existe un usuario con ese correo")
        cur.execute(
            """
            INSERT INTO usuarios (sede_id, nombre, correo, password_hash, rol)
            VALUES (%s, %s, lower(%s), %s, %s)
            RETURNING id
            """,
            (
                datos.sede_id,
                datos.nombre.strip(),
                datos.correo.strip(),
                seguridad.hashear_password(datos.password),
                datos.rol,
            ),
        )
        nuevo = cur.fetchone()
    return {"id": nuevo["id"], "rol": datos.rol}


@app.get("/admin/usuarios")
def listar_usuarios(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    with conexion() as conn, conn.cursor() as cur:
        exigir_admin(autenticar(cur, cred))
        cur.execute(
            """
            SELECT u.id, u.nombre, u.correo, u.rol, u.activo, s.nombre AS sede
            FROM usuarios u LEFT JOIN sedes s ON s.id = u.sede_id
            ORDER BY u.id
            """
        )
        usuarios = cur.fetchall()
    return {"usuarios": usuarios}


class CambioActivo(BaseModel):
    activo: bool


@app.post("/admin/usuarios/{usuario_id}/activo")
def activar_usuario(
    usuario_id: int,
    datos: CambioActivo,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    with conexion() as conn, conn.cursor() as cur:
        admin = autenticar(cur, cred)
        exigir_admin(admin)
        if usuario_id == admin["id"] and not datos.activo:
            raise HTTPException(status_code=400, detail="No puedes desactivarte a ti mismo")
        cur.execute(
            "UPDATE usuarios SET activo = %s WHERE id = %s RETURNING id",
            (datos.activo, usuario_id),
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"id": usuario_id, "activo": datos.activo}
