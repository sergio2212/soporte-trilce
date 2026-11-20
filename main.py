"""API del sistema de soporte técnico multisede Trilce (versión 2).

Incluye: reporte del docente por QR, login con roles (técnico / administrador),
gestión de tickets para soporte, historial, indicadores y administración de usuarios.
"""
import hmac
import os
import re
import secrets
from contextlib import contextmanager
from typing import Literal, Optional

import psycopg2
import psycopg2.extras
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

import correos
import seguridad

DATABASE_URL = os.environ.get("DATABASE_URL")
# En producción pon aquí las URLs de tus páginas, separadas por coma.
URL_DOCENTE = os.environ.get("URL_DOCENTE", "https://soporte-trilce-docente.onrender.com")
ORIGENES = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
# Dominios de correo aceptados para docentes, separados por coma (ej. "trilce.edu.pe").
# Si la variable no existe, se usa el del colegio. Déjala vacía ("") para aceptar cualquier correo.
DOMINIOS_DOCENTES = [d.strip().lower().lstrip("@") for d in os.environ.get("DOMINIO_DOCENTES", "trilce.edu.pe").split(",") if d.strip()]

# ------------------------------------------------------------------
# Regla de prioridad PROVISIONAL (hasta confirmar la sección 5 del documento).
# Charter: la prioridad depende de si hay una clase activa; el objetivo de
# primera respuesta en clase activa es menor a 8 minutos.
# ------------------------------------------------------------------
# El docente ya no indica si está en clase: todo ticket nace con prioridad "media" y
# este plazo de primera respuesta (PROVISIONAL). El equipo de Soporte ajusta la urgencia.
PLAZO_RESPUESTA_MIN = 15
PRIORIDAD_INICIAL = "media"

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


def notificar_estado(ticket_id: int):
    """Envía al docente el correo con el estado actual de su reporte (se corre en segundo plano)."""
    try:
        with conexion() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.id, t.estado, d.correo, d.nombre AS docente_nombre, s.nombre AS sede, te.nombre AS equipo,
                       f.descripcion AS falla, t.aula_reportada AS aula, t.piso_reportado AS piso
                FROM tickets t
                JOIN docentes d ON d.id = t.docente_id
                JOIN sedes s ON s.id = t.sede_id
                JOIN tipos_falla f ON f.id = t.tipo_falla_id
                JOIN tipos_equipo te ON te.id = f.tipo_equipo_id
                WHERE t.id = %s
                """,
                (ticket_id,),
            )
            t = cur.fetchone()
        if t:
            asunto, cuerpo, plano = correos.armar_correo(t, URL_DOCENTE)
            correos.enviar(t["correo"], asunto, cuerpo, plano)
    except Exception as ex:   # noqa: BLE001  (el correo nunca debe romper el flujo)
        print("notificar_estado falló:", repr(ex))


def calcular_prioridad(tipo_falla_id: int):
    """Devuelve (prioridad, plazo_en_minutos). Regla provisional: ver arriba."""
    return PRIORIDAD_INICIAL, PLAZO_RESPUESTA_MIN


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


ROLES_SOPORTE = ("tecnico", "admin")
ROLES_CAMPO = ("tecnico_campo", "admin")


def autenticar(cur, cred: Optional[HTTPAuthorizationCredentials], roles=ROLES_SOPORTE):
    """Devuelve el usuario del token, verificando en la base que siga activo y su rol.

    roles=None acepta a cualquiera. 'tecnico' y 'admin' usan la página de Soporte;
    'tecnico_campo' (técnico que va al aula) solo usa la página del técnico."""
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
    if roles is not None and usuario["rol"] not in roles:
        raise HTTPException(status_code=403, detail="Tu usuario no tiene acceso a esta sección")
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
ORDEN_EQUIPOS = ["PC", "Internet", "Impresora", "Proyector"]


def _catalogo_tipos(cur):
    cur.execute(
        """
        SELECT te.id AS tipo_id, te.nombre AS tipo, f.id, f.descripcion, f.es_otro
        FROM tipos_falla f JOIN tipos_equipo te ON te.id = f.tipo_equipo_id
        WHERE f.activo
        ORDER BY te.id, f.orden, f.id
        """
    )
    tipos = {}
    for f in cur.fetchall():
        t = tipos.setdefault(f["tipo_id"], {"id": f["tipo_id"], "nombre": f["tipo"], "fallas": []})
        t["fallas"].append({"id": f["id"], "descripcion": f["descripcion"], "es_otro": f["es_otro"]})
    return sorted(
        tipos.values(),
        key=lambda t: ORDEN_EQUIPOS.index(t["nombre"]) if t["nombre"] in ORDEN_EQUIPOS else 99,
    )


@app.get("/catalogo")
def catalogo():
    """Página del docente sin QR: lista de sedes y catálogo de equipos con sus fallas."""
    with conexion() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nombre FROM sedes WHERE activa ORDER BY nombre")
        sedes = cur.fetchall()
        return {"sedes": sedes, "tipos": _catalogo_tipos(cur)}


@app.get("/qr/{token}")
def leer_qr(token: str):
    """Si el docente entra por un QR: devuelve su sede ya identificada y el catálogo."""
    with conexion() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.id AS sede_id, s.nombre AS sede
            FROM equipos e JOIN sedes s ON s.id = e.sede_id
            WHERE e.token_qr = %s AND e.activo
            """,
            (token,),
        )
        qr = cur.fetchone()
        if not qr:
            raise HTTPException(status_code=404, detail="QR no válido")
        return {"sede_id": qr["sede_id"], "sede": qr["sede"], "tipos": _catalogo_tipos(cur)}


class TicketNuevo(BaseModel):
    token_qr: Optional[str] = Field(default=None, max_length=200)
    sede_id: Optional[int] = None
    tipo_falla_id: int
    aula: str = Field(min_length=1, max_length=40)
    piso: str = Field(min_length=1, max_length=20)
    descripcion: Optional[str] = Field(default=None, max_length=300)
    correo: str = Field(min_length=5, max_length=200)
    nombre: Optional[str] = Field(default=None, max_length=60)      # solo la primera vez
    apellido: Optional[str] = Field(default=None, max_length=60)


REGEX_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
REGEX_NOMBRE = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' .-]{2,60}$")


def normalizar_correo(correo: str) -> str:
    correo = correo.strip().lower()
    if not REGEX_CORREO.match(correo):
        raise HTTPException(status_code=400, detail="Escribe un correo válido")
    if DOMINIOS_DOCENTES and correo.split("@")[1] not in DOMINIOS_DOCENTES:
        raise HTTPException(status_code=400, detail="Usa tu correo institucional (@" + DOMINIOS_DOCENTES[0] + ")")
    return correo


def identificar_docente(cur, correo: str, nombre: Optional[str], apellido: Optional[str]):
    """Registro al vuelo: si el correo ya existe se usa; si no, se crea con nombre y apellido.
    Va dentro de la misma transacción que el ticket: si el ticket falla, tampoco queda el docente."""
    correo = normalizar_correo(correo)
    nombre = " ".join((nombre or "").split())
    apellido = " ".join((apellido or "").split())
    cur.execute("SELECT id, correo, nombre, apellido FROM docentes WHERE correo = %s", (correo,))
    docente = cur.fetchone()
    if docente and (docente["nombre"] or "").strip():
        return docente                                   # ya identificado: no se piden ni se devuelven nombres
    if not REGEX_NOMBRE.match(nombre) or not REGEX_NOMBRE.match(apellido):
        raise HTTPException(status_code=422, detail="Escribe tus nombres y apellidos (solo letras)")
    cur.execute(
        """
        INSERT INTO docentes (correo, nombre, apellido) VALUES (%s, %s, %s)
        ON CONFLICT (correo) DO UPDATE SET nombre = COALESCE(NULLIF(docentes.nombre, ''), EXCLUDED.nombre),
                                           apellido = COALESCE(NULLIF(docentes.apellido, ''), EXCLUDED.apellido)
        RETURNING id, correo, nombre, apellido
        """,
        (correo, nombre, apellido),
    )
    return cur.fetchone()


class DocenteVerificar(BaseModel):
    correo: str = Field(min_length=5, max_length=200)


@app.post("/docentes/verificar")
def docente_verificar(datos: DocenteVerificar):
    """Paso 1: ¿hay que pedirle los nombres? Nunca devuelve nombres ni apellidos."""
    correo = normalizar_correo(datos.correo)
    with conexion() as conn, conn.cursor() as cur:
        cur.execute("SELECT nombre FROM docentes WHERE correo = %s", (correo,))
        d = cur.fetchone()
    return {"existe": bool(d), "pide_nombre": (not d) or not (d["nombre"] or "").strip()}


@app.post("/tickets", status_code=201)
def crear_ticket(datos: TicketNuevo, tareas: BackgroundTasks):
    """El docente presiona 'Registrar problema'. Se identifica por su correo institucional."""
    aula, piso = datos.aula.strip(), datos.piso.strip()
    if not aula or not piso:
        raise HTTPException(status_code=400, detail="Indica el aula y el piso")
    with conexion() as conn, conn.cursor() as cur:
        docente = identificar_docente(cur, datos.correo, datos.nombre, datos.apellido)
        if datos.token_qr:
            cur.execute(
                "SELECT id, sede_id FROM equipos WHERE token_qr = %s AND activo",
                (datos.token_qr,),
            )
            equipo = cur.fetchone()
            if not equipo:
                raise HTTPException(status_code=404, detail="QR no válido")
        else:
            cur.execute("SELECT id FROM sedes WHERE id = %s AND activa", (datos.sede_id,))
            sede = cur.fetchone()
            if not sede:
                raise HTTPException(status_code=400, detail="Elige una sede válida")
            equipo = {"id": None, "sede_id": sede["id"]}   # reporte sin equipo registrado

        cur.execute(
            "SELECT id, tipo_equipo_id FROM tipos_falla WHERE id = %s AND activo",
            (datos.tipo_falla_id,),
        )
        falla = cur.fetchone()
        if not falla:
            raise HTTPException(status_code=400, detail="Falla no válida")

        prioridad, plazo_min = calcular_prioridad(datos.tipo_falla_id)
        token_seguimiento = secrets.token_urlsafe(16)

        cur.execute(
            """
            INSERT INTO tickets (sede_id, equipo_id, tipo_falla_id, descripcion,
                                 en_clase, contacto_docente, prioridad, token_seguimiento,
                                 plazo_atencion, aula_reportada, piso_reportado, tipo_equipo_id,
                                 docente_id)
            VALUES (%s, %s, %s, %s, FALSE, %s, %s, %s,
                    now() + make_interval(mins => %s), %s, %s, %s, %s)
            RETURNING id, estado, prioridad, token_seguimiento
            """,
            (
                equipo["sede_id"],
                equipo["id"],
                datos.tipo_falla_id,
                (datos.descripcion or "").strip() or None,
                docente["correo"],
                prioridad,
                token_seguimiento,
                plazo_min,
                aula,
                piso,
                falla["tipo_equipo_id"],
                docente["id"],
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
    tareas.add_task(notificar_estado, ticket["id"])
    return ticket


@app.get("/seguimiento/{token}")
def seguimiento(token: str):
    """Enlace de seguimiento: el docente ve en qué estado va su reporte."""
    with conexion() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.estado, t.prioridad, t.creado_en, t.atendido_en, t.resuelto_en,
                   te.nombre AS equipo, f.descripcion AS falla,
                   t.aula_reportada AS aula, t.piso_reportado AS piso
            FROM tickets t
            JOIN tipos_falla f ON f.id = t.tipo_falla_id
            JOIN tipos_equipo te ON te.id = f.tipo_equipo_id
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
        usuario = autenticar(cur, cred, roles=None)
    return datos_publicos(usuario)


# ------------------------------------------------------------------
# Página de soporte (requiere login)
# ------------------------------------------------------------------
SQL_TICKETS = """
SELECT t.id, t.estado, t.prioridad, t.en_clase, t.descripcion,
       t.creado_en, t.atendido_en, t.resuelto_en, t.plazo_atencion,
       te.nombre AS equipo, te.nombre AS tipo_equipo,
       COALESCE(t.aula_reportada, a.nombre) AS ambiente,
       COALESCE(t.piso_reportado, a.piso::text) AS piso, s.nombre AS sede,
       f.descripcion AS falla, u.nombre AS tecnico,
       CASE WHEN d.id IS NULL THEN NULL
            ELSE COALESCE(NULLIF(trim(coalesce(d.nombre,'') || ' ' || coalesce(d.apellido,'')), ''), d.correo)
       END AS docente, d.correo AS docente_correo,
       t.tecnico_campo_id, tc.nombre AS tecnico_campo, t.tecnico_enviado_en
FROM tickets t
LEFT JOIN equipos e ON e.id = t.equipo_id
LEFT JOIN ambientes a ON a.id = e.ambiente_id
JOIN sedes s ON s.id = t.sede_id
JOIN tipos_falla f ON f.id = t.tipo_falla_id
JOIN tipos_equipo te ON te.id = f.tipo_equipo_id
LEFT JOIN usuarios u ON u.id = t.tecnico_id
LEFT JOIN usuarios tc ON tc.id = t.tecnico_campo_id
LEFT JOIN docentes d ON d.id = t.docente_id
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


def obtener_ticket(cur, usuario, ticket_id: int, bloquear: bool = False):  # noqa: D401
    """Busca un ticket respetando la sede del usuario; 404 si no existe o no es suyo."""
    sede = filtro_sede(usuario)
    sql = "SELECT id, sede_id, estado, tecnico_campo_id FROM tickets WHERE id = %s"
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
    ticket_id: int,
    tareas: BackgroundTasks,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
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
    tareas.add_task(notificar_estado, ticket_id)
    return {"id": ticket_id, "estado": "en_atencion"}


ETAPAS = ["nuevo", "en_atencion", "en_camino", "solucionando", "resuelto"]


class EnvioTecnico(BaseModel):
    tecnico_id: Optional[int] = None     # None = cualquier técnico de la sede


@app.get("/soporte/tecnicos")
def listar_tecnicos(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    """Técnicos de campo disponibles para enviar a un aula (los de la sede del usuario)."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        sql = """
            SELECT u.id, u.nombre, u.sede_id, s.nombre AS sede,
                   (SELECT count(*) FROM tickets t
                     WHERE t.tecnico_campo_id = u.id AND t.estado IN ('en_camino','solucionando')) AS ocupado_con
            FROM usuarios u LEFT JOIN sedes s ON s.id = u.sede_id
            WHERE u.rol = 'tecnico_campo' AND u.activo
        """
        params = []
        if sede is not None:
            sql += " AND u.sede_id = %s"
            params.append(sede)
        cur.execute(sql + " ORDER BY u.nombre", params)
        tecnicos = cur.fetchall()
    return {"tecnicos": tecnicos}


@app.post("/soporte/tickets/{ticket_id}/enviar-tecnico")
def enviar_tecnico(
    ticket_id: int,
    datos: EnvioTecnico,
    tareas: BackgroundTasks,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """Soporte llama a un técnico. Desde aquí solo el técnico puede dar el problema por resuelto."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        ticket = obtener_ticket(cur, usuario, ticket_id, bloquear=True)
        if ticket["estado"] == "nuevo":
            raise HTTPException(status_code=409, detail="Primero atiende el ticket")
        if ticket["estado"] == "resuelto":
            raise HTTPException(status_code=409, detail="Este ticket ya está resuelto")
        if ticket["estado"] != "en_atencion":
            raise HTTPException(status_code=409, detail="Ya hay un técnico en este ticket")
        nombre_tecnico = None
        if datos.tecnico_id is not None:
            cur.execute(
                "SELECT id, nombre, sede_id FROM usuarios WHERE id = %s AND rol = 'tecnico_campo' AND activo",
                (datos.tecnico_id,),
            )
            tec = cur.fetchone()
            if not tec or tec["sede_id"] != ticket["sede_id"]:
                raise HTTPException(status_code=400, detail="Ese técnico no está disponible en esta sede")
            nombre_tecnico = tec["nombre"]
        cur.execute(
            """
            UPDATE tickets
            SET estado = 'en_camino', tecnico_campo_id = %s, tecnico_enviado_en = now()
            WHERE id = %s
            """,
            (datos.tecnico_id, ticket_id),
        )
        nota = "Técnico en camino: " + (nombre_tecnico or "cualquier técnico de la sede")
        cur.execute(
            """
            INSERT INTO ticket_historial
                (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
            VALUES (%s, %s, 'en_atencion', 'en_camino', %s, %s)
            """,
            (ticket_id, ticket["sede_id"], usuario["id"], nota),
        )
    tareas.add_task(notificar_estado, ticket_id)
    return {"id": ticket_id, "estado": "en_camino", "tecnico": nombre_tecnico}


# ------------------------------------------------------------------
# Página del técnico (rol tecnico_campo): él decide si se resolvió o no
# ------------------------------------------------------------------
@app.get("/tecnico/tickets")
def tecnico_tickets(
    estado: Literal["pendientes", "resueltos"] = "pendientes",
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred, roles=ROLES_CAMPO)
        sede = filtro_sede(usuario)
        condiciones, params = [], []
        if sede is not None:
            condiciones.append("t.sede_id = %s")
            params.append(sede)
        if estado == "pendientes":
            condiciones.append("t.estado IN ('en_camino', 'solucionando')")
            if usuario["rol"] != "admin":
                condiciones.append("(t.tecnico_campo_id IS NULL OR t.tecnico_campo_id = %s)")
                params.append(usuario["id"])
            orden = " ORDER BY t.tecnico_enviado_en NULLS LAST, t.creado_en"
        else:
            condiciones.append("t.estado = 'resuelto'")
            if usuario["rol"] != "admin":
                condiciones.append("t.tecnico_campo_id = %s")
                params.append(usuario["id"])
            orden = " ORDER BY t.resuelto_en DESC LIMIT 30"
        cur.execute(SQL_TICKETS + " WHERE " + " AND ".join(condiciones) + orden, params)
        tickets = cur.fetchall()
        cur.execute("SELECT now() AS ahora")
        ahora = cur.fetchone()["ahora"]
    return {"ahora": ahora, "tickets": tickets}


def ticket_de_tecnico(cur, usuario, ticket_id: int):
    ticket = obtener_ticket(cur, usuario, ticket_id, bloquear=True)
    if ticket["estado"] not in ("en_camino", "solucionando"):
        raise HTTPException(status_code=409, detail="Este ticket no está pendiente de técnico")
    if (
        usuario["rol"] != "admin"
        and ticket["tecnico_campo_id"] is not None
        and ticket["tecnico_campo_id"] != usuario["id"]
    ):
        raise HTTPException(status_code=409, detail="Este ticket fue asignado a otro técnico")
    return ticket


class NotaTecnico(BaseModel):
    nota: str = Field(max_length=500)


@app.post("/tecnico/tickets/{ticket_id}/solucionando")
def tecnico_solucionando(
    ticket_id: int,
    tareas: BackgroundTasks,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """El técnico llegó y empezó a trabajar."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred, roles=ROLES_CAMPO)
        ticket = ticket_de_tecnico(cur, usuario, ticket_id)
        if ticket["estado"] == "solucionando":
            raise HTTPException(status_code=409, detail="Ya estás solucionando este ticket")
        cur.execute(
            "UPDATE tickets SET estado = 'solucionando', tecnico_campo_id = COALESCE(tecnico_campo_id, %s) WHERE id = %s",
            (usuario["id"], ticket_id),
        )
        cur.execute(
            """
            INSERT INTO ticket_historial
                (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
            VALUES (%s, %s, 'en_camino', 'solucionando', %s, 'Técnico solucionando el problema')
            """,
            (ticket_id, ticket["sede_id"], usuario["id"]),
        )
    tareas.add_task(notificar_estado, ticket_id)
    return {"id": ticket_id, "estado": "solucionando"}


@app.post("/tecnico/tickets/{ticket_id}/resolver")
def tecnico_resolver(
    ticket_id: int,
    datos: NotaTecnico,
    tareas: BackgroundTasks,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """Solo el técnico puede marcar el problema como resuelto."""
    nota = datos.nota.strip()
    if len(nota) < 3:
        raise HTTPException(status_code=400, detail="Describe brevemente qué se hizo")
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred, roles=ROLES_CAMPO)
        ticket = ticket_de_tecnico(cur, usuario, ticket_id)
        cur.execute(
            """
            UPDATE tickets
            SET estado = 'resuelto', resuelto_en = now(),
                tecnico_campo_id = COALESCE(tecnico_campo_id, %s),
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
            (ticket_id, ticket["sede_id"], ticket["estado"], usuario["id"], "Técnico: " + nota),
        )
    tareas.add_task(notificar_estado, ticket_id)
    return {"id": ticket_id, "estado": "resuelto"}


@app.post("/tecnico/tickets/{ticket_id}/no-resuelto")
def tecnico_no_resuelto(
    ticket_id: int,
    datos: NotaTecnico,
    tareas: BackgroundTasks,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """El técnico no pudo resolverlo: el ticket vuelve a Soporte con su explicación."""
    nota = datos.nota.strip()
    if len(nota) < 3:
        raise HTTPException(status_code=400, detail="Cuéntale a Soporte por qué no se pudo resolver")
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred, roles=ROLES_CAMPO)
        ticket = ticket_de_tecnico(cur, usuario, ticket_id)
        cur.execute(
            "UPDATE tickets SET estado = 'en_atencion', tecnico_campo_id = NULL, tecnico_enviado_en = NULL WHERE id = %s",
            (ticket_id,),
        )
        cur.execute(
            """
            INSERT INTO ticket_historial
                (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
            VALUES (%s, %s, %s, 'en_atencion', %s, %s)
            """,
            (ticket_id, ticket["sede_id"], ticket["estado"], usuario["id"], "Técnico: NO resuelto. " + nota),
        )
    tareas.add_task(notificar_estado, ticket_id)
    return {"id": ticket_id, "estado": "en_atencion"}


# ------------------------------------------------------------------
# Soporte: qué docentes reportan y con qué frecuencia
# ------------------------------------------------------------------
@app.get("/soporte/docentes")
def soporte_docentes(
    dias: int = 0, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    """Ranking de docentes por cantidad de incidencias (dias=0: todo el historial)."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        condiciones, params = ["t.docente_id IS NOT NULL"], []
        if sede is not None:
            condiciones.append("t.sede_id = %s")
            params.append(sede)
        if dias and dias > 0:
            condiciones.append("t.creado_en >= now() - make_interval(days => %s)")
            params.append(min(dias, 3650))
        cur.execute(
            f"""
            SELECT d.id, d.correo,
                   COALESCE(NULLIF(trim(coalesce(d.nombre,'') || ' ' || coalesce(d.apellido,'')), ''), d.correo) AS nombre,
                   count(*) AS total,
                   count(*) FILTER (WHERE t.estado <> 'resuelto') AS abiertos,
                   max(t.creado_en) AS ultimo,
                   mode() WITHIN GROUP (ORDER BY te.nombre) AS equipo_frecuente
            FROM tickets t
            JOIN docentes d ON d.id = t.docente_id
            JOIN tipos_equipo te ON te.id = t.tipo_equipo_id
            WHERE {" AND ".join(condiciones)}
            GROUP BY d.id
            ORDER BY total DESC, ultimo DESC
            LIMIT 100
            """,
            params,
        )
        docentes = cur.fetchall()
    return {
        "docentes": docentes,
        "total_docentes": len(docentes),
        "total_incidencias": sum(int(x["total"]) for x in docentes),
    }


@app.get("/soporte/docentes/{docente_id}/tickets")
def soporte_docente_tickets(
    docente_id: int, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        condiciones, params = ["t.docente_id = %s"], [docente_id]
        if sede is not None:
            condiciones.append("t.sede_id = %s")
            params.append(sede)
        cur.execute(
            SQL_TICKETS + " WHERE " + " AND ".join(condiciones) + " ORDER BY t.creado_en DESC LIMIT 50",
            params,
        )
        tickets = cur.fetchall()
    return {"tickets": tickets}


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
                 WHERE COALESCE(t.atendido_en, now()) > t.plazo_atencion
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
            SELECT te.nombre AS equipo,
                   COALESCE(t.aula_reportada, a.nombre) AS ambiente, s.nombre AS sede,
                   count(*)::int AS fallas
            FROM tickets t
            LEFT JOIN equipos e ON e.id = t.equipo_id
            LEFT JOIN ambientes a ON a.id = e.ambiente_id
            JOIN tipos_falla f ON f.id = t.tipo_falla_id
            JOIN tipos_equipo te ON te.id = f.tipo_equipo_id
            JOIN sedes s ON s.id = t.sede_id
            {filtro}
            GROUP BY te.nombre, COALESCE(t.aula_reportada, a.nombre), s.nombre
            HAVING count(*) >= 2
            ORDER BY fallas DESC
            LIMIT 5
            """,
            params,
        )
        recurrentes = cur.fetchall()
    return {**resumen, "por_sede": por_sede, "fallas_recurrentes": recurrentes}


# ------------------------------------------------------------------
# Activos tecnológicos y sedes (técnicos: solo su sede; admin: todas)
# ------------------------------------------------------------------
ESTADOS_ACTIVO = ("operativo", "en_mantenimiento", "en_revision", "baja")
AMBIENTE_QR = "Código QR de la sede"      # ambiente interno donde viven los QR por sede


@app.get("/soporte/activos")
def listar_activos(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        sql = """
            SELECT e.id, e.codigo, e.nombre, te.nombre AS tipo, s.id AS sede_id, s.nombre AS sede,
                   a.nombre AS ambiente, a.piso, e.estado, e.ultimo_mantenimiento
            FROM equipos e
            JOIN tipos_equipo te ON te.id = e.tipo_equipo_id
            JOIN sedes s ON s.id = e.sede_id
            JOIN ambientes a ON a.id = e.ambiente_id
            WHERE e.activo AND NOT e.es_punto_qr
        """
        params = []
        if sede is not None:
            sql += " AND e.sede_id = %s"
            params.append(sede)
        sql += " ORDER BY s.nombre, a.nombre, e.nombre"
        cur.execute(sql, params)
        return {"activos": cur.fetchall()}


class ActivoNuevo(BaseModel):
    sede_id: Optional[int] = None
    ambiente: str = Field(min_length=1, max_length=60)
    piso: Optional[int] = Field(default=None, ge=0, le=20)
    tipo_equipo_id: int
    nombre: str = Field(min_length=2, max_length=80)
    codigo: Optional[str] = Field(default=None, max_length=30)


@app.post("/soporte/activos", status_code=201)
def crear_activo(
    datos: ActivoNuevo, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede_id = filtro_sede(usuario)
        if sede_id is None:                      # administrador: debe elegir la sede
            sede_id = datos.sede_id
            cur.execute("SELECT 1 FROM sedes WHERE id = %s AND activa", (sede_id,))
            if sede_id is None or not cur.fetchone():
                raise HTTPException(status_code=400, detail="Elige una sede válida")
        cur.execute("SELECT 1 FROM tipos_equipo WHERE id = %s", (datos.tipo_equipo_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=400, detail="Tipo de equipo no válido")

        nombre_amb = datos.ambiente.strip()
        if nombre_amb[:1].isdigit():
            nombre_amb = "Aula " + nombre_amb
        if nombre_amb == AMBIENTE_QR:
            raise HTTPException(status_code=400, detail="Nombre de ambiente no permitido")
        codigo = (datos.codigo or "").strip().upper() or None
        if codigo:
            cur.execute("SELECT 1 FROM equipos WHERE codigo = %s", (codigo,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Ya existe un activo con ese código")

        cur.execute(
            "SELECT id FROM ambientes WHERE sede_id = %s AND lower(nombre) = lower(%s)",
            (sede_id, nombre_amb),
        )
        amb = cur.fetchone()
        if not amb:
            cur.execute(
                "INSERT INTO ambientes (sede_id, nombre, piso) VALUES (%s, %s, %s) RETURNING id",
                (sede_id, nombre_amb, datos.piso),
            )
            amb = cur.fetchone()
        cur.execute(
            """
            INSERT INTO equipos (sede_id, ambiente_id, tipo_equipo_id, nombre, token_qr, codigo)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """,
            (sede_id, amb["id"], datos.tipo_equipo_id, datos.nombre.strip(),
             "act-" + secrets.token_urlsafe(8), codigo),
        )
        nuevo = cur.fetchone()
        if not codigo:
            cur.execute(
                "UPDATE equipos SET codigo = %s WHERE id = %s",
                ("ACT-" + str(nuevo["id"]).zfill(4), nuevo["id"]),
            )
    return {"id": nuevo["id"]}


class CambioEstadoActivo(BaseModel):
    estado: Optional[str] = Field(default=None, max_length=20)
    mantenimiento_hoy: bool = False


@app.post("/soporte/activos/{activo_id}")
def actualizar_activo(
    activo_id: int,
    datos: CambioEstadoActivo,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    if datos.estado is not None and datos.estado not in ESTADOS_ACTIVO:
        raise HTTPException(status_code=400, detail="Estado no válido")
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        sql = "SELECT id FROM equipos WHERE id = %s AND activo AND NOT es_punto_qr"
        params = [activo_id]
        if sede is not None:
            sql += " AND sede_id = %s"
            params.append(sede)
        cur.execute(sql, params)
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Activo no encontrado")
        if datos.estado is not None:
            cur.execute("UPDATE equipos SET estado = %s WHERE id = %s", (datos.estado, activo_id))
        if datos.mantenimiento_hoy:
            cur.execute("UPDATE equipos SET ultimo_mantenimiento = CURRENT_DATE WHERE id = %s", (activo_id,))
    return {"id": activo_id}


@app.get("/soporte/sedes")
def listar_sedes(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        extra, params = ("AND s.id = %s", [sede]) if sede is not None else ("", [])
        cur.execute(
            f"""
            SELECT s.id, s.nombre,
              (SELECT count(*) FROM equipos e
                WHERE e.sede_id = s.id AND e.activo AND NOT e.es_punto_qr)::int AS activos,
              (SELECT count(*) FROM tickets t
                WHERE t.sede_id = s.id AND t.estado <> 'resuelto')::int AS tickets_abiertos,
              (SELECT count(*) FROM tickets t WHERE t.sede_id = s.id)::int AS tickets_total
            FROM sedes s WHERE s.activa {extra} ORDER BY s.nombre
            """,
            params,
        )
        sedes = cur.fetchall()
        cur.execute(
            """
            SELECT a.id, a.sede_id, a.nombre, a.piso,
                   count(e.id) FILTER (WHERE e.activo AND NOT e.es_punto_qr)::int AS activos
            FROM ambientes a LEFT JOIN equipos e ON e.ambiente_id = a.id
            WHERE a.nombre <> %s
            GROUP BY a.id ORDER BY a.piso NULLS LAST, a.nombre
            """,
            (AMBIENTE_QR,),
        )
        ambientes = cur.fetchall()
    for s_ in sedes:
        s_["ambientes"] = [a for a in ambientes if a["sede_id"] == s_["id"]]
    return {"sedes": sedes}


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
    rol: Literal["tecnico", "admin", "tecnico_campo"]
    sede_id: Optional[int] = None


@app.post("/admin/usuarios", status_code=201)
def crear_usuario(
    datos: UsuarioNuevo, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    with conexion() as conn, conn.cursor() as cur:
        exigir_admin(autenticar(cur, cred))
        if datos.rol in ("tecnico", "tecnico_campo") and datos.sede_id is None:
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
