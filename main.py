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

import unicodedata
import correos
import seguridad

DATABASE_URL = os.environ.get("DATABASE_URL")
# En producción pon aquí las URLs de tus páginas, separadas por coma.
URL_DOCENTE = os.environ.get("URL_DOCENTE", "https://soporte-trilce-docente.onrender.com")
ORIGENES = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
# Dominios de correo aceptados para docentes, separados por coma (por defecto Gmail, Hotmail, Yahoo y Outlook).
# Si la variable no existe, se usa el del colegio. Déjala vacía ("") para aceptar cualquier correo.
DOMINIOS_DOCENTES = [d.strip().lower().lstrip("@") for d in os.environ.get("DOMINIO_DOCENTES", "gmail.com,hotmail.com,yahoo.com,outlook.com").split(",") if d.strip()]
if DOMINIOS_DOCENTES and "ucss.pe" not in DOMINIOS_DOCENTES:
    DOMINIOS_DOCENTES.append("ucss.pe")          # correo institucional

# ------------------------------------------------------------------
# SLA (definido por el profesor)
#   Prioridad según el equipo con falla: PC = crítica, Proyector = media, Impresora = baja
#   (Internet y Monitor, que no se definieron, quedan en media).
#   Si el docente NO está en clase, la prioridad baja un nivel.
#   Plazo de atención: crítica 15 min, media 30 min, baja 50 min.
# ------------------------------------------------------------------
PLAZOS_SLA_MIN = {"critica": 15, "media": 30, "baja": 50}
PRIORIDAD_POR_EQUIPO = {"pc": "critica", "proyector": "media", "impresora": "baja"}
BAJAR_PRIORIDAD = {"critica": "media", "media": "baja", "baja": "baja"}

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
                SELECT t.id, t.estado, t.token_seguimiento, d.correo, d.nombre AS docente_nombre, s.nombre AS sede, te.nombre AS equipo,
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


def calcular_prioridad(cur, tipo_falla_id: int, en_clase: bool):
    """Devuelve (prioridad, plazo_en_minutos) según el SLA."""
    cur.execute(
        "SELECT te.nombre FROM tipos_falla f JOIN tipos_equipo te ON te.id = f.tipo_equipo_id WHERE f.id = %s",
        (tipo_falla_id,),
    )
    fila = cur.fetchone()
    prioridad = PRIORIDAD_POR_EQUIPO.get((fila["nombre"] if fila else "").strip().lower(), "media")
    if not en_clase:
        prioridad = BAJAR_PRIORIDAD[prioridad]
    return prioridad, PLAZOS_SLA_MIN[prioridad]


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


ROLES_SOPORTE = ("tecnico", "admin")   # pueden VER la información (cada uno según su sede)
ROLES_GESTION = ("tecnico",)           # solo Soporte gestiona: atender, en camino y resolver
ROLES_INVENTARIO = ("admin",)          # el inventario (activos) solo lo ve y modifica el administrador


def autenticar(cur, cred: Optional[HTTPAuthorizationCredentials], roles=ROLES_SOPORTE):
    """Devuelve el usuario del token, verificando en la base que siga activo y su rol.

    roles=None acepta a cualquiera. 'tecnico' y 'admin' usan la página de Soporte;
    El administrador solo observa; Soporte gestiona."""
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
    """None = ve todas las sedes (administrador). Cada cuenta de Soporte ve solo su sede."""
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
    piso: Optional[str] = Field(default=None, max_length=20)      # se deduce del aula (505 = piso 5)
    en_clase: Optional[bool] = None
    descripcion: Optional[str] = Field(default=None, max_length=300)
    correo: str = Field(min_length=5, max_length=200)
    nombre: Optional[str] = Field(default=None, max_length=60)      # solo la primera vez
    apellido: Optional[str] = Field(default=None, max_length=60)


REGEX_CORREO = re.compile(r"^[a-z0-9]+([._-][a-z0-9]+)*@[a-z0-9]+([.-][a-z0-9]+)*\.(com|pe)$")   # dominio terminado en .com o .pe
DOMINIOS_CONOCIDOS = {"gmail", "hotmail", "yahoo", "outlook", "live", "icloud", "ucss", "msn", "protonmail"}
REGEX_NOMBRE = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' .-]{2,60}$")
REGEX_AULA = re.compile(r"^[1-6]0[1-6]$")          # 101-106, 201-206 ... 601-606 (el 1.er número es el piso)
REGEX_PALABRA = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]{2,20}$")
TECLADO = ("qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop", "asdf", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl", "zxc", "xcv", "cvb", "vbn", "bnm")


def _plausible(palabra: str, racha: int = 5, razon: float = 0.2) -> bool:
    """Descarta teclazos como 'jfdksaajfalkfdjlafk': necesita vocales, sin rachas imposibles."""
    t = unicodedata.normalize("NFD", palabra.lower())
    t = "".join(c for c in t if unicodedata.category(c) != "Mn")
    vocales = sum(1 for c in t if c in "aeiou")
    if vocales == 0 or vocales / len(t) < razon:
        return False
    if re.search(r"(.)\1\1", t) or re.search(r"[^aeiou]{%d,}" % racha, t) or re.search(r"[aeiou]{4,}", t):
        return False
    if re.search(r"(..+)\1\1", t):
        return False
    return not any(k in t for k in TECLADO)


def validar_nombres(nombre: str, apellido: str):
    """Hasta 2 nombres y 2 apellidos, solo letras y con aspecto de nombre real."""
    def revisar(texto, etiqueta):
        palabras = texto.split()
        if not 1 <= len(palabras) <= 2:
            raise HTTPException(status_code=422, detail=f"Escribe {etiqueta} (máximo 2)")
        for p in palabras:
            if not REGEX_PALABRA.match(p) or not _plausible(p):
                raise HTTPException(status_code=422, detail=f"«{p}» no parece un nombre válido. Usa solo letras y tu nombre real")
        return " ".join(p[:1].upper() + p[1:].lower() for p in palabras)
    return revisar(" ".join(nombre.split()), "tus nombres"), revisar(" ".join(apellido.split()), "tus apellidos")


def validar_correo_nuevo(correo: str) -> None:
    """Solo para cuentas NUEVAS: rechaza correos tecleados al azar (fasfdgsfdhsfddasdawsfeddf312)."""
    usuario = correo.split("@")[0]
    if not 3 <= len(usuario) <= 30 or not re.fullmatch(r"[a-z0-9]+([._-][a-z0-9]+)*", usuario):
        raise HTTPException(status_code=422, detail="Ese correo no parece real. Escribe tu correo de verdad (4 a 30 caracteres, solo letras, números y puntos)")
    es_codigo = re.fullmatch(r"[a-z]?[0-9]{6,12}", usuario) is not None   # código de alumno/docente: 2021200739, u202120073
    if re.fullmatch(r"[0-9]+", usuario) and not es_codigo:
        raise HTTPException(status_code=422, detail="Ese correo no parece real. Si usas tu código, escríbelo completo (6 a 12 números)")
    for seg in ([] if es_codigo else re.findall(r"[a-z]+", usuario)):
        if len(seg) >= 3 and not _plausible(seg, racha=6, razon=0.14):
            raise HTTPException(status_code=422, detail="Ese correo no parece real. Escribe tu correo de verdad, por ejemplo nombre.apellido@gmail.com")
    if len(re.sub(r"[^0-9]", "", usuario)) > 12:
        raise HTTPException(status_code=422, detail="Ese correo no parece real. Escribe tu correo de verdad")
    for parte in correo.split("@")[1].split(".")[:-1]:
        if parte in DOMINIOS_CONOCIDOS:
            continue
        letras = re.sub(r"[^a-z]", "", parte) or "a"
        if len(parte) < 2 or (len(parte) >= 3 and not _plausible(letras, racha=6, razon=0.14)):
            raise HTTPException(status_code=422, detail="Ese correo no parece real. Escribe tu correo de verdad, por ejemplo nombre.apellido@gmail.com")


def normalizar_correo(correo: str) -> str:
    correo = correo.strip().lower()
    if not REGEX_CORREO.match(correo):
        raise HTTPException(status_code=400, detail="Escribe un correo válido que termine en .com o .pe")
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
    nombre, apellido = validar_nombres(nombre, apellido)
    validar_correo_nuevo(correo)
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


class DocenteRegistro(BaseModel):
    nombre: str = Field(min_length=2, max_length=60)
    apellido: str = Field(min_length=2, max_length=60)
    correo: str = Field(min_length=5, max_length=200)


@app.post("/docentes/registrar", status_code=201)
def docente_registrar(datos: DocenteRegistro):
    """Registro: nombres, apellidos y correo Gmail. Sin contraseña. No devuelve datos del docente."""
    correo = normalizar_correo(datos.correo)
    nombre = " ".join(datos.nombre.split())
    apellido = " ".join(datos.apellido.split())
    nombre, apellido = validar_nombres(nombre, apellido)
    validar_correo_nuevo(correo)
    with conexion() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM docentes WHERE correo = %s", (correo,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Este correo ya ha sido registrado")
        cur.execute("INSERT INTO docentes (correo, nombre, apellido) VALUES (%s, %s, %s)", (correo, nombre, apellido))
    return {"ok": True}


@app.post("/tickets", status_code=201)
def crear_ticket(datos: TicketNuevo, tareas: BackgroundTasks):
    """El docente presiona 'Registrar problema'. Se identifica por su correo Gmail."""
    aula = datos.aula.strip()
    if not REGEX_AULA.match(aula):
        raise HTTPException(status_code=400, detail="Elige un aula válida (101 al 606)")
    piso = aula[0]                       # el primer número del aula es el piso
    en_clase = True if datos.en_clase is None else bool(datos.en_clase)
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

        prioridad, plazo_min = calcular_prioridad(cur, datos.tipo_falla_id, en_clase)
        token_seguimiento = secrets.token_urlsafe(16)

        cur.execute(
            """
            INSERT INTO tickets (sede_id, equipo_id, tipo_falla_id, descripcion,
                                 en_clase, contacto_docente, prioridad, token_seguimiento,
                                 plazo_atencion, aula_reportada, piso_reportado, tipo_equipo_id,
                                 docente_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s,
                    now() + make_interval(mins => %s), %s, %s, %s, %s)
            RETURNING id, estado, prioridad, token_seguimiento
            """,
            (
                equipo["sede_id"],
                equipo["id"],
                datos.tipo_falla_id,
                (datos.descripcion or "").strip() or None,
                en_clase,
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
       t.tecnico_campo_id, tc.nombre AS tecnico_campo, t.tecnico_enviado_en,
       (COALESCE(t.atendido_en, now()) > t.plazo_atencion) AS atendido_tarde
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
    if usuario["rol"] != "admin":          # la marca «Atendido tarde» es solo del administrador
        for t in tickets:
            t.pop("atendido_tarde", None)
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
        usuario = autenticar(cur, cred, roles=ROLES_GESTION)
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


class NotaResolucion(BaseModel):
    nota: str = Field(max_length=500)


@app.post("/soporte/tickets/{ticket_id}/en-camino")
def ticket_en_camino(
    ticket_id: int,
    tareas: BackgroundTasks,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """Soporte sale hacia el aula. Desde este momento se mide el tiempo de resolución."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred, roles=ROLES_GESTION)
        ticket = obtener_ticket(cur, usuario, ticket_id, bloquear=True)
        if ticket["estado"] == "nuevo":
            raise HTTPException(status_code=409, detail="Primero atiende el ticket")
        if ticket["estado"] == "resuelto":
            raise HTTPException(status_code=409, detail="Este ticket ya está resuelto")
        if ticket["estado"] != "en_atencion":
            raise HTTPException(status_code=409, detail="Este ticket ya está en camino")
        cur.execute(
            "UPDATE tickets SET estado = 'en_camino', tecnico_enviado_en = now() WHERE id = %s",
            (ticket_id,),
        )
        cur.execute(
            """
            INSERT INTO ticket_historial
                (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
            VALUES (%s, %s, 'en_atencion', 'en_camino', %s, 'Soporte en camino al aula')
            """,
            (ticket_id, ticket["sede_id"], usuario["id"]),
        )
    tareas.add_task(notificar_estado, ticket_id)
    return {"id": ticket_id, "estado": "en_camino"}


@app.post("/soporte/tickets/{ticket_id}/resolver")
def resolver_ticket(
    ticket_id: int,
    datos: NotaResolucion,
    tareas: BackgroundTasks,
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
):
    """Soporte da el problema por resuelto (solo después de 'En camino')."""
    nota = datos.nota.strip()
    if len(nota) < 3:
        raise HTTPException(status_code=400, detail="Describe brevemente qué se hizo")
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred, roles=ROLES_GESTION)
        ticket = obtener_ticket(cur, usuario, ticket_id, bloquear=True)
        if ticket["estado"] != "en_camino":
            raise HTTPException(status_code=409, detail="Primero presiona «En camino»" if ticket["estado"] in ("nuevo", "en_atencion") else "Este ticket ya está resuelto")
        cur.execute(
            "UPDATE tickets SET estado = 'resuelto', resuelto_en = now() WHERE id = %s",
            (ticket_id,),
        )
        cur.execute(
            """
            INSERT INTO ticket_historial
                (ticket_id, sede_id, estado_anterior, estado_nuevo, usuario_id, nota)
            VALUES (%s, %s, 'en_camino', 'resuelto', %s, %s)
            """,
            (ticket_id, ticket["sede_id"], usuario["id"], "Resuelto: " + nota),
        )
    tareas.add_task(notificar_estado, ticket_id)
    return {"id": ticket_id, "estado": "resuelto"}


# ------------------------------------------------------------------
# Encuesta de satisfacción (la responde el docente desde el enlace del correo)
# ------------------------------------------------------------------
class EncuestaRespuesta(BaseModel):
    satisfaccion: int = Field(ge=1, le=5)
    resolucion: Literal["si", "parcial", "no"]
    comentario: Optional[str] = Field(default=None, max_length=1000)


def _ticket_de_encuesta(cur, token: str):
    cur.execute(
        """
        SELECT t.id, t.estado, t.sede_id, t.docente_id, t.tecnico_id, s.nombre AS sede,
               te.nombre AS equipo, f.descripcion AS falla,
               EXISTS (SELECT 1 FROM encuestas e WHERE e.ticket_id = t.id) AS ya_respondida
        FROM tickets t
        JOIN sedes s ON s.id = t.sede_id
        JOIN tipos_falla f ON f.id = t.tipo_falla_id
        JOIN tipos_equipo te ON te.id = f.tipo_equipo_id
        WHERE t.token_seguimiento = %s
        """,
        (token,),
    )
    t = cur.fetchone()
    if not t:
        raise HTTPException(status_code=404, detail="Este enlace de encuesta no es válido")
    return t


@app.get("/encuesta/{token}")
def encuesta_datos(token: str):
    with conexion() as conn, conn.cursor() as cur:
        t = _ticket_de_encuesta(cur, token)
    return {
        "reporte": t["id"], "equipo": t["equipo"], "falla": t["falla"], "sede": t["sede"],
        "disponible": t["estado"] == "resuelto", "ya_respondida": t["ya_respondida"],
    }


@app.post("/encuesta/{token}", status_code=201)
def encuesta_responder(token: str, datos: EncuestaRespuesta):
    comentario = (datos.comentario or "").strip() or None
    with conexion() as conn, conn.cursor() as cur:
        t = _ticket_de_encuesta(cur, token)
        if t["ya_respondida"]:
            raise HTTPException(status_code=409, detail="Esta encuesta ya fue completada")
        if t["estado"] != "resuelto":
            raise HTTPException(status_code=409, detail="La encuesta estará disponible cuando el reporte esté resuelto")
        cur.execute(
            """
            INSERT INTO encuestas (ticket_id, sede_id, docente_id, tecnico_campo_id, satisfaccion, resolucion, comentario)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (ticket_id) DO NOTHING
            RETURNING id
            """,
            (t["id"], t["sede_id"], t["docente_id"], t["tecnico_id"], datos.satisfaccion, datos.resolucion, comentario),
        )
        if not cur.fetchone():
            raise HTTPException(status_code=409, detail="Esta encuesta ya fue completada")
    return {"ok": True}


@app.get("/soporte/encuestas")
def soporte_encuestas(
    dias: int = 0, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    """Resultados de las encuestas (dias=0: todo el historial). Lo ven Soporte y el administrador."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        cond, params = ["TRUE"], []
        cond_t, params_t = ["t.estado = 'resuelto'"], []
        if sede is not None:
            cond.append("e.sede_id = %s"); params.append(sede)
            cond_t.append("t.sede_id = %s"); params_t.append(sede)
        if dias and dias > 0:
            cond.append("e.creado_en >= now() - make_interval(days => %s)"); params.append(min(dias, 3650))
            cond_t.append("t.resuelto_en >= now() - make_interval(days => %s)"); params_t.append(min(dias, 3650))
        donde = " AND ".join(cond)
        cur.execute(
            f"""
            SELECT count(*)::int AS total,
                   round(avg(satisfaccion)::numeric, 2)::float AS promedio,
                   count(*) FILTER (WHERE satisfaccion = 1)::int AS s1,
                   count(*) FILTER (WHERE satisfaccion = 2)::int AS s2,
                   count(*) FILTER (WHERE satisfaccion = 3)::int AS s3,
                   count(*) FILTER (WHERE satisfaccion = 4)::int AS s4,
                   count(*) FILTER (WHERE satisfaccion = 5)::int AS s5,
                   count(*) FILTER (WHERE resolucion = 'si')::int AS r_si,
                   count(*) FILTER (WHERE resolucion = 'parcial')::int AS r_parcial,
                   count(*) FILTER (WHERE resolucion = 'no')::int AS r_no
            FROM encuestas e WHERE {donde}
            """,
            params,
        )
        r = cur.fetchone()
        cur.execute(f"SELECT count(*)::int AS n FROM tickets t WHERE {' AND '.join(cond_t)}", params_t)
        resueltos = cur.fetchone()["n"]
        cur.execute(
            f"""
            SELECT s.nombre AS sede, count(*)::int AS total,
                   round(avg(e.satisfaccion)::numeric, 2)::float AS promedio
            FROM encuestas e JOIN sedes s ON s.id = e.sede_id
            WHERE {donde} GROUP BY s.nombre ORDER BY s.nombre
            """,
            params,
        )
        por_sede = cur.fetchall()
        cur.execute(
            f"""
            SELECT e.id, e.ticket_id, e.satisfaccion, e.resolucion, e.comentario, e.creado_en,
                   s.nombre AS sede, tc.nombre AS tecnico,
                   COALESCE(NULLIF(trim(coalesce(d.nombre,'') || ' ' || coalesce(d.apellido,'')), ''), d.correo) AS docente,
                   te.nombre AS equipo, f.descripcion AS falla
            FROM encuestas e
            JOIN sedes s ON s.id = e.sede_id
            JOIN tickets t ON t.id = e.ticket_id
            JOIN tipos_falla f ON f.id = t.tipo_falla_id
            JOIN tipos_equipo te ON te.id = f.tipo_equipo_id
            LEFT JOIN docentes d ON d.id = e.docente_id
            LEFT JOIN usuarios tc ON tc.id = e.tecnico_campo_id
            WHERE {donde} ORDER BY e.creado_en DESC LIMIT 200
            """,
            params,
        )
        lista = cur.fetchall()
    total = r["total"]
    satisfechos = r["s4"] + r["s5"]
    return {
        "total": total,
        "promedio": r["promedio"],
        "satisfechos_pct": round(100 * satisfechos / total) if total else None,
        "distribucion": [r["s1"], r["s2"], r["s3"], r["s4"], r["s5"]],
        "resolucion": {"si": r["r_si"], "parcial": r["r_parcial"], "no": r["r_no"]},
        "resueltos": resueltos,
        "tasa_respuesta_pct": min(100, round(100 * total / resueltos)) if resueltos else None,
        "por_sede": por_sede,
        "encuestas": lista,
    }


@app.delete("/admin/encuestas/{encuesta_id}")
def admin_habilitar_encuesta(encuesta_id: int, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    """Solo el administrador: borra la respuesta para que el docente pueda responder de nuevo."""
    with conexion() as conn, conn.cursor() as cur:
        exigir_admin(autenticar(cur, cred))
        cur.execute("DELETE FROM encuestas WHERE id = %s RETURNING id", (encuesta_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="No existe esa encuesta")
    return {"ok": True}


# ------------------------------------------------------------------
# Mensajes del administrador a Soporte (por ticket o por encuesta)
# ------------------------------------------------------------------
class MensajeNuevo(BaseModel):
    ticket_id: Optional[int] = None
    encuesta_id: Optional[int] = None
    texto: str = Field(min_length=3, max_length=500)


@app.post("/admin/mensajes", status_code=201)
def enviar_mensaje(datos: MensajeNuevo, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    """Solo el administrador. El mensaje le llega a Soporte de la sede del ticket o de la encuesta."""
    if datos.ticket_id is None and datos.encuesta_id is None:
        raise HTTPException(status_code=400, detail="Indica el ticket o la encuesta")
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        exigir_admin(usuario)
        ticket_id = datos.ticket_id
        if datos.encuesta_id is not None:
            cur.execute("SELECT ticket_id FROM encuestas WHERE id = %s", (datos.encuesta_id,))
            e = cur.fetchone()
            if not e:
                raise HTTPException(status_code=404, detail="Encuesta no encontrada")
            ticket_id = e["ticket_id"]
        cur.execute("SELECT id, sede_id FROM tickets WHERE id = %s", (ticket_id,))
        t = cur.fetchone()
        if not t:
            raise HTTPException(status_code=404, detail="Ticket no encontrado")
        cur.execute(
            """
            INSERT INTO mensajes (sede_id, ticket_id, encuesta_id, de_usuario_id, texto)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
            """,
            (t["sede_id"], t["id"], datos.encuesta_id, usuario["id"], datos.texto.strip()),
        )
        nuevo = cur.fetchone()
    return {"id": nuevo["id"]}


@app.get("/soporte/mensajes")
def listar_mensajes(cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    """Soporte ve los mensajes de su sede; el administrador ve todos los que envió."""
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred)
        sede = filtro_sede(usuario)
        sql = """
            SELECT m.id, m.ticket_id, m.encuesta_id, m.texto, m.creado_en, m.leido_en,
                   s.nombre AS sede, u.nombre AS de
            FROM mensajes m JOIN sedes s ON s.id = m.sede_id JOIN usuarios u ON u.id = m.de_usuario_id
        """
        params = []
        if sede is not None:
            sql += " WHERE m.sede_id = %s"
            params.append(sede)
        cur.execute(sql + " ORDER BY m.creado_en DESC LIMIT 100", params)
        return {"mensajes": cur.fetchall()}


@app.post("/soporte/mensajes/{mensaje_id}/leido")
def marcar_mensaje_leido(mensaje_id: int, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    with conexion() as conn, conn.cursor() as cur:
        usuario = autenticar(cur, cred, roles=ROLES_GESTION)
        sede = filtro_sede(usuario)
        sql = "UPDATE mensajes SET leido_en = COALESCE(leido_en, now()) WHERE id = %s"
        params = [mensaje_id]
        if sede is not None:
            sql += " AND sede_id = %s"
            params.append(sede)
        cur.execute(sql + " RETURNING id", params)
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Mensaje no encontrado")
    return {"ok": True}


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
              ((avg(extract(epoch FROM (t.resuelto_en - t.tecnico_enviado_en)))
                 FILTER (WHERE t.resuelto_en IS NOT NULL AND t.tecnico_enviado_en IS NOT NULL)) / 60)::float8 AS mttr_min,
              (count(*) FILTER (
                 WHERE COALESCE(t.atendido_en, now()) > t.plazo_atencion
              ))::int AS atendidos_tarde,
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
        usuario = autenticar(cur, cred, roles=ROLES_INVENTARIO)
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
        usuario = autenticar(cur, cred, roles=ROLES_INVENTARIO)
        sede_id = filtro_sede(usuario)
        if sede_id is None:                      # el administrador elige la sede
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
        usuario = autenticar(cur, cred, roles=ROLES_INVENTARIO)
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
    rol: Literal["tecnico", "admin"]
    sede_id: Optional[int] = None


@app.post("/admin/usuarios", status_code=201)
def crear_usuario(
    datos: UsuarioNuevo, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)
):
    with conexion() as conn, conn.cursor() as cur:
        exigir_admin(autenticar(cur, cred))
        if datos.rol in ("tecnico", "tecnico_campo") and datos.sede_id is None:
            raise HTTPException(status_code=400, detail="Una cuenta de Soporte necesita una sede")
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
