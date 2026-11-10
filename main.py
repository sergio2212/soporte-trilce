"""API inicial del sistema de soporte técnico multisede Trilce."""
import os
import secrets
from contextlib import contextmanager
from typing import Optional

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DATABASE_URL = os.environ.get("DATABASE_URL")
# En producción pon aquí las URLs de tus frontends, separadas por coma.
ORIGENES = os.environ.get("ALLOWED_ORIGINS", "*").split(",")

app = FastAPI(title="Soporte Trilce")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGENES,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


def calcular_prioridad(tipo_falla_id: int, en_clase: bool) -> str:
    """PENDIENTE: aquí va el motor de prioridad (regla de la sección 5 del documento).

    Mientras no se implemente, todos los tickets quedan con prioridad 'media'.
    """
    return "media"


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
# Página del docente
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

        prioridad = calcular_prioridad(datos.tipo_falla_id, datos.en_clase)
        token_seguimiento = secrets.token_urlsafe(16)

        cur.execute(
            """
            INSERT INTO tickets (sede_id, equipo_id, tipo_falla_id, descripcion,
                                 en_clase, contacto_docente, prioridad, token_seguimiento)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
