"""Correos de estado del reporte (solo librería estándar).

Se envían con la API HTTP de Brevo (gratis, 300 correos/día). No se usa SMTP porque
Render (plan gratis) bloquea los puertos de correo.

Variables de entorno en Render:
  BREVO_API_KEY     clave de la API de Brevo (si falta, no se envía nada y todo sigue funcionando)
  CORREO_REMITENTE  correo remitente verificado en Brevo
  CORREO_NOMBRE     nombre que ve el docente (por defecto "Soporte Trilce")
  URL_DOCENTE       página del docente (por defecto la de Render)
"""
import html
import json
import os
import urllib.request

NARANJA = "#F26A1B"
NARANJA_SUAVE = "#FFF1E6"
VERDE = "#1E9E57"
GRIS = "#C9CED6"
TEXTO = "#1F2933"
TEXTO_SUAVE = "#5B6670"

# Lo que ve el docente (los estados internos son más finos: en_camino y solucionando = "Técnico asignado";
# al resolverse el técnico, el reporte queda Resuelto y Cerrado).
ETAPAS = [
    ("nuevo", "Reporte recibido"),
    ("en_atencion", "En atención"),
    ("tecnico", "Técnico asignado"),
    ("resuelto", "Resuelto"),
    ("cerrado", "Cerrado"),
]
INDICE_ETAPA = {"nuevo": 0, "en_atencion": 1, "en_camino": 2, "solucionando": 2, "resuelto": 4}

TEXTO_RESUELTO = "El técnico solucionó su problema. Gracias por reportarlo."
TEXTO_INTERNET_RESUELTO = "El técnico solucionó el problema de internet. Gracias por reportarlo."


def mensaje(estado: str, falla: str):
    """(título, texto, asunto corto) según el estado; mismos textos que la página."""
    if estado == "en_atencion":
        return ("¡Gracias por la espera!", "Nuestro equipo de soporte está trabajando en ello.", "Soporte lo está atendiendo")
    if estado == "en_camino":
        return ("¡Gracias por la espera!", "Un técnico va en camino.", "Técnico en camino")
    if estado == "solucionando":
        return ("¡Gracias por la espera!", "El técnico está solucionando el problema.", "Técnico solucionando el problema")
    if estado == "resuelto":
        texto = TEXTO_INTERNET_RESUELTO if "internet" in (falla or "").lower() else TEXTO_RESUELTO
        return ("¡Listo!", texto, "Resuelto")
    return ("Recibimos tu reporte", "Nuestro equipo de soporte lo atenderá en breve.", "Reporte registrado")


def _linea(color: str) -> str:
    return (f'<td width="50%" valign="middle" style="vertical-align:middle"><div style="height:3px;line-height:3px;'
            f'font-size:0;background:{color}">&nbsp;</div></td>')


def _linea_vacia() -> str:
    return '<td width="50%">&nbsp;</td>'


def _linea_de_tiempo(estado: str) -> str:
    """Los 5 pasos con puntos y líneas, como en el correo de ejemplo."""
    actual = INDICE_ETAPA.get(estado, 0)
    celdas, etiquetas = [], []
    ultimo = len(ETAPAS) - 1

    def seg(j):   # línea que llega al paso j
        if j > actual:
            return GRIS
        return VERDE if j == ultimo else NARANJA
    for i, (clave, nombre) in enumerate(ETAPAS):
        final_verde = (clave == "cerrado" and i <= actual)
        color_punto = VERDE if final_verde else (NARANJA if i <= actual else "#FFFFFF")
        borde = VERDE if final_verde else (NARANJA if i <= actual else GRIS)
        izq = _linea_vacia() if i == 0 else _linea(seg(i))
        der = _linea_vacia() if i == len(ETAPAS) - 1 else _linea(seg(i + 1))
        punto = (f'<td width="16" style="width:16px"><div style="width:12px;height:12px;border-radius:50%;'
                 f'background:{color_punto};border:2px solid {borde}"></div></td>')
        celdas.append(
            '<td width="20%" align="center" style="width:20%">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
            f'{izq}{punto}{der}</tr></table></td>')
        peso = "700" if i == actual else "400"
        col = (VERDE if final_verde else NARANJA) if i == actual else TEXTO_SUAVE
        etiquetas.append(
            f'<td width="20%" align="center" valign="top" style="width:20%;padding:8px 2px 0;font-size:11px;'
            f'line-height:14px;color:{col};font-weight:{peso}">{html.escape(nombre)}</td>')
    return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
            f'<tr>{"".join(celdas)}</tr><tr>{"".join(etiquetas)}</tr></table>')


def armar_correo(t: dict, url_docente: str):
    """t: id, estado, equipo, falla, sede, aula, piso. Devuelve (asunto, html, texto plano)."""
    estado = t["estado"]
    titulo, texto, corto = mensaje(estado, t.get("falla") or "")
    resuelto = estado == "resuelto"
    color = VERDE if resuelto else NARANJA
    e = html.escape
    detalle = [
        ("Reporte Nº", f'{t["id"]}'),
        ("Equipo", f'{t.get("equipo") or ""}: {t.get("falla") or ""}'),
        ("Sede", t.get("sede") or ""),
        ("Aula y piso", f'Aula {t.get("aula") or "-"} · Piso {t.get("piso") or "-"}'),
    ]
    filas = "".join(
        f'<tr><td style="padding:6px 0;font-size:13px;color:{TEXTO_SUAVE};width:38%">{e(k)}</td>'
        f'<td style="padding:6px 0;font-size:14px;color:{TEXTO};font-weight:600">{e(v)}</td></tr>'
        for k, v in detalle)
    saludo = (f'<p style="margin:16px 0 0;font-size:14px;color:{TEXTO_SUAVE}">Hola, {e(t["docente_nombre"])}</p>'
              if t.get("docente_nombre") else "")
    cuerpo = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><title>{e(titulo)}</title></head>
<body style="margin:0;padding:0;background:#F4F5F7;font-family:Arial,Helvetica,sans-serif;color:{TEXTO}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F4F5F7"><tr><td align="center" style="padding:16px 8px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;background:#FFFFFF;border-radius:12px;overflow:hidden">
  <tr><td style="background:#FFFFFF;border-top:5px solid {NARANJA};padding:18px 24px">
    <span style="display:inline-block;background:{NARANJA};color:#FFFFFF;font-weight:700;font-size:20px;width:38px;height:38px;line-height:38px;text-align:center;border-radius:8px">T</span>
    <span style="font-size:17px;font-weight:700;color:{TEXTO};vertical-align:middle;margin-left:8px">Soporte Trilce</span>
  </td></tr>
  <tr><td style="padding:8px 24px 0">
    {saludo}<h1 style="margin:6px 0 8px;font-size:24px;line-height:30px;color:{color}">{e(titulo)}</h1>
    <p style="margin:0 0 4px;font-size:15px;line-height:22px;color:{TEXTO}">{e(texto)}</p>
  </td></tr>
  <tr><td style="padding:28px 16px 8px">{_linea_de_tiempo(estado)}</td></tr>
  <tr><td style="padding:16px 24px 8px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{NARANJA_SUAVE};border-radius:8px"><tr><td style="padding:12px 16px;font-size:13px;line-height:19px;color:{TEXTO}">
      Puede ver el estado de su reporte en su correo. Le avisaremos por aquí cada vez que cambie.
    </td></tr></table>
  </td></tr>
  <tr><td style="padding:12px 24px 8px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-top:1px solid #E5E7EB">{filas}</table>
  </td></tr>
  <tr><td style="padding:16px 24px 24px;font-size:12px;line-height:18px;color:{TEXTO_SUAVE}">
    Este es un mensaje automático del equipo de Soporte de Trilce. No es necesario responderlo.
  </td></tr>
</table></td></tr></table></body></html>"""
    plano = (f"{titulo}\n{texto}\n\nReporte Nº {t['id']} - {t.get('equipo') or ''}: {t.get('falla') or ''}\n"
             f"Sede {t.get('sede') or ''} - Aula {t.get('aula') or '-'}, piso {t.get('piso') or '-'}\n\n"
             f"Estado: {corto}\nPuede ver el estado de su reporte en su correo.\n")
    asunto = f"Reporte #{t['id']} · {corto}"
    return asunto, cuerpo, plano


def enviar(destino: str, asunto: str, html_cuerpo: str, texto: str) -> bool:
    """Envía por Brevo. Nunca lanza error: un correo caído no debe romper el ticket."""
    clave = os.environ.get("BREVO_API_KEY")
    remitente = os.environ.get("CORREO_REMITENTE")
    if not clave or not remitente:
        return False
    datos = {
        "sender": {"name": os.environ.get("CORREO_NOMBRE", "Soporte Trilce"), "email": remitente},
        "to": [{"email": destino}],
        "subject": asunto,
        "htmlContent": html_cuerpo,
        "textContent": texto,
    }
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=json.dumps(datos).encode("utf-8"),
        headers={"api-key": clave, "content-type": "application/json", "accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except Exception as ex:   # noqa: BLE001
        print("No se pudo enviar el correo:", repr(ex))
        return False
