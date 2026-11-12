"""Seguridad del sistema: contraseñas y tokens de sesión.

Usa solo la librería estándar de Python, así no hay que instalar nada extra.
"""
import base64
import hashlib
import hmac
import json
import os
import time

ITERACIONES = 200_000
DURACION_SESION_S = 12 * 3600  # 12 horas


def hashear_password(password: str) -> str:
    """Devuelve la contraseña convertida en un hash con sal (nunca se guarda en claro)."""
    sal = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), sal, ITERACIONES)
    return f"pbkdf2_sha256${ITERACIONES}${sal.hex()}${dk.hex()}"


def verificar_password(password: str, guardado: str) -> bool:
    """Comprueba una contraseña contra el hash guardado."""
    try:
        algoritmo, iteraciones, sal_hex, hash_hex = guardado.split("$")
        if algoritmo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(sal_hex), int(iteraciones)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError, TypeError):
        return False


def _b64(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def _desb64(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def _firmar(cuerpo: str, secreto: str) -> str:
    return _b64(hmac.new(secreto.encode("utf-8"), cuerpo.encode("ascii"), hashlib.sha256).digest())


def crear_token(usuario_id: int, secreto: str, duracion_s: int = DURACION_SESION_S) -> str:
    """Crea un token firmado que identifica al usuario y vence solo."""
    datos = {"uid": usuario_id, "exp": int(time.time()) + duracion_s}
    cuerpo = _b64(json.dumps(datos, separators=(",", ":")).encode("utf-8"))
    return f"{cuerpo}.{_firmar(cuerpo, secreto)}"


def leer_token(token: str, secreto: str):
    """Devuelve los datos del token si es válido y no venció; si no, None."""
    try:
        cuerpo, firma = token.split(".")
        if not hmac.compare_digest(firma, _firmar(cuerpo, secreto)):
            return None
        datos = json.loads(_desb64(cuerpo))
        if int(datos["exp"]) < time.time():
            return None
        return datos
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
