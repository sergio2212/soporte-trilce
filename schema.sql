-- Esquema inicial: Sistema de soporte técnico multisede Trilce
-- Motor: PostgreSQL (Neon). Todas las tablas de datos operativos llevan sede_id.

-- ============================================================
-- Catálogos base
-- ============================================================

CREATE TABLE sedes (
    id        SERIAL PRIMARY KEY,
    nombre    TEXT NOT NULL UNIQUE,
    direccion TEXT,
    activa    BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE ambientes (
    id      SERIAL PRIMARY KEY,
    sede_id INT NOT NULL REFERENCES sedes(id),
    nombre  TEXT NOT NULL,              -- ej. "Aula 305"
    piso    SMALLINT,
    UNIQUE (sede_id, nombre),
    UNIQUE (id, sede_id)                -- permite verificar que equipo y ambiente son de la misma sede
);

CREATE TABLE tipos_equipo (
    id     SERIAL PRIMARY KEY,
    nombre TEXT NOT NULL UNIQUE         -- Computadora, Impresora, Monitor, ...
);

-- Fallas comunes que ve el docente según el tipo de equipo
CREATE TABLE tipos_falla (
    id             SERIAL PRIMARY KEY,
    tipo_equipo_id INT NOT NULL REFERENCES tipos_equipo(id),
    descripcion    TEXT NOT NULL,
    es_otro        BOOLEAN NOT NULL DEFAULT FALSE,  -- opción "Otro / no sé qué es"
    orden          SMALLINT NOT NULL DEFAULT 0,
    activo         BOOLEAN NOT NULL DEFAULT TRUE
);

-- ============================================================
-- Equipos (cada uno lleva un QR con token único)
-- ============================================================

CREATE TABLE equipos (
    id             SERIAL PRIMARY KEY,
    sede_id        INT NOT NULL REFERENCES sedes(id),
    ambiente_id    INT NOT NULL,
    tipo_equipo_id INT NOT NULL REFERENCES tipos_equipo(id),
    nombre         TEXT NOT NULL,       -- ej. "PC del docente"
    token_qr       TEXT NOT NULL UNIQUE,
    activo         BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (id, sede_id),
    FOREIGN KEY (ambiente_id, sede_id) REFERENCES ambientes (id, sede_id)
);

-- ============================================================
-- Usuarios del equipo de soporte
-- ============================================================

CREATE TABLE usuarios (
    id            SERIAL PRIMARY KEY,
    sede_id       INT REFERENCES sedes(id),   -- NULL = admin con acceso a todas las sedes
    nombre        TEXT NOT NULL,
    correo        TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    rol           TEXT NOT NULL CHECK (rol IN ('tecnico', 'admin')),
    activo        BOOLEAN NOT NULL DEFAULT TRUE
);

-- ============================================================
-- Tickets
-- Estado = en qué etapa va. Prioridad = qué tan urgente es (la calcula el sistema).
-- ============================================================

CREATE TABLE tickets (
    id                 SERIAL PRIMARY KEY,
    sede_id            INT NOT NULL REFERENCES sedes(id),
    equipo_id          INT NOT NULL,
    tipo_falla_id      INT NOT NULL REFERENCES tipos_falla(id),
    descripcion        TEXT,                    -- solo si eligió "Otro"
    en_clase           BOOLEAN NOT NULL,        -- ¿el docente está en clase?
    contacto_docente   TEXT,                    -- opcional: correo para avisarle
    estado             TEXT NOT NULL DEFAULT 'nuevo'
                       CHECK (estado IN ('nuevo', 'en_atencion', 'resuelto')),
    prioridad          TEXT NOT NULL DEFAULT 'media'
                       CHECK (prioridad IN ('critica', 'alta', 'media', 'baja')),
    tecnico_id         INT REFERENCES usuarios(id),
    token_seguimiento  TEXT NOT NULL UNIQUE,    -- enlace para que el docente vea el estado
    plazo_atencion     TIMESTAMPTZ,             -- para la cuenta regresiva y la alerta
    creado_en          TIMESTAMPTZ NOT NULL DEFAULT now(),
    atendido_en        TIMESTAMPTZ,
    resuelto_en        TIMESTAMPTZ,
    FOREIGN KEY (equipo_id, sede_id) REFERENCES equipos (id, sede_id)
);

CREATE INDEX idx_tickets_sede_estado ON tickets (sede_id, estado);
CREATE INDEX idx_tickets_plazo ON tickets (plazo_atencion) WHERE estado <> 'resuelto';

-- Registro de cada cambio de estado (quién, cuándo, nota)
CREATE TABLE ticket_historial (
    id              SERIAL PRIMARY KEY,
    ticket_id       INT NOT NULL REFERENCES tickets(id),
    sede_id         INT NOT NULL REFERENCES sedes(id),
    estado_anterior TEXT,
    estado_nuevo    TEXT NOT NULL,
    usuario_id      INT REFERENCES usuarios(id),
    nota            TEXT,
    creado_en       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_historial_ticket ON ticket_historial (ticket_id);

-- ============================================================
-- Datos de ejemplo (editen o borren a su gusto)
-- ============================================================

INSERT INTO sedes (nombre) VALUES ('Sede de prueba');

INSERT INTO ambientes (sede_id, nombre, piso) VALUES (1, 'Aula 305', 3);

INSERT INTO tipos_equipo (nombre) VALUES
    ('Computadora'), ('Impresora'), ('Monitor'), ('Proyector'), ('Wifi / Red');

INSERT INTO tipos_falla (tipo_equipo_id, descripcion, es_otro, orden) VALUES
    (1, 'No enciende', FALSE, 1),
    (1, 'Se apagó sola', FALSE, 2),
    (1, 'No hay internet', FALSE, 3),
    (1, 'Otro problema', TRUE, 99),
    (2, 'La impresora no funciona', FALSE, 1),
    (3, 'No enciende / pantalla negra', FALSE, 1),
    (3, 'Otro problema', TRUE, 99),
    (4, 'No enciende', FALSE, 1),
    (4, 'No se ve la imagen', FALSE, 2),
    (4, 'Otro problema', TRUE, 99),
    (5, 'El wifi no prende', FALSE, 1),
    (5, 'No hay internet', FALSE, 2),
    (5, 'Otro problema', TRUE, 99);

-- Equipo de prueba: sirve para probar /qr/demo-pc-001
INSERT INTO equipos (sede_id, ambiente_id, tipo_equipo_id, nombre, token_qr)
VALUES (1, 1, 1, 'PC del docente', 'demo-pc-001');
