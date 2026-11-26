"""Ejecuciones reproducibles y gestión local de alertas en SQLite."""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

from auditoria import DATA_DIR, Finding, RULESET_VERSION, load_audit, rule_parameters
from validacion import FILES

STATES = ('Pendiente', 'En revisión', 'Resuelta', 'Descartada')
DEFAULT_CASE = {'owner': '', 'status': 'Pendiente', 'resolution': '', 'revision': 0, 'updated_at': ''}


def encode(value):
    if isinstance(value, date):
        return {'__date__': value.isoformat()}
    if isinstance(value, Decimal):
        return {'__decimal__': str(value)}
    raise TypeError(type(value).__name__)


def decode(value):
    if set(value) == {'__date__'}:
        return date.fromisoformat(value['__date__'])
    if set(value) == {'__decimal__'}:
        return Decimal(value['__decimal__'])
    return value


@dataclass(frozen=True)
class AuditRun:
    id: str
    created_at: str
    metadata: dict
    payments: dict
    rules: dict
    findings: tuple
    master: dict

    @property
    def start(self):
        return min((p['paid_on'] for p in self.payments.values()), default=None)

    @property
    def end(self):
        return max((p['paid_on'] for p in self.payments.values()), default=None)


class ConflictError(ValueError):
    pass


class AuditStore:
    def __init__(self, path, data_dir=DATA_DIR):
        self.path = Path(path)
        self.data_dir = Path(data_dir)

    @contextmanager
    def connection(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, metadata TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, status TEXT NOT NULL, resolution TEXT NOT NULL,
                    revision INTEGER NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
                    run_id TEXT NOT NULL, owner TEXT NOT NULL, status TEXT NOT NULL, resolution TEXT NOT NULL,
                    revision INTEGER NOT NULL, updated_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_case ON events(case_id, sequence);
            ''')
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def refresh(self):
        # Evaluate exactly the captured bytes, even when the source files change during processing.
        source = {name: (self.data_dir / name).read_bytes() for name in FILES}
        metadata = {'ruleset_version': RULESET_VERSION, 'parameters': rule_parameters(),
                    'files': {name: sha256(content).hexdigest() for name, content in source.items()},
                    'engine_sha256': sha256(Path(__file__).with_name('auditoria.py').read_bytes()).hexdigest(),
                    'validation_sha256': sha256(Path(__file__).with_name('validacion.py').read_bytes()).hexdigest()}
        run_id = sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
        with self.connection() as db:
            exists = db.execute('SELECT 1 FROM runs WHERE id = ?', (run_id,)).fetchone()
        if exists:
            return self.get_run(run_id)
        with TemporaryDirectory() as directory:
            for name, content in source.items():
                (Path(directory) / name).write_bytes(content)
            payments, rules, findings, master = load_audit(Path(directory))
        payload = json.dumps({'payments': payments, 'rules': rules, 'findings': [asdict(f) for f in findings],
                              'master': master}, default=encode, ensure_ascii=False)
        created_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with self.connection() as db:
            db.execute('INSERT OR IGNORE INTO runs VALUES (?, ?, ?, ?)',
                       (run_id, created_at, json.dumps(metadata), payload))
        return self.get_run(run_id)

    @lru_cache(maxsize=4)
    def get_run(self, run_id):
        with self.connection() as db:
            row = db.execute('SELECT * FROM runs WHERE id = ?', (run_id,)).fetchone()
        if row is None:
            raise ValueError('Ejecución no disponible. Recarga la página.')
        data = json.loads(row['payload'], object_hook=decode)
        metadata = json.loads(row['metadata'])
        for item in data['findings']:
            item.setdefault('ruleset_version', metadata['ruleset_version'])
            for field in ('payment_ids', 'vendor_ids', 'context_ids'):
                item[field] = tuple(item[field])
        return AuditRun(row['id'], row['created_at'], metadata, data['payments'],
                        data['rules'], tuple(Finding(**item) for item in data['findings']), data['master'])

    def latest(self):
        with self.connection() as db:
            row = db.execute('SELECT id FROM runs ORDER BY rowid DESC LIMIT 1').fetchone()
        return self.get_run(row['id']) if row else None

    def cases(self):
        with self.connection() as db:
            return {row['id']: dict(row) for row in db.execute('SELECT * FROM cases')}

    def history(self, case_id):
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                'SELECT * FROM events WHERE case_id = ? ORDER BY sequence DESC', (case_id,))]

    def save_case(self, run_id, case_id, owner, status, resolution, revision):
        run = self.get_run(run_id)
        if case_id not in {f.id for f in run.findings}:
            raise ValueError('La alerta no pertenece a esta ejecución.')
        owner, resolution = (owner or '').strip(), (resolution or '').strip()
        if status not in STATES or not isinstance(revision, int):
            raise ValueError('Estado o revisión inválidos.')
        if len(owner) > 120 or len(resolution) > 4000:
            raise ValueError('Máximo: responsable de 120 caracteres y resolución de 4.000.')
        if status != 'Pendiente' and not owner:
            raise ValueError('Asigna un responsable para cambiar el estado.')
        if status in ('Resuelta', 'Descartada') and not resolution:
            raise ValueError('Documenta la resolución antes de cerrar o descartar la alerta.')
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT revision FROM cases WHERE id = ?', (case_id,)).fetchone()
            if (current['revision'] if current else 0) != revision:
                raise ConflictError('Otro usuario modificó esta alerta. Selecciónala de nuevo antes de guardar.')
            values = (case_id, owner, status, resolution, revision + 1, now)
            db.execute('INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET '
                       'owner=excluded.owner, status=excluded.status, resolution=excluded.resolution, '
                       'revision=excluded.revision, updated_at=excluded.updated_at', values)
            db.execute('INSERT INTO events(case_id, run_id, owner, status, resolution, revision, updated_at) '
                       'VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (case_id, run_id, owner, status, resolution, revision + 1, now))
        return revision + 1
