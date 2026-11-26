"""Carga el extracto y evalúa las reglas sobre todo el historial."""
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal
from itertools import groupby
from pathlib import Path
import re
import hashlib
import json
from validacion import validate_inputs
from statistics import median

import duckdb

DATA_DIR = Path(__file__).resolve().parent / "datos"
RULESET_VERSION = "2.0.0"

WINDOW_DAYS = 3
AUTHORIZATION_LIMIT = Decimal("50000.00")
LOWER_LIMIT = AUTHORIZATION_LIMIT * Decimal("0.90")


@dataclass(frozen=True)
class Finding:
    rule: str
    payment_ids: tuple[str, ...]
    evidence: str

    vendor_ids: tuple[str, ...] = ()
    site: str | None = None
    occurred_on: date | None = None
    context_ids: tuple[str, ...] = ()
    scope_key: str | None = None
    ruleset_version: str = RULESET_VERSION

    @property
    def id(self):
        identity = [self.ruleset_version, self.rule, self.scope_key, sorted(self.payment_ids), sorted(self.vendor_ids), self.site]
        digest = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()
        return f"{self.rule}:{digest}"


def money(value):
    return f"{value:,.2f}"


def load_audit(data_dir=DATA_DIR):
    data_dir = Path(data_dir)
    validate_inputs(data_dir)
    with duckdb.connect() as db:
        db.read_csv(str(data_dir / "Maestro_auditoria.csv"), all_varchar=True).create_view("master")
        db.read_csv(str(data_dir / "Pagos_auditoria.csv"), all_varchar=True).create_view("raw_payments")
        db.read_csv(str(data_dir / "matriz_alertas.csv"), all_varchar=True).create_view("matrix")
        db.execute("""
            CREATE TEMP TABLE payments AS
            SELECT p.INVOICE_ID AS id, p.VENDOR_ID AS vendor_id, p.VENDOR_NAME AS vendor,
                   p.SITE AS site,
                   strptime(trim(p.FECHA_D_PAGO), '%d/%m/%y')::DATE AS paid_on,
                   strptime(trim(p.FECHA_VENCIMIENTO), '%d/%m/%y')::DATE AS due_on,
                   regexp_replace(p.PAGADO, '[$,[:space:]]', '', 'g')::DECIMAL(18,2) AS paid,
                   upper(trim(p.SEGMENT1)) AS payment_rfc,
                   upper(trim(m.RFC)) AS master_rfc,
                   trim(p.NUM_FACTURA) AS invoice, trim(p.UUID) AS uuid,
                   try_strptime(trim(p.FECHA_FACTURA), '%d/%m/%y')::DATE AS invoiced_on,
                   p.IMPORTE_AP::DECIMAL(30,12) AS ap,
                   round(p.IMPORTE_AP::DECIMAL(30,12), 2) AS ap_rounded,
                   trim(p.BANK_ACCOUNT_NUM) AS account, trim(p.PAYMENT_REASON_COMMENTS) AS comments,
                   trim(p.REFERENCIA) AS reference, trim(p.NO_DOC) AS document,
                   trim(p.SOURCE) AS source, trim(p.APPROVAL_DESCRIPTION) AS approval,
                   trim(p.SEGMENT4) AS ledger
            FROM raw_payments p
            LEFT JOIN master m ON p.VENDOR_ID = m."Id Proveedor"
        """)
        result = db.execute("SELECT * FROM payments ORDER BY paid_on, id")
        columns = [col[0] for col in result.description]
        payments = {row[0]: dict(zip(columns, row)) for row in result.fetchall()}
        rules = {
            code: {"name": name, "severity": severity, "risk": risk, "goal": goal,
                   "category": category, "criterion": CRITERIA.get(code, criterion)}
            for code, name, severity, risk, goal, category, criterion in db.execute(
                'SELECT ID, Alerta, Severidad, "Riesgo asociado", Objetivo, "Categoría", "Regla funcional" FROM matrix'
            ).fetchall()
        }
        master_rows = db.execute("""
            SELECT "Id Proveedor" AS id, "Nombre Proveedor" AS vendor, Site AS site,
                   trim(RFC) AS rfc, trim(Cuenta) AS account, trim(Banco) AS bank,
                   trim(Correo) AS email, trim(Telefono) AS phone,
                   try_strptime(trim("Fecha Creacion Prov"), '%d-%b-%y')::DATE AS created,
                   try_strptime(trim("Fecha Proveedor Inactivo"), '%d-%b-%y')::DATE AS inactive,
                   try_strptime(trim("Fecha Site Inactivo"), '%d-%b-%y')::DATE AS site_inactive,
                   try_strptime(trim("Inactivacion Cuenta"), '%d-%b-%y')::DATE AS account_inactive,
                   try_strptime(trim("Actualizacion Cuenta"), '%d-%b-%y')::DATE AS account_updated
            FROM master
        """)
        columns = [col[0] for col in master_rows.description]
        master = {row[0]: dict(zip(columns, row)) for row in master_rows.fetchall()}
        findings = [
            Finding("A02", (pid,), f"RFC en pago: {payment_rfc or 'vacío'} · RFC en maestro: {master_rfc}")
            for pid, payment_rfc, master_rfc in db.execute("""
                SELECT id, payment_rfc, master_rfc FROM payments
                WHERE master_rfc IS NOT NULL AND payment_rfc IS DISTINCT FROM master_rfc
                ORDER BY paid_on, id
            """).fetchall()
        ]
        findings.extend(
            Finding("A13", (pid,), f"{days} {'día' if days == 1 else 'días'} después del vencimiento")
            for pid, days in db.execute("""
                SELECT id, paid_on - due_on FROM payments
                WHERE paid_on > due_on ORDER BY paid_on, id
            """).fetchall()
        )
        groups = db.execute("""
            WITH eligible AS (
                SELECT * FROM payments WHERE paid >= ? AND paid < ?
            ), anchors AS (
                SELECT DISTINCT vendor_id, paid_on FROM eligible
            )
            SELECT list(p.id ORDER BY p.paid_on, p.id), sum(p.paid)
            FROM anchors a JOIN eligible p ON p.vendor_id = a.vendor_id
                AND p.paid_on BETWEEN a.paid_on AND a.paid_on + ?::INTEGER
            GROUP BY a.vendor_id, a.paid_on
            HAVING count(*) >= 2 AND sum(p.paid) > ?
            ORDER BY count(*) DESC, a.vendor_id, a.paid_on
        """, [LOWER_LIMIT, AUTHORIZATION_LIMIT, WINDOW_DAYS, AUTHORIZATION_LIMIT]).fetchall()

    # Keep maximal groups from overlapping candidate windows. A shared payment
    # can still belong to separate windows when their union exceeds three days.
    accepted_by_vendor = {}
    for ids, total in groups:
        accepted = accepted_by_vendor.setdefault(payments[ids[0]]["vendor_id"], [])
        members = set(ids)
        if any(members <= previous for previous in accepted):
            continue
        accepted.append(members)
        findings.append(Finding("A30", tuple(ids), f"{len(ids)} pagos por {money(total)} en conjunto"))
    findings.extend(evaluate_rules(payments, master))
    return payments, rules, findings, master


RECENT_VENDOR_DAYS = 30
RECENT_ACCOUNT_DAYS = 7
HISTORY_MINIMUM = 3
AMOUNT_MULTIPLIER = 3
CONCENTRATION_LIMIT = Decimal("0.10")
FIRST_PAYMENT_LIMIT = Decimal("500000")
BASELINE_MONTHS = 3
# Add references here only when there is evidence of an authorized batch.
JUSTIFIED_BATCH_REFERENCES = frozenset()

CRITERIA = {
    "A05": "Agrupa cuentas normalizadas del maestro asociadas a más de un proveedor.",
    "A06": "Fecha de pago estrictamente posterior a la inactivación del proveedor.",
    "A07": "Pago posterior a la inactivación del sitio, para el sitio registrado en el maestro.",
    "A08": "Pago posterior a la inactivación de la cuenta registrada, con la misma cuenta normalizada.",
    "A12": "Compara el monto pagado con el importe AP redondeado a dos decimales.",
    "A16": "Busca vacíos, marcadores genéricos e inconsistencias de formato en RFC, cuenta, banco, correo y teléfono.",
    "A17": f"Pago entre 0 y {RECENT_VENDOR_DAYS} días calendario después del alta.",
    "A18": f"Pago entre 0 y {RECENT_ACCOUNT_DAYS} días calendario después de actualizar la cuenta registrada.",
    "A19": f"Importe AP a centavos superior a {AMOUNT_MULTIPLIER} veces la mediana de al menos "
           f"{HISTORY_MINIMUM} pagos de fechas anteriores del mismo proveedor y sitio.",
    "A20": f"Más del {CONCENTRATION_LIMIT:.0%} de lo pagado en todo el extracto, por proveedor.",
    "A21": "Proveedor activo sin pagos en los 12 meses anteriores al corte, o sin actividad histórica.",
    "A22": f"Primer pago observado mayor a {money(FIRST_PAYMENT_LIMIT)} en unidades del extracto.",
    "A23": f"Monto mensual por proveedor superior a {AMOUNT_MULTIPLIER} veces el promedio de los "
           f"{BASELINE_MONTHS} meses calendario anteriores, con base positiva.",
    "A24": f"Monto mensual por sitio superior a {AMOUNT_MULTIPLIER} veces el promedio de los "
           f"{BASELINE_MONTHS} meses calendario anteriores, con base positiva.",
    "A26": "Referencia no vacía repetida en más de un registro de pago. Excluye los lotes documentados en la configuración.",
    "A28": f"Fuente o aprobación difiere de la moda única de al menos {HISTORY_MINIMUM} valores "
           "observados en pagos de fechas anteriores del proveedor.",
    "A29": f"Cuenta contable difiere de la moda única de al menos {HISTORY_MINIMUM} valores "
           "observados en pagos de fechas anteriores del proveedor.",
    "A30": f"Al menos dos pagos del mismo proveedor en hasta {WINDOW_DAYS} días. Cada pago debe alcanzar "
           f"{money(LOWER_LIMIT)} y quedar por debajo de {money(AUTHORIZATION_LIMIT)}. "
           f"La suma debe superar {money(AUTHORIZATION_LIMIT)}. Importes en unidades del extracto.",
}


def digits(value):
    return re.sub(r"[^0-9]", "", value or "")


def quality_issues(vendor):
    patterns = {
        "rfc": (r"[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}", "RFC"),
        "account": (r"\d{6,18}", "cuenta"),
        "bank": (r".*[^\W\d_].*", "banco"),
        "email": (r"[^\s@]+@[^\s@]+\.[^\s@]+", "correo"),
        "phone": (r"\d{10}", "teléfono"),
    }
    placeholders = {"N/A", "NA", "SIN DATO", "SIN DATOS", "PENDIENTE", "XAXX010101000", "XEXX010101000"}
    issues = []
    for field, (pattern, label) in patterns.items():
        raw = vendor[field] or ""
        value = digits(raw) if field in {"account", "phone"} else raw
        if not raw:
            issues.append(f"{label} vacío")
        elif raw.upper() in placeholders or not re.fullmatch(pattern, value, re.IGNORECASE) or set(value) == {"0"}:
            issues.append(f"{label} inválido o genérico")
    return issues


def monthly_findings(rows_by_entity, rule, first_day, cutoff):
    first_month = first_day.year * 12 + first_day.month - 1
    for entity, rows in rows_by_entity.items():
        buckets = defaultdict(list)
        for p in rows:
            day = p["paid_on"]
            buckets[day.year * 12 + day.month - 1].append(p)
        totals = {month: sum(p["paid"] for p in rows) for month, rows in buckets.items()}
        for month, current in buckets.items():
            start = date(month // 12, month % 12 + 1, 1)
            if month - BASELINE_MONTHS < first_month:
                continue
            baseline = [p for past in range(month - BASELINE_MONTHS, month) for p in buckets.get(past, ())]
            previous_total = sum(totals.get(past, Decimal(0)) for past in range(month - BASELINE_MONTHS, month))
            if previous_total > 0 and totals[month] * BASELINE_MONTHS > AMOUNT_MULTIPLIER * previous_total:
                average = previous_total / BASELINE_MONTHS
                yield Finding(
                    rule, tuple(p["id"] for p in current),
                    f"{start:%m/%Y} · Pagado {money(totals[month])} · Promedio anterior {money(average)}",
                    vendor_ids=(entity,) if rule == "A23" else (),
                    site=entity if rule == "A24" else None,
                    occurred_on=min(cutoff, date((month + 1) // 12, (month + 1) % 12 + 1, 1) - timedelta(days=1)),
                    context_ids=tuple(p["id"] for p in baseline),
                    scope_key=f"{entity}:{start:%Y-%m}",
                )


def historical_patterns(rows):
    histories = {field: Counter() for field in ("source", "approval", "ledger")}
    seen_ids = []
    pattern_names = {"source": "fuente", "approval": "aprobación", "ledger": "cuenta contable"}

    for _, same_day in groupby(rows, key=lambda p: p["paid_on"]):
        current = list(same_day)
        for p in current:
            anomalies = defaultdict(list)
            for field, counts in histories.items():
                leaders = counts.most_common(2)
                if (not p[field] or counts.total() < HISTORY_MINIMUM or
                        (len(leaders) > 1 and leaders[0][1] == leaders[1][1])):
                    continue
                mode = leaders[0][0]
                if p[field] != mode:
                    key = "A29" if field == "ledger" else "A28"
                    anomalies[key].append(f"{pattern_names[field]}: {p[field]} (habitual: {mode})")
            for key, details in anomalies.items():
                yield Finding(key, (p["id"],), " · ".join(details), context_ids=tuple(seen_ids))
        for p in current:
            seen_ids.append(p["id"])
            for field, counts in histories.items():
                if p[field]:
                    counts[p[field]] += 1


def evaluate_rules(payments, master):
    by_vendor, by_site, by_vendor_site = defaultdict(list), defaultdict(list), defaultdict(list)
    invoice_groups, uuid_groups, daily_groups, reference_groups = (defaultdict(list) for _ in range(4))
    if not payments:
        for vid, m in master.items():
            issues = quality_issues(m)
            if issues:
                yield Finding("A16", (), " · ".join(issues), vendor_ids=(vid,), scope_key=vid)
        accounts = defaultdict(list)
        for vid, m in master.items():
            if digits(m["account"]):
                accounts[digits(m["account"])].append(vid)
        for account, vids in accounts.items():
            if len(vids) > 1:
                yield Finding("A05", (), f"Cuenta {account} compartida por {len(vids)} proveedores", vendor_ids=tuple(vids), scope_key=":".join(sorted(vids)))
        return
    payments = dict(sorted(payments.items(), key=lambda item: (item[1]["paid_on"], item[0])))
    start = min(p["paid_on"] for p in payments.values())
    cutoff = max(p["paid_on"] for p in payments.values())
    # Clamp leap-day cutoffs to the last day of February in the comparison year.
    lookback = cutoff.replace(year=cutoff.year - 1, day=28 if (cutoff.month, cutoff.day) == (2, 29) else cutoff.day)
    total_paid = sum(p["paid"] for p in payments.values())

    for pid, p in payments.items():
        vid, site, day = p["vendor_id"], p["site"], p["paid_on"]
        by_vendor[vid].append(p)
        by_site[site].append(p)
        by_vendor_site[vid, site].append(p)
        daily_groups[vid, day].append(pid)
        if p["invoice"]:
            invoice_groups[vid, p["invoice"], p["payment_rfc"], p["ap"]].append(pid)
        if p["reference"] and p["reference"] not in JUSTIFIED_BATCH_REFERENCES:
            reference_groups[p["reference"]].append(p)
        if p["uuid"]:
            uuid_groups[p["uuid"]].append(pid)
        else:
            yield Finding("A11", (pid,), "UUID vacío")
        if p["paid"] != p["ap_rounded"]:
            yield Finding("A12", (pid,), f"Pagado {money(p['paid'])} · AP {money(p['ap_rounded'])} · "
                          f"Diferencia {money(p['paid'] - p['ap_rounded'])}")
        if p["invoiced_on"] and day < p["invoiced_on"]:
            yield Finding("A14", (pid,), f"Pago {(p['invoiced_on'] - day).days} día(s) antes de la factura "
                          f"del {p['invoiced_on']:%d/%m/%Y}")
        if "FALTA NC" in (p["comments"] or "").upper():
            yield Finding("A15", (pid,), p["comments"])
        m = master.get(vid)
        if not m:
            yield Finding("A01", (pid,), f"Proveedor {vid} ausente del maestro")
            continue
        same_site = (site or "").strip().upper() == (m["site"] or "").strip().upper()
        account = digits(p["account"])
        same_account = account == digits(m["account"])
        if not same_site:
            yield Finding("A03", (pid,), f"Sitio en pago: {site or 'vacío'} · Maestro: {m['site'] or 'vacío'}")
        if not same_account:
            yield Finding("A04", (pid,), f"Cuenta en pago: {account or 'vacía'} · Maestro: {digits(m['account']) or 'vacía'}")
        for rule, field, applies in (
            ("A06", "inactive", True), ("A07", "site_inactive", same_site),
            ("A08", "account_inactive", bool(account) and same_account),
        ):
            if applies and m[field] and day > m[field]:
                yield Finding(rule, (pid,), f"Inactivación {m[field]:%d/%m/%Y} · Pago {day:%d/%m/%Y}")
        for rule, field, limit, applies in (
            ("A17", "created", RECENT_VENDOR_DAYS, True),
            ("A18", "account_updated", RECENT_ACCOUNT_DAYS, same_account and bool(account)),
        ):
            if applies and m[field] and 0 <= (day - m[field]).days <= limit:
                yield Finding(rule, (pid,), f"{(day - m[field]).days} día(s) desde el {m[field]:%d/%m/%Y}")

    account_groups = defaultdict(list)
    for vid, m in master.items():
        account = digits(m["account"])
        if account:
            account_groups[account].append(vid)
        issues = quality_issues(m)
        if issues:
            yield Finding("A16", (), " · ".join(issues), vendor_ids=(vid,), scope_key=vid)
        history = by_vendor.get(vid, [])
        if (not m["inactive"] or m["inactive"] > cutoff) and (not m["created"] or m["created"] <= cutoff):
            last = history[-1]["paid_on"] if history else None
            if not last or last < lookback:
                evidence = f"Último pago {last:%d/%m/%Y}" if last else "Sin actividad histórica"
                yield Finding("A21", (), f"{evidence} · Corte {cutoff:%d/%m/%Y}",
                              vendor_ids=(vid,), occurred_on=cutoff, scope_key=vid)
    for account, vendors in account_groups.items():
        if len(vendors) > 1:
            yield Finding("A05", (), f"Cuenta {account} compartida por {len(vendors)} proveedores",
                          vendor_ids=tuple(vendors), scope_key=":".join(sorted(vendors)))

    for (vid, invoice, _, _), ids in invoice_groups.items():
        if len(ids) > 1:
            yield Finding("A09", tuple(ids), f"Factura {invoice} repetida {len(ids)} veces para {vid}")
    for uuid, ids in uuid_groups.items():
        if len(ids) > 1:
            yield Finding("A10", tuple(ids), f"UUID {uuid} repetido {len(ids)} veces")
    for (_, day), ids in daily_groups.items():
        if len(ids) > 1:
            yield Finding("A25", tuple(ids), f"{len(ids)} pagos al mismo proveedor el {day:%d/%m/%Y}")
    for reference, rows in reference_groups.items():
        if len(rows) > 1:
            yield Finding("A26", tuple(p["id"] for p in rows),
                          f"Referencia {reference} repetida en {len(rows)} pagos")

    for vid, rows in by_vendor.items():
        if total_paid > 0:
            share = sum(p["paid"] for p in rows) / total_paid
            if share > CONCENTRATION_LIMIT:
                yield Finding("A20", tuple(p["id"] for p in rows), f"{share:.2%} del total pagado al corte",
                              vendor_ids=(vid,), occurred_on=cutoff, scope_key=vid)
        first = rows[0]
        if first["paid"] > FIRST_PAYMENT_LIMIT:
            yield Finding("A22", (first["id"],), f"Primer pago observado por {money(first['paid'])}")
        yield from historical_patterns(rows)

    for rows in by_vendor_site.values():
        previous = []

        for _, same_day in groupby(rows, key=lambda p: p["paid_on"]):
            current = list(same_day)
            if len(previous) >= HISTORY_MINIMUM:
                typical = median(p["ap_rounded"] for p in previous)
                for p in current:
                    if typical > 0 and p["ap_rounded"] > AMOUNT_MULTIPLIER * typical:
                        yield Finding("A19", (p["id"],),
                                      f"Importe AP {money(p['ap_rounded'])} · Mediana previa {money(typical)} "
                                      f"({len(previous)} pagos)",
                                      context_ids=tuple(r["id"] for r in previous))
            previous.extend(current)

    yield from monthly_findings(by_vendor, "A23", start, cutoff)
    yield from monthly_findings(by_site, "A24", start, cutoff)


def rule_parameters():
    return {
        "recent_vendor_days": RECENT_VENDOR_DAYS, "recent_account_days": RECENT_ACCOUNT_DAYS,
        "history_minimum": HISTORY_MINIMUM, "amount_multiplier": AMOUNT_MULTIPLIER,
        "concentration_limit": str(CONCENTRATION_LIMIT), "first_payment_limit": str(FIRST_PAYMENT_LIMIT),
        "baseline_months": BASELINE_MONTHS, "window_days": WINDOW_DAYS,
        "authorization_limit": str(AUTHORIZATION_LIMIT), "lower_limit": str(LOWER_LIMIT),
        "justified_batch_references": sorted(JUSTIFIED_BATCH_REFERENCES),
    }
