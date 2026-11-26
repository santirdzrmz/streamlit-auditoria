"""Consultas DuckDB sobre las tablas normalizadas del extracto."""

from auditoria import (
    AMOUNT_MULTIPLIER, AUTHORIZATION_LIMIT, BASELINE_MONTHS, CONCENTRATION_LIMIT,
    FIRST_PAYMENT_LIMIT, HISTORY_MINIMUM, JUSTIFIED_BATCH_REFERENCES, LOWER_LIMIT,
    RECENT_ACCOUNT_DAYS, RECENT_VENDOR_DAYS, WINDOW_DAYS,
)

JOIN = "SELECT p.id FROM payments p JOIN master m ON m.id = p.vendor_id"
ACCOUNT = "regexp_replace(coalesce({}.account, ''), '[^0-9]', '', 'g')"
PA, MA = ACCOUNT.format("p"), ACCOUNT.format("m")
SAME_SITE = "upper(trim(coalesce(p.site, ''))) = upper(trim(coalesce(m.site, '')))"


def repeated(fields, condition="true"):
    return f"""SELECT id FROM payments WHERE {condition}
QUALIFY count(*) OVER (PARTITION BY {fields}) > 1"""


def monthly(column):
    return f"""WITH monthly AS (
    SELECT {column} AS entity, date_trunc('month', paid_on) AS month, sum(paid) AS total
    FROM payments GROUP BY ALL
), totals AS (
    SELECT *, sum(total) OVER (
        PARTITION BY entity ORDER BY month
        RANGE BETWEEN INTERVAL '{BASELINE_MONTHS} months' PRECEDING AND INTERVAL '1 month' PRECEDING
    ) AS previous_total
    FROM monthly
)
SELECT p.id FROM payments p JOIN totals t
  ON p.{column} IS NOT DISTINCT FROM t.entity AND date_trunc('month', p.paid_on) = t.month
WHERE t.month >= (SELECT date_trunc('month', min(paid_on)) FROM payments)
    + INTERVAL '{BASELINE_MONTHS} months'
  AND t.previous_total > 0
  AND t.total * {BASELINE_MONTHS} > {AMOUNT_MULTIPLIER} * t.previous_total"""


def unusual_fields(fields):
    return f"""WITH values_by_field AS (
    UNPIVOT payments ON {', '.join(fields)} INTO NAME field VALUE entry
), frequencies AS (
    SELECT cur.id, cur.entry AS current_entry, old.entry, cur.field, count(*) AS n
    FROM values_by_field cur JOIN values_by_field old
      ON cur.vendor_id = old.vendor_id AND cur.field = old.field AND old.paid_on < cur.paid_on
    WHERE cur.entry <> '' AND old.entry <> ''
    GROUP BY ALL
), ranked AS (
    SELECT *, rank() OVER (PARTITION BY id, field ORDER BY n DESC) AS position,
        count(*) OVER (PARTITION BY id, field, n) AS tied,
        sum(n) OVER (PARTITION BY id, field) AS history
    FROM frequencies
)
SELECT DISTINCT id FROM ranked
WHERE history >= {HISTORY_MINIMUM} AND position = 1 AND tied = 1 AND current_entry <> entry"""


MASTERS = {"A05", "A16", "A21"}
EXCEPTIONS = ", ".join("'" + ref.replace("'", "''") + "'" for ref in sorted(JUSTIFIED_BATCH_REFERENCES))
REFERENCE_FILTER = "reference <> ''" + (f" AND reference NOT IN ({EXCEPTIONS})" if EXCEPTIONS else "")
QUERIES = {
    "A01": "SELECT p.id FROM payments p ANTI JOIN master m ON m.id = p.vendor_id",
    "A02": f"{JOIN}\nWHERE p.master_rfc IS NOT NULL AND p.payment_rfc IS DISTINCT FROM p.master_rfc",
    "A03": f"{JOIN}\nWHERE NOT ({SAME_SITE})",
    "A04": f"{JOIN}\nWHERE {PA} <> {MA}",
    "A05": f"""SELECT m.id FROM master m WHERE {MA} <> ''
QUALIFY count(*) OVER (PARTITION BY {MA}) > 1""",
    "A06": f"{JOIN}\nWHERE p.paid_on > m.inactive",
    "A07": f"{JOIN}\nWHERE {SAME_SITE} AND p.paid_on > m.site_inactive",
    "A08": f"{JOIN}\nWHERE {PA} <> '' AND {PA} = {MA} AND p.paid_on > m.account_inactive",
    "A09": repeated("vendor_id, invoice, payment_rfc, ap", "invoice <> ''"),
    "A10": repeated("uuid", "uuid <> ''"),
    "A11": "SELECT id FROM payments WHERE coalesce(uuid, '') = ''",
    "A12": "SELECT id FROM payments WHERE paid <> ap_rounded",
    "A13": "SELECT id FROM payments WHERE paid_on > due_on",
    "A14": "SELECT id FROM payments WHERE paid_on < invoiced_on",
    "A15": "SELECT id FROM payments WHERE contains(upper(coalesce(comments, '')), 'FALTA NC')",
    "A16": """SELECT DISTINCT id FROM (
    UNPIVOT (SELECT id, coalesce(rfc, '') AS rfc, coalesce(account, '') AS account,
        coalesce(bank, '') AS bank, coalesce(email, '') AS email,
        coalesce(phone, '') AS phone FROM master)
    ON rfc, account, bank, email, phone INTO NAME field VALUE value
) fields
WHERE value = '' OR upper(value) IN (
    'N/A', 'NA', 'SIN DATO', 'SIN DATOS', 'PENDIENTE', 'XAXX010101000', 'XEXX010101000'
) OR CASE field
    WHEN 'rfc' THEN NOT regexp_full_match(upper(value), '[A-ZÑ&]{3,4}[0-9]{6}[A-Z0-9]{3}')
    WHEN 'account' THEN NOT regexp_full_match(regexp_replace(value, '[^0-9]', '', 'g'), '[0-9]{6,18}')
        OR regexp_full_match(regexp_replace(value, '[^0-9]', '', 'g'), '0+')
    WHEN 'bank' THEN NOT regexp_matches(value, '[\\p{L}\\p{Nl}\\p{No}]')
    WHEN 'email' THEN NOT regexp_full_match(value, '[^\\s@]+@[^\\s@]+[.][^\\s@]+')
    WHEN 'phone' THEN NOT regexp_full_match(regexp_replace(value, '[^0-9]', '', 'g'), '[0-9]{10}')
        OR regexp_full_match(regexp_replace(value, '[^0-9]', '', 'g'), '0+')
END""",
    "A17": f"{JOIN}\nWHERE p.paid_on - m.created BETWEEN 0 AND {RECENT_VENDOR_DAYS}",
    "A18": f"{JOIN}\nWHERE {PA} <> '' AND {PA} = {MA}\n"
           f"  AND p.paid_on - m.account_updated BETWEEN 0 AND {RECENT_ACCOUNT_DAYS}",
    "A19": f"""SELECT p.id FROM payments p JOIN payments h
  ON p.vendor_id = h.vendor_id AND p.site IS NOT DISTINCT FROM h.site AND h.paid_on < p.paid_on
GROUP BY p.id, p.ap_rounded
HAVING count(*) >= {HISTORY_MINIMUM} AND median(h.ap_rounded::DECIMAL(20,3)) > 0
  AND p.ap_rounded > {AMOUNT_MULTIPLIER} * median(h.ap_rounded::DECIMAL(20,3))""",
    "A20": f"""WITH big AS (
    SELECT vendor_id FROM payments GROUP BY vendor_id
    HAVING (SELECT sum(paid) FROM payments) > 0
       AND sum(paid) > {CONCENTRATION_LIMIT} * (SELECT sum(paid) FROM payments)
)
SELECT p.id FROM payments p JOIN big USING (vendor_id)""",
    "A21": """WITH cutoff AS (SELECT max(paid_on) AS day FROM payments)
SELECT m.id FROM master m CROSS JOIN cutoff c
WHERE c.day IS NOT NULL AND (m.inactive IS NULL OR m.inactive > c.day)
  AND (m.created IS NULL OR m.created <= c.day)
  AND NOT EXISTS (
    SELECT 1 FROM payments p WHERE p.vendor_id = m.id
      AND p.paid_on >= c.day - INTERVAL '1 year'
  )""",
    "A22": f"""SELECT id FROM (
    SELECT id, paid, row_number() OVER (PARTITION BY vendor_id ORDER BY paid_on, id) AS position
    FROM payments
) first_payment WHERE position = 1 AND paid > {FIRST_PAYMENT_LIMIT}""",
    "A23": monthly("vendor_id"),
    "A24": monthly("site"),
    "A25": repeated("vendor_id, paid_on"),
    "A26": repeated("reference", REFERENCE_FILTER),
    "A28": unusual_fields(("source", "approval")),
    "A29": unusual_fields(("ledger",)),
    "A30": f"""WITH eligible AS (
    SELECT * FROM payments WHERE paid >= {LOWER_LIMIT} AND paid < {AUTHORIZATION_LIMIT}
), qualifying AS (
    SELECT a.vendor_id, a.paid_on FROM (SELECT DISTINCT vendor_id, paid_on FROM eligible) a
    JOIN eligible p ON a.vendor_id = p.vendor_id
       AND p.paid_on BETWEEN a.paid_on AND a.paid_on + {WINDOW_DAYS}
    GROUP BY ALL HAVING count(*) >= 2 AND sum(p.paid) > {AUTHORIZATION_LIMIT}
)
SELECT DISTINCT p.id FROM eligible p JOIN qualifying a ON p.vendor_id = a.vendor_id
  AND p.paid_on BETWEEN a.paid_on AND a.paid_on + {WINDOW_DAYS}""",
}


def execute_queries(payments, master, selected):
    """Devuelve los IDs detectados por cada consulta en su unidad de análisis."""
    import duckdb
    import pandas as pd

    with duckdb.connect() as db:
        for name, records, date_fields in (
            ("payments", payments, ("paid_on", "due_on", "invoiced_on")),
            ("master", master, ("inactive", "site_inactive", "account_inactive", "created", "account_updated")),
        ):
            if not records:
                continue
            frame = pd.DataFrame(records.values())
            db.register("input_rows", frame)
            dates = ", ".join(f"{field}::DATE AS {field}" for field in date_fields)
            db.execute(f"CREATE TEMP TABLE {name} AS SELECT * REPLACE ({dates}) FROM input_rows")
            db.unregister("input_rows")
        if not master:
            db.execute("""CREATE TEMP TABLE master (id VARCHAR, site VARCHAR, account VARCHAR,
                rfc VARCHAR, bank VARCHAR, email VARCHAR, phone VARCHAR, inactive DATE,
                site_inactive DATE, account_inactive DATE, created DATE, account_updated DATE)""")
        if not payments:
            db.execute("CREATE TEMP TABLE payments (paid_on DATE, vendor_id VARCHAR)")
        return {
            code: {row[0] for row in db.execute(QUERIES[code]).fetchall()}
            if payments or code in MASTERS else set()
            for code in selected
        }
