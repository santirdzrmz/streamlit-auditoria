from pathlib import Path

import pandas as pd
import streamlit as st

from consultas import MASTERS, QUERIES, execute_queries


@st.cache_data(max_entries=2)
def extract(run_id, _run):
    columns = {"id": "INVOICE_ID", "vendor_id": "VENDOR_ID", "vendor": "VENDOR_NAME",
               "uuid": "UUID", "site": "SITE", "account": "BANK_ACCOUNT_NUM", "ap": "IMPORTE_AP",
               "paid_on": "FECHA_D_PAGO", "invoiced_on": "FECHA_FACTURA", "due_on": "FECHA_VENCIMIENTO"}
    payments = pd.DataFrame(_run.payments.values(), columns=list(columns)).rename(columns=columns)
    for col in ("FECHA_D_PAGO", "FECHA_FACTURA", "FECHA_VENCIMIENTO"):
        payments[col] = pd.to_datetime(payments[col]).dt.strftime("%d/%m/%y")
    return payments.fillna("").astype(str)


def download(frame, label, filename):
    st.download_button(label, frame.to_csv(index=False).encode("utf-8-sig"), filename, "text/csv", icon=":material/download:")


def validation(run):
    cases = pd.read_csv(Path(__file__).parent/"datos"/"casos_esperados.csv")
    verdicts = []
    for row in cases.itertuples():
        items = [item for item in run.findings if item.rule == row.ID]
        keys = [k.strip() for k in row.Registros.split(",")]
        expected = set(keys)
        if row.ID in {"A06", "A07", "A08"}:
            flagged = {k for item in items for k in item.payment_ids}
            ok = keys[0] not in flagged and keys[1] in flagged
        elif row.ID in {"A05", "A16", "A20", "A21"}:
            ok = any(expected == set(item.vendor_ids) for item in items)
        elif row.ID == "A24":
            ok = any(item.site == keys[0] and item.occurred_on.strftime("%Y-%m") == keys[1] for item in items)
        elif row.ID in {"A19", "A23", "A28", "A29"}:
            ok = any(keys[-1] in item.payment_ids and expected <= set(item.payment_ids + item.context_ids) for item in items)
        else:
            ok = any(expected == set(item.payment_ids) for item in items)
        verdicts.append(ok)
    cases["Verificado"] = verdicts
    st.metric("Casos de referencia detectados", f"{sum(verdicts)} / {len(cases)}")
    st.caption("La cobertura se calcula sobre los casos documentados. Las etiquetas parciales permiten verificar ejemplos concretos de las reglas.")
    st.dataframe(cases, hide_index=True)
    download(cases, "Descargar validación", "validacion.csv")


@st.cache_data(max_entries=8)
def sql_results(run_id, selected, _run):
    return execute_queries(_run.payments, _run.master, selected)


def show_sql(run, payments, period):
    st.subheader("Consultas de auditoría")
    def rule_label(code):
        return f"{code} · {run.rules[code]['name']}"

    rules = sorted(run.rules)
    selected = st.multiselect("Reglas para consultar", rules,
                              default=["A01", "A04", "A05", "A10"], format_func=rule_label)
    query = st.text_input("Buscar ID, proveedor, cuenta o UUID").strip()
    only = st.checkbox("Solo registros con alguna regla seleccionada", True)
    matches = sql_results(run.id, tuple(selected), run)
    if period and not period[0] <= run.end <= period[1] and "A21" in matches:
        matches["A21"] = set()
    st.caption("Las reglas se evalúan con el historial completo y los pagos se muestran según el periodo.")
    payment_rules = [code for code in selected if code not in MASTERS]
    master_rules = [code for code in selected if code in MASTERS]
    suppliers = pd.DataFrame([
        {"ID proveedor": vid, "Proveedor": row["vendor"], "Sitio": row["site"], "Cuenta": row["account"]}
        for vid, row in run.master.items()
    ], columns=["ID proveedor", "Proveedor", "Sitio", "Cuenta"])
    search_cols = ["INVOICE_ID", "VENDOR_ID", "VENDOR_NAME", "BANK_ACCOUNT_NUM", "UUID"]
    pay_tab, master_tab, code_tab = st.tabs([
        ":material/payments: Pagos", ":material/groups: Maestro de proveedores", ":material/code: Consultas SQL",
    ])
    with pay_tab:
        show_sql_table(payments, "INVOICE_ID", search_cols, payment_rules, matches,
                       query, only, "Pagos", "consultas_pagos.csv")
    with master_tab:
        st.caption("A05, A16 y A21 identifican proveedores del maestro. A05 y A16 carecen de fecha. A21 se muestra si el periodo incluye el corte del extracto.")
        show_sql_table(suppliers, "ID proveedor", ["ID proveedor", "Proveedor", "Cuenta"],
                       master_rules, matches, query, only, "Proveedores", "consultas_maestro.csv")
    with code_tab:
        code = st.selectbox("Ver consulta", rules, format_func=rule_label)
        st.caption("DuckDB ejecuta estas consultas sobre las tablas normalizadas payments y master.")
        st.code(QUERIES[code], language="sql")


def show_sql_table(frame, id_column, search_cols, rules, matches, query, only, label, filename):
    flags = pd.DataFrame({code: frame[id_column].isin(matches[code]) for code in rules}, index=frame.index)
    mask = flags.any(axis=1) if only else pd.Series(True, index=frame.index)
    if query:
        mask &= frame[search_cols].apply(
            lambda col: col.fillna("").str.contains(query, case=False, regex=False)).any(axis=1)
    table = frame.loc[mask].join(flags)
    if rules:
        table["Reglas cumplidas"] = [
            ", ".join(row.index[row]) for _, row in flags.loc[mask].iterrows()
        ]
    st.metric(f"{label} en la selección", len(table))
    st.dataframe(table, hide_index=True)
    download(table, f"Descargar {label.lower()}", filename)


def show_analysis(run, section, period):
    if section == "Validación de casos":
        st.caption("La validación comprueba los casos documentados del extracto completo.")
        validation(run)
        return
    payments = extract(run.id, run)
    if period:
        start, end = period
        mask = payments["INVOICE_ID"].map(lambda key: start <= run.payments[key]["paid_on"] <= end)
        payments = payments.loc[mask].reset_index(drop=True)
        st.caption(f"{start:%d/%m/%Y} al {end:%d/%m/%Y} · {len(payments):,} pagos del periodo")
    show_sql(run, payments, period)
