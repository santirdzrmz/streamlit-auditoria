"""Panel local de auditoría de pagos."""
from collections import Counter
from statistics import median
from pathlib import Path
import os
import sqlite3

import pandas as pd
import streamlit as st

from auditoria import money
from reporte import matches, report, vendor_options
from seguimiento import AuditStore, ConflictError, DEFAULT_CASE, STATES
from validacion import DataValidationError

st.set_page_config(page_title="Auditoría de pagos", layout="wide")


@st.cache_resource
def get_store():
    return AuditStore(Path(os.environ.get("AUDIT_DB_PATH", str(Path(__file__).parent / "datos" / "seguimiento.sqlite3"))))


FILTERS = ("periodo", "sitio", "proveedor", "categoria", "regla", "severidad", "estado", "responsable", "mes_auditoria", "modo_periodo")
COLUMNS = {
    "rule": "Regla", "date": "Fecha", "severity": "Severidad", "site": "Sitio",
    "vendor": "Proveedor", "amount": "Importe afectado", "status": "Estado",
    "owner": "Responsable", "evidence": "Evidencia",
}


def clear_filters():
    for key in FILTERS:
        st.session_state.pop(key, None)


def payment_table(run, ids):
    rows = [run.payments[key] for key in ids]
    st.dataframe([{
        "ID de factura": p["id"], "Proveedor": p["vendor"], "Sitio": p["site"],
        "Fecha de pago": p["paid_on"], "Vencimiento": p["due_on"], "Pagado": money(p["paid"]),
    } for p in rows], hide_index=True)


def follow_up(store, run, item, case, scope):
    with st.form(f"seguimiento-{scope}-{item.id}-{case['revision']}"):
        owner = st.text_input("Responsable", value=case["owner"], max_chars=120)
        status = st.selectbox("Estado del caso", STATES, index=STATES.index(case["status"]))
        resolution = st.text_area("Resolución", value=case["resolution"], max_chars=4000)
        if st.form_submit_button("Guardar seguimiento", icon=":material/save:"):
            try:
                store.save_case(run.id, item.id, owner, status, resolution, case["revision"])
            except ConflictError as error:
                st.warning(str(error))
            except (ValueError, sqlite3.Error) as error:
                st.error(str(error))
            else:
                st.session_state["mensaje"] = f"Seguimiento guardado para {item.rule}."
                st.rerun()

    with st.expander("Historial de seguimiento"):
        events = store.history(item.id)
        if events:
            st.dataframe([{
                "Fecha UTC": x["updated_at"], "Estado": x["status"],
                "Responsable": x["owner"], "Resolución": x["resolution"],
            } for x in events], hide_index=True)
        else:
            st.caption("Sin cambios registrados.")


def show_detail(store, run, item, cases, vendors, scope="explorador"):
    rule = run.rules[item.rule]
    st.subheader(f"{item.rule} · {rule['name']}")
    st.text(rule["criterion"])
    st.caption(rule["risk"])
    st.info(item.evidence)
    if item.payment_ids:
        st.markdown("**Pagos del caso**")
        payment_table(run, item.payment_ids)
    else:
        st.dataframe([
            {"Proveedor": vendors[key], "Sitio": run.master[key]["site"]}
            for key in item.vendor_ids
        ], hide_index=True)
    if item.context_ids:
        with st.expander(f"Historial de comparación · {len(item.context_ids)} pagos"):
            payment_table(run, item.context_ids)
    follow_up(store, run, item, cases.get(item.id, DEFAULT_CASE), scope)


MONTH_NAMES = (
    "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
    "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre",
)


def month_label(month):
    return f"{MONTH_NAMES[month.month - 1]} {month.year}"


def show_monthly(store, run, cases, vendors, filters, month, period):
    first, last = month.start_time.date(), month.end_time.date()
    begin, finish = period
    previous = month - 1
    prior_finish = previous.end_time.date()
    prior_begin = prior_finish.replace(day=begin.day) if begin.day <= prior_finish.day else None
    partial = (begin, finish) != (first, last)
    if partial:
        prior_finish = prior_finish.replace(day=min(finish.day, prior_finish.day))
    comparable = prior_begin is not None and run.start <= prior_begin <= prior_finish
    st.caption(f"{'Mes parcial · ' if partial else ''}{begin:%d/%m/%Y} al {finish:%d/%m/%Y}. "
               "Se aplican los filtros laterales de Auditoría.")
    if comparable:
        st.caption(f"Periodo de comparación · {prior_begin:%d/%m/%Y} al {prior_finish:%d/%m/%Y}")
    else:
        st.caption("El extracto no cubre el periodo comparable del mes anterior.")

    def metrics_for(start, end):
        rows, _, _, payments, affected, _, _ = report(run, cases, start.isoformat(), end.isoformat(), **filters)
        dated = [row for row in rows if row["date"]]
        return rows, dated, (payments, len(dated), affected, 100 * affected / payments if payments else None)

    rows, dated, current = metrics_for(begin, finish)
    _, previous_rows, past = metrics_for(prior_begin, prior_finish) if comparable else ([], [], (None,) * 4)
    labels = ("Pagos del mes", "Hallazgos del mes", "Pagos afectados", "Tasa de afectación")
    for index, (col, label, value, prior) in enumerate(zip(st.columns(4), labels, current, past)):
        rate = index == 3
        displayed = "—" if value is None else (f"{value:.1f}%" if rate else f"{value:,}")
        delta = None if value is None or prior is None else (f"{value - prior:+.1f} pp" if rate else f"{value - prior:+,}")
        col.metric(label, displayed, delta, delta_color="off", border=True)

    population = [p for p in run.payments.values() if matches(p, begin, finish, filters["site"], filters["vendor"])]
    late = [(p["paid_on"] - p["due_on"]).days for p in population if p["due_on"] and p["paid_on"] > p["due_on"]]
    if population:
        delay = f" Mediana de atraso: {median(late):g} días." if late else ""
        st.caption(f"Pagos tardíos · {len(late):,} de {len(population):,} ({len(late) / len(population):.1%})." + delay)

    st.subheader("Hallazgos por regla")
    st.caption("Un caso agrupado aparece en cada mes con pagos vinculados. Los hallazgos del maestro con fecha se cuentan en su mes de registro.")
    current_counts = Counter(row["rule"] for row in dated)
    past_counts = Counter(row["rule"] for row in previous_rows)
    codes = sorted(current_counts.keys() | past_counts.keys(), key=lambda code: (-current_counts[code], code))
    if codes:
        st.dataframe([{
            "Regla": code, "Alerta": run.rules[code]["name"], "Categoría": run.rules[code]["category"],
            "Este mes": current_counts[code], "Mes anterior": past_counts[code] if comparable else None,
            "Variación": current_counts[code] - past_counts[code] if comparable else None,
        } for code in codes], hide_index=True)
    else:
        st.info("No hay hallazgos fechados para los filtros y periodos seleccionados.")

    if codes:
        by_category = Counter(run.rules[row["rule"]]["category"] for row in dated)
        prior_categories = Counter(run.rules[row["rule"]]["category"] for row in previous_rows)
        with st.expander("Comparar por categoría"):
            st.dataframe([{
                "Categoría": name, "Este mes": by_category[name],
                "Mes anterior": prior_categories[name] if comparable else None,
                "Variación": by_category[name] - prior_categories[name] if comparable else None,
            } for name in sorted(by_category.keys() | prior_categories.keys())], hide_index=True)

    undated = [row for row in rows if not row["date"]]
    if undated:
        with st.expander(f"Hallazgos del maestro sin fecha · {len(undated):,}"):
            st.dataframe([{"Regla": row["rule"], "Proveedor": row["vendor"], "Evidencia": row["evidence"]}
                          for row in undated], hide_index=True)

    if rows:
        visible = sorted({row["rule"] for row in rows})
        rule = st.selectbox("Regla para revisar casos", [None, *visible], key="regla_mensual",
                            format_func=lambda code: f"{code} · {run.rules[code]['name']}" if code else "Todas")
        options = {row["id"]: row for row in rows if rule is None or row["rule"] == rule}
        case = st.selectbox("Caso para revisar", [None, *options], key="caso_mensual",
                            format_func=lambda key: (
                                f"{options[key]['rule']} · {options[key]['date'] or 'Sin fecha'} · "
                                f"{options[key]['vendor']} · {key[-8:]}" if key else "Selecciona un caso"
                            ))
        if case:
            item = next(item for item in run.findings if item.id == case)
            show_detail(store, run, item, cases, vendors, scope="mensual")


def request_refresh():
    st.session_state["actualizar_datos"] = True


def main():
    store = get_store()
    st.title("Auditoría de pagos")
    refresh = st.session_state.pop("actualizar_datos", False)
    if refresh or "run_id" not in st.session_state:
        try:
            run = store.refresh()
            if run.id != st.session_state.get("run_id"):
                clear_filters()
            st.session_state["run_id"] = run.id
        except (OSError, sqlite3.Error, DataValidationError) as error:
            st.error(f"Error al cargar el extracto. {error}")
    if "run_id" not in st.session_state:
        st.sidebar.button("Actualizar datos", width="stretch", on_click=request_refresh, icon=":material/refresh:")
        st.stop()
    run = store.get_run(st.session_state["run_id"])
    message = st.session_state.pop("mensaje", None)
    if message:
        st.success(message)
    st.caption(f"Datos simulados · Corte {run.end or 'sin pagos'} · {len(run.rules)} reglas · Ejecución {run.id[:12]}")
    vendors = vendor_options(run)
    cases = store.cases()
    sites = sorted({r["site"] for r in (*run.payments.values(), *run.master.values())} - {""})
    categories = sorted({r["category"] for r in run.rules.values()})
    severities = sorted({r["severity"] for r in run.rules.values()})

    with st.sidebar:
        st.html("""
            <div style="border-left: 4px solid #EF5660; padding: 0.35rem 0 0.35rem 0.85rem; margin-bottom: 0.85rem">
                <div style="font-size: 1.8rem; font-weight: 800; letter-spacing: 0.08em; line-height: 1.15">Anomalía 27</div>
                <div style="font-size: 0.9rem">Auditoría de pagos</div>
            </div>
        """)
        with st.expander("Periodo y filtros", expanded=False, icon=":material/filter_alt:"):
            month = None
            period = ()
            if run.start:
                mode = st.segmented_control(
                    "Modo de periodo", ["Mes a mes", "Selección libre"], default="Selección libre",
                    required=True, width="stretch", key="modo_periodo",
                )
                if mode == "Mes a mes":
                    months = list(pd.period_range(run.start, run.end, freq="M"))[::-1]
                    month = st.selectbox("Mes de análisis", months, key="mes_auditoria", format_func=month_label)
                    period = (max(run.start, month.start_time.date()), min(run.end, month.end_time.date()))
                else:
                    period = st.date_input("Periodo de pago", (run.start, run.end), min_value=run.start,
                                           max_value=run.end, key="periodo")
            st.caption("Los filtros siguientes se aplican a Auditoría.")
            site = st.selectbox("Sitio", [None, *sites], format_func=lambda x: x or "Todos", key="sitio")
            vendor = st.selectbox("Proveedor", [None, *sorted(vendors, key=vendors.get)],
                                  format_func=lambda x: vendors.get(x, "Todos"), key="proveedor")
            category = st.selectbox("Categoría", [None, *categories], format_func=lambda x: x or "Todas", key="categoria")
            rule = st.selectbox("Regla", [None, *sorted(run.rules)], key="regla",
                                format_func=lambda x: f"{x} · {run.rules[x]['name']}" if x else "Todas")
            severity = st.selectbox("Severidad", [None, *severities], format_func=lambda x: x or "Todas", key="severidad")
            status = st.selectbox("Estado", [None, *STATES], format_func=lambda x: x or "Todos", key="estado")
            owner = st.text_input("Responsable", key="responsable")
            st.button("Limpiar filtros", on_click=clear_filters, width="stretch", icon=":material/filter_alt_off:")
        st.button("Actualizar datos", on_click=request_refresh, width="stretch", icon=":material/refresh:")

    if run.start and len(period) != 2:
        st.info("Selecciona el inicio y el fin del periodo.")
        st.stop()
    dates = [day.isoformat() for day in period] or [None, None]
    rows, monthly, counts, payments, affected, suppliers, total = report(
        run, cases, *dates, site, vendor, severity, rule, category, status, owner
    )
    labels = {
        "Pagos revisados": f"{payments:,}", "Alertas": f"{len(rows):,}",
        "Pagos afectados": f"{affected:,}", "Proveedores afectados": f"{suppliers:,}",
        "Importe afectado": money(total), "Tasa de afectación": f"{affected / payments:.1%}" if payments else "—",
    }
    indicators = list(labels.items())
    for group in (indicators[:3], indicators[3:]):
        for col, (label, value) in zip(st.columns(3), group):
            col.metric(label, value, border=True)
    st.caption("Importes en unidades del extracto. Cada pago afectado aporta una sola vez al total.")

    tab_names = ["Resumen", "Explorar alertas", "Matriz de reglas", "Explorador SQL", "Validación de casos"]
    if month is not None:
        tab_names.insert(1, "Vista mensual")
    tab_icons = {
        "Resumen": "dashboard", "Vista mensual": "calendar_month", "Explorar alertas": "search",
        "Matriz de reglas": "table_chart", "Explorador SQL": "database", "Validación de casos": "fact_check",
    }
    labels = [f":material/{tab_icons[name]}: {name}" for name in tab_names]
    tabs = dict(zip(tab_names, st.tabs(labels)))
    overview, explorer, catalog = (tabs[name] for name in ("Resumen", "Explorar alertas", "Matriz de reglas"))
    with overview:
        if month is None:
            st.subheader("Alertas por mes")
            if run.start:
                months = pd.period_range(dates[0], dates[1], freq="M")
                st.line_chart(pd.Series(
                    [monthly.get(month.start_time.date(), 0) for month in months],
                    index=months.to_timestamp(), name="Alertas"), color="#137C72")
            else:
                st.caption("Sin pagos en el extracto.")
        st.subheader("Alertas por categoría")
        category_counts = {k: v for k, v in counts.items() if category is None or k == category}
        st.bar_chart(pd.Series(category_counts, name="Alertas"), horizontal=True, color="#3982AA")

        st.subheader("Reglas con más hallazgos")
        rule_counts = Counter(r["rule"] for r in rows)
        if rule_counts:
            st.dataframe([{"Regla": code, "Alerta": run.rules[code]["name"],
                           "Severidad": run.rules[code]["severity"], "Hallazgos": n}
                          for code, n in rule_counts.most_common()], hide_index=True, row_height=35, height=387)
        else:
            st.caption("Sin hallazgos para la selección.")
    if month is not None:
        with tabs["Vista mensual"]:
            show_monthly(store, run, cases, vendors, dict(
                site=site, vendor=vendor, severity=severity, rule=rule, category=category,
                case_status=status, case_owner=owner,
            ), month, period)
    with explorer:
        if not rows:
            st.info("No hay alertas con los filtros seleccionados.")
        else:
            order = st.selectbox("Ordenar por", ["Fecha", "Importe", "Severidad"])
            severity_rank = {"Crítica": 4, "Alta": 3, "Media/Alta": 2, "Media": 1}
            order_key = {"Fecha": lambda r: r["date"], "Importe": lambda r: r["amount"],
                         "Severidad": lambda r: severity_rank.get(r["severity"], 0)}[order]
            rows.sort(key=lambda r: (order_key(r), r["id"]), reverse=True)
            exported = pd.DataFrame(rows).rename(columns=COLUMNS)
            st.download_button("Descargar alertas filtradas", exported.to_csv(index=False).encode("utf-8-sig"),
                               "alertas_filtradas.csv", "text/csv", icon=":material/download:")
            page = st.number_input("Página", min_value=1, max_value=(len(rows) + 24) // 25, step=1)
            page_rows = rows[(page - 1) * 25:page * 25]
            index = {r["id"]: r for r in page_rows}
            st.dataframe([{label: money(r[key]) if key == "amount" else r[key]
                           for key, label in COLUMNS.items()} for r in page_rows], hide_index=True)
            selected = st.selectbox("Alerta para revisar", [None, *index], format_func=lambda key: (
                f"{index[key]['rule']} · {index[key]['date'] or 'Sin fecha'} · "
                f"{index[key]['vendor']} · {key[-8:]}" if key else "Selecciona una alerta de esta página"
            ))
            if selected:
                item = next(item for item in run.findings if item.id == selected)
                show_detail(store, run, item, cases, vendors)
    with catalog:
        count_by_rule = Counter(r["rule"] for r in rows)
        matrix = pd.DataFrame([{
            "ID": key, "Alerta": r["name"], "Categoría": r["category"], "Severidad": r["severity"],
            "Coincidencias visibles": count_by_rule[key], "Regla funcional": r["criterion"],
        } for key, r in sorted(run.rules.items())])
        severity_styles = {
            "Crítica": "background-color: #FDE2E2; color: #8B1D26",
            "Alta": "background-color: #FFE8D2; color: #823800",
            "Media/Alta": "background-color: #FFF1BE; color: #674A00",
            "Media": "background-color: #DBEDF9; color: #174A70",
        }
        st.dataframe(matrix.style.map(severity_styles.get, subset=["Severidad"]), hide_index=True)
        with st.expander("Parámetros de esta ejecución"):
            st.json(run.metadata["parameters"], expanded=False)

    from analisis import show_analysis
    for section in ("Explorador SQL", "Validación de casos"):
        with tabs[section]:
            show_analysis(run, section, period)


main()
