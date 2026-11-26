from collections import Counter
from datetime import date
from decimal import Decimal

from seguimiento import DEFAULT_CASE


def vendor_options(run):
    values = {p["vendor_id"]: vendor_label(p) for p in run.payments.values()}
    values.update({key: f"{row['vendor']} · {key}" for key, row in run.master.items()})
    return values


def vendor_label(p):
    return f'{p["vendor"]} · {p["vendor_id"]}'


def matches(p, begin, finish, site, vendor):
    return begin <= p["paid_on"] <= finish and (not site or site == p["site"]) and (
        not vendor or vendor == p["vendor_id"]
    )


def report(run, cases, begin=None, finish=None, site=None, vendor=None,
           severity=None, rule=None, category=None, case_status=None, case_owner=None):
    payments, rules, findings, master = run.payments, run.rules, run.findings, run.master
    vendors = vendor_options(run)
    start, end = run.start or date.today(), run.end or date.today()
    CATEGORIES = tuple(dict.fromkeys(rules[code]["category"] for code in sorted(rules)))
    begin = date.fromisoformat(begin) if begin else start
    finish = date.fromisoformat(finish) if finish else end
    visible_ids = {pid for pid, p in payments.items() if matches(p, begin, finish, site, vendor)}
    rows = []
    affected = set()
    affected_vendors = set()
    monthly = Counter()
    counts = dict.fromkeys(CATEGORIES, 0)
    for item in findings:
        if begin > finish:
            break
        metadata = rules[item.rule]
        management = cases.get(item.id, DEFAULT_CASE)
        if case_status and management['status'] != case_status:
            continue
        if case_owner and case_owner.strip().casefold() not in management['owner'].casefold():
            continue
        if rule and item.rule != rule:
            continue
        if severity and severity != metadata["severity"]:
            continue
        matching_ids = [pid for pid in item.payment_ids if pid in visible_ids]
        if item.payment_ids:
            if not matching_ids:
                continue
            payment = payments[matching_ids[0]]
            day = item.occurred_on or payment["paid_on"]
            sites = list(dict.fromkeys(payments[pid]["site"] for pid in matching_ids))
            vendor_ids = list(dict.fromkeys(payments[pid]["vendor_id"] for pid in matching_ids))
        else:
            day = item.occurred_on
            vendor_ids = [key for key in item.vendor_ids
                          if (not vendor or key == vendor) and (not site or master[key]["site"] == site)]
            if not vendor_ids or (day and not begin <= day <= finish):
                continue
            sites = list(dict.fromkeys(master[key]["site"] for key in vendor_ids))

        counts[metadata["category"]] += 1
        if category and metadata["category"] != category:
            continue
        affected.update(matching_ids)
        affected_vendors.update(vendor_ids)
        if day and begin <= day <= finish:
            monthly[day.replace(day=1)] += 1
        vendor_text = vendors[vendor_ids[0]] if len(vendor_ids) == 1 else f"{len(vendor_ids)} proveedores"
        rows.append(dict(id=item.id, date=day.isoformat() if day else "", rule=item.rule,
                         severity=metadata["severity"], site=item.site or ", ".join(s for s in sites if s),
                         vendor=vendor_text, evidence=item.evidence,
                         status=management['status'], owner=management['owner'],
                         amount=sum((payments[pid]['paid'] for pid in matching_ids), Decimal(0))))

    total = sum((payments[pid]['paid'] for pid in affected), Decimal(0))
    return rows, monthly, counts, len(visible_ids), len(affected), len(affected_vendors), total
