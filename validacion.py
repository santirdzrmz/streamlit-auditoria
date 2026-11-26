"""Validación previa: una carga inválida nunca produce resultados parciales."""
import csv
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation, localcontext

FILES = ('Maestro_auditoria.csv', 'Pagos_auditoria.csv', 'matriz_alertas.csv')
PAYMENT_FIELDS = 'INVOICE_ID VENDOR_ID VENDOR_NAME SITE FECHA_D_PAGO FECHA_VENCIMIENTO PAGADO SEGMENT1 NUM_FACTURA UUID FECHA_FACTURA IMPORTE_AP BANK_ACCOUNT_NUM PAYMENT_REASON_COMMENTS REFERENCIA NO_DOC SOURCE APPROVAL_DESCRIPTION SEGMENT4'.split()
MASTER_FIELDS = ['Id Proveedor', 'Nombre Proveedor', 'Site', 'RFC', 'Cuenta', 'Banco', 'Correo', 'Telefono', 'Fecha Creacion Prov', 'Fecha Proveedor Inactivo', 'Fecha Site Inactivo', 'Inactivacion Cuenta', 'Actualizacion Cuenta']
MATRIX_FIELDS = ['ID', 'Alerta', 'Severidad', 'Riesgo asociado', 'Objetivo', 'Categoría', 'Regla funcional']
RULE_IDS = {f'A{i:02}' for i in range(1, 31)} - {'A27'}


class DataValidationError(ValueError):
    def __init__(self, issues):
        self.issues = issues
        super().__init__('Carga rechazada:\n' + '\n'.join(issues))


def validate_inputs(directory):
    issues = []
    specs = [(FILES[0], MASTER_FIELDS, 'Id Proveedor'), (FILES[1], PAYMENT_FIELDS, 'INVOICE_ID'),
             (FILES[2], MATRIX_FIELDS, 'ID')]
    for filename, required, key in specs:
        try:
            with (directory / filename).open(encoding='utf-8-sig', newline='') as file:
                reader = csv.DictReader(file)
                missing = set(required) - set(reader.fieldnames or ())
                if missing:
                    issues.append(f'{filename}: faltan columnas {", ".join(sorted(missing))}')
                    continue
                seen = set()
                for number, row in enumerate(reader, 2):
                    where = f'{filename}, fila {number}'
                    if None in row or any(row[field] is None for field in required):
                        issues.append(f'{where}: número de columnas incorrecto')
                        continue
                    identity = row[key].strip()
                    if not identity or identity in seen:
                        issues.append(f'{where}: {key} vacío o duplicado ({identity})')
                    if row[key] != identity:
                        issues.append(f'{where}: {key} contiene espacios exteriores')
                    seen.add(identity)
                    if filename == FILES[1]:
                        if not row['VENDOR_ID'].strip() or row['VENDOR_ID'] != row['VENDOR_ID'].strip():
                            issues.append(f'{where}: VENDOR_ID vacío o con espacios exteriores')
                        dates = [(field, '%d/%m/%y', field != 'FECHA_FACTURA') for field in
                                 ('FECHA_D_PAGO', 'FECHA_VENCIMIENTO', 'FECHA_FACTURA')]
                        for field in ('PAGADO', 'IMPORTE_AP'):
                            raw = row[field]
                            value = re.sub(r'[$,\s]', '', raw) if field == 'PAGADO' else raw
                            try:
                                amount = Decimal(value)
                                integer_limit, scale = (16, 2) if field == 'PAGADO' else (18, 12)
                                if not amount.is_finite() or abs(amount) >= 10 ** integer_limit:
                                    raise InvalidOperation
                                with localcontext() as context:
                                    context.prec = 40
                                    if amount != amount.quantize(Decimal(1).scaleb(-scale)):
                                        raise InvalidOperation
                            except (InvalidOperation, ValueError):
                                issues.append(f'{where}: {field} inválido o fuera de precisión admitida')
                    elif filename == FILES[0]:
                        dates = [(field, '%d-%b-%y', False) for field in MASTER_FIELDS[8:]]
                    else:
                        dates = []
                        for field in MATRIX_FIELDS:
                            if not row[field].strip():
                                issues.append(f'{where}: {field} vacío')
                    for field, fmt, mandatory in dates:
                        value = row[field].strip()
                        if not value and not mandatory:
                            continue
                        try:
                            datetime.strptime(value, fmt)
                        except ValueError:
                            issues.append(f'{where}: {field} inválida ({value or "vacía"}), formato {fmt}')
                if filename == FILES[2] and seen != RULE_IDS:
                    issues.append(f'{filename}: se requieren las 29 reglas A01–A30, excepto A27')
        except (OSError, UnicodeError, csv.Error) as error:
            issues.append(f'{filename}: no se pudo leer ({error})')
    if issues:
        raise DataValidationError(issues)
