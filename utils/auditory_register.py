from flask import request
from database import db
from database.user_models import AuditLog
from flask import request

def registrar_auditoria(usuario_id, accion, detalles=None):
    # Validar y establecer valores por defecto
    ip_origen = request.remote_addr or "Unknown"
    dispositivo = request.user_agent.platform or "Unknown"
    user_agent = request.headers.get('User-Agent') or "Unknown"

    audit_log = AuditLog(
        usuario_id=usuario_id,
        accion=accion,
        detalles=detalles,
        ip_origen=ip_origen,
        dispositivo=dispositivo,
        user_agent=user_agent,
    )
    db.session.add(audit_log)
    db.session.commit()