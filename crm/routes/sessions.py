from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from ..services.anydesk_api import AnyDeskAPI

sessions_bp = Blueprint("sessions", __name__)

anydesk_api = AnyDeskAPI()

@sessions_bp.route("/", methods=["GET"])
def list_sessions():
    sessions = anydesk_api.get_sessions()
    return render_template("sessions.html", sessions=sessions)

@sessions_bp.route("/<sid>", methods=["GET"])
def session_details(sid):
    session = anydesk_api.get_session_details(sid)
    if not session:
        flash("Sessão não encontrada.", "error")
        return redirect(url_for("sessions.list_sessions"))
    return render_template("session_details.html", session=session)

@sessions_bp.route("/<sid>/close", methods=["POST"])
def close_session(sid):
    if anydesk_api.close_session(sid):
        flash("Sessão encerrada com sucesso!", "success")
    else:
        flash("Erro ao encerrar sessão!", "error")
    return redirect(url_for("sessions.list_sessions"))

@sessions_bp.route("/<sid>/comment", methods=["POST"])
def change_comment(sid):
    comment = request.form.get("comment")
    anydesk_api.update_session_comment(sid, comment)
    flash("Comentário atualizado com sucesso!", "success")
    return redirect(url_for("sessions.list_sessions"))