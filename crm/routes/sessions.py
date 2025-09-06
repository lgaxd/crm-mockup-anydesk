from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app

sessions_bp = Blueprint("sessions", __name__)

@sessions_bp.route("/", methods=["GET"])
def list_sessions():
    sessions = current_app.anodesk_api.get_sessions()
    return render_template("sessions.html", sessions=sessions, mode=current_app.anodesk_api.mode)

@sessions_bp.route("/<sid>", methods=["GET"])
def session_details(sid):
    session = current_app.anodesk_api.get_session_details(sid)
    return render_template("session_details.html", session=session, mode=current_app.anodesk_api.mode)

@sessions_bp.route("/<sid>/close", methods=["POST"])
def close_session(sid):
    if current_app.anodesk_api.close_session(sid):
        flash("Sessão encerrada com sucesso!", "success")
    else:
        flash("Erro ao encerrar sessão!", "error")
    return redirect(url_for("sessions.list_sessions"))

@sessions_bp.route("/<sid>/comment", methods=["POST"])
def change_comment(sid):
    comment = request.form.get("comment")
    if current_app.anodesk_api.update_session_comment(sid, comment):
        flash("Comentário atualizado com sucesso!", "success")
    else:
        flash("Erro ao atualizar comentário!", "error")
    return redirect(url_for("sessions.session_details", sid=sid))