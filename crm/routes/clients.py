from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app

clients_bp = Blueprint("clients", __name__)

@clients_bp.route("/", methods=["GET"])
def list_clients():
    clients = current_app.anodesk_api.get_clients()  # Retorna lista mock ou real
    return render_template("users.html", clients=clients, mode=current_app.anodesk_api.mode)

@clients_bp.route("/<cid>", methods=["GET"])
def client_details(cid):
    client = current_app.anodesk_api.get_client_details(cid)
    return render_template("client_details.html", client=client, mode=current_app.anodesk_api.mode)

@clients_bp.route("/<cid>/alias", methods=["POST"])
def change_alias(cid):
    alias = request.form.get("alias")
    if current_app.anodesk_api.update_client_alias(cid, alias):
        flash("Alias atualizado com sucesso!", "success")
    else:
        flash("Erro ao atualizar alias!", "error")
    return redirect(url_for("clients.client_details", cid=cid))

@clients_bp.route("/<cid>/alias/remove", methods=["POST"])
def remove_alias(cid):
    if current_app.anodesk_api.remove_client_alias(cid):
        flash("Alias removido com sucesso!", "success")
    else:
        flash("Erro ao remover alias!", "error")
    return redirect(url_for("clients.client_details", cid=cid))