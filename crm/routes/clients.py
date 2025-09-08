from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from ..services.anydesk_api import AnyDeskAPI

clients_bp = Blueprint("clients", __name__)

anydesk_api = AnyDeskAPI()

@clients_bp.route("/", methods=["GET"])
def list_clients():
    clients = anydesk_api.get_clients()  # Retorna lista mock ou real
    return render_template("users.html", clients=clients, mode=anydesk_api.mode)

@clients_bp.route("/<cid>", methods=["GET"])
def client_details(cid):
    client = anydesk_api.get_client_details(cid)
    return render_template("client_details.html", client=client, mode=anydesk_api.mode)

@clients_bp.route("/<cid>/alias", methods=["POST"])
def change_alias(cid):
    alias = request.form.get("alias")
    if anydesk_api.update_client_alias(cid, alias):
        flash("Alias atualizado com sucesso!", "success")
    else:
        flash("Erro ao atualizar alias!", "error")
    return redirect(url_for("clients.list_clients", cid=cid, _mode=anydesk_api.mode))

@clients_bp.route("/<cid>/alias/remove", methods=["POST"])
def remove_alias(cid):
    if anydesk_api.remove_client_alias(cid):
        flash("Alias removido com sucesso!", "success")
    else:
        flash("Erro ao remover alias!", "error")
    return redirect(url_for("clients.client_details", cid=cid, _mode=anydesk_api.mode))