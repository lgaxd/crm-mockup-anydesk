from flask import Flask
from crm.routes.main import main_bp
from crm.routes.clients import clients_bp
from crm.routes.sessions import sessions_bp
from crm.services.anydesk_api import AnyDeskAPI

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = "anydesk_poc_secret"

    # Registrar blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(clients_bp, url_prefix="/clients")
    app.register_blueprint(sessions_bp, url_prefix="/sessions")

    # Inicializar integração com API AnyDesk
    app.anodesk_api = AnyDeskAPI()

    return app