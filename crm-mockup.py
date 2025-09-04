import os
import time
import hmac
import hashlib
import base64
import json
from urllib.parse import urlencode, quote

import requests
from flask import Flask, render_template, request, redirect, url_for, flash

# ==============================
# Config
# ==============================
ANYDESK_API_BASE = os.getenv("ANYDESK_API_BASE", "https://v1.api.anydesk.com:8081")
ANYDESK_LICENSE_ID = os.getenv("ANYDESK_LICENSE_ID")  # ex: "1438129266231705"
ANYDESK_API_PASSWORD = os.getenv("ANYDESK_API_PASSWORD")  # ex: "UYETICGU2CT3KES"
ANYDESK_MODE = os.getenv("ANYDESK_MODE", "auto").lower()  # auto | real | mock

# ==============================
# Flask
# ==============================
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET", "anydesk_poc_secret")

# ==============================
# Util: assinatura e cliente HTTP
# ==============================

def _sha1_base64(data: bytes) -> str:
    """Retorna Base64(SHA1(data)). Para sem body, usar b''."""
    sha = hashlib.sha1()
    sha.update(data)
    return base64.b64encode(sha.digest()).decode()

def _hmac_sha1_base64(key: str, message: str) -> str:
    """Retorna Base64(HMAC-SHA1(key, message))."""
    h = hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha1)
    return base64.b64encode(h.digest()).decode()

def _build_query(params: dict | None, flag_params: list[str] | None = None) -> str:
    """
    Monta querystring ordenada. Para flags booleanas (sem valor), se True inclui
    o nome puro (ex: '?online'); se False, omite. Os demais pares vão com urlencode.
    """
    params = params or {}
    flag_params = flag_params or []
    parts = []

    # Pares chave=valor (exclui flags)
    kv = {k: v for k, v in params.items() if k not in flag_params and v is not None}
    if kv:
        # ordenar por chave para ter um Resource estável para assinatura
        ordered = dict(sorted(kv.items(), key=lambda x: x[0]))
        parts.append(urlencode(ordered, doseq=True, safe="/:@"))

    # Flags (sem valor)
    for name in sorted(flag_params):
        if params.get(name) is True:
            parts.append(quote(name, safe=""))

    if not parts:
        return ""
    return "?" + "&".join(parts)

class AnyDeskClient:
    def __init__(self, base_url: str, license_id: str | None, api_password: str | None):
        self.base_url = base_url.rstrip("/")
        self.license_id = license_id
        self.api_password = api_password

    @property
    def enabled(self) -> bool:
        return bool(self.license_id and self.api_password)

    def _build_auth_headers(self, http_method: str, resource: str, body_bytes: bytes | None) -> dict:
        """
        Monta o header Authorization conforme doc:
        Authorization: AD <LicenseId>:<Timestamp>:<Token>
        Token = Base64(HMAC-SHA1(ApiPassword, RequestString))
        RequestString = HttpMethod + "\n" + Resource + "\n" + Timestamp + "\n" + ContentHash
        ContentHash = Base64(SHA1(body)) (SHA1 do string vazio se não houver body)
        """
        if not self.enabled:
            return {}

        http_method = http_method.upper()
        timestamp = str(int(time.time()))
        content_hash = _sha1_base64(body_bytes or b"")
        request_string = f"{http_method}\n{resource}\n{timestamp}\n{content_hash}"
        token = _hmac_sha1_base64(self.api_password, request_string)
        return {
            "Authorization": f"AD {self.license_id}:{timestamp}:{token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(self, method: str, path: str, query: str = "", json_body: dict | None = None):
        """
        Executa a requisição com assinatura. `resource` = path + query (ex: /clients?online).
        """
        resource = f"{path}{query}"
        body_bytes = b""
        if json_body is not None:
            # Importante: serialização consistente com a que será enviada
            body_bytes = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = self._build_auth_headers(method, resource, body_bytes)

        url = f"{self.base_url}{resource}"
        if not self.enabled:
            raise RuntimeError("AnyDesk client not enabled (missing license or API password)")

        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=(body_bytes if json_body is not None else None),
            timeout=20,
        )
        if resp.status_code >= 400:
            # Tenta extrair a mensagem de erro do JSON, se existir
            try:
                err = resp.json()
            except Exception:
                err = {"error": resp.text}
            raise requests.HTTPError(f"{resp.status_code} from AnyDesk: {err}", response=resp)

        # 204 No Content → não tem body
        if resp.status_code == 204:
            return None
        # Demais → retorna JSON
        if resp.content:
            return resp.json()
        return None

    # ------------- Endpoints -------------

    def auth_test(self):
        return self._request("GET", "/auth")

    def sysinfo(self):
        return self._request("GET", "/sysinfo")

    # Clients
    def clients_list(self, offset: int = 0, limit: int = 50, sort: str | None = None,
                     order: str = "desc", online: bool = False):
        params = {
            "offset": offset,
            "limit": limit if limit is not None else -1,
            "sort": sort,
            "order": order,
            "online": online,  # flag sem valor quando True
        }
        query = _build_query(params, flag_params=["online"])
        return self._request("GET", "/clients", query=query)

    def client_details(self, cid: str):
        return self._request("GET", f"/clients/{cid}")

    def change_alias(self, cid: str, alias: str | None):
        body = {"alias": alias}  # alias string ou null para remover
        return self._request("PATCH", f"/clients/{cid}", json_body=body)

    # Sessions
    def sessions_list(self, cid: str | None = None, direction: str | None = None,
                      ts_from: int | None = None, ts_to: int | None = None,
                      offset: int = 0, limit: int = 50, sort: str | None = None, order: str = "desc"):
        params = {
            "cid": cid,
            "direction": direction,  # "in", "out" ou "inout" (doc menciona "in" ou "out"; default é "inout")
            "from": ts_from,
            "to": ts_to,
            "offset": offset,
            "limit": limit if limit is not None else -1,
            "sort": sort,
            "order": order,
        }
        query = _build_query(params)
        return self._request("GET", "/sessions", query=query)

    def session_details(self, sid: str):
        return self._request("GET", f"/sessions/{sid}")

    def close_session(self, sid: str):
        # POST /sessions/<sid>/action  { "action": "close" }
        body = {"action": "close"}
        return self._request("POST", f"/sessions/{sid}/action", json_body=body)

    def change_session_comment(self, sid: str, comment: str | None):
        # PATCH /sessions/<sid>  { "comment": "..." } ou null para deletar
        body = {"comment": comment}
        return self._request("PATCH", f"/sessions/{sid}", json_body=body)

# ==============================
# Mock data (fallback)
# ==============================
mock_clients = [
    {"cid": "123-456-789", "alias": "Lucas-PC", "client_version": "7.1.10", "online": True, "online_time": 7200},
    {"cid": "987-654-321", "alias": "FIAP-Lab", "client_version": "7.1.10", "online": False, "online_time": 0},
    {"cid": "555-111-999", "alias": "Servidor-Teste", "client_version": "7.1.10", "online": True, "online_time": 3600},
]
mock_sessions = [
    {"sid": "S001", "from": {"alias": "Lucas-PC", "cid": "123-456-789"}, "to": {"alias": "Servidor-Teste", "cid": "555-111-999"}, "duration": 300, "active": True, "comment": "Sessão de manutenção"},
    {"sid": "S002", "from": {"alias": "FIAP-Lab", "cid": "987-654-321"}, "to": {"alias": "Lucas-PC", "cid": "123-456-789"}, "duration": 600, "active": False, "comment": None},
]

def running_mode() -> str:
    """
    'real'  → força real (erro se faltar credenciais)
    'mock'  → força mock
    'auto'  → real se credenciais existirem, senão mock
    """
    if ANYDESK_MODE == "real":
        return "Real" if (ANYDESK_LICENSE_ID and ANYDESK_API_PASSWORD) else "Erro"
    if ANYDESK_MODE == "mock":
        return "Mock"
    # auto
    return "Real" if (ANYDESK_LICENSE_ID and ANYDESK_API_PASSWORD) else "Mock"

def get_client() -> AnyDeskClient | None:
    mode = running_mode()
    if mode == "Real":
        return AnyDeskClient(ANYDESK_API_BASE, ANYDESK_LICENSE_ID, ANYDESK_API_PASSWORD)
    return None

# ==============================
# Rotas (compatíveis com seus templates)
# ==============================

@app.route("/")
def home():
    return redirect(url_for("list_users"))

# ----- Users -----
@app.route("/users")
def list_users():
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            data = api.clients_list(offset=0, limit=50, online=False)
            # Normaliza para a estrutura esperada pelo template
            # Resposta esperada (doc): { "list": [ { "cid":..., "alias":..., "client-version":..., "online":..., "online-time":... } ] }
            items = data.get("list", []) if isinstance(data, dict) else []
            clients = [
                {
                    "cid": it.get("cid"),
                    "alias": it.get("alias"),
                    "client_version": it.get("client-version"),
                    "online": it.get("online"),
                    "online_time": it.get("online-time"),
                }
                for it in items
            ]
            return render_template("users.html", clients=clients, mode=mode)
        except Exception as e:
            flash(f"Falha ao buscar clientes (API): {e}", "error")
            # fallback para mock na página para não quebrar a demo
            return render_template("users.html", clients=mock_clients, mode="Mock")
    else:
        return render_template("users.html", clients=mock_clients, mode=mode)

@app.route("/clients/<cid>")
def client_details(cid):
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            details = api.client_details(cid)
            client = {
                "cid": details.get("cid"),
                "alias": details.get("alias"),
                "client_version": details.get("client-version"),
                "online": details.get("online"),
                "online_time": details.get("online-time"),
                "last_sessions": [
                    {
                        "sid": s.get("sid"),
                        "from": {"cid": s.get("from", {}).get("cid"), "alias": s.get("from", {}).get("alias")},
                        "to": {"cid": s.get("to", {}).get("cid"), "alias": s.get("to", {}).get("alias")},
                        "active": s.get("active"),
                        "start_time": s.get("start-time"),
                        "end_time": s.get("end-time"),
                        "duration": s.get("duration"),
                        "comment": s.get("comment"),
                    }
                    for s in (details.get("last-sessions") or [])
                ],
            }
            return render_template("client_details.html", client=client, mode=mode)
        except Exception as e:
            flash(f"Falha ao buscar detalhes do cliente (API): {e}", "error")
            # fallback mock do cliente e suas sessões
            c = next((x for x in mock_clients if x["cid"] == cid), None)
            if not c:
                c = mock_clients[0] | {"cid": cid}
            c = dict(c)
            c["last_sessions"] = [s for s in mock_sessions if s["from"]["cid"] == cid or s["to"]["cid"] == cid]
            return render_template("client_details.html", client=c, mode="Mock")
    else:
        c = next((x for x in mock_clients if x["cid"] == cid), None)
        if not c:
            flash("Cliente não encontrado (mock)!", "error")
            return redirect(url_for("list_users"))
        c = dict(c)
        c["last_sessions"] = [s for s in mock_sessions if s["from"]["cid"] == cid or s["to"]["cid"] == cid]
        return render_template("client_details.html", client=c, mode=mode)

@app.route("/clients/<cid>/alias", methods=["POST"])
def change_alias(cid):
    new_alias = request.form.get("alias", "").strip()
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            api.change_alias(cid, new_alias if new_alias else None)
            msg = f"Alias do cliente {cid} " + ("atualizado" if new_alias else "removido") + " com sucesso!"
            flash(msg, "success")
        except Exception as e:
            flash(f"Falha ao alterar alias (API): {e}", "error")
    else:
        client = next((c for c in mock_clients if c["cid"] == cid), None)
        if not client:
            flash("Cliente (mock) não encontrado!", "error")
        else:
            client["alias"] = new_alias if new_alias else None
            msg = f"(mock) Alias do cliente {cid} " + ("atualizado" if new_alias else "removido") + "!"
            flash(msg, "success")
    return redirect(url_for("list_users"))

@app.route("/clients/<cid>/alias/remove", methods=["POST"])
def remove_alias(cid):
    # Apenas atalho para enviar alias = null
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            api.change_alias(cid, None)
            flash(f"Alias do cliente {cid} removido!", "success")
        except Exception as e:
            flash(f"Falha ao remover alias (API): {e}", "error")
    else:
        client = next((c for c in mock_clients if c["cid"] == cid), None)
        if not client:
            flash("Cliente (mock) não encontrado!", "error")
        else:
            client["alias"] = None
            flash(f"(mock) Alias do cliente {cid} removido!", "success")
    return redirect(url_for("list_users"))

# ----- Sessions -----
@app.route("/sessions")
def list_sessions():
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            data = api.sessions_list(offset=0, limit=50)
            items = data.get("list", []) if isinstance(data, dict) else []
            sessions = [
                {
                    "sid": it.get("sid"),
                    "from": {"alias": it.get("from", {}).get("alias"), "cid": it.get("from", {}).get("cid")},
                    "to": {"alias": it.get("to", {}).get("alias"), "cid": it.get("to", {}).get("cid")},
                    "active": it.get("active"),
                    "start_time": it.get("start-time"),
                    "end_time": it.get("end-time"),
                    "duration": it.get("duration"),
                    "comment": it.get("comment"),
                }
                for it in items
            ]
            return render_template("sessions.html", sessions=sessions, mode=mode)
        except Exception as e:
            flash(f"Falha ao listar sessões (API): {e}", "error")
            return render_template("sessions.html", sessions=mock_sessions, mode="Mock")
    else:
        return render_template("sessions.html", sessions=mock_sessions, mode=mode)

@app.route("/sessions/<sid>")
def session_details(sid):
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            it = api.session_details(sid)
            session = {
                "sid": it.get("sid"),
                "from": {"alias": it.get("from", {}).get("alias"), "cid": it.get("from", {}).get("cid")},
                "to": {"alias": it.get("to", {}).get("alias"), "cid": it.get("to", {}).get("cid")},
                "active": it.get("active"),
                "start_time": it.get("start-time"),
                "end_time": it.get("end-time"),
                "duration": it.get("duration"),
                "comment": it.get("comment"),
            }
            return render_template("session_details.html", session=session, mode=mode)
        except Exception as e:
            flash(f"Falha ao buscar detalhes da sessão (API): {e}", "error")
            s = next((x for x in mock_sessions if x["sid"] == sid), None)
            if not s:
                s = mock_sessions[0] | {"sid": sid}
            return render_template("session_details.html", session=s, mode="Mock")
    else:
        s = next((x for x in mock_sessions if x["sid"] == sid), None)
        if not s:
            flash("Sessão (mock) não encontrada!", "error")
            return redirect(url_for("list_sessions"))
        return render_template("session_details.html", session=s, mode=mode)

@app.route("/sessions/<sid>/close", methods=["POST"])
def close_session(sid):
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            api.close_session(sid)
            flash(f"Sessão {sid} encerrada!", "success")
        except Exception as e:
            flash(f"Falha ao encerrar sessão (API): {e}", "error")
    else:
        s = next((x for x in mock_sessions if x["sid"] == sid), None)
        if not s:
            flash("Sessão (mock) não encontrada!", "error")
        elif not s.get("active"):
            flash("Sessão (mock) já está encerrada!", "error")
        else:
            s["active"] = False
            flash(f"(mock) Sessão {sid} encerrada!", "success")
    return redirect(url_for("list_sessions"))

@app.route("/sessions/<sid>/comment", methods=["POST"])
def update_comment(sid):
    new_comment = request.form.get("comment", "").strip()
    mode = running_mode()
    if mode == "Real":
        try:
            api = get_client()
            api.change_session_comment(sid, new_comment if new_comment else None)
            flash(f"Comentário da sessão {sid} atualizado!", "success")
        except Exception as e:
            flash(f"Falha ao atualizar comentário (API): {e}", "error")
    else:
        s = next((x for x in mock_sessions if x["sid"] == sid), None)
        if not s:
            flash("Sessão (mock) não encontrada!", "error")
        else:
            s["comment"] = new_comment if new_comment else None
            flash(f"(mock) Comentário da sessão {sid} atualizado!", "success")
    return redirect(url_for("list_sessions"))

# ==============================
# Run
# ==============================
if __name__ == "__main__":
    mode = running_mode()
    print(f"→ AnyDesk CRM Mockup iniciado em modo: {mode}")
    if mode == "Erro":
        print("Faltam variáveis: ANYDESK_LICENSE_ID e/ou ANYDESK_API_PASSWORD.")
        print("Defina-as ou use ANYDESK_MODE=mock para rodar em modo simulado.")
    app.run(debug=True)
