import time
import hmac
import hashlib
import base64
import requests
import json
import os

MOCK_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "mock_data.json")

def load_mock_data():
    """Carrega os dados do arquivo JSON."""
    with open(MOCK_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_mock_data(data):
    """Salva alterações no arquivo JSON."""
    with open(MOCK_DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

class AnyDeskAPI:
    def __init__(self):
        self.base_url = "https://v1.api.anydesk.com:8081"
        self.license_id = None  # Coloque sua licença real se for usar modo real
        self.api_password = None
        if not self.license_id or not self.api_password:
            self.mode = "Mock"
        else:
            self.mode = "Real"

    def _generate_auth(self, method, resource, body=""):
        timestamp = str(int(time.time()))
        content_hash = base64.b64encode(hashlib.sha1(body.encode()).digest()).decode()
        request_string = f"{method}\n{resource}\n{timestamp}\n{content_hash}"
        token = base64.b64encode(
            hmac.new(self.api_password.encode(), request_string.encode(), hashlib.sha1).digest()
        ).decode()
        return f"AD {self.license_id}:{timestamp}:{token}"

    # ---------- Clientes ----------
    def get_clients(self):
        if self.mode == "Mock":
            return load_mock_data()["clients"]
        url = f"{self.base_url}/clients"
        headers = {"Authorization": self._generate_auth("GET", "/clients")}
        return requests.get(url, headers=headers).json().get("list", [])

    def get_client_details(self, cid):
        if self.mode == "Mock":
            data = load_mock_data()
            return next((c for c in data["clients"] if c["cid"] == cid), None)
        url = f"{self.base_url}/clients/{cid}"
        headers = {"Authorization": self._generate_auth("GET", f"/clients/{cid}")}
        return requests.get(url, headers=headers).json()

    def update_client_alias(self, cid, alias):
        if self.mode == "Mock":
                data = load_mock_data()
                for client in data["clients"]:
                    if client["cid"] == cid:
                        client["alias"] = alias
                        save_mock_data(data)
                        return client
                # Return None if the session is not found
                return None
        url = f"{self.base_url}/clients/{cid}"
        headers = {
            "Authorization": self._generate_auth("PATCH", f"/clients/{cid}", f'{{"alias": "{alias}"}}'),
            "Content-Type": "application/json"
        }
        return requests.patch(url, headers=headers, json={"alias": alias}).status_code == 204

    def remove_client_alias(self, cid):
        return self.update_client_alias(cid, None)

    # ---------- Sessões ----------
    def get_sessions(self):
        if self.mode == "Mock":
            return load_mock_data()["sessions"]
        url = f"{self.base_url}/sessions"
        headers = {"Authorization": self._generate_auth("GET", "/sessions")}
        return requests.get(url, headers=headers).json().get("list", [])

    def get_session_details(self, sid):
        if self.mode == "Mock":
            data = load_mock_data()
            return next((s for s in data["sessions"] if s["sid"] == sid), None)
        url = f"{self.base_url}/sessions/{sid}"
        headers = {"Authorization": self._generate_auth("GET", f"/sessions/{sid}")}
        return requests.get(url, headers=headers).json()

    def close_session(self, sid):
        if self.mode == "Mock":
            data = load_mock_data()
            for session in data["sessions"]:
                if session["sid"] == sid:
                    session["active"] = False
                    session["end_time"] = int(__import__("time").time())
                    save_mock_data(data)
                    return session
            return None
        url = f"{self.base_url}/sessions/{sid}/action"
        headers = {
            "Authorization": self._generate_auth("POST", f"/sessions/{sid}/action", '{"action":"close"}'),
            "Content-Type": "application/json"
        }
        return requests.post(url, headers=headers, json={"action": "close"}).status_code == 204

    def update_session_comment(self, sid, comment):
        if self.mode == "Mock":
            data = load_mock_data()
            for session in data["sessions"]:
                if session["sid"] == sid:
                    if session.get("comment") != comment:
                        session["comment"] = comment
                        save_mock_data(data)
                    return session
            return None
        url = f"{self.base_url}/sessions/{sid}"
        headers = {
            "Authorization": self._generate_auth("PATCH", f"/sessions/{sid}", f'{{"comment": "{comment}"}}'),
            "Content-Type": "application/json"
        }
        return requests.patch(url, headers=headers, json={"comment": comment}).status_code == 204