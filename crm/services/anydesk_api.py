import time
import hmac
import hashlib
import base64
import requests

class AnyDeskAPI:
    def __init__(self):
        self.base_url = "https://v1.api.anydesk.com:8081"
        self.license_id = None  # Coloque sua licença real se for usar modo real
        self.api_password = None
        self.mode = "Mock" if not self.license_id or not self.api_password else "Real"

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
            return [
                {"cid": "123-456-789", "alias": "Lucas-PC", "client_version": "7.1.10", "online": True},
                {"cid": "987-654-321", "alias": "FIAP-Lab", "client_version": "7.1.10", "online": False},
            ]
        url = f"{self.base_url}/clients"
        headers = {"Authorization": self._generate_auth("GET", "/clients")}
        return requests.get(url, headers=headers).json().get("list", [])

    def get_client_details(self, cid):
        if self.mode == "Mock":
            return {
                "cid": cid,
                "alias": "Lucas-PC",
                "client_version": "7.1.10",
                "online": True,
                "online_time": 3600,
                "last_sessions": []
            }
        url = f"{self.base_url}/clients/{cid}"
        headers = {"Authorization": self._generate_auth("GET", f"/clients/{cid}")}
        return requests.get(url, headers=headers).json()

    def update_client_alias(self, cid, alias):
        if self.mode == "Mock":
            return True
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
            return [
                {"sid": "S123", "from": {"alias": "Lucas-PC"}, "to": {"alias": "Servidor"}, "duration": 120, "active": True, "comment": "Sessão de teste"},
                {"sid": "S456", "from": {"alias": "Notebook"}, "to": {"alias": "Lucas-PC"}, "duration": 200, "active": False, "comment": None},
            ]
        url = f"{self.base_url}/sessions"
        headers = {"Authorization": self._generate_auth("GET", "/sessions")}
        return requests.get(url, headers=headers).json().get("list", [])

    def get_session_details(self, sid):
        if self.mode == "Mock":
            return {
                "sid": sid,
                "from": {"alias": "Lucas-PC"},
                "to": {"alias": "Servidor"},
                "active": True,
                "duration": 300,
                "comment": "Sessão ativa para manutenção"
            }
        url = f"{self.base_url}/sessions/{sid}"
        headers = {"Authorization": self._generate_auth("GET", f"/sessions/{sid}")}
        return requests.get(url, headers=headers).json()

    def close_session(self, sid):
        if self.mode == "Mock":
            return True
        url = f"{self.base_url}/sessions/{sid}/action"
        headers = {
            "Authorization": self._generate_auth("POST", f"/sessions/{sid}/action", '{"action":"close"}'),
            "Content-Type": "application/json"
        }
        return requests.post(url, headers=headers, json={"action": "close"}).status_code == 204

    def update_session_comment(self, sid, comment):
        if self.mode == "Mock":
            return True
        url = f"{self.base_url}/sessions/{sid}"
        headers = {
            "Authorization": self._generate_auth("PATCH", f"/sessions/{sid}", f'{{"comment": "{comment}"}}'),
            "Content-Type": "application/json"
        }
        return requests.patch(url, headers=headers, json={"comment": comment}).status_code == 204