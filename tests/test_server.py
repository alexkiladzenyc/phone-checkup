import http.client
import json
import re
import threading

import pytest

from phonecheck import server as server_module
from phonecheck.adb import AdbDeviceEntry, AdbError
from phonecheck.rules import build_context
from phonecheck.server import MAX_BODY, TOKEN_HEADER, make_server
from phonecheck.source import DeviceSource


def start(httpd):
    """Serve in a background thread; a short poll interval keeps shutdown() from waiting half a second."""
    thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    return thread


class Client:
    def __init__(self, httpd, state):
        self.port = httpd.server_address[1]
        self.token = state.token

    def request(self, method, path, body=None, *, headers=None, host=None, token=True, json_body=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        send = {"Host": host or f"127.0.0.1:{self.port}"}
        if token is True:
            send[TOKEN_HEADER] = self.token
        elif token:
            send[TOKEN_HEADER] = token
        payload = None
        if body is not None:
            payload = body if isinstance(body, (bytes, str)) else json.dumps(body)
        if payload is not None and json_body:
            send["Content-Type"] = "application/json"
        send.update(headers or {})
        connection.request(method, path, body=payload, headers=send)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        try:
            data = json.loads(raw)
        except ValueError:
            data = raw.decode("utf-8", "replace")
        return response.status, response, data


@pytest.fixture
def web():
    httpd, state = make_server(DeviceSource(demo="messy"), build_context(), port=0)
    thread = start(httpd)
    yield Client(httpd, state), state, httpd
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


class TestPages:
    def test_index_serves_the_page_with_this_runs_token(self, web):
        client, state, _ = web
        status, response, html = client.request("GET", "/", token=False)
        assert status == 200
        assert response.getheader("Content-Type").startswith("text/html")
        assert f'content="{state.token}"' in html
        assert "__TOKEN__" not in html
        assert "<script>" not in html  # external script file only, so the CSP can forbid inline code

    def test_static_files(self, web):
        client, _, _ = web
        status, response, _ = client.request("GET", "/app.js", token=False)
        assert status == 200 and response.getheader("Content-Type").startswith("text/javascript")
        status, response, _ = client.request("GET", "/app.css", token=False)
        assert status == 200 and response.getheader("Content-Type").startswith("text/css")

    @pytest.mark.parametrize("path", ["/nope", "/../../etc/passwd", "/app.js/../../secret", "/index.html", "/api/"])
    def test_unknown_paths_are_404(self, web, path):
        client, _, _ = web
        assert client.request("GET", path)[0] == 404

    def test_security_headers_on_every_response(self, web):
        client, _, _ = web
        for method, path in (("GET", "/"), ("GET", "/app.js"), ("GET", "/api/status"), ("GET", "/nope")):
            _, response, _ = client.request(method, path)
            assert response.getheader("Cache-Control") == "no-store"
            assert response.getheader("X-Content-Type-Options") == "nosniff"
            assert response.getheader("X-Frame-Options") == "DENY"
            csp = response.getheader("Content-Security-Policy")
            assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
            assert "unsafe-inline" not in csp and "unsafe-eval" not in csp

    def test_no_cors_headers_ever(self, web):
        client, _, _ = web
        for method, path in (("GET", "/"), ("GET", "/api/status"), ("POST", "/api/scan")):
            _, response, _ = client.request(method, path, body={} if method == "POST" else None, headers={"Origin": "https://evil.example"})
            assert response.getheader("Access-Control-Allow-Origin") is None

    def test_preflight_is_not_approved(self, web):
        client, _, _ = web
        status, response, _ = client.request("OPTIONS", "/api/remove", headers={"Origin": "https://evil.example"})
        assert status >= 400 and response.getheader("Access-Control-Allow-Origin") is None

    def test_server_header_does_not_leak_versions(self, web):
        client, _, _ = web
        _, response, _ = client.request("GET", "/")
        assert response.getheader("Server") == "phonecheck"


class TestAuthentication:
    @pytest.mark.parametrize("host", ["evil.example", "evil.example:80", "127.0.0.1", "localhost", "127.0.0.1:1", "0.0.0.0:8000"])
    def test_wrong_host_header_is_rejected_even_for_the_page(self, web, host):
        client, _, _ = web
        assert client.request("GET", "/", host=host, token=False)[0] == 403
        assert client.request("GET", "/api/status", host=host)[0] == 403

    def test_localhost_name_is_accepted(self, web):
        client, _, _ = web
        assert client.request("GET", "/api/status", host=f"localhost:{client.port}")[0] == 200

    @pytest.mark.parametrize("token", [False, "", "wrong", "x" * 500])
    def test_api_needs_the_right_token(self, web, token):
        client, _, _ = web
        assert client.request("GET", "/api/status", token=token)[0] == 403
        assert client.request("POST", "/api/scan", body={}, token=token)[0] == 403
        assert client.request("POST", "/api/remove", body={"packages": ["com.freegames.puzzle.colorblast"], "confirm": "remove"}, token=token)[0] == 403

    def test_a_bad_token_removes_nothing(self, web):
        client, _state, _ = web
        client.request("POST", "/api/remove", body={"packages": ["com.freegames.puzzle.colorblast"], "confirm": "remove"}, token="wrong")
        _, _, report = client.request("POST", "/api/scan", body={})
        assert report["scanned_apps"] == 13

    def test_tokens_differ_between_runs(self):
        a, state_a = make_server(DeviceSource(demo="clean"), build_context(), port=0)
        b, state_b = make_server(DeviceSource(demo="clean"), build_context(), port=0)
        try:
            assert state_a.token != state_b.token and len(state_a.token) >= 32
        finally:
            a.server_close()
            b.server_close()

    def test_binds_to_localhost_only(self, web):
        _, _, httpd = web
        assert httpd.server_address[0] == "127.0.0.1"


class TestRequestValidation:
    def test_post_must_be_json(self, web):
        client, _, _ = web
        status, _, _data = client.request("POST", "/api/scan", body="{}", headers={"Content-Type": "text/plain"}, json_body=False)
        assert status == 415
        status, _, _ = client.request("POST", "/api/scan", body="a=b", headers={"Content-Type": "application/x-www-form-urlencoded"}, json_body=False)
        assert status == 415

    def test_post_without_a_content_type_is_rejected(self, web):
        client, _, _ = web
        assert client.request("POST", "/api/scan", body="{}", json_body=False)[0] == 415

    def test_invalid_json(self, web):
        client, _, _ = web
        assert client.request("POST", "/api/scan", body="{not json")[0] == 400

    def test_json_must_be_an_object(self, web):
        client, _, _ = web
        assert client.request("POST", "/api/scan", body="[1,2]")[0] == 400

    def test_oversized_body(self, web):
        # The limit is checked against the declared length before anything is read. Declaring a
        # large body without streaming it keeps the test deterministic: streaming 64 KB into a
        # socket the server has already answered and closed is reset by Windows mid-send.
        client, _, _ = web
        status, _, _ = client.request("POST", "/api/scan", body="{}", headers={"Content-Length": str(MAX_BODY + 1)})
        assert status == 413

    def test_wrong_methods_are_not_routed(self, web):
        client, _, _ = web
        assert client.request("GET", "/api/scan")[0] == 404
        assert client.request("POST", "/api/status", body={})[0] == 404
        assert client.request("POST", "/", body={})[0] == 404
        assert client.request("DELETE", "/api/remove")[0] >= 400


class TestScanApi:
    def test_status_describes_the_simulated_phone(self, web):
        client, _, _ = web
        status, _, data = client.request("GET", "/api/status")
        assert status == 200
        assert data == {"source": "demo phone (messy)", "simulated": True, "phones": [], "note": None}

    def test_scan_returns_the_report(self, web):
        client, _, _ = web
        status, _, report = client.request("POST", "/api/scan", body={})
        assert status == 200
        assert report["scanned_apps"] == 13
        assert [f["package"] for f in report["findings"]][:2] == [
            "com.fastphone.supercleaner.pro",
            "com.virusshield.antivirus.free",
        ]

    def test_phone_errors_become_a_clear_502(self, web, monkeypatch):
        client, _, _ = web

        def unplugged(self):
            raise AdbError("No phone found. Plug it in with a data cable and turn on USB debugging.")

        monkeypatch.setattr(DeviceSource, "open", unplugged)
        status, _, data = client.request("POST", "/api/scan", body={})
        assert status == 502 and "No phone found" in data["error"]

    def test_unexpected_errors_do_not_leak_details(self, web, monkeypatch, capsys):
        client, _, _ = web

        def explode(self):
            raise RuntimeError("secret internal detail /home/someone/path")

        monkeypatch.setattr(DeviceSource, "open", explode)
        status, _, data = client.request("POST", "/api/scan", body={})
        assert status == 500
        assert "secret" not in json.dumps(data) and "/home" not in json.dumps(data)
        assert "secret internal detail" in capsys.readouterr().err  # but it is logged for the operator

    def test_real_phone_mode_lists_connected_phones(self, monkeypatch):
        monkeypatch.setattr(
            server_module,
            "list_devices",
            lambda adb_path: [AdbDeviceEntry("R58M123ABC", "device", "model:Demo")],
        )
        httpd, state = make_server(DeviceSource(serial="R58M123ABC"), build_context(), port=0)
        start(httpd)
        try:
            client = Client(httpd, state)
            _, _, data = client.request("GET", "/api/status")
            assert data["simulated"] is False
            assert data["phones"] == [{"serial": "R58M123ABC", "state": "device", "description": "model:Demo"}]
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_status_survives_a_missing_adb(self, monkeypatch):
        def no_adb(adb_path):
            raise AdbError("Could not run 'adb'.")

        monkeypatch.setattr(server_module, "list_devices", no_adb)
        httpd, state = make_server(DeviceSource(), build_context(), port=0)
        start(httpd)
        try:
            status, _, data = Client(httpd, state).request("GET", "/api/status")
            assert status == 200 and data["phones"] == [] and "Could not run" in data["note"]
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestRemoveApi:
    def remove(self, client, packages, confirm="remove"):
        body = {"packages": packages}
        if confirm is not None:
            body["confirm"] = confirm
        return client.request("POST", "/api/remove", body=body)

    def test_removal_needs_explicit_confirmation(self, web):
        client, _, _ = web
        assert self.remove(client, ["com.freegames.puzzle.colorblast"], confirm=None)[0] == 400
        assert self.remove(client, ["com.freegames.puzzle.colorblast"], confirm="yes")[0] == 400
        assert self.remove(client, ["com.freegames.puzzle.colorblast"], confirm=True)[0] == 400
        _, _, report = client.request("POST", "/api/scan", body={})
        assert report["scanned_apps"] == 13

    @pytest.mark.parametrize("packages", [None, "com.a.b", [1, 2], [["com.a.b"]], {"a": 1}])
    def test_packages_must_be_a_list_of_strings(self, web, packages):
        client, _, _ = web
        status, _, _ = client.request("POST", "/api/remove", body={"packages": packages, "confirm": "remove"})
        assert status == 400

    @pytest.mark.parametrize("packages", [["com.android.systemui"], ["com.x.y; reboot"], [], ["com.freegames.puzzle.colorblast", "com.nope.nothere"]])
    def test_refused_requests_are_409_and_change_nothing(self, web, packages):
        client, _, _ = web
        status, _, data = self.remove(client, packages)
        assert status == 409 and data["error"]
        _, _, report = client.request("POST", "/api/scan", body={})
        assert report["scanned_apps"] == 13

    def test_removal_then_fresh_report(self, web):
        client, _, _ = web
        status, _, data = self.remove(client, ["com.fastphone.supercleaner.pro"])
        assert status == 200
        assert data["results"] == [
            {"package": "com.fastphone.supercleaner.pro", "ok": True, "message": "Success", "hint": None}
        ]
        assert data["report"]["scanned_apps"] == 12
        assert "com.fastphone.supercleaner.pro" not in [f["package"] for f in data["report"]["findings"]]

    def test_device_admin_failure_is_reported_not_hidden(self, web):
        client, _, _ = web
        status, _, data = self.remove(client, ["com.virusshield.antivirus.free"])
        assert status == 200
        (result,) = data["results"]
        assert result["ok"] is False and "device administrator" in result["hint"]
        assert "com.virusshield.antivirus.free" in [f["package"] for f in data["report"]["findings"]]


class TestFrontEnd:
    """The JavaScript can't run here, but its safety rule can be checked statically."""

    def test_page_data_is_only_ever_inserted_as_text(self):
        source = (server_module.WEB_ROOT / "app.js").read_text(encoding="utf-8")
        for dangerous in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert dangerous not in source, dangerous

    def test_token_is_never_put_in_a_url(self):
        source = (server_module.WEB_ROOT / "app.js").read_text(encoding="utf-8")
        assert not re.search(r"fetch\([^)]*token", source)
        assert "X-Phonecheck-Token" in source
