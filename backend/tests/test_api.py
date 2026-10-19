import pytest

A = "/api/v1/analyze"


def test_health_ready(client):
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    r = client.get("/api/v1/ready").json()
    assert r["database"] and r["model"]


def test_auth_required(client):
    assert client.post(A, json={"url": "https://example.com"}).status_code == 401


def test_bad_login_generic(client):
    r = client.post("/api/v1/auth/login", json={"email": "x@y.com", "password": "nope"})
    assert r.status_code == 401 and r.json()["detail"] == "Credenciales inválidas"


def test_authorized_domain_is_low(client, operator):
    r = client.post(A, json={"url": "https://www.bcp.com.pe/personas"}, headers=operator).json()
    assert r["level"] == "seguro_provisional" and r["score"] <= 5


def test_lookalike_is_flagged(client, operator):
    r = client.post(A, json={"url": "http://bcp-seguro.xyz/login"}, headers=operator).json()
    assert r["level"] in ("alto", "critico", "medio")
    assert any(i["code"] in ("brand_abuse", "lookalike_domain") for i in r["indicators"])
    r2 = client.post(A, json={"url": "https://bcq.com.pe/login"}, headers=operator).json()
    assert any(i["code"] == "lookalike_domain" for i in r2["indicators"])


def test_ip_host_flagged(client, operator):
    r = client.post(A, json={"url": "http://45.33.32.156/bcp/verify/login.php"}, headers=operator).json()
    assert any(i["code"] == "ip_host" for i in r["indicators"]) and r["level"] in ("medio", "alto", "critico")


@pytest.mark.parametrize("url", ["http://127.0.0.1/admin", "http://localhost:8080", "http://169.254.169.254/latest/meta-data",
                                 "http://10.0.0.5/", "http://192.168.1.1", "file:///etc/passwd", "javascript:alert(1)",
                                 "ftp://example.com/x", "http://[::1]/"])
def test_ssrf_and_schemes_rejected(client, operator, url):
    assert client.post(A, json={"url": url}, headers=operator).status_code == 422


def test_threat_intel_confirmed(client, operator, analyst):
    r = client.post(A, json={"url": "http://bcp-seguro-acceso.example-phish.test/login?token=SECRETO"}, headers=operator).json()
    assert r["level"] == "critico" and r["score"] >= 95
    assert "SECRETO" not in r["url"]  # no se persisten parámetros
    alerts = client.get("/api/v1/alerts", headers=analyst).json()
    assert any(a["analysis_id"] == r["id"] for a in alerts)


def test_unknown_not_declared_safe_without_intel(client, operator):
    r = client.post(A, json={"url": "https://example.org/"}, headers=operator).json()
    assert r["data_incomplete"] is True and r["level"] != "seguro_provisional"


def test_rbac(client, operator, analyst, admin):
    assert client.get("/api/v1/alerts", headers=operator).status_code == 403
    assert client.get("/api/v1/audit/events", headers=analyst).status_code == 403
    assert client.get("/api/v1/audit/events", headers=admin).status_code == 200
    assert client.get("/api/v1/users", headers=analyst).status_code == 403


def test_alert_patch(client, analyst, operator):
    client.post(A, json={"url": "http://bcp-seguro-acceso.example-phish.test/login"}, headers=operator)
    aid = client.get("/api/v1/alerts", headers=analyst).json()[0]["id"]
    r = client.patch(f"/api/v1/alerts/{aid}", json={"status": "resolved", "note": "ok"}, headers=analyst)
    assert r.status_code == 200 and r.json()["status"] == "resolved"
    assert client.patch(f"/api/v1/alerts/{aid}", json={"status": "resolved"}, headers=operator).status_code == 403


def test_batch(client, operator):
    r = client.post(A + "/batch", json={"items": [{"url": "https://www.bbva.pe"}, {"url": "file:///x"}]}, headers=operator).json()
    assert r["count"] == 2 and r["items"][0]["ok"] and not r["items"][1]["ok"]


def test_operator_cannot_read_others_analysis(client, operator, analyst):
    a = client.post(A, json={"url": "https://www.bbva.pe"}, headers=analyst).json()
    assert client.get(f"/api/v1/analyses/{a['id']}", headers=operator).status_code == 403
    assert client.get(f"/api/v1/analyses/{a['id']}", headers=analyst).status_code == 200


def test_dashboard_and_reports(client, analyst):
    s = client.get("/api/v1/dashboard/summary", headers=analyst).json()
    assert s["total"] > 0
    for fmt, magic in (("pdf", b"%PDF"), ("xlsx", b"PK"), ("docx", b"PK")):
        r = client.get(f"/api/v1/reports/download?format={fmt}", headers=analyst)
        assert r.status_code == 200 and r.content.startswith(magic), fmt


def test_create_user_and_weak_password(client, admin):
    assert client.post("/api/v1/users", json={"email": "n@x.com", "password": "short"}, headers=admin).status_code == 422
    r = client.post("/api/v1/users", json={"email": "nuevo@x.com", "password": "UnaClaveLarga#1", "role": "auditor"}, headers=admin)
    assert r.status_code == 201


def test_login_lockout(client):
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": "lock@x.com", "password": "bad"})
    assert client.post("/api/v1/auth/login", json={"email": "lock@x.com", "password": "bad"}).status_code == 429
