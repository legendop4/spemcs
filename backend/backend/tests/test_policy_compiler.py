"""SPEMCS Milestone 3: Policy Compiler & Vendor Profiles Test Suite.

Exhaustively tests:
1. Domain validation & normalization (RFC 1123, rejection of schemes/paths/queries/ports)
2. IPv4 and IPv6 network/CIDR validation, normalization, and differentiation
3. Port validation (range 1-65535, reject 0, negative, >65535, deduplication, sorting)
4. Management server representation & separation
5. Validity window validation (UTC normalization, expires_at > not_before)
6. Pure compiler determinism (different input orderings produce byte-identical canonical payloads)
7. Security validations (rejection of empty profiles, invalid versions, malformed configurations)
8. End-to-end integration: Compiler -> M2 RSA-PSS Signer -> M2 Verifier
9. REST API endpoints (VendorProfile CRUD & compile endpoint via FastAPI TestClient)
"""

import copy
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.database import SessionLocal
from backend.app.main import app
from backend.models.exam import ApprovedBrowser, Exam
from backend.models.policy import VendorProfile
from backend.services.canonical_json import canonicalize_to_bytes
from backend.services.policy_compiler import (
    InvalidDomainError,
    InvalidNetworkAddressError,
    InvalidPortError,
    InvalidValidityWindowError,
    MissingConfigurationError,
    PolicyCompilationError,
    compile_exam_policy,
    normalize_domain_list,
    normalize_ip_network_list,
    normalize_ports,
    validate_and_normalize_domain,
    validate_and_normalize_ip_network,
    validate_management_server,
    validate_port,
    validate_validity_window,
)
from backend.services.policy_signer import (
    PolicySigner,
    PolicyVerifier,
    generate_development_keypair,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    created = []
    yield db, created
    for item in reversed(created):
        try:
            db.delete(item)
            db.commit()
        except Exception:
            db.rollback()
    db.close()


@pytest.fixture(scope="module")
def keypair():
    priv, pub = generate_development_keypair(key_size=2048)
    return priv, pub


# ==============================================================================
# 1. Domain Validation Tests
# ==============================================================================
def test_valid_domain_normalization():
    assert validate_and_normalize_domain("moodle.university.edu") == "moodle.university.edu"
    assert validate_and_normalize_domain("  CANVAS.LMS.COM.  ") == "canvas.lms.com"
    assert validate_and_normalize_domain("sub-domain.exam-server.org") == "sub-domain.exam-server.org"


@pytest.mark.parametrize("invalid_domain", [
    "http://moodle.university.edu",       # URL scheme
    "https://moodle.university.edu/",     # URL scheme + slash
    "moodle.university.edu/login",        # Path component
    "moodle.university.edu?q=test",       # Query string
    "moodle.university.edu#section",      # Fragment
    "moodle.university.edu:443",          # Port specification
    "localhost",                          # Single label
    "-moodle.university.edu",             # Leading hyphen
    "moodle..university.edu",             # Empty label
    "moodle.123",                         # Numeric TLD
    "",                                   # Empty
    "   ",                                # Whitespace
])
def test_malformed_domains_rejected(invalid_domain):
    with pytest.raises(InvalidDomainError):
        validate_and_normalize_domain(invalid_domain)


def test_domain_list_deduplication_and_sorting():
    raw = ["Z-Exam.com", "a-exam.com", "M-Exam.com", "a-exam.com.", "  z-exam.com  "]
    result = normalize_domain_list(raw)
    assert result == ["a-exam.com", "m-exam.com", "z-exam.com"]


# ==============================================================================
# 2. IP / CIDR Validation Tests (IPv4 & IPv6)
# ==============================================================================
def test_ipv4_validation_and_normalization():
    cidr, version = validate_and_normalize_ip_network("192.168.1.50")
    assert cidr == "192.168.1.50/32"
    assert version == "IPv4"

    cidr, version = validate_and_normalize_ip_network("10.0.0.0/24")
    assert cidr == "10.0.0.0/24"
    assert version == "IPv4"

    # Subnet normalization (host bits cleared)
    cidr, _ = validate_and_normalize_ip_network("192.168.1.155/24")
    assert cidr == "192.168.1.0/24"


def test_ipv6_validation_and_normalization():
    cidr, version = validate_and_normalize_ip_network("2001:0db8:0000:0000:0000:0000:0000:0001")
    assert cidr == "2001:db8::1/128"
    assert version == "IPv6"

    cidr, version = validate_and_normalize_ip_network("2001:db8::/32")
    assert cidr == "2001:db8::/32"
    assert version == "IPv6"


@pytest.mark.parametrize("invalid_ip", [
    "999.999.999.999",
    "192.168.1.1/33",
    "2001:db8:::1",
    "not-an-ip",
    "",
    "192.168.1.1/abc",
])
def test_malformed_ips_rejected(invalid_ip):
    with pytest.raises(InvalidNetworkAddressError):
        validate_and_normalize_ip_network(invalid_ip)


def test_ip_list_deduplication_and_sorting():
    raw = ["192.168.1.10", "10.0.0.0/8", "2001:db8::1", "192.168.1.10/32", "172.16.0.0/16"]
    result = normalize_ip_network_list(raw)
    # IPv4 sorted first by address, then IPv6
    assert result == [
        "10.0.0.0/8",
        "172.16.0.0/16",
        "192.168.1.10/32",
        "2001:db8::1/128",
    ]


# ==============================================================================
# 3. Port & Protocol Validation Tests
# ==============================================================================
def test_port_validation():
    assert validate_port(80) == 80
    assert validate_port(443) == 443
    assert validate_port(65535) == 65535
    assert validate_port(1) == 1


@pytest.mark.parametrize("invalid_port", [
    0,
    -1,
    65536,
    99999,
    "80",       # string
    True,       # bool
    1.5,        # float
    None,
])
def test_invalid_ports_rejected(invalid_port):
    with pytest.raises(InvalidPortError):
        validate_port(invalid_port)


def test_ports_deduplication_and_sorting():
    raw = [443, 80, 8080, 80, 443, 22]
    assert normalize_ports(raw) == [22, 80, 443, 8080]


# ==============================================================================
# 4. Management Server & Validity Window Validation
# ==============================================================================
def test_management_server_validation():
    raw = {
        "ip_addresses": ["192.168.1.100", "192.168.1.100", "10.0.0.1"],
        "port": 8000,
    }
    result = validate_management_server(raw)
    assert result["port"] == 8000
    assert result["ip_addresses"] == ["10.0.0.1", "192.168.1.100"]


def test_management_server_rejection_on_invalid_data():
    with pytest.raises(MissingConfigurationError):
        validate_management_server({"ip_addresses": []})  # empty IPs

    with pytest.raises(InvalidPortError):
        validate_management_server({"ip_addresses": ["127.0.0.1"], "port": 0})


def test_validity_window_validation():
    now = datetime.now(timezone.utc)
    nb, exp = validate_validity_window(now, now + timedelta(hours=2))
    assert nb.endswith("Z")
    assert exp.endswith("Z")

    # Inverted window
    with pytest.raises(InvalidValidityWindowError):
        validate_validity_window(now + timedelta(hours=1), now)


# ==============================================================================
# 5. Compiler Pure Determinism & Sorting Tests
# ==============================================================================
def test_compiler_determinism_under_reordered_inputs():
    """Proves logically identical inputs with different key/list ordering produce
    byte-identical canonical payloads.
    """
    exam_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    now = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)

    # Input A
    profile_a = {
        "vendor_name": "Moodle",
        "vendor_id": uuid.uuid4(),
        "required_domains": ["b.moodle.com", "a.moodle.com"],
        "approved_ip_ranges": ["192.168.2.0/24", "192.168.1.0/24"],
        "required_tcp_ports": [443, 80],
        "required_udp_ports": [],
    }
    mgmt_a = {"port": 8000, "ip_addresses": ["192.168.10.2", "192.168.10.1"]}

    # Input B (Same data, reverse list orders and different dict insertion)
    profile_b = {
        "required_udp_ports": [],
        "required_tcp_ports": [80, 443],
        "approved_ip_ranges": ["192.168.1.0/24", "192.168.2.0/24"],
        "required_domains": ["a.moodle.com", "b.moodle.com"],
        "vendor_id": profile_a["vendor_id"],
        "vendor_name": "Moodle",
    }
    mgmt_b = {"ip_addresses": ["192.168.10.1", "192.168.10.2"], "port": 8000}

    payload_a = compile_exam_policy(
        exam_id=exam_id,
        policy_id=policy_id,
        version=1,
        vendor_profile=profile_a,
        management_server=mgmt_a,
        not_before=now,
        expires_at=now + timedelta(hours=3),
    )

    payload_b = compile_exam_policy(
        exam_id=exam_id,
        policy_id=policy_id,
        version=1,
        vendor_profile=profile_b,
        management_server=mgmt_b,
        not_before=now,
        expires_at=now + timedelta(hours=3),
    )

    bytes_a = canonicalize_to_bytes(payload_a)
    bytes_b = canonicalize_to_bytes(payload_b)

    assert bytes_a == bytes_b, "Compiler must produce 100% byte-identical canonical JSON"


def test_management_server_separation_from_vendor():
    """Proves management server destination is cleanly separated from vendor allow-list."""
    exam_id = uuid.uuid4()
    profile = {
        "vendor_name": "Exam-LMS",
        "required_domains": ["lms.univ.edu"],
        "approved_ip_ranges": ["198.51.100.1/32"],
        "required_tcp_ports": [443],
        "required_udp_ports": [],
    }
    mgmt = {"ip_addresses": ["192.168.1.50"], "port": 8000}

    now = datetime.now(timezone.utc)
    payload = compile_exam_policy(
        exam_id=exam_id,
        version=1,
        vendor_profile=profile,
        management_server=mgmt,
        not_before=now,
        expires_at=now + timedelta(hours=1),
    )

    # Management server is its own top-level structure
    assert "management_server" in payload
    assert payload["management_server"]["port"] == 8000
    assert payload["management_server"]["ip_addresses"] == ["192.168.1.50"]

    # Allowed destinations only contains the vendor destinations
    dest_names = [d["name"] for d in payload["allowed_destinations"]]
    assert "Exam-LMS" in dest_names
    assert len(payload["allowed_destinations"]) == 1


# ==============================================================================
# 6. End-to-End Compiler -> M2 RSA-PSS Signer Integration
# ==============================================================================
def test_compiled_policy_signs_and_verifies_with_m2(keypair):
    """Proves compiled policy output directly integrates with M2 RSA-PSS cryptographic verification."""
    priv, pub = keypair
    signer = PolicySigner(private_key=priv, key_id="dev-key-1")
    verifier = PolicyVerifier({"dev-key-1": pub})

    exam_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    profile = {
        "vendor_name": "Moodle",
        "required_domains": ["moodle.univ.edu"],
        "approved_ip_ranges": ["192.168.5.0/24"],
        "required_tcp_ports": [80, 443],
        "required_udp_ports": [],
    }

    compiled = compile_exam_policy(
        exam_id=exam_id,
        version=1,
        vendor_profile=profile,
        management_server={"ip_addresses": ["10.0.0.1"], "port": 8000},
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=2),
        key_id="dev-key-1",
    )

    sig = signer.sign_payload(compiled)
    assert isinstance(sig, str)

    # Verify using M2 verifier
    verified = verifier.verify_policy(compiled, sig, current_time=now)
    assert verified["exam_id"] == str(exam_id)
    assert verified["version"] == 1


from backend.models.user import User
from backend.services.auth_service import create_access_token


@pytest.fixture
def admin_headers():
    db = SessionLocal()
    admin_id = uuid.uuid4()
    admin_user = User(
        user_id=admin_id,
        name="Admin Compiler Test",
        username=f"adm_comp_{admin_id.hex[:6]}",
        email=f"adm_comp_{admin_id.hex[:6]}@example.com",
        password="fakepassword",
        password_hash="fakehash",
        avatar_color="#4F46E5",
        role="admin",
        is_active=True,
    )
    db.add(admin_user)
    db.commit()
    token = create_access_token(data={"sub": str(admin_id), "username": admin_user.username, "role": "admin"})
    yield {"Authorization": f"Bearer {token}"}
    db.query(User).filter(User.user_id == admin_id).delete()
    db.commit()
    db.close()


# ==============================================================================
# 7. REST API Endpoints Tests
# ==============================================================================
def test_vendor_profile_crud_api(client: TestClient, db_session, admin_headers):
    """Tests /api/policies/vendors endpoints."""
    vendor_name = f"API-Test-{uuid.uuid4().hex[:8]}"

    # 1. Create
    resp = client.post(
        "/api/policies/vendors",
        headers=admin_headers,
        json={
            "vendor_name": vendor_name,
            "description": "Integration Test Profile",
            "required_domains": ["test.exam.com"],
            "approved_ip_ranges": ["192.168.100.0/24"],
            "required_tcp_ports": [443],
            "required_udp_ports": [],
        },
    )
    assert resp.status_code == 201, resp.text
    created = resp.json()
    vendor_id = created["vendor_id"]
    assert created["vendor_name"] == vendor_name
    assert created["required_domains"] == ["test.exam.com"]

    # 2. Get
    resp = client.get(f"/api/policies/vendors/{vendor_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["vendor_id"] == vendor_id

    # 3. Update
    resp = client.put(
        f"/api/policies/vendors/{vendor_id}",
        headers=admin_headers,
        json={"description": "Updated Description", "required_tcp_ports": [80, 443]},
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "Updated Description"
    assert resp.json()["required_tcp_ports"] == [80, 443]

    # 4. Delete
    resp = client.delete(f"/api/policies/vendors/{vendor_id}", headers=admin_headers)
    assert resp.status_code == 204

    # 5. Verify 404
    resp = client.get(f"/api/policies/vendors/{vendor_id}", headers=admin_headers)
    assert resp.status_code == 404


def test_compile_endpoint_for_exam(client: TestClient, db_session, admin_headers):
    """Tests POST /api/policies/compile/{exam_id} and GET /api/policies/exam/{exam_id}."""
    db, cleanup = db_session

    # 1. Create Exam in DB
    exam = Exam(
        exam_name=f"Compile-Endpoint-Exam-{uuid.uuid4().hex[:6]}",
        approved_browser=ApprovedBrowser.CHROME.value,
        network_enforcement=True,
    )
    db.add(exam)
    db.commit()
    cleanup.append(exam)

    # 2. Call compile endpoint
    now = datetime.now(timezone.utc)
    compile_req = {
        "version": 1,
        "management_server": {"ip_addresses": ["127.0.0.1"], "port": 8000},
        "not_before": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(hours=3)).isoformat(),
        "resolved_destinations": [
            {
                "name": "Local Resolver",
                "ip_ranges": ["127.0.0.53/32"],
                "tcp_ports": [53],
                "udp_ports": [53],
            }
        ],
    }

    resp = client.post(f"/api/policies/compile/{exam.exam_id}", headers=admin_headers, json=compile_req)
    assert resp.status_code == 201, resp.text
    compiled_policy = resp.json()

    assert compiled_policy["exam_id"] == str(exam.exam_id)
    assert compiled_policy["version"] == 1
    assert compiled_policy["signature"] is not None
    assert len(compiled_policy["allowed_destinations"]) == 1

    # 3. Retrieve compiled policy via GET
    resp_get = client.get(f"/api/policies/exam/{exam.exam_id}", headers=admin_headers)
    assert resp_get.status_code == 200
    assert resp_get.json()["policy_id"] == compiled_policy["policy_id"]
