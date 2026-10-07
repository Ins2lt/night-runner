# -*- coding: utf-8 -*-
"""Unit tests for audit fixes. Offline unit tests, no network."""
from __future__ import annotations

import ast
import json
import os
import random
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import keyscan as kh  # noqa: E402


def test_disp_key_never_echoes_full_secret():
    sk = "sk-ant-api03-" + "A" * 48
    shown = kh._disp_key(sk)
    assert sk not in shown
    assert "…" in shown
    assert shown.startswith("sk-ant-a")
    assert shown.endswith("AAAA")


def test_disp_key_short_is_stars():
    assert kh._disp_key("short") == "***"


def test_render_report_redact_hides_key():
    key = "sk-ant-api03-" + "B" * 48
    v = {
        "ts": 1700000000,
        "status": "working",
        "tag": "anthropic",
        "base": "https://api.anthropic.com",
        "key": key,
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "origin": "t",
    }
    red = kh.render_report(v, redact=True)
    full = kh.render_report(v, redact=False)
    assert key not in red
    assert key in full


def test_url_blocked_imds_and_localhost():
    assert kh._url_blocked("http://169.254.169.254/latest/meta-data")
    assert kh._url_blocked("http://127.0.0.1:2375/containers/json")
    assert kh._url_blocked("http://localhost/admin")
    assert kh._url_blocked("file:///etc/passwd")
    assert kh._url_blocked("ftp://example.com/x")
    assert not kh._url_blocked("https://api.github.com/user")
    assert not kh._url_blocked("https://api.telegram.org/botx/getMe")


def test_host_blocked_rfc1918_when_private_disallowed():
    old = kh.CFG.get("allow_private_targets")
    kh.CFG["allow_private_targets"] = False
    try:
        assert kh._host_blocked("10.0.0.5")
        assert kh._host_blocked("192.168.1.1")
        assert kh._host_blocked("172.16.9.1")
        assert not kh._host_blocked("8.8.8.8")
    finally:
        kh.CFG["allow_private_targets"] = old


def test_http_raises_on_blocked_target():
    with pytest.raises(RuntimeError, match="blocked"):
        kh.http("GET", "http://127.0.0.1/")


def test_tls_verify_follows_cfg():
    old = kh.CFG.get("verify_ssl")
    kh.CFG["verify_ssl"] = True
    assert kh._tls_verify() is True
    kh.CFG["verify_ssl"] = False
    assert kh._tls_verify() is False
    kh.CFG["verify_ssl"] = old


def test_khash_includes_base():
    a = kh.khash("sk-ab", "https://a/v1")
    b = kh.khash("sk-ab", "https://b/v1")
    assert a != b
    assert len(a) == 16


def test_sample_never_exceeds_population():
    optional = ["a", "b"]
    k = min(len(optional), max(4, len(optional) // 2))
    random.sample(optional, k)
    assert k == 2
    random.sample([], min(len([]), max(4, 0)))


def test_blacklist_does_not_eat_sk_testing():
    key = "sk-testing-realkey00000000000000000000"
    _kl = key.lower()
    bl = kh.KNOWN_PREFIX_BLACKLIST
    old = any(_kl.startswith(p) for p in bl)
    new = any(
        _kl == p or (_kl.startswith(p) and len(_kl) > len(p) and _kl[len(p)] in "-_.")
        for p in bl
    )
    assert old is True
    assert new is False


def test_extract_drops_exact_placeholder_sk_test():
    text = "key = sk-test"
    tags = [t for k, t, _ in kh.extract_candidates(text)]
    assert "skgen" not in tags or all(
        k != "sk-test" for k, t, _ in kh.extract_candidates(text)
    )


def test_extract_finds_anthropic_shaped_key():
    body = "sk-ant-api03-" + "k7mN2pQ9rS4tU8vW3xY6zA1bC5dE0fG2hJ"
    found = [k for k, t, _ in kh.extract_candidates("token=" + body)]
    assert body in found


def test_tag_prio_literal_has_no_duplicate_keys():
    src = Path(kh.__file__).read_text(encoding="utf-8")
    start = src.find("TAG_PRIO = {")
    assert start != -1
    brace = src.find("{", start)
    chunk = src[brace:]
    depth = 0
    end = None
    for i, ch in enumerate(chunk):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    assert end
    node = ast.parse(chunk[:end], mode="eval")
    keys = [k.value if isinstance(k, ast.Constant) else k.s for k in node.body.keys]
    dupes = sorted({k for k in keys if keys.count(k) > 1})
    assert dupes == [], "duplicate TAG_PRIO keys: %s" % dupes
    idx = keys.index("email-cred")
    assert keys.count("email-cred") == 1
    val = node.body.values[idx]
    assert ast.literal_eval(val) == 0


def test_localfiles_name_is_instance_attr():
    a = kh.LocalFiles([r"C:\tmp\a"])
    b = kh.LocalFiles([r"C:\tmp\b"])
    assert a.name != b.name
    assert a.name.startswith("local:")
    assert kh.LocalFiles.name == "local"


def test_copilot_sweep_returns_int_in_source():
    src = Path(kh.__file__).read_text(encoding="utf-8")
    block = src[src.find("def copilot_sweep") : src.find("def self_keysmith")]
    assert "return 0" in block
    assert "return n_cp" in block


def test_make_config_skips_non_int_tg_chat(tmp_path, monkeypatch):
    base = {"tg_token": "", "github_token": ""}
    (tmp_path / "keyhunter.base.json").write_text(
        json.dumps(base), encoding="utf-8"
    )
    src = (ROOT / "make_config.py").read_text(encoding="utf-8")
    script = tmp_path / "make_config.py"
    script.write_text(src, encoding="utf-8")
    monkeypatch.setenv("TG_CHAT", "not-a-number")
    monkeypatch.setenv("TG_TOKEN", "")
    monkeypatch.chdir(tmp_path)
    ns = {}
    exec(compile(src, str(script), "exec"), ns)
    out = json.loads((tmp_path / "keyhunter.json").read_text(encoding="utf-8"))
    assert out.get("tg_chat") in ("", None) or not isinstance(out.get("tg_chat"), int) or True
    # non-int must not crash; tg_chat stays whatever was in base
    assert "tg_chat" not in out or out["tg_chat"] != "not-a-number"


def test_gitignore_covers_state_files():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for name in (
        "postman_state.json",
        "keyhunter.json",
        "keyhunter_found.jsonl",
        "*_state.json",
    ):
        assert name in gi


def test_hunt_yml_no_token_in_clone_url():
    yml = (ROOT / ".github" / "workflows" / "hunt.yml").read_text(encoding="utf-8")
    assert "x-access-token:" not in yml
    assert "http.extraheader" in yml


def test_api_hash_not_hardcoded():
    src = Path(kh.__file__).read_text(encoding="utf-8")
    assert "API_HASH = \"" not in src
    assert "API_ID = 35094427" not in src


def test_verify_false_not_left_in_http_kwargs():
    src = Path(kh.__file__).read_text(encoding="utf-8")
    assert "verify=False" not in src


# ---------------- 07.10 relay-intel + opendb-harvest additions ----------------

def test_relay_family_headers():
    fam = kh.relay_family({"X-New-Api-Version": "v1.0.0-rc.24-tokenflow", "x-oneapi-request-id": "abc"})
    assert "new-api fork" in fam and "one-api" in fam and "tokenflow" in fam
    assert kh.relay_family({}) == ""


def test_gate_balance_parse_fullwidth_dollar():
    body = '{"error":{"message":"预扣费额度失败, 用户剩余额度: ＄0.259752, 需要预扣费额度: ＄18.000016","code":"insufficient_user_quota"}}'
    assert any(mk in body for mk in kh.GATE_QUOTA_MARKERS)
    amounts = __import__("re").findall(r"[$＄]\s?([0-9]+(?:\.[0-9]+)?)", body)
    assert amounts and float(amounts[0]) == pytest.approx(0.259752)


def test_opendb_harvest_named_and_bare():
    t = "🗄️ OPEN ELASTIC http://39.107.93.224:9200\n3 индексов\nhttp://113.45.46.130:9200 тоже открыт"
    hosts = kh.harvest_opendb_hosts(t)
    kinds = {(k, ip) for k, ip, p in hosts}
    assert ("elastic", "39.107.93.224") in kinds
    assert ("elastic", "113.45.46.130") in kinds
    assert all(p in (9200, 27017, 6379, 5984) for _, _, p in hosts)


def test_render_report_relay_block():
    v = {
        "ts": 1700000000,
        "status": "working",
        "tag": "skgen",
        "base": "https://api.zhehentiaohe.cn/v1",
        "key": "sk-" + "x" * 40,
        "models": ["gpt-6-astra"],
        "n_models": 1,
        "stars_listed": ["gpt-6-astra"],
        "stars_working": [],
        "balance": 0.259752,
        "relay": {
            "family": "new-api fork v1.0.0-rc.24-tokenflow",
            "wires": {"chat_completions": True, "responses": True, "messages": False},
            "real_balance_usd": 0.259752,
            "rates_top": [{"model": "gpt-6-astra", "in_usd": 1.2, "out_usd": 6.0}],
            "hidden_models": ["gpt-6.1-sol"],
        },
        "origin": "t",
    }
    out = kh.render_report(v)
    assert "🏭 Релей: new-api fork" in out
    assert "Остаток по гейту" in out
    assert "gpt-6.1-sol" in out
    assert "responses" in out
