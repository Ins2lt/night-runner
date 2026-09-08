#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сборка keyhunter.json из базы (репо) + секретов (Actions env).
Секреты НИКОГДА не коммитятся — json генерится на раннере и живёт только там."""

import json
import os

base = json.load(open("keyhunter.base.json", encoding="utf-8"))

ENV_MAP = {
    "github_token": "GH_TOKEN",
    "tg_token": "TG_TOKEN",
    "shodan_key": "SHODAN_KEY",
    "urlscan_key": "URLSCAN_KEY",
    "kaggle_token": "KAGGLE_TOKEN",
    "censys_key": "CENSYS_KEY",
    "leakix_key": "LEAKIX_KEY",
    "virustotal_key": "VT_KEY",
    "fofa_key": "FOFA_KEY",
    "zoomeye_key": "ZOOMEYE_KEY",
    "netlas_key": "NETLAS_KEY",
}
for cfg_key, env_name in ENV_MAP.items():
    v = os.environ.get(env_name, "").strip()
    if v:
        base[cfg_key] = v

chat = os.environ.get("TG_CHAT", "").strip()
if chat:
    base["tg_chat"] = int(chat)

pool = [t.strip() for t in os.environ.get("GH_POOL", "").split(",") if t.strip()]
if base.get("github_token") and base["github_token"] not in pool:
    pool.insert(0, base["github_token"])
if pool:
    base["github_tokens_pool"] = pool

shj = os.environ.get("SHODAN_KEYS_JSON", "").strip()
if shj:
    with open("shodan-keys.json", "w", encoding="utf-8") as f:
        f.write(shj)

with open("keyhunter.json", "w", encoding="utf-8") as f:
    json.dump(base, f, ensure_ascii=False, indent=2)

print(
    "config built: tg=%s chat=%s gh=%s pool=%d shodan_file=%s"
    % (
        bool(base.get("tg_token")),
        bool(base.get("tg_chat")),
        bool(base.get("github_token")),
        len(base.get("github_tokens_pool", [])),
        bool(shj),
    )
)
