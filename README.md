# night-runner

Полный keyhunter на GitHub Actions, 24/7. ПК можно выключать.

- **Расписание**: каждые 30 минут (public repo — минуты Actions бесплатные).
- **Секреты**: только в Actions Secrets (`GH_TOKEN`, `TG_TOKEN`, `TG_CHAT`,
  `SHODAN_KEY`, `SHODAN_KEYS_JSON`, `GH_POOL`, ключи поисковиков).
  `make_config.py` собирает `keyhunter.json` на раннере — в git секретов нет.
- **Стор/дедуп**: Actions cache (`hunter-state-*`), не коммитится.
- **Находки**: TG-чат.
- **Keepalive**: timestamp-коммит держит schedule от 60-дневного сна.

## Управление

- Стоп: Actions → night-hunt → ⋮ → Disable workflow
- Ручной запуск: Actions → night-hunt → Run workflow
