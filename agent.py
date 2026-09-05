#!/usr/bin/env python3
"""
Мост между локальными выгрузками и сайтом Albion Ledger.

Что делает: следит за папкой, забирает оттуда новые CSV и JSON файлы
с торговой историей и отправляет события на сервер пачками.

Чего не делает: не читает сетевой трафик и не трогает клиент игры.
Снифер — отдельный процесс, который кладёт файлы в эту же папку
(см. раздел про источники в README).

Запуск:
    python agent.py --once      разово загрузить всё новое
    python agent.py             следить за папкой постоянно
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent
CONFIG_PATH = BASE / "config.json"
STATE_PATH = BASE / "state.json"

log = logging.getLogger("agent")


# ---------------------------------------------------------------- конфиг


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(
            f"Нет файла {CONFIG_PATH.name}. Скопируйте config.sample.json "
            f"в config.json и впишите адрес сайта и токен."
        )
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    for key in ("api_url", "token"):
        if not cfg.get(key):
            sys.exit(f"В config.json не заполнено поле {key}.")
    cfg.setdefault("watch_dir", str(BASE / "inbox"))
    cfg.setdefault("processed_dir", str(BASE / "processed"))
    cfg.setdefault("character", None)
    cfg.setdefault("server", "europe")
    cfg.setdefault("batch_size", 200)
    cfg.setdefault("poll_seconds", 20)
    return cfg


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("state.json повреждён, начинаю с чистого листа")
    return {"sent": []}


def save_state(state: dict) -> None:
    # локальный список отправленного держим коротким: сервер всё равно
    # отсекает повторы сам, здесь это только экономия трафика
    state["sent"] = state["sent"][-20000:]
    STATE_PATH.write_text(json.dumps(state), encoding="utf-8")


# ---------------------------------------------------------------- чтение файлов


REQUIRED = ("type", "item_id", "qty", "unit_price", "occurred_at")


def read_csv(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            clean = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            if not clean.get("type"):
                continue
            rows.append(clean)
    return rows


def read_json(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("events", [])
    return [d for d in data if isinstance(d, dict)]


def read_file(path: Path) -> list[dict]:
    if path.suffix.lower() == ".csv":
        return read_csv(path)
    if path.suffix.lower() == ".json":
        return read_json(path)
    return []


def event_key(ev: dict) -> str:
    """Локальный отпечаток — тот же набор полей, что и на сервере."""
    parts = [
        str(ev.get("type", "")),
        str(ev.get("item_id", "")).upper(),
        str(ev.get("enchant", 0)),
        str(ev.get("quality", 1)),
        str(ev.get("qty", 0)),
        str(ev.get("unit_price", 0)),
        str(ev.get("city", "")),
        str(ev.get("occurred_at", "")),
        str(ev.get("character", "")),
    ]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


def validate(ev: dict) -> str | None:
    missing = [f for f in REQUIRED if not str(ev.get(f, "")).strip()]
    if ev.get("type") == "expense":
        missing = [f for f in missing if f not in ("item_id", "qty")]
    return f"нет полей: {', '.join(missing)}" if missing else None


# ---------------------------------------------------------------- отправка


def post(cfg: dict, payload: dict) -> dict:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        cfg["api_url"],
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {cfg['token']}",
            "User-Agent": "albion-ledger-agent/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_batch(cfg: dict, events: list[dict]) -> dict:
    payload = {"action": "events", "events": events, "server": cfg["server"]}
    if cfg.get("character"):
        payload["character"] = cfg["character"]

    delay = 3
    for attempt in range(1, 5):
        try:
            return post(cfg, payload)
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")[:300]
            if err.code in (401, 403):
                sys.exit(f"Сервер отклонил токен ({err.code}): {detail}")
            if err.code < 500:
                log.error("Сервер отказал (%s): %s", err.code, detail)
                return {"accepted": 0, "duplicate": 0, "rejected": len(events)}
            log.warning("Ошибка сервера %s, попытка %s из 4", err.code, attempt)
        except (urllib.error.URLError, TimeoutError) as err:
            log.warning("Нет связи (%s), попытка %s из 4", err, attempt)
        time.sleep(delay)
        delay *= 2

    log.error("Пачка не ушла, файл останется в папке до следующего запуска")
    return {"accepted": 0, "duplicate": 0, "rejected": 0, "failed": True}


# ---------------------------------------------------------------- цикл


def process_file(cfg: dict, state: dict, path: Path) -> bool:
    try:
        rows = read_file(path)
    except (json.JSONDecodeError, UnicodeDecodeError, csv.Error) as err:
        log.error("%s: файл не разобран (%s)", path.name, err)
        return False

    fresh, skipped_bad = [], 0
    for ev in rows:
        problem = validate(ev)
        if problem:
            skipped_bad += 1
            continue
        key = event_key(ev)
        if key in state["sent"]:
            continue
        ev["_key"] = key
        fresh.append(ev)

    if not fresh:
        log.info("%s: нового нет (пропущено битых: %s)", path.name, skipped_bad)
        return True

    totals = {"accepted": 0, "duplicate": 0, "rejected": 0}
    size = int(cfg["batch_size"])

    for i in range(0, len(fresh), size):
        chunk = fresh[i : i + size]
        keys = [ev.pop("_key") for ev in chunk]
        result = send_batch(cfg, chunk)
        if result.get("failed"):
            return False
        for k in ("accepted", "duplicate", "rejected"):
            totals[k] += int(result.get(k, 0))
        state["sent"].extend(keys)
        save_state(state)

    log.info(
        "%s: принято %s, повторов %s, отклонено %s%s",
        path.name, totals["accepted"], totals["duplicate"], totals["rejected"],
        f", битых строк {skipped_bad}" if skipped_bad else "",
    )
    return True


def scan_once(cfg: dict, state: dict) -> None:
    watch = Path(cfg["watch_dir"])
    done = Path(cfg["processed_dir"])
    watch.mkdir(parents=True, exist_ok=True)
    done.mkdir(parents=True, exist_ok=True)

    files = sorted(p for p in watch.iterdir() if p.suffix.lower() in (".csv", ".json"))
    if not files:
        return

    for path in files:
        # файл может ещё дописываться — ждём, пока размер перестанет меняться
        size = path.stat().st_size
        time.sleep(0.5)
        if path.stat().st_size != size:
            log.info("%s ещё пишется, отложил", path.name)
            continue

        if process_file(cfg, state, path):
            target = done / f"{int(time.time())}_{path.name}"
            path.rename(target)


def main() -> None:
    ap = argparse.ArgumentParser(description="Агент Albion Ledger")
    ap.add_argument("--once", action="store_true", help="один проход вместо постоянного слежения")
    ap.add_argument("--ping", action="store_true", help="проверить связь и токен")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg = load_config()

    if args.ping:
        try:
            print(post(cfg, {"action": "ping"}))
        except urllib.error.HTTPError as err:
            sys.exit(f"Ошибка {err.code}: {err.read().decode('utf-8', 'replace')[:300]}")
        return

    state = load_state()

    if args.once:
        scan_once(cfg, state)
        return

    log.info("Слежу за папкой %s. Остановить — Ctrl+C.", cfg["watch_dir"])
    try:
        while True:
            scan_once(cfg, state)
            time.sleep(int(cfg["poll_seconds"]))
    except KeyboardInterrupt:
        log.info("Остановлен.")


if __name__ == "__main__":
    main()
