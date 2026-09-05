#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Albion Ledger — снифер-агент.

Висит в трее, читает сетевой трафик игры, разбирает рыночные сделки и
отправляет их на ваш сайт под вашим аккаунтом. Аналог albiondata-client,
только данные идут не в общий пул, а к вам, по вашему токену.

Что делает по шагам:
  1. При запуске проверяет токен на сайте (action=ping). Не прошёл — не стартует.
  2. Слушает UDP-порт игры и скармливает пакеты Photon-парсеру.
  3. Сопоставляет коды операций/событий с рыночными сделками (коды — в конфиге).
  4. Приводит сделку к формату сайта и шлёт пачками на /api.php.

ВАЖНО про коды. operation_codes/event_codes в конфиге меняются почти каждый
патч игры. Если после обновления сделки перестали ловиться — запустите
`python sniffer_agent.py --discover`, проведите одну сделку в игре, посмотрите,
под каким кодом пришли данные, и впишите его в sniffer_config.json. Это единственное,
что требует ручной поддержки; всё остальное патчей не боится.

Зависит от Npcap (тот же, что ставили для прошлой программы) и трёх пакетов:
  pip install scapy photon-packet-parser requests
Трей и иконка — по желанию:
  pip install pystray Pillow

Запуск от администратора: захват трафика требует прав. На Windows —
«Запуск от имени администратора», на Linux/macOS — через sudo.
"""

import argparse
import json
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Конфиг лежит рядом с программой. Для собранного .exe это папка самого exe
# (sys.executable), а не временная папка распаковки PyInstaller — иначе файл
# терялся бы при каждом закрытии. Для запуска из исходника — папка скрипта.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "sniffer_config.json"


# ---------------------------------------------------------------- конфиг

DEFAULT_CONFIG = {
    "site_url": "https://ваш-домен.ru",
    "token": "agent_xxxxxxxx",
    "character": "",          # можно оставить пустым — возьмётся из пакетов
    "server": "europe",
    "game_port": 5056,        # UDP-порт Photon у Albion
    "interface": "",          # пусто = автоопределение; иначе имя из --list-ifaces
    "batch_size": 50,         # столько сделок копим перед отправкой
    "flush_seconds": 10,      # ...или столько ждём, если не набралось
    # Коды операций и событий. МЕНЯЮТСЯ НА ПАТЧАХ — сверяйте через --discover.
    # Значения ниже — стартовые ориентиры, а не гарантия. Ключи справа —
    # это то, как их понимает агент; трогать нужно только числа.
    "operation_codes": {
        "auction_buy_offer": 82,      # выставить/исполнить ордер на покупку
        "auction_sell_offer": 81,     # выставить/исполнить ордер на продажу
        "auction_get_finished": 84,   # забрать исполненные ордера
        "read_mail": 121              # чтение рыночной почты (итоги сделок)
    },
    "event_codes": {
        "new_mail": 3                 # уведомление о новой почте рынка
    },
    # Индексы полей внутри parameters. Тоже сверяются через --discover,
    # но меняются реже, чем сами коды.
    "field_map": {
        "item_id": 0,
        "quantity": 1,
        "unit_price": 2,
        "tax": 3
    },
    "verify_tls": True
}


def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(
            json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"Создан {CONFIG_PATH.name}. Впишите адрес сайта и токен, потом запустите снова.")
        sys.exit(1)
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    # добираем поля, если конфиг из старой версии
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg


# ---------------------------------------------------------------- лог

class Log:
    """Пишет и в консоль, и в кольцевой буфер для окна трея."""
    def __init__(self, limit=500):
        self.lines = []
        self.limit = limit
        self.lock = threading.Lock()

    def __call__(self, msg, level="info"):
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}"
        with self.lock:
            self.lines.append(line)
            if len(self.lines) > self.limit:
                self.lines.pop(0)
        print(line, flush=True)

    def tail(self, n=25):
        with self.lock:
            return "\n".join(self.lines[-n:])


log = Log()


# ---------------------------------------------------------------- отправка на сайт

class Uploader:
    """Копит сделки и шлёт их пачками. Сеть упала — сделки ждут в очереди."""
    def __init__(self, cfg):
        self.cfg = cfg
        self.q = queue.Queue()
        self.sent = 0
        self.dup = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def add(self, event):
        self.q.put(event)

    def _loop(self):
        import requests
        buf = []
        last = time.time()
        while not self._stop.is_set():
            timeout = max(0.5, self.cfg["flush_seconds"] - (time.time() - last))
            try:
                buf.append(self.q.get(timeout=timeout))
            except queue.Empty:
                pass
            due = len(buf) >= self.cfg["batch_size"] or \
                (buf and time.time() - last >= self.cfg["flush_seconds"])
            if not due:
                continue
            try:
                r = requests.post(
                    self.cfg["site_url"].rstrip("/") + "/api.php",
                    headers={"Authorization": "Bearer " + self.cfg["token"]},
                    json={
                        "action": "events",
                        "character": self.cfg["character"],
                        "server": self.cfg["server"],
                        "events": buf,
                    },
                    timeout=15,
                    verify=self.cfg["verify_tls"],
                )
                data = r.json()
                if r.status_code == 200 and data.get("ok"):
                    self.sent += data.get("accepted", 0)
                    self.dup += data.get("duplicate", 0)
                    log(f"отправлено {len(buf)}: принято {data.get('accepted',0)}, "
                        f"дублей {data.get('duplicate',0)}")
                    buf = []
                    last = time.time()
                elif r.status_code == 401:
                    log("сайт вернул 401 — токен неверный или отозван. "
                        "Проверьте sniffer_config.json.", "error")
                    time.sleep(30)
                else:
                    log(f"сайт ответил {r.status_code}, повтор позже", "warn")
                    time.sleep(10)
            except Exception as e:
                # не сбрасываем buf: сделки ждут восстановления связи
                log(f"нет связи с сайтом ({e.__class__.__name__}), повтор позже", "warn")
                time.sleep(10)


# ---------------------------------------------------------------- парсинг сделок

class TradeExtractor:
    """
    Превращает Photon-события в записи для сайта.

    В обычном режиме сопоставляет коды из конфига. В режиме discover просто
    печатает все ответы операций и события с их параметрами — так находят
    актуальные коды после патча.
    """
    def __init__(self, cfg, uploader, discover=False):
        self.cfg = cfg
        self.up = uploader
        self.discover = discover
        self.op = cfg["operation_codes"]
        self.ev = cfg["event_codes"]
        self.fm = cfg["field_map"]

    def on_event(self, event):
        code = getattr(event, "code", None)
        if self.discover:
            self._dump("EVENT", code, getattr(event, "parameters", {}))
            return
        if code == self.ev.get("new_mail"):
            log("пришла рыночная почта — сделка будет забрана при чтении почты")

    def on_request(self, request):
        if self.discover:
            self._dump("REQUEST", getattr(request, "operation_code", None),
                       getattr(request, "parameters", {}))

    def on_response(self, response):
        code = getattr(response, "operation_code", None)
        params = getattr(response, "parameters", {}) or {}
        if self.discover:
            self._dump("RESPONSE", code, params)
            return
        try:
            if code == self.op.get("auction_buy_offer"):
                self._emit("buy", params)
            elif code == self.op.get("auction_sell_offer"):
                self._emit("sell", params)
        except Exception as e:
            log(f"не разобрал сделку (code={code}): {e}", "warn")

    def _emit(self, trade_type, params):
        fm = self.fm
        item = params.get(fm["item_id"])
        qty = params.get(fm["quantity"])
        price = params.get(fm["unit_price"])
        if not item or not qty:
            return
        if isinstance(item, (bytes, bytearray)):
            item = item.decode("utf-8", "ignore")
        ev = {
            "type": trade_type,
            "item_id": str(item),
            "qty": int(qty),
            "unit_price": float(price or 0),
            "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
        tax = params.get(fm.get("tax", -1))
        if tax is not None:
            ev["tax_total"] = float(tax)
        self.up.add(ev)
        log(f"{trade_type}: {ev['item_id']} × {ev['qty']} по {ev['unit_price']:.0f}")

    def _dump(self, kind, code, params):
        # компактно печатаем структуру, обрезая длинные значения
        def short(v):
            s = repr(v)
            return s if len(s) <= 60 else s[:57] + "..."
        fields = ", ".join(f"{k}={short(v)}" for k, v in (params or {}).items())
        log(f"{kind} code={code} | {fields}")


# ---------------------------------------------------------------- захват трафика

class Sniffer:
    def __init__(self, cfg, extractor):
        self.cfg = cfg
        from photon_packet_parser import PhotonPacketParser
        self.parser = PhotonPacketParser(
            extractor.on_event, extractor.on_request, extractor.on_response
        )
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        from scapy.all import sniff, UDP
        port = self.cfg["game_port"]
        iface = self.cfg["interface"] or None
        log(f"слушаю UDP-порт {port}" + (f" на {iface}" if iface else " (все интерфейсы)"))

        seen = {"n": 0}

        def handle(pkt):
            if UDP not in pkt:
                return
            udp = pkt[UDP]
            if udp.sport != port and udp.dport != port:
                return
            payload = bytes(udp.payload)
            if not payload:
                return
            seen["n"] += 1
            if seen["n"] == 1:
                log("пошёл игровой трафик, разбираю сделки")
            try:
                self.parser.HandlePayload(payload)
            except Exception:
                pass  # битые/чужие пакеты игнорируем молча

        # ВАЖНО: без BPF-фильтра (filter=...). На Windows при захвате с
        # конкретного \Device\NPF_ фильтр ядра молча отсекает весь трафик —
        # именно из-за него агент раньше ловил ноль, хотя Wireshark всё видел.
        # Порт проверяем сами в handle() — это надёжнее.
        sniff(
            prn=handle,
            store=False,
            iface=iface,
            stop_filter=lambda _: self._stop.is_set(),
        )


# ---------------------------------------------------------------- проверка токена

def verify_token(cfg):
    import requests
    try:
        r = requests.post(
            cfg["site_url"].rstrip("/") + "/api.php",
            headers={"Authorization": "Bearer " + cfg["token"]},
            json={"action": "ping"},
            timeout=15,
            verify=cfg["verify_tls"],
        )
        if r.status_code == 200 and r.json().get("ok"):
            who = r.json().get("user", "?")
            log(f"токен принят, аккаунт: {who}")
            return True
        if r.status_code == 401:
            log("токен не принят (401). Выпустите новый в «Настройках» на сайте.", "error")
        else:
            log(f"сайт ответил {r.status_code} на проверку токена", "error")
    except Exception as e:
        log(f"не достучался до сайта: {e}", "error")
    return False


# ---------------------------------------------------------------- трей

def run_tray(stopper):
    """Иконка в трее. Если pystray/Pillow не стоят — молча работаем без неё."""
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        log("pystray/Pillow не установлены — работаю без иконки в трее")
        return None

    img = Image.new("RGB", (64, 64), (24, 26, 32))
    d = ImageDraw.Draw(img)
    d.rectangle((16, 34, 24, 48), fill=(120, 190, 255))
    d.rectangle((28, 24, 36, 48), fill=(120, 190, 255))
    d.rectangle((40, 14, 48, 48), fill=(120, 190, 255))

    def show_log(_i, _item):
        print("\n----- последние строки -----\n" + log.tail(30) + "\n")

    def do_quit(icon, _item):
        stopper()
        icon.stop()

    icon = pystray.Icon(
        "albion_ledger", img, "Albion Ledger — агент",
        menu=pystray.Menu(
            pystray.MenuItem("Показать лог", show_log),
            pystray.MenuItem("Выход", do_quit),
        ),
    )
    threading.Thread(target=icon.run, daemon=True).start()
    return icon


# ---------------------------------------------------------------- утилиты CLI

def list_interfaces():
    from scapy.all import get_if_list
    print("Доступные интерфейсы (впишите нужный в sniffer_config.json → interface):")
    for name in get_if_list():
        print("  ", name)


def sniff_test(cfg, seconds=20):
    """
    Диагностика захвата. Ловит ЛЮБЫЕ пакеты на выбранной карте (не только
    игровые) и отдельно считает пакеты на порту 5056. Разделяет две причины
    тишины: карта вообще ничего не отдаёт против «трафик есть, но не 5056».
    """
    from scapy.all import sniff, IP, UDP, TCP
    iface = cfg["interface"] or None
    port = cfg["game_port"]
    log(f"тест захвата на {iface or 'всех интерфейсах'}, {seconds} сек. "
        f"Походите в игре и поторгуйте.")

    stats = {"all": 0, "udp": 0, "game": 0}
    seen_ports = {}

    def handle(pkt):
        stats["all"] += 1
        if UDP in pkt:
            stats["udp"] += 1
            sp, dp = pkt[UDP].sport, pkt[UDP].dport
            if sp == port or dp == port:
                stats["game"] += 1
            for p in (sp, dp):
                seen_ports[p] = seen_ports.get(p, 0) + 1

    sniff(prn=handle, store=False, iface=iface, timeout=seconds)

    log(f"итого пакетов: {stats['all']}, из них UDP: {stats['udp']}, "
        f"на порту {port}: {stats['game']}")
    if stats["all"] == 0:
        log("НИ ОДНОГО пакета — карта не отдаёт трафик. Причина в Npcap или "
            "выбрана не та карта (проверьте VPN и --list-ifaces).", "warn")
    elif stats["game"] == 0:
        top = sorted(seen_ports.items(), key=lambda x: -x[1])[:8]
        ports = ", ".join(f"{p}:{c}" for p, c in top)
        log(f"трафик есть, но на порту {port} пусто. Активные UDP-порты: {ports}", "warn")
        log("если игра идёт через другой порт — впишите его в game_port.", "warn")
    else:
        log("захват работает: игровые пакеты идут. Можно запускать --discover.")


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Снифер-агент Albion Ledger")
    ap.add_argument("--discover", action="store_true",
                    help="печатать все коды и параметры — для поиска актуальных кодов после патча")
    ap.add_argument("--list-ifaces", action="store_true",
                    help="показать сетевые интерфейсы и выйти")
    ap.add_argument("--sniff-test", action="store_true",
                    help="проверить захват: ловит любые пакеты и считает игровые")
    ap.add_argument("--no-tray", action="store_true", help="без иконки в трее")
    args = ap.parse_args()

    if args.list_ifaces:
        list_interfaces()
        return

    cfg = load_config()

    if args.sniff_test:
        sniff_test(cfg)
        return

    if not args.discover and not verify_token(cfg):
        sys.exit(2)

    up = Uploader(cfg)
    if not args.discover:
        up.start()

    extractor = TradeExtractor(cfg, up, discover=args.discover)
    sniffer = Sniffer(cfg, extractor)

    stopping = threading.Event()

    def stopper():
        stopping.set()
        sniffer.stop()
        up.stop()

    icon = None if args.no_tray else run_tray(stopper)

    if args.discover:
        log("режим поиска кодов: проведите одну сделку в игре и смотрите вывод")
    else:
        log("агент запущен. Держите окно открытым во время игры.")

    try:
        sniffer.run()
    except KeyboardInterrupt:
        pass
    except PermissionError:
        log("нет прав на захват трафика. Запустите от администратора "
            "и убедитесь, что установлен Npcap.", "error")
        sys.exit(3)
    finally:
        stopper()
        if icon:
            icon.stop()


if __name__ == "__main__":
    main()
