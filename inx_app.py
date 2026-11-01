"""
inx_app.py: приложение INEXION для Mac, Windows и Linux. Кошелёк, переводы и майнинг в одном окне.

  python3 inx_app.py            открыть приложение (окно на tkinter)
  python3 inx_app.py --web      то же в браузере (http://127.0.0.1:ПОРТ), если tkinter недоступен

Только стандартная библиотека. Версия в браузере работает на вашем компьютере, на 127.0.0.1: снаружи к ней не подключиться.
Секретный ключ не покидает компьютер: перевод подписывается здесь, в сеть уходит уже готовая подпись.
Файлы кошельков лежат в папке ~/.inexion; кошельки из других мест (например, wallet.json) можно открыть тоже.
"""
import argparse
import glob
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import core as C
import miner as M
import wallet as W

HOME_DIR = os.path.join(os.path.expanduser("~"), ".inexion")
SETTINGS = os.path.join(HOME_DIR, "app.json")
DEFAULT_NODE = "https://inexion.org"
IDLE_LOCK = 15 * 60          # секунд без действий до автоблокировки


def _load_settings():
    try:
        with open(SETTINGS) as f:
            s = json.load(f)
        return s if isinstance(s, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_settings(s):
    os.makedirs(HOME_DIR, mode=0o700, exist_ok=True)
    tmp = SETTINGS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f)
    os.replace(tmp, SETTINGS)


def find_wallets():
    """Файлы кошельков: ~/.inexion, Рабочий стол и его подпапки первого уровня, Документы."""
    home = os.path.expanduser("~")
    pats = [os.path.join(HOME_DIR, "*.json"), os.path.join(home, "Desktop", "*wallet*.json"),
            os.path.join(home, "Desktop", "*", "*wallet*.json"), os.path.join(home, "Documents", "*wallet*.json")]
    found = []
    for p in pats:
        for f in sorted(glob.glob(p)):
            if os.path.basename(f) == "app.json" or f in found:
                continue
            try:
                with open(f) as fh:
                    d = json.load(fh)
                if isinstance(d, dict) and d.get("address") and ("enc" in d or "seed" in d):
                    found.append(f)
            except (OSError, ValueError):
                pass
    return found


class Miner:
    def __init__(self):
        self.thread, self.stop_ev = None, threading.Event()
        self.log, self.blocks, self.rate, self.started, self.engine = [], 0, 0.0, 0, ""
        self.lock = threading.Lock()

    def say(self, msg):
        with self.lock:
            self.log.append("%s  %s" % (time.strftime("%H:%M:%S"), msg))
            del self.log[:-200]

    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def start(self, node, address, threads):
        if self.running():
            return
        self.stop_ev = threading.Event()
        self.blocks, self.rate, self.started = 0, 0.0, int(time.time())
        self.thread = threading.Thread(target=self._run, args=(node, address, threads, self.stop_ev), daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_ev.set()

    def _run(self, node, address, threads, stop):
        scan = None
        try:
            import miner_fast as MF
            MF.ensure_binary(self.say)
            scan, self.engine = MF.scan, "C, %d потоков" % threads
        except Exception as e:                                         # нет компилятора и готовой сборки
            self.say("Быстрый майнер недоступен (%s). Считаю на Python: это намного медленнее." % e)
            self.engine, threads = "Python, 1 поток", 1
        self.say("Майнинг запущен: %s" % self.engine)
        node, chunk = node.rstrip("/"), 20_000_000 if scan else 200_000
        while not stop.is_set():
            try:
                tpl = M._get("%s/api/template?address=%s" % (node, address))
            except (urllib.error.URLError, OSError, ValueError) as e:
                self.say("Узел недоступен (%s). Повтор через 5 с." % e)
                stop.wait(5)
                continue
            target = int(tpl["target"], 16)
            t = max(tpl["min_time"], int(time.time()))
            prefix = C.header_prefix(tpl["height"], tpl["prev"], tpl["merkle"], t, tpl["target"])
            base, t_start, hashes, nonce = 0, time.time(), 0, None
            while nonce is None and not stop.is_set():
                t0 = time.time()
                try:
                    nonce = scan(prefix, tpl["target"], base, chunk, threads) if scan else _py_scan(prefix, target, base, chunk)
                except Exception as e:
                    self.say("Ошибка майнера: %s" % e)
                    stop.wait(3)
                    break
                dt = max(time.time() - t0, 1e-6)
                if nonce is None:
                    base += chunk
                    hashes += chunk
                    self.rate = chunk / dt
                    if scan:
                        chunk = max(1_000_000, min(int(chunk * 1.5 / dt), 2_000_000_000))
                    try:
                        if M._get(node + "/api/status")["tip"] != tpl["prev"] or time.time() - t_start > 25:
                            break
                    except (urllib.error.URLError, OSError, ValueError):
                        break
            if nonce is None:
                continue
            self.rate = (hashes + (nonce - base)) / max(time.time() - t_start, 1e-3)
            h = C.sha256d(prefix + str(nonce).encode())
            if int.from_bytes(h, "big") > target:
                self.say("Майнер вернул неверное значение, пропускаю шаблон.")
                continue
            block = {"height": tpl["height"], "prev": tpl["prev"], "merkle": tpl["merkle"], "time": t,
                     "target": tpl["target"], "nonce": nonce, "txs": tpl["txs"], "hash": h.hex()}
            try:
                res = M._post(node + "/api/block", block)
            except (urllib.error.URLError, OSError, ValueError) as e:
                self.say("Не удалось отправить блок: %s" % e)
                continue
            if res.get("status") == "accepted":
                self.blocks += 1
                self.say("Блок #%d найден и принят, награда %s INX" % (block["height"], C.format_amount(tpl["txs"][0]["amount"])))
            else:
                self.say("Блок #%d не принят: %s" % (block["height"], res.get("error") or res.get("status")))
        self.say("Майнинг остановлен.")


def _py_scan(prefix, target, start, count):
    sha = hashlib.sha256
    for n in range(start, start + count):
        if int.from_bytes(sha(sha(prefix + str(n).encode()).digest()).digest(), "big") <= target:
            return n
    return None


class State:
    """Всё, что приложение помнит. Секретный ключ лежит только здесь, в памяти, и только пока кошелёк разблокирован."""

    def __init__(self, node):
        s = _load_settings()
        self.node = node or s.get("node") or DEFAULT_NODE
        self.last_file = s.get("last_file")
        self.address = self.priv = self.seed = self.file = None
        self.touched = time.time()
        self.miner = Miner()
        self.lock = threading.Lock()

    def unlocked(self):
        return self.priv is not None

    def touch(self):
        self.touched = time.time()

    def check_idle(self):
        if self.unlocked() and not self.miner.running() and time.time() - self.touched > IDLE_LOCK:
            self.lock_wallet()

    def unlock_seed(self, seed, file):
        w = W.wallet_from_seed(seed)
        self.address, self.priv, self.seed, self.file = w["address"], int.from_bytes(seed, "big"), seed, file
        self.touch()
        self.last_file = file
        s = _load_settings()
        s["last_file"] = file
        _save_settings(s)

    def lock_wallet(self):
        self.miner.stop()
        self.address = self.priv = self.seed = self.file = None

    def set_node(self, url):
        u = urllib.parse.urlparse(url.strip())
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError("Адрес узла должен начинаться с http:// или https://")
        self.node = url.strip().rstrip("/")
        s = _load_settings()
        s["node"] = self.node
        _save_settings(s)


def read_wallet_file(path, password):
    """Открывает файл кошелька. Возвращает seed или бросает ValueError с понятным текстом."""
    path = os.path.expanduser(path or "")
    if not path.endswith(".json") or not os.path.isfile(path):
        raise ValueError("Файл кошелька не найден")
    try:
        with open(path) as f:
            w = json.load(f)
        if "enc" in w:
            seed = W.decrypt_seed(w["enc"], password)
        else:
            seed = bytes.fromhex(w["seed"])
        if W.wallet_from_seed(seed)["address"] != w["address"]:
            raise ValueError("файл кошелька повреждён")
        return seed
    except (OSError, KeyError, TypeError) as e:
        raise ValueError("Не удалось прочитать файл кошелька: %s" % e)


def save_new_wallet(seed, password):
    if len(password) < 10:
        raise ValueError("Пароль слишком короткий: нужно не меньше 10 символов")
    os.makedirs(HOME_DIR, mode=0o700, exist_ok=True)
    w = W.wallet_from_seed(seed)
    to_save = {k: v for k, v in w.items() if k != "seed"}
    to_save["enc"] = W.encrypt_seed(seed, password)
    path = os.path.join(HOME_DIR, "wallet-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    n = 1
    while os.path.exists(path):
        n += 1
        path = os.path.join(HOME_DIR, "wallet-%s-%d.json" % (time.strftime("%Y%m%d-%H%M%S"), n))
    W.save_wallet(to_save, path)
    return path


def make_handler(state, token, port):
    allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
    allowed_origins = {"http://" + h for h in allowed_hosts}

    class H(BaseHTTPRequestHandler):
        server_version = "INXApp"

        def log_message(self, *a):
            pass

        def _send(self, obj, code=200, ctype="application/json"):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype != "application/json" else ""))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _guard(self, api):
            if self.headers.get("Host", "") not in allowed_hosts:
                self._send({"error": "запрещено"}, 403)
                return False
            if api and not secrets.compare_digest(self.headers.get("X-Token", ""), token):
                self._send({"error": "нет доступа"}, 403)
                return False
            org = self.headers.get("Origin")
            if org and org not in allowed_origins:
                self._send({"error": "запрещено"}, 403)
                return False
            return True

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            if u.path == "/":
                q = urllib.parse.parse_qs(u.query)
                if not self._guard(False):
                    return
                if not secrets.compare_digest(q.get("t", [""])[0], token):
                    return self._send("Откройте приложение по ссылке, которую напечатал inx_app.py.".encode(), 403, "text/plain")
                return self._send(PAGE.replace("__TOKEN__", token).encode(), 200, "text/html")
            if not self._guard(True):
                return
            self._route(u.path, None)

        def do_POST(self):
            if not self._guard(True):
                return
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n > 100_000:
                    return self._send({"error": "слишком большой запрос"}, 413)
                body = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._send({"error": "некорректный запрос"}, 400)
            self._route(urllib.parse.urlparse(self.path).path, body)

        def _route(self, path, body):
            state.check_idle()
            try:
                out = api(state, path, body)
            except ValueError as e:
                return self._send({"error": str(e)}, 400)
            except (urllib.error.URLError, OSError) as e:
                return self._send({"error": "Нет связи с узлом %s (%s)" % (state.node, getattr(e, "reason", e))}, 502)
            except Exception:
                return self._send({"error": "внутренняя ошибка приложения"}, 500)
            if out is None:
                return self._send({"error": "не найдено"}, 404)
            self._send(out)

    return H


def _node_get(state, path):
    return M._get(state.node + path)


def api(st, path, b):
    if b is None:                                                      # GET
        if path == "/api/state":
            return {"unlocked": st.unlocked(), "address": st.address, "node": st.node, "wallets": find_wallets(),
                    "last_file": st.last_file, "ticker": C.TICKER, "cpu": os.cpu_count() or 1,
                    "idle_lock_minutes": IDLE_LOCK // 60}
        if path == "/api/account":
            if not st.unlocked():
                raise ValueError("Кошелёк заблокирован")
            info = _node_get(st, "/api/address/" + st.address)
            return {"info": info, "status": _node_get(st, "/api/status")}
        if path == "/api/mining":
            m = st.miner
            with m.lock:
                log = list(m.log[-60:])
            return {"running": m.running(), "blocks": m.blocks, "rate": m.rate, "engine": m.engine,
                    "started": m.started, "log": log}
        return None
    # POST
    if path == "/api/unlock":
        seed = read_wallet_file(b.get("file"), str(b.get("password", "")))
        st.unlock_seed(seed, os.path.expanduser(b["file"]))
        return {"ok": True}
    if path == "/api/create":
        pw = str(b.get("password", ""))
        if pw != str(b.get("password2", pw)):
            raise ValueError("Пароли не совпали")
        seed = secrets.token_bytes(32)
        while not 0 < int.from_bytes(seed, "big") < C.N:
            seed = secrets.token_bytes(32)
        file = save_new_wallet(seed, pw)
        st.unlock_seed(seed, file)
        return {"ok": True, "file": file, "recovery": W.recovery_code(seed)}
    if path == "/api/restore":
        seed = W.parse_recovery_code(str(b.get("code", "")))
        file = save_new_wallet(seed, str(b.get("password", "")))
        st.unlock_seed(seed, file)
        return {"ok": True, "file": file}
    if path == "/api/lock":
        st.lock_wallet()
        return {"ok": True}
    if path == "/api/node":
        st.set_node(str(b.get("url", "")))
        return {"ok": True, "node": st.node}
    if not st.unlocked():
        raise ValueError("Кошелёк заблокирован")
    st.touch()
    if path == "/api/recovery":
        read_wallet_file(st.file, str(b.get("password", "")))         # повторно просим пароль
        return {"recovery": W.recovery_code(st.seed)}
    if path == "/api/send":
        to = str(b.get("to", "")).strip()
        if not C.is_valid_address(to):
            raise ValueError("Адрес получателя неверный (не сходится контрольная сумма)")
        amount, fee = C.parse_amount(str(b.get("amount", ""))), C.parse_amount(str(b.get("fee") or "0.0001"))
        if amount <= 0:
            raise ValueError("Сумма должна быть больше нуля")
        if fee < C.MIN_FEE:
            raise ValueError("Комиссия меньше минимальной (%s INX)" % C.format_amount(C.MIN_FEE))
        status = _node_get(st, "/api/status")
        info = _node_get(st, "/api/account/" + st.address)
        if amount + fee > info["spendable"]:
            raise ValueError("Недостаточно доступных монет: можно потратить %s INX" % C.format_amount(info["spendable"]))
        tx = C.make_transfer(st.priv, status["chain_id"], to, amount, fee, info["pending_nonce"])
        res = M._post(st.node + "/api/tx", tx)
        if "txid" not in res:
            raise ValueError("Узел отклонил перевод: %s" % res.get("error"))
        return {"txid": res["txid"]}
    if path == "/api/mine/start":
        threads = max(1, min(int(b.get("threads") or 1), 256))
        st.miner.start(st.node, st.address, threads)
        return {"ok": True}
    if path == "/api/mine/stop":
        st.miner.stop()
        return {"ok": True}
    return None


def main():
    ap = argparse.ArgumentParser(description="Приложение INEXION: кошелёк, переводы, майнинг")
    ap.add_argument("--node", help="адрес узла (по умолчанию https://inexion.org)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true", help="не открывать браузер (только с --web)")
    ap.add_argument("--web", action="store_true", help="открыть в браузере вместо окна приложения")
    a = ap.parse_args()
    state = State(a.node)
    if not a.web:
        try:
            import tkinter
            if tkinter.TkVersion < 8.6:
                raise ImportError("старая версия Tk %s" % tkinter.TkVersion)
            import inx_gui
        except ImportError as e:
            print("Окно приложения недоступно (%s). Открываю версию в браузере." % e)
        else:
            return inx_gui.run(state)
    token, srv = secrets.token_urlsafe(24), None
    for port in [a.port] + [0]:
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
            break
        except OSError:
            continue
    if srv is None:
        sys.exit("Не удалось занять порт.")
    port = srv.server_address[1]
    srv.RequestHandlerClass = make_handler(state, token, port)
    url = "http://127.0.0.1:%d/?t=%s" % (port, token)
    print("INEXION запущен. Если браузер не открылся, откройте ссылку:\n  %s\nОстановить: Ctrl+C" % url)
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка…")
    finally:
        state.lock_wallet()
        srv.server_close()


PAGE = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>INEXION</title>
<style>
:root{--bg:#EDF1F4;--card:#fff;--ink:#0E1923;--sl:#566678;--ln:#CBD4DC;--cb:#2438F2;--am:#F2A71B;--ok:#0a7a45;--er:#b3261e;--code:#0E1923}
@media(prefers-color-scheme:dark){:root{--bg:#0b121a;--card:#121c27;--ink:#E8EDF2;--sl:#9FB0C2;--ln:#26364a;--cb:#6b7bff;--ok:#3ecf8e;--er:#ff7b72}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:#2438F2;color:#fff;padding:14px 20px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.brand{font:600 19px Georgia,serif;letter-spacing:.14em}.hdr small{opacity:.85}
main{max-width:860px;margin:0 auto;padding:20px 16px 60px}
.card{background:var(--card);border:1px solid var(--ln);border-radius:10px;padding:20px;margin:0 0 16px}
h2{margin:0 0 12px;font-size:19px}.mut{color:var(--sl);font-size:14px}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13.5px;word-break:break-all}
label{display:block;margin:12px 0 4px;font-size:14px;color:var(--sl)}
input,select{width:100%;padding:10px 12px;font:inherit;border:1px solid var(--ln);border-radius:7px;background:var(--bg);color:var(--ink)}
button{font:inherit;font-weight:600;padding:10px 18px;border-radius:7px;border:0;background:var(--cb);color:#fff;cursor:pointer}
button.sec{background:transparent;color:var(--cb);border:1px solid var(--cb)}button.dng{background:var(--er)}button:disabled{opacity:.5;cursor:default}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
.tabs{display:flex;gap:6px;margin:0 0 16px;flex-wrap:wrap}.tabs button{background:var(--card);color:var(--ink);border:1px solid var(--ln)}.tabs button.on{background:var(--cb);color:#fff;border-color:var(--cb)}
.big{font:600 34px Georgia,serif}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.grid>div{background:var(--bg);border-radius:8px;padding:12px}
.msg{padding:10px 14px;border-radius:7px;margin-top:12px;font-size:14px}.msg.err{background:rgba(179,38,30,.12);color:var(--er)}.msg.ok{background:rgba(10,122,69,.12);color:var(--ok)}
.warn{border-left:5px solid var(--am);background:var(--card);padding:12px 16px;border-radius:0 8px 8px 0;margin:0 0 16px;font-size:14px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:8px 6px;border-bottom:1px solid var(--ln);text-align:left}td.r,th.r{text-align:right}
pre{background:var(--code);color:#E8EDF2;border-radius:8px;padding:12px;font-size:12.5px;max-height:260px;overflow:auto;white-space:pre-wrap;margin:12px 0 0}
.rec{background:var(--bg);border:2px dashed var(--am);padding:14px;border-radius:8px;font:600 15px ui-monospace,Menlo,monospace;word-break:break-all;margin:12px 0}
.hide{display:none}
</style></head><body>
<header><span class="brand">INEXION</span><span class="hdr"><small id="nodeinfo"></small></span></header>
<main>
<div class="warn">Тестовая сеть: монеты ничего не стоят. Экспериментальное ПО без аудита, используйте на свой риск.</div>

<section id="login" class="hide">
 <div class="card"><h2>Открыть кошелёк</h2>
  <label>Файл кошелька</label><select id="lfile"></select>
  <label>или путь к файлу</label><input id="lpath" placeholder="/Users/вы/Desktop/wallet.json">
  <label>Пароль</label><input id="lpass" type="password" autocomplete="current-password">
  <div class="row"><button id="bunlock">Открыть</button></div><div id="lmsg"></div></div>
 <div class="card"><h2>Новый кошелёк</h2><p class="mut">Придумайте пароль (не короче 10 символов). Затем вы получите код восстановления: запишите его на бумагу.</p>
  <label>Пароль</label><input id="cpass" type="password" autocomplete="new-password"><label>Повторите пароль</label><input id="cpass2" type="password" autocomplete="new-password">
  <div class="row"><button id="bcreate" class="sec">Создать кошелёк</button></div><div id="cmsg"></div></div>
 <div class="card"><h2>Восстановить по коду</h2>
  <label>Код восстановления</label><input id="rcode" placeholder="XXXX-XXXX-…"><label>Новый пароль</label><input id="rpass" type="password" autocomplete="new-password">
  <div class="row"><button id="brestore" class="sec">Восстановить</button></div><div id="rmsg"></div></div>
</section>

<section id="rec" class="hide"><div class="card"><h2>Код восстановления</h2>
 <p>Запишите этот код на бумагу и храните отдельно от компьютера. Без файла кошелька или этого кода монеты не вернуть, а с ним их может забрать любой.</p>
 <div class="rec" id="reccode"></div><div class="row"><button id="brecdone">Я записал код</button></div></div></section>

<section id="app" class="hide">
 <div class="tabs"><button data-t="w" class="on">Кошелёк</button><button data-t="s">Отправить</button><button data-t="m">Майнинг</button><button data-t="x">Настройки</button></div>
 <div id="t-w">
  <div class="card"><div class="mut">Баланс</div><div class="big"><span id="bal">…</span> INX</div>
   <div class="grid" style="margin-top:12px"><div><div class="mut">Можно потратить</div><b id="spend">…</b></div><div><div class="mut">Заморожено</div><b id="locked">…</b></div><div><div class="mut">Блоков в сети</div><b id="height">…</b></div></div>
   <div class="mut" style="margin-top:14px">Ваш адрес (его можно показывать)</div><div class="mono" id="addr"></div>
   <div class="row"><button class="sec" id="bcopy">Скопировать адрес</button></div></div>
  <div class="card"><h2>История</h2><table><thead><tr><th>Блок</th><th>Что</th><th>Кто</th><th class="r">Сумма</th></tr></thead><tbody id="hist"></tbody></table><div class="mut" id="hempty"></div></div>
 </div>
 <div id="t-s" class="hide"><div class="card"><h2>Отправить INX</h2>
  <label>Адрес получателя</label><input id="sto" placeholder="INX…"><label>Сумма, INX</label><input id="samt" inputmode="decimal" placeholder="1.5">
  <label>Комиссия, INX</label><input id="sfee" inputmode="decimal" value="0.0001">
  <div class="row"><button id="bsend">Отправить</button></div><div id="smsg"></div></div></div>
 <div id="t-m" class="hide"><div class="card"><h2>Майнинг</h2><p class="mut">Награда за блок идёт на адрес вашего кошелька. Приложение должно оставаться открытым.</p>
  <div class="grid"><div><div class="mut">Состояние</div><b id="mst">остановлен</b></div><div><div class="mut">Скорость</div><b id="mrate">0</b></div><div><div class="mut">Найдено блоков</div><b id="mblocks">0</b></div><div><div class="mut">Способ</div><b id="meng">…</b></div></div>
  <label>Потоков процессора</label><input id="mthr" type="number" min="1" value="1">
  <div class="row"><button id="bmine">Начать майнинг</button></div><pre id="mlog">—</pre></div></div>
 <div id="t-x" class="hide">
  <div class="card"><h2>Узел</h2><label>Адрес узла</label><input id="nurl"><div class="row"><button id="bnode" class="sec">Сохранить</button></div><div id="nmsg"></div></div>
  <div class="card"><h2>Безопасность</h2><p class="mut">Кошелёк сам блокируется через <span id="idle">15</span> минут без действий.</p>
   <label>Показать код восстановления (нужен пароль)</label><input id="xpass" type="password"><div class="row"><button id="brec" class="sec">Показать код</button><button id="block" class="dng">Заблокировать кошелёк</button></div><div id="xmsg"></div><div class="rec hide" id="xrec"></div>
   <p class="mut">Файл кошелька: <span class="mono" id="wfile"></span></p></div>
 </div>
</section>
</main>
<script>
const T="__TOKEN__";
const $=id=>document.getElementById(id);
async function call(path,body){
  const o={headers:{"X-Token":T}};
  if(body!==undefined){o.method="POST";o.headers["Content-Type"]="application/json";o.body=JSON.stringify(body)}
  const r=await fetch(path,o);let j={};try{j=await r.json()}catch(e){}
  if(!r.ok)throw new Error(j.error||("Ошибка "+r.status));return j}
function msg(id,t,ok){const e=$(id);e.innerHTML="";if(!t)return;const d=document.createElement("div");d.className="msg "+(ok?"ok":"err");d.textContent=t;e.appendChild(d)}
const fmt=n=>{const s=(n/1e8).toFixed(8);return s.replace(/\.?0+$/,"")||"0"};
const short=a=>a?a.slice(0,10)+"…"+a.slice(-6):"";
let S=null,tab="w",poll=null;
function show(id){["login","rec","app"].forEach(x=>$(x).classList.toggle("hide",x!==id))}
async function refreshState(){
  S=await call("/api/state");$("nodeinfo").textContent=S.node;
  if(!S.unlocked){stopPoll();show("login");
    const sel=$("lfile");sel.innerHTML="";S.wallets.forEach(f=>{const o=document.createElement("option");o.value=f;o.textContent=f;if(f===S.last_file)o.selected=true;sel.appendChild(o)});
    if(!S.wallets.length){const o=document.createElement("option");o.value="";o.textContent="Файлы не найдены, укажите путь ниже";sel.appendChild(o)}
    return}
  show("app");$("addr").textContent=S.address;$("nurl").value=S.node;$("idle").textContent=S.idle_lock_minutes;$("wfile").textContent=S.last_file||"";
  $("mthr").max=S.cpu;if(!$("mthr").dataset.set){$("mthr").value=Math.max(1,S.cpu-1);$("mthr").dataset.set=1}
  startPoll()}
async function refreshAccount(){
  try{const r=await call("/api/account");const i=r.info;
    $("bal").textContent=fmt(i.balance);$("spend").textContent=fmt(i.spendable);$("locked").textContent=fmt(i.locked);$("height").textContent=r.status.height;
    const tb=$("hist");tb.innerHTML="";const names={mined:"майнинг",sent:"отправлено",received:"получено",founder:"доля основателя"};
    i.history.forEach(h=>{const tr=document.createElement("tr");const sign=(h.kind==="sent")?"−":"+";
      [h.height,names[h.kind]||h.kind,short(h.other)||"—"].forEach(v=>{const td=document.createElement("td");td.textContent=v;tr.appendChild(td)});
      const td=document.createElement("td");td.className="r";td.textContent=sign+fmt(h.amount);tr.appendChild(td);tb.appendChild(tr)});
    $("hempty").textContent=i.history.length?"":"Операций пока нет."
  }catch(e){if(/заблокирован/.test(e.message))refreshState();else $("bal").textContent="нет связи"}}
async function refreshMining(){
  try{const m=await call("/api/mining");$("mst").textContent=m.running?"идёт":"остановлен";
    $("mrate").textContent=m.running?(m.rate>=1e6?(m.rate/1e6).toFixed(2)+" МХеш/с":(m.rate/1e3).toFixed(1)+" кХеш/с"):"0";
    $("mblocks").textContent=m.blocks;$("meng").textContent=m.engine||"…";$("bmine").textContent=m.running?"Остановить":"Начать майнинг";$("bmine").className=m.running?"dng":"";
    const l=$("mlog");l.textContent=m.log.length?m.log.join("\n"):"—";l.scrollTop=l.scrollHeight}catch(e){}}
function startPoll(){stopPoll();refreshAccount();refreshMining();poll=setInterval(()=>{if(tab==="w")refreshAccount();if(tab==="m")refreshMining()},3000)}
function stopPoll(){if(poll){clearInterval(poll);poll=null}}
document.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>{tab=b.dataset.t;
  document.querySelectorAll(".tabs button").forEach(x=>x.classList.toggle("on",x===b));
  ["w","s","m","x"].forEach(t=>$("t-"+t).classList.toggle("hide",t!==tab));if(tab==="w")refreshAccount();if(tab==="m")refreshMining()});
$("bunlock").onclick=async()=>{try{msg("lmsg","");await call("/api/unlock",{file:$("lpath").value.trim()||$("lfile").value,password:$("lpass").value});$("lpass").value="";await refreshState()}catch(e){msg("lmsg",e.message)}};
$("lpass").onkeydown=e=>{if(e.key==="Enter")$("bunlock").click()};
$("bcreate").onclick=async()=>{try{msg("cmsg","");const r=await call("/api/create",{password:$("cpass").value,password2:$("cpass2").value});$("cpass").value=$("cpass2").value="";
  $("reccode").textContent=r.recovery;show("rec")}catch(e){msg("cmsg",e.message)}};
$("brecdone").onclick=()=>{$("reccode").textContent="";refreshState()};
$("brestore").onclick=async()=>{try{msg("rmsg","");await call("/api/restore",{code:$("rcode").value,password:$("rpass").value});$("rcode").value=$("rpass").value="";await refreshState()}catch(e){msg("rmsg",e.message)}};
$("bcopy").onclick=async()=>{try{await navigator.clipboard.writeText(S.address);$("bcopy").textContent="Скопировано"}catch(e){$("bcopy").textContent="Выделите адрес вручную"}setTimeout(()=>$("bcopy").textContent="Скопировать адрес",1800)};
$("bsend").onclick=async()=>{msg("smsg","");const to=$("sto").value.trim(),amt=$("samt").value.trim(),fee=$("sfee").value.trim();
  if(!confirm("Отправить "+amt+" INX на адрес\n"+to+"\nКомиссия: "+fee+" INX.\nПеревод нельзя отменить."))return;
  $("bsend").disabled=true;try{const r=await call("/api/send",{to,amount:amt,fee});msg("smsg","Перевод отправлен. Он подтвердится, когда попадёт в блок. ID: "+r.txid,true);$("samt").value=""}catch(e){msg("smsg",e.message)}$("bsend").disabled=false};
$("bmine").onclick=async()=>{try{const run=$("bmine").textContent==="Остановить";await call(run?"/api/mine/stop":"/api/mine/start",run?{}:{threads:+$("mthr").value});setTimeout(refreshMining,400)}catch(e){$("mlog").textContent=e.message}};
$("bnode").onclick=async()=>{try{msg("nmsg","");await call("/api/node",{url:$("nurl").value});msg("nmsg","Сохранено.",true);refreshState()}catch(e){msg("nmsg",e.message)}};
$("block").onclick=async()=>{await call("/api/lock",{});refreshState()};
$("brec").onclick=async()=>{try{msg("xmsg","");const r=await call("/api/recovery",{password:$("xpass").value});$("xpass").value="";const e=$("xrec");e.textContent=r.recovery;e.classList.remove("hide");setTimeout(()=>{e.textContent="";e.classList.add("hide")},30000)}catch(e){msg("xmsg",e.message)}};
refreshState().catch(e=>{document.body.textContent="Не удалось связаться с приложением: "+e.message});
</script></body></html>"""

if __name__ == "__main__":
    main()
