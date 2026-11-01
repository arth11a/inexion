"""
node.py: полный узел INEXION. Хранит и проверяет всю цепочку, общается с другими узлами (P2P по HTTP),
принимает переводы, отдаёт майнерам шаблоны блоков и показывает обозреватель блоков.

  python3 node.py --genesis genesis.json --datadir data --port 9333 --peer http://1.2.3.4:9333

Узел не доверяет никому: каждый блок и перевод проверяется по правилам из core.py.
"""
import argparse
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import core as C
import netutil

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 2_000_000
MAX_RESPONSE = 8_000_000
MAX_PEERS = 64
MAX_MEMPOOL = 5_000
MAX_PER_SENDER = 25
SYNC_BATCH = 200
MAX_SYNC_BLOCKS = 5_000
MEMPOOL_TTL = 24 * 3600


class PeerError(Exception):
    """Узел-собеседник из другой сети или ведёт себя неверно."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # редиректы запрещены: через них обходят проверку адреса пира
        return None


_opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=netutil.CONTEXT))


def http_json(url, data=None, timeout=6, peer_url=None):
    headers = {"Content-Type": "application/json", "User-Agent": "inexion-node/1"}
    if peer_url:
        headers["X-Inexion-Peer"] = peer_url
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    with _opener.open(req, timeout=timeout) as r:
        raw = r.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("ответ слишком большой")
    return json.loads(raw)


def normalize_url(url):
    try:
        u = urlparse(str(url).strip())
        if u.scheme not in ("http", "https") or not u.hostname:
            return None
        port = u.port or (443 if u.scheme == "https" else 80)
        host = u.hostname if ":" not in u.hostname else "[%s]" % u.hostname
        return "%s://%s:%d" % (u.scheme, host, port)
    except ValueError:
        return None


class Node:
    def __init__(self, genesis, datadir, host="127.0.0.1", port=9333, peers=(), public_url=None,
                 allow_private=False, sync_interval=10, log=print, trust_proxy=False):
        self.lock = threading.RLock()
        self.chain = C.Chain(genesis)
        self.datadir = datadir
        os.makedirs(datadir, exist_ok=True)
        self.host, self.port = host, port
        self.public_url = normalize_url(public_url) if public_url else None
        self.allow_private = allow_private
        self.trust_proxy = trust_proxy      # узел стоит за Caddy/nginx на этой же машине: настоящий IP из X-Forwarded-For
        self.sync_interval = sync_interval
        self.log = log
        self.mempool = {}          # txid -> {"tx", "sender", "added"}
        self.peers = {}            # url -> число подряд идущих сбоев
        self.rates = {}
        self.httpd = None
        self._stop = threading.Event()
        self._syncing = set()
        self._sem = threading.BoundedSemaphore(32)
        self._load_chain()
        self._load_peers()
        for p in peers:
            self.add_peer(p)

    # ------------------------------------------------------------ хранение
    def _chain_path(self):
        return os.path.join(self.datadir, "chain.jsonl")

    def _load_chain(self):
        path = self._chain_path()
        if not os.path.exists(path):
            return
        with open(path) as f:
            lines = f.read().splitlines()
        bad = False
        for i, line in enumerate(lines, 1):
            try:
                self.chain.add_block(json.loads(line), check_future=False)
            except (ValueError, C.ConsensusError) as e:
                self.log("chain.jsonl: строка %d отвергнута (%s), остаток отброшен" % (i, e))
                bad = True
                break
        if bad:
            self._rewrite_chain()
        self.log("Загружено блоков: %d" % self.chain.height)

    def _append_block(self, block):
        with open(self._chain_path(), "a") as f:
            f.write(json.dumps(block, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _rewrite_chain(self):
        tmp = self._chain_path() + ".tmp"
        with open(tmp, "w") as f:
            for b in self.chain.blocks[1:]:
                f.write(json.dumps(b, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._chain_path())

    def _peers_path(self):
        return os.path.join(self.datadir, "peers.json")

    def _load_peers(self):
        try:
            with open(self._peers_path()) as f:
                for u in json.load(f):
                    n = normalize_url(u)
                    if n and n != self.public_url:
                        self.peers[n] = 0
        except (OSError, ValueError):
            pass

    def _save_peers(self):
        try:
            with open(self._peers_path(), "w") as f:
                json.dump(sorted(self.peers), f)
        except OSError:
            pass

    # ------------------------------------------------------------ пиры
    def _url_ok(self, url):
        """Защита от SSRF: чужой узел не должен заставить нас стучаться во внутреннюю сеть."""
        try:
            u = urlparse(url)
            if u.scheme not in ("http", "https") or not u.hostname:
                return False
            if self.allow_private:
                return True
            port = u.port or (443 if u.scheme == "https" else 80)
            for info in socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP):
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
                        or ip.is_reserved or ip.is_unspecified:
                    return False
            return True
        except (OSError, ValueError):
            return False

    def add_peer(self, url):
        n = normalize_url(url)
        if not n or n == self.public_url:
            return False
        with self.lock:
            if n in self.peers:
                return True
            if len(self.peers) >= MAX_PEERS:
                return False
        if not self._url_ok(n):
            return False
        with self.lock:
            self.peers[n] = 0
            self._save_peers()
        return True

    def _drop_peer(self, url):
        with self.lock:
            self.peers.pop(url, None)
            self._save_peers()

    def _penalize(self, url):
        with self.lock:
            if url in self.peers:
                self.peers[url] += 1
                if self.peers[url] >= 8:
                    self.peers.pop(url, None)
                    self._save_peers()

    # ------------------------------------------------------------ состояние для API
    def status(self):
        with self.lock:
            c = self.chain
            now = int(time.time())
            h = c.height + 1
            to_halving = ((h - 1) // C.HALVING_INTERVAL + 1) * C.HALVING_INTERVAL + 1 - h
            return {"coin": C.COIN_NAME, "ticker": C.TICKER, "protocol": C.PROTOCOL_VERSION,
                    "chain_id": c.params.chain_id, "height": c.height, "tip": c.tip["hash"],
                    "work": str(c.work[-1]), "time": c.tip["time"], "target": c.tip["target"],
                    "peers": len(self.peers), "mempool": len(self.mempool),
                    "mined_supply": C.mined_supply_through(c.height), "max_supply": C.MAX_SUPPLY,
                    "founder_alloc": C.FOUNDER_ALLOC, "founder_address": c.params.founder,
                    "founder_locked": c.params.locked(c.params.founder, now),
                    "founder_unlock_end": c.params.genesis_time + c.params.vest_seconds,
                    "next_reward": C.block_reward(h), "blocks_to_halving": to_halving,
                    "decimals": C.DECIMALS, "block_time": C.BLOCK_TIME, "min_fee": C.MIN_FEE}

    def pending_nonce(self, addr):
        with self.lock:
            return self.chain.nonce.get(addr, 0) + sum(1 for e in self.mempool.values() if e["sender"] == addr)

    def tx_detail(self, tid):
        with self.lock:
            if tid in self.mempool:
                return {"txid": tid, "tx": self.mempool[tid]["tx"], "status": "pending"}
            h = self.chain.txindex.get(tid)
            if h is None:
                return None
            for t in self.chain.blocks[h]["txs"]:
                if C.txid(t) == tid:
                    return {"txid": tid, "tx": t, "status": "confirmed", "height": h,
                            "confirmations": self.chain.height - h + 1}
            return None

    def address_detail(self, addr, limit=50):
        with self.lock:
            info = self.chain.account(addr)
            info["pending_nonce"] = self.pending_nonce(addr)
            hist = []
            for h, tid in reversed(self.chain.addr_txs.get(addr, [])[-limit:]):
                tx = next((t for t in self.chain.blocks[h]["txs"] if C.txid(t) == tid), None)
                if tx is None:
                    continue
                if tx["type"] == "coinbase":
                    kind, other, amount = "mined", None, tx["amount"]
                elif tx["type"] == "allocation":
                    kind, other, amount = "founder", None, tx["amount"]
                elif C.tx_sender(tx) == addr:
                    kind, other, amount = "sent", tx["to"], tx["amount"] + tx["fee"]
                else:
                    kind, other, amount = "received", C.tx_sender(tx), tx["amount"]
                hist.append({"height": h, "txid": tid, "kind": kind, "other": other, "amount": amount,
                             "time": self.chain.blocks[h]["time"]})
            info["history"] = hist
            return info

    # ------------------------------------------------------------ мемпул
    def _check_mempool_tx(self, tx):
        C.check_transfer_schema(tx)
        sender = C.tx_sender(tx)
        mine = sorted((e for e in self.mempool.values() if e["sender"] == sender), key=lambda e: e["tx"]["nonce"])
        if len(mine) >= MAX_PER_SENDER:
            raise C.ConsensusError("слишком много неподтверждённых переводов с этого адреса")
        ov, now = C.Overlay(self.chain.bal, self.chain.nonce), int(time.time())
        for e in mine:
            try:
                self.chain.apply_transfer(e["tx"], ov, now)
            except C.ConsensusError:
                pass
        self.chain.apply_transfer(tx, ov, now)
        return sender

    def submit_tx(self, tx, source=None):
        if not isinstance(tx, dict):
            raise C.ConsensusError("неверная структура перевода")
        with self.lock:
            C.check_transfer_schema(tx)
            tid = C.txid(tx)
            if tid in self.mempool:
                return tid
            if tid in self.chain.txindex:
                raise C.ConsensusError("перевод уже в блоке")
            if len(self.mempool) >= MAX_MEMPOOL:
                raise C.ConsensusError("мемпул переполнен, попробуйте позже")
            sender = self._check_mempool_tx(tx)
            self.mempool[tid] = {"tx": tx, "sender": sender, "added": time.time()}
        self.broadcast("/api/tx", tx, exclude=source)
        return tid

    def _revalidate_mempool(self):
        ov, now, keep = C.Overlay(self.chain.bal, self.chain.nonce), int(time.time()), {}
        for tid, e in sorted(self.mempool.items(), key=lambda kv: (kv[1]["sender"], kv[1]["tx"]["nonce"])):
            if time.time() - e["added"] > MEMPOOL_TTL:
                continue
            try:
                self.chain.apply_transfer(e["tx"], ov, now)
                keep[tid] = e
            except C.ConsensusError:
                pass
        self.mempool = keep

    def _readd_orphaned(self, old_tail):
        for b in old_tail:
            for t in b["txs"][1:]:
                try:
                    tid = C.txid(t)
                    if tid not in self.mempool and tid not in self.chain.txindex:
                        self.mempool[tid] = {"tx": t, "sender": self._check_mempool_tx(t), "added": time.time()}
                except C.ConsensusError:
                    pass

    # ------------------------------------------------------------ майнинг
    def template(self, miner_addr):
        if not C.is_valid_address(miner_addr):
            raise ValueError("неверный адрес майнера")
        with self.lock:
            c = self.chain
            h, prev = c.height + 1, c.tip
            t_min = c.mtp(h) + 1
            t = max(t_min, int(time.time()))
            ov, picked, fees = C.Overlay(c.bal, c.nonce), [], 0
            cand = sorted(self.mempool.values(), key=lambda e: (-e["tx"]["fee"], e["tx"]["nonce"]))
            chosen = set()
            for _ in range(3):
                for e in cand:
                    tid = id(e)
                    if tid in chosen or len(picked) >= C.MAX_BLOCK_TXS:
                        continue
                    try:
                        c.apply_transfer(e["tx"], ov, t)
                    except C.ConsensusError:
                        continue
                    chosen.add(tid)
                    picked.append(e["tx"])
                    fees += e["tx"]["fee"]
            coinbase = {"type": "coinbase", "to": miner_addr, "amount": C.block_reward(h) + fees, "height": h}
            txs = [coinbase] + picked
            return {"height": h, "prev": prev["hash"], "time": t, "min_time": t_min,
                    "target": "%064x" % c.expected_target(h), "txs": txs,
                    "merkle": C.merkle_root([C.txid(x) for x in txs])}

    # ------------------------------------------------------------ приём блоков
    def submit_block(self, block, source=None):
        accepted = False
        with self.lock:
            C.check_block_schema(block)
            if block["hash"] != C.block_hash(block):
                raise C.ConsensusError("хеш блока не совпадает с содержимым")
            h = block["height"]
            if h <= self.chain.height and self.chain.blocks[h]["hash"] == block["hash"]:
                return "known"
            if block["prev"] == self.chain.tip["hash"]:
                self.chain.add_block(block)
                self._append_block(block)
                self._revalidate_mempool()
                accepted = True
        if accepted:
            self.log("Новый блок #%d %s…" % (block["height"], block["hash"][:12]))
            self.broadcast("/api/block", block, exclude=source)
            return "accepted"
        if source:
            threading.Thread(target=self._safe_sync, args=(source,), daemon=True).start()
        return "orphan"

    # ------------------------------------------------------------ синхронизация
    def _safe_sync(self, url):
        try:
            self.sync_with(url)
        except PeerError:
            self._drop_peer(url)
        except Exception:
            self._penalize(url)

    def sync_with(self, url):
        with self.lock:
            if url in self._syncing:
                return
            self._syncing.add(url)
        try:
            self._sync(url)
        finally:
            with self.lock:
                self._syncing.discard(url)

    def _sync(self, url):
        st = http_json(url + "/api/status")
        if st.get("chain_id") != self.chain.params.chain_id:
            raise PeerError("другая сеть")
        peer_work, peer_height = int(st["work"]), int(st["height"])
        with self.lock:
            my_work, my_height = self.chain.work[-1], self.chain.height
        if peer_work <= my_work:
            return
        lo, hi = 0, min(my_height, peer_height)          # поиск точки ветвления двоичным поиском
        while lo < hi:
            mid = (lo + hi + 1) // 2
            ph = http_json("%s/api/hash/%d" % (url, mid))["hash"]
            with self.lock:
                mh = self.chain.blocks[mid]["hash"] if mid <= self.chain.height else None
            if mh == ph:
                lo = mid
            else:
                hi = mid - 1
        fork, h = lo, lo + 1
        if fork == my_height:                             # чистое продолжение: применяем порциями
            while h <= peer_height:
                batch = http_json("%s/api/blocks?from=%d&limit=%d" % (url, h, SYNC_BATCH))
                if not isinstance(batch, list) or not batch:
                    break
                with self.lock:
                    try:
                        for b in batch:
                            self.chain.add_block(b)
                            self._append_block(b)
                    except C.ConsensusError as e:
                        self.log("Блок от %s отвергнут: %s" % (url, e))
                        raise PeerError("неверный блок")
                    self._revalidate_mempool()
                h += len(batch)
            self.log("Синхронизировано с %s до высоты %d" % (url, self.chain.height))
            return
        new_blocks = []
        while h <= peer_height and len(new_blocks) < MAX_SYNC_BLOCKS:
            batch = http_json("%s/api/blocks?from=%d&limit=%d" % (url, h, SYNC_BATCH))
            if not isinstance(batch, list) or not batch:
                break
            new_blocks.extend(batch)
            h += len(batch)
        if not new_blocks:
            return
        with self.lock:
            if fork > self.chain.height or self.chain.blocks[fork]["hash"] != new_blocks[0].get("prev"):
                return                                    # пока качали, наша цепочка изменилась
            try:
                old_tail = self.chain.reorg(fork, new_blocks)
            except C.ConsensusError as e:
                self.log("Ветка от %s отвергнута: %s" % (url, e))
                raise PeerError("неверная ветка")
            self._rewrite_chain()
            self._revalidate_mempool()
            self._readd_orphaned(old_tail)
        self.log("Реорганизация: откат с высоты %d до %d, новая высота %d" % (my_height, fork, self.chain.height))

    def _sync_loop(self):
        while not self._stop.wait(self.sync_interval):
            for url in list(self.peers):
                try:
                    self.sync_with(url)
                    with self.lock:
                        if url in self.peers:
                            self.peers[url] = 0
                    for u in http_json(url + "/api/peers").get("peers", [])[:20]:
                        self.add_peer(u)
                except PeerError:
                    self._drop_peer(url)
                except Exception:
                    self._penalize(url)
            with self.lock:
                self._revalidate_mempool()

    # ------------------------------------------------------------ рассылка
    def broadcast(self, path, payload, exclude=None):
        for url in list(self.peers):
            if url != exclude and self._sem.acquire(blocking=False):
                threading.Thread(target=self._post_quiet, args=(url, path, payload), daemon=True).start()

    def _post_quiet(self, url, path, payload):
        try:
            http_json(url + path, payload, timeout=5, peer_url=self.public_url)
        except Exception:
            self._penalize(url)
        finally:
            self._sem.release()

    def _announce(self):
        if not self.public_url:
            return
        for url in list(self.peers):
            try:
                http_json(url + "/api/peers", {"url": self.public_url}, timeout=4)
            except Exception:
                pass

    # ------------------------------------------------------------ ограничение частоты запросов
    def rate_ok(self, ip, post):
        if ip in ("127.0.0.1", "::1"):
            return True
        now = int(time.time() // 10)
        if len(self.rates) > 10_000:
            self.rates.clear()
        w, n = self.rates.get(ip, (now, 0))
        if w != now:
            w, n = now, 0
        n += 5 if post else 1
        self.rates[ip] = (w, n)
        return n <= 600

    # ------------------------------------------------------------ запуск
    def start(self):
        self.httpd = ThreadingHTTPServer((self.host, self.port), make_handler(self))
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        threading.Thread(target=self._sync_loop, daemon=True).start()
        threading.Thread(target=self._announce, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()


def make_handler(node):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, code=200, ctype="application/json; charset=utf-8"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

        def do_GET(self):
            self._handle(False)

        def do_POST(self):
            self._handle(True)

        def _handle(self, post):
            ip = self.client_address[0]
            if node.trust_proxy and ip in ("127.0.0.1", "::1"):
                xff = self.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
                if xff:
                    ip = xff                               # последний адрес дописывает наш прокси, ему можно верить
            if not node.rate_ok(ip, post):
                return self._send({"error": "слишком много запросов"}, 429)
            try:
                u = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                body = None
                if post:
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > MAX_BODY:
                        left = min(n, 8_000_000)               # дочитываем ограниченно, чтобы ответ дошёл чисто
                        while left > 0:
                            chunk = self.rfile.read(min(65536, left))
                            if not chunk:
                                break
                            left -= len(chunk)
                        return self._send({"error": "тело запроса слишком большое"}, 413)
                    body = json.loads(self.rfile.read(n) or b"null")
                self._route(u.path, q, body, post)
            except C.ConsensusError as e:
                self._send({"error": str(e)}, 400)
            except (ValueError, KeyError, TypeError, IndexError) as e:
                self._send({"error": "некорректный запрос: %s" % e}, 400)
            except Exception:
                self._send({"error": "внутренняя ошибка узла"}, 500)

        def _route(self, path, q, body, post):
            parts = [p for p in path.split("/") if p]
            if not post and (not parts or parts[0] == "explorer"):
                with open(os.path.join(HERE, "explorer.html"), "rb") as f:
                    return self._send(f.read(), 200, "text/html; charset=utf-8")
            if not parts or parts[0] != "api":
                return self._send({"error": "не найдено"}, 404)
            a = parts[1] if len(parts) > 1 else ""
            arg = parts[2] if len(parts) > 2 else None
            c = node.chain
            if post:
                if a == "tx":
                    return self._send({"txid": node.submit_tx(body, source=self._peer())})
                if a == "block":
                    return self._send({"status": node.submit_block(body, source=self._peer())})
                if a == "peers":
                    return self._send({"ok": node.add_peer((body or {}).get("url", ""))})
                return self._send({"error": "не найдено"}, 404)
            if a == "status":
                return self._send(node.status())
            if a == "hash" and arg is not None:
                with node.lock:
                    h = int(arg)
                    if not 0 <= h <= c.height:
                        return self._send({"error": "нет такого блока"}, 404)
                    return self._send({"hash": c.blocks[h]["hash"]})
            if a == "block" and arg is not None:
                with node.lock:
                    h = c.hindex.get(arg) if C.is_hex(arg, 64) else (int(arg) if arg.isdigit() else None)
                    if h is None or not 0 <= h <= c.height:
                        return self._send({"error": "блок не найден"}, 404)
                    b = c.blocks[h]
                    return self._send(dict(b, txids=[C.txid(t) for t in b["txs"]]))
            if a == "blocks":
                start, limit = int(q.get("from", 0)), min(int(q.get("limit", 50)), SYNC_BATCH)
                with node.lock:
                    return self._send(c.blocks[max(0, start):max(0, start) + max(0, limit)])
            if a == "tx" and arg is not None:
                d = node.tx_detail(arg)
                return self._send(d if d else {"error": "перевод не найден"}, 200 if d else 404)
            if a == "account" and arg is not None:
                if not C.is_valid_address(arg):
                    return self._send({"error": "неверный адрес"}, 400)
                with node.lock:
                    info = c.account(arg)
                    info["pending_nonce"] = node.pending_nonce(arg)
                return self._send(info)
            if a == "address" and arg is not None:
                if not C.is_valid_address(arg):
                    return self._send({"error": "неверный адрес"}, 400)
                return self._send(node.address_detail(arg))
            if a == "mempool":
                with node.lock:
                    return self._send([{"txid": t, "tx": e["tx"]} for t, e in list(node.mempool.items())[:200]])
            if a == "peers":
                return self._send({"peers": list(node.peers)})
            if a == "template":
                return self._send(node.template(q.get("address", "")))
            return self._send({"error": "не найдено"}, 404)

        def _peer(self):
            n = normalize_url(self.headers.get("X-Inexion-Peer", ""))
            return n if n and n in node.peers else None

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Полный узел INEXION")
    ap.add_argument("--genesis", default="genesis.json", help="файл первого блока (должен быть одинаковым у всех)")
    ap.add_argument("--datadir", default="data", help="папка с цепочкой")
    ap.add_argument("--host", default="127.0.0.1", help="адрес прослушивания; 0.0.0.0 чтобы принимать другие узлы")
    ap.add_argument("--port", type=int, default=9333)
    ap.add_argument("--peer", action="append", default=[], help="адрес другого узла, можно несколько раз")
    ap.add_argument("--public-url", help="публичный адрес этого узла, чтобы другие могли подключаться")
    ap.add_argument("--trust-proxy", action="store_true",
                    help="узел за обратным прокси (Caddy/nginx) на этой машине: лимит запросов по X-Forwarded-For")
    ap.add_argument("--allow-private", action="store_true", help="разрешить локальные/частные адреса пиров (для тестов)")
    args = ap.parse_args()
    try:
        with open(args.genesis) as f:
            genesis = json.load(f)
        node = Node(genesis, args.datadir, args.host, args.port, args.peer, args.public_url, args.allow_private,
                    trust_proxy=args.trust_proxy)
    except (OSError, ValueError, C.ConsensusError) as e:
        print("Не удалось запустить узел: %s" % e)
        sys.exit(1)
    node.start()
    print("INEXION: узел запущен на http://%s:%d  (обозреватель блоков по тому же адресу)" % (node.host, node.port))
    print("chain_id: %s" % node.chain.params.chain_id)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nОстановка…")
        node.stop()


if __name__ == "__main__":
    main()
