import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from testutil import ALICE_PRIV, BOB_PRIV, FOUNDER_PRIV, MINER_PRIV, C, addr, make_genesis, solve
import node as N

ALICE, BOB, MINER, FOUNDER = addr(ALICE_PRIV), addr(BOB_PRIV), addr(MINER_PRIV), addr(FOUNDER_PRIV)
INX = C.UNIT
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def url(node):
    return "http://127.0.0.1:%d" % node.port


def get(node, path):
    with urllib.request.urlopen(url(node) + path, timeout=10) as r:
        return json.loads(r.read())


def post(node, path, data, raw=None):
    req = urllib.request.Request(url(node) + path, data=raw if raw is not None else json.dumps(data).encode(),
                                 method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait(cond, timeout=20, step=0.2):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


def mine_on(node, address, n=1, shift=0):
    for _ in range(n):
        tpl = node.template(address)
        blk = solve(tpl["height"], tpl["prev"], tpl["merkle"], tpl["time"] + shift, int(tpl["target"], 16), tpl["txs"])
        res = node.submit_block(blk)
        assert res == "accepted", res


class NetBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.genesis = make_genesis()
        self.nodes = []

    def tearDown(self):
        for n in self.nodes:
            n.stop()
        self.tmp.cleanup()

    def start(self, name, genesis=None, peers=(), allow_private=True, trust_proxy=False):
        n = N.Node(copy.deepcopy(genesis or self.genesis), os.path.join(self.tmp.name, name), port=0,
                   allow_private=allow_private, sync_interval=1, log=lambda *a: None, trust_proxy=trust_proxy)
        n.start()
        n.public_url = url(n)
        for p in peers:
            n.add_peer(url(p))
        n._announce()
        self.nodes.append(n)
        return n

    def heights(self, *ns):
        return [n.chain.height for n in ns]


class ReverseProxy(NetBase):
    def hits(self, node, n, xff=None):
        codes = []
        for _ in range(n):
            req = urllib.request.Request(url(node) + "/api/status")
            if xff:
                req.add_header("X-Forwarded-For", xff)
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    codes.append(r.status)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        return codes

    def test_rate_limit_uses_forwarded_ip_only_when_trusted(self):
        a = self.start("a", trust_proxy=True)
        self.assertIn(429, self.hits(a, 700, "203.0.113.7"), "клиент за прокси ограничивается по своему IP")
        self.assertEqual(self.hits(a, 3, "198.51.100.9"), [200, 200, 200], "другой клиент не пострадал")
        b = self.start("b")                                    # без --trust-proxy заголовок игнорируется
        self.assertNotIn(429, self.hits(b, 700, "203.0.113.7"))


class Propagation(NetBase):
    def test_blocks_and_transactions_spread_across_three_nodes(self):
        a = self.start("a")
        b = self.start("b", peers=[a])
        c = self.start("c", peers=[b])                          # цепочка узлов a - b - c
        self.assertTrue(wait(lambda: url(b) in a.peers and url(c) in b.peers), "узлы узнали друг о друге")

        mine_on(a, ALICE, 3)
        self.assertTrue(wait(lambda: self.heights(a, b, c) == [3, 3, 3]), "блоки дошли до всех: %s" % self.heights(a, b, c))
        self.assertEqual(a.chain.tip["hash"], c.chain.tip["hash"])

        tx = C.make_transfer(ALICE_PRIV, a.chain.params.chain_id, BOB, 10 * INX, 20_000, 0)
        code, res = post(c, "/api/tx", tx)                      # перевод отправлен на самый дальний узел
        self.assertEqual(code, 200, res)
        self.assertTrue(wait(lambda: len(a.mempool) == 1 and len(b.mempool) == 1), "перевод разошёлся по сети")

        code, res = post(a, "/api/tx", C.make_transfer(ALICE_PRIV, a.chain.params.chain_id, MINER, 1 * INX, 20_000, 0))
        self.assertEqual(code, 400, "второй перевод с тем же nonce (двойная трата) отвергнут")

        mine_on(b, MINER, 1)                                    # блок собирает другой узел
        self.assertTrue(wait(lambda: self.heights(a, b, c) == [4, 4, 4]))
        for n in (a, b, c):
            acc = get(n, "/api/account/" + BOB)
            self.assertEqual(acc["balance"], 10 * INX, "баланс получателя одинаков на всех узлах")
            self.assertEqual(len(n.mempool), 0)
        self.assertEqual(get(a, "/api/account/" + MINER)["balance"], 45 * INX // 10 + 20_000, "майнер получил награду и комиссию")

    def test_late_node_catches_up_by_syncing(self):
        a = self.start("a")
        mine_on(a, ALICE, 25)
        d = self.start("d", peers=[a])
        self.assertTrue(wait(lambda: d.chain.height == 25, 30), "новый узел скачал и проверил 25 блоков: %s" % d.chain.height)
        self.assertEqual(d.chain.bal, a.chain.bal)


class Forks(NetBase):
    def test_longer_branch_wins_and_orphaned_tx_returns_to_mempool(self):
        d, e = self.start("d"), self.start("e")                 # две изолированные сети с одним генезисом
        mine_on(d, ALICE)                                       # d: блок 1 -> Alice
        tx = C.make_transfer(ALICE_PRIV, d.chain.params.chain_id, BOB, 1 * INX, 20_000, 0)
        d.submit_tx(tx)
        mine_on(d, MINER)                                       # d: блок 2 содержит перевод Alice -> Bob
        self.assertEqual(d.chain.height, 2)
        mine_on(e, ALICE, shift=5)                              # e: другой блок 1 -> тоже Alice
        mine_on(e, MINER, 4)                                    # e: всего 5 блоков, работы больше
        self.assertNotEqual(d.chain.blocks[1]["hash"], e.chain.blocks[1]["hash"])

        d.add_peer(url(e))
        self.assertTrue(wait(lambda: d.chain.tip["hash"] == e.chain.tip["hash"], 30), "d перешёл на более длинную ветку")
        self.assertEqual(d.chain.height, 5)
        self.assertEqual(d.chain.bal, e.chain.bal)
        self.assertEqual(d.chain.bal.get(BOB, 0), 0, "перевод из отброшенной ветки отменён")
        self.assertTrue(wait(lambda: len(d.mempool) == 1), "но он вернулся в мемпул, т.к. у Alice есть монеты в новой ветке")

    def test_node_from_other_network_is_dropped_and_not_followed(self):
        a = self.start("a")
        other = self.start("x", genesis=make_genesis(message="чужая сеть"))
        mine_on(other, ALICE, 5)
        a.add_peer(url(other))
        self.assertTrue(wait(lambda: url(other) not in a.peers, 10), "чужую сеть отключили")
        self.assertEqual(a.chain.height, 0)

    def test_invalid_chain_from_peer_rejected(self):
        a = self.start("a")
        evil = self.start("evil")
        mine_on(evil, ALICE, 4)
        evil.chain.blocks[2]["txs"][0]["amount"] += 1 * INX     # узел-злодей раздаёт испорченный блок
        a.add_peer(url(evil))
        self.assertTrue(wait(lambda: url(evil) not in a.peers, 10), "узел с неверными блоками отключён")
        self.assertLessEqual(a.chain.height, 1)


class Api(NetBase):
    def test_http_robustness_and_explorer(self):
        a = self.start("a")
        mine_on(a, ALICE, 2)
        self.assertIn("INEXION", urllib.request.urlopen(url(a) + "/").read().decode())
        st = get(a, "/api/status")
        self.assertEqual((st["height"], st["next_reward"], st["max_supply"]), (2, 45 * INX // 10, 21_000_000 * INX))
        self.assertEqual(st["founder_alloc"], 2_100_000 * INX)
        self.assertGreater(st["founder_locked"], 0)
        b1 = get(a, "/api/block/1")
        self.assertEqual(len(b1["txids"]), 1)
        self.assertEqual(get(a, "/api/block/" + b1["hash"])["height"], 1)
        tx = get(a, "/api/tx/" + b1["txids"][0])
        self.assertEqual((tx["status"], tx["confirmations"]), ("confirmed", 2))
        hist = get(a, "/api/address/" + ALICE)["history"]
        self.assertEqual([h["kind"] for h in hist], ["mined", "mined"])
        self.assertEqual(len(get(a, "/api/blocks?from=0&limit=500")), 3, "лимит и диапазон блоков")

        self.assertEqual(post(a, "/api/tx", None, raw=b"{not json")[0], 400)
        self.assertEqual(post(a, "/api/tx", {"type": "transfer"})[0], 400)
        self.assertEqual(post(a, "/api/block", {"height": 1})[0], 400)
        bad = {**get(a, "/api/block/2")}
        bad.pop("txids")
        bad["nonce"] += 1
        self.assertEqual(post(a, "/api/block", bad)[0], 400, "блок с неверным хешем отвергнут")
        self.assertEqual(post(a, "/api/tx", None, raw=b"x" * 3_000_000)[0], 413, "слишком большое тело")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            get(a, "/api/nothing")
        self.assertEqual(cm.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            get(a, "/api/account/INXbroken")
        self.assertEqual(cm.exception.code, 400)

    def test_ssrf_protection_on_peers(self):
        n = self.start("p", allow_private=False)
        for bad in ("http://127.0.0.1:9", "http://10.0.0.5:9333", "http://192.168.1.1:80", "http://localhost:1",
                    "ftp://example.com", "http://169.254.169.254", "javascript:alert(1)", ""):
            self.assertFalse(n.add_peer(bad), bad)
        self.assertTrue(n.add_peer("http://8.8.8.8:9333"))


class Persistence(NetBase):
    def test_restart_keeps_chain_and_recovers_from_corruption(self):
        a = self.start("a")
        mine_on(a, ALICE, 4)
        tip, bal = a.chain.tip["hash"], dict(a.chain.bal)
        a.stop()
        self.nodes.remove(a)
        a2 = N.Node(copy.deepcopy(self.genesis), os.path.join(self.tmp.name, "a"), log=lambda *x: None)
        self.assertEqual((a2.chain.height, a2.chain.tip["hash"], a2.chain.bal), (4, tip, bal))
        with open(os.path.join(self.tmp.name, "a", "chain.jsonl"), "a") as f:
            f.write('{"broken": true}\n')
        a3 = N.Node(copy.deepcopy(self.genesis), os.path.join(self.tmp.name, "a"), log=lambda *x: None)
        self.assertEqual(a3.chain.height, 4, "испорченный хвост отброшен, цепочка цела")
        with open(os.path.join(self.tmp.name, "a", "chain.jsonl")) as f:
            self.assertEqual(len(f.read().splitlines()), 4, "файл переписан без мусора")


class Tools(NetBase):
    """Консольные программы: майнер, кошелёк, генератор первого блока."""

    def sh(self, *args, timeout=120):
        return subprocess.run([sys.executable] + list(args), cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                              env=dict(os.environ, INX_WALLET_PASSWORD="test-password-123"))

    def test_fast_miner_cli_mines_blocks(self):
        import shutil
        if not shutil.which("cc"):
            self.skipTest("нет компилятора C")
        a = self.start("a")
        r = self.sh("miner_fast.py", "--node", url(a), "--address", ALICE, "--threads", "2", "--blocks", "3", timeout=170)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(a.chain.height, 3)
        self.assertEqual(a.chain.bal[ALICE], 3 * 45 * INX // 10)

    def test_miner_cli_mines_blocks_to_given_address(self):
        a = self.start("a")
        r = self.sh("miner.py", "--node", url(a), "--address", ALICE, "--workers", "2", "--blocks", "3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(a.chain.height, 3)
        self.assertEqual(a.chain.bal[ALICE], 3 * 45 * INX // 10)
        self.assertNotEqual(self.sh("miner.py", "--address", "INXbad").returncode, 0, "неверный адрес отвергается")

    def test_wallet_cli_full_cycle(self):
        a = self.start("a")
        w1, w2 = os.path.join(self.tmp.name, "w1.json"), os.path.join(self.tmp.name, "w2.json")
        r = self.sh("wallet.py", "new", "--file", w1)
        self.assertEqual(r.returncode, 0, r.stderr)
        address = next(l.split(": ")[1] for l in r.stdout.splitlines() if l.startswith("Ваш адрес"))
        code = next(l.strip() for l in r.stdout.splitlines() if l.startswith("  ") and "-" in l)
        self.assertTrue(C.is_valid_address(address))
        self.assertEqual(oct(os.stat(w1).st_mode & 0o777), "0o600", "файл кошелька закрыт для других пользователей")
        self.assertNotEqual(self.sh("wallet.py", "new", "--file", w1).returncode, 0, "существующий кошелёк не перезаписывается")

        r = self.sh("wallet.py", "restore", "--code", code, "--file", w2)         # восстановление по коду
        self.assertIn(address, r.stdout)
        bad = code[:-1] + ("A" if code[-1] != "A" else "B")
        self.assertNotEqual(self.sh("wallet.py", "restore", "--code", bad, "--file", w2 + "x").returncode, 0,
                            "опечатка в коде восстановления ловится контрольной суммой")

        mine_on(a, address, 2)                                                       # у кошелька 9 INX
        r = self.sh("wallet.py", "balance", "--node", url(a), "--file", w1)
        self.assertIn("9.00000000", r.stdout)
        r = self.sh("wallet.py", "send", "--to", BOB, "--amount", "1.25", "--node", url(a), "--file", w1, "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        mine_on(a, MINER, 1)
        self.assertEqual(a.chain.bal[BOB], int(1.25 * INX))
        self.assertEqual(a.chain.bal[address], 9 * INX - int(1.25 * INX) - 10_000)
        r = self.sh("wallet.py", "send", "--to", BOB[:-1] + "x", "--amount", "1", "--node", url(a), "--file", w1, "--yes")
        self.assertNotEqual(r.returncode, 0, "адрес с неверной контрольной суммой отвергается до отправки")
        r = self.sh("wallet.py", "send", "--to", BOB, "--amount", "0.123456789", "--node", url(a), "--file", w1, "--yes")
        self.assertNotEqual(r.returncode, 0, "сумма с лишними знаками отвергается")

    def test_genesis_cli(self):
        out = os.path.join(self.tmp.name, "g.json")
        r = self.sh("genesis.py", "create", "--founder", FOUNDER, "--message", "hello", "--bits", "8", "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("chain_id", r.stdout)
        self.assertEqual(self.sh("genesis.py", "verify", out).returncode, 0)
        self.assertNotEqual(self.sh("genesis.py", "create", "--founder", FOUNDER, "--out", out).returncode, 0,
                            "готовый генезис не перезаписывается")
        with open(out) as f:
            g = json.load(f)
        g["block"]["txs"][0]["amount"] += 1
        with open(out, "w") as f:
            json.dump(g, f)
        self.assertNotEqual(self.sh("genesis.py", "verify", out).returncode, 0, "изменённый генезис не проходит проверку")
        self.assertNotEqual(self.sh("genesis.py", "create", "--founder", "INXbad", "--out", out + "2").returncode, 0)

    def test_node_cli_starts_and_serves(self):
        gpath = os.path.join(self.tmp.name, "genesis.json")
        with open(gpath, "w") as f:
            json.dump(self.genesis, f)
        p = subprocess.Popen([sys.executable, "node.py", "--genesis", gpath, "--datadir",
                              os.path.join(self.tmp.name, "cli"), "--port", "39333"], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            def up():
                try:
                    return json.loads(urllib.request.urlopen("http://127.0.0.1:39333/api/status", timeout=1).read())
                except Exception:
                    return None
            self.assertTrue(wait(lambda: up() is not None, 15), "узел из командной строки поднялся")
            self.assertEqual(up()["chain_id"], self.genesis["block"]["hash"])
        finally:
            p.terminate()
            p.wait(timeout=10)
        r = self.sh("node.py", "--genesis", os.path.join(self.tmp.name, "missing.json"))
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
