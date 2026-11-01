import copy
import hashlib
import time
import unittest

from testutil import (ALICE_PRIV, BOB_PRIV, FOUNDER_PRIV, MINER_PRIV, C, addr, build_block, extend,
                      fresh_chain, make_genesis, solve, transfer)

ALICE, BOB, MINER, FOUNDER = addr(ALICE_PRIV), addr(BOB_PRIV), addr(MINER_PRIV), addr(FOUNDER_PRIV)
INX = C.UNIT


class Crypto(unittest.TestCase):
    def test_known_vector(self):
        sig = C.sign(1, hashlib.sha256(b"Satoshi Nakamoto").digest())
        self.assertEqual(sig, "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
                              "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5")

    def test_sign_verify_and_failures(self):
        d = hashlib.sha256(b"msg").digest()
        pub = C.pubkey_from_priv(777)
        sig = C.sign(777, d)
        self.assertTrue(C.verify(pub, d, sig))
        self.assertFalse(C.verify(pub, hashlib.sha256(b"other").digest(), sig))
        self.assertFalse(C.verify(C.pubkey_from_priv(778), d, sig))
        r, s = int(sig[:64], 16), int(sig[64:], 16)
        self.assertFalse(C.verify(pub, d, "%064x%064x" % (r, C.N - s)), "высокий s (зеркальная подпись) отвергается")
        self.assertFalse(C.verify(pub, d, sig.upper()), "hex только в нижнем регистре")
        self.assertFalse(C.verify(pub, d, sig[:-2]))
        self.assertFalse(C.verify(b"\x04" + b"\x00" * 32, d, sig))

    def test_deterministic(self):
        d = b"\x05" * 32
        self.assertEqual(C.sign(5, d), C.sign(5, d))

    def test_addresses(self):
        a = addr(5)
        self.assertTrue(C.is_valid_address(a) and a.startswith("INX"))
        for bad in (a[:-1], a[:-1] + ("2" if a[-1] != "2" else "3"), "INX", "BTC" + a[3:], "", None, 5):
            self.assertFalse(C.is_valid_address(bad))
        self.assertTrue(C.is_valid_address(C.address_from_pub(b"\x02" + b"\x00" * 32)))

    def test_amounts(self):
        self.assertEqual(C.parse_amount("1.5"), 150_000_000)
        self.assertEqual(C.parse_amount("0.00000001"), 1)
        self.assertEqual(C.parse_amount(" 21000000 "), 21_000_000 * INX)
        for bad in ("0", "-1", "1.123456789", "abc", "nan", "inf", "", "1e-9"):
            with self.assertRaises(ValueError):
                C.parse_amount(bad)
        self.assertEqual(C.format_amount(150_000_000), "1.50000000")
        self.assertEqual(C.format_amount(1), "0.00000001")


class Emission(unittest.TestCase):
    def test_parameters(self):
        self.assertEqual(C.MAX_SUPPLY, 2_100_000_000_000_000)
        self.assertEqual(C.FOUNDER_ALLOC, 210_000_000_000_000)
        self.assertEqual(C.FOUNDER_ALLOC * 10, C.MAX_SUPPLY, "основателю ровно 10%")
        self.assertEqual(C.INITIAL_REWARD, 45 * INX // 10)

    def test_halving(self):
        self.assertEqual(C.block_reward(0), 0)
        self.assertEqual(C.block_reward(1), 45 * INX // 10)
        self.assertEqual(C.block_reward(2_100_000), 45 * INX // 10)
        self.assertEqual(C.block_reward(2_100_001), 2 * INX + 25_000_000)
        self.assertEqual(C.block_reward(4_200_001), INX + 12_500_000)
        self.assertEqual(C.block_reward(10 ** 9), 0)

    def test_total_never_exceeds_limit(self):
        mined = C.mined_supply_through(10 ** 9)
        self.assertLessEqual(mined, C.MINER_SUPPLY)
        self.assertGreater(mined, C.MINER_SUPPLY - INX, "недобор из-за округления меньше 1 INX")
        self.assertLessEqual(mined + C.FOUNDER_ALLOC, C.MAX_SUPPLY)
        # и построчно, без формулы
        brute, h = 0, 0
        for e in range(0, 70):
            brute += (C.INITIAL_REWARD >> e) * C.HALVING_INTERVAL
        self.assertEqual(brute, mined)


class Genesis(unittest.TestCase):
    def test_valid(self):
        g = make_genesis()
        p = C.Params(g)
        self.assertEqual(p.chain_id, g["block"]["hash"])
        self.assertEqual(p.founder, FOUNDER)

    def test_tampering_rejected(self):
        g = make_genesis()
        for mutate in (lambda x: x["block"]["txs"][0].update(amount=C.FOUNDER_ALLOC + 1),
                       lambda x: x["block"]["txs"][0].update(vesting_seconds=1),
                       lambda x: x["block"]["txs"][0].update(to=BOB),
                       lambda x: x["block"].update(time=x["block"]["time"] + 1),
                       lambda x: x["block"].update(nonce=x["block"]["nonce"] + 1),
                       lambda x: x.update(ticker="XXX"),
                       lambda x: x["block"]["txs"].append({}),
                       lambda x: x["block"].update(prev="11" * 32)):
            h = copy.deepcopy(g)
            mutate(h)
            with self.assertRaises(C.ConsensusError):
                C.Params(h)

    def test_founder_balance_and_lock(self):
        ch = fresh_chain()
        self.assertEqual(ch.bal[FOUNDER], C.FOUNDER_ALLOC)
        p, gt, v = ch.params, ch.params.genesis_time, ch.params.vest_seconds
        self.assertEqual(p.locked(FOUNDER, gt), C.FOUNDER_ALLOC)
        self.assertEqual(p.locked(FOUNDER, gt + v // 2), C.FOUNDER_ALLOC // 2)
        self.assertEqual(p.locked(FOUNDER, gt + v), 0)
        self.assertEqual(p.locked(FOUNDER, gt + 10 * v), 0)
        self.assertEqual(p.locked(ALICE, gt), 0)


class Blocks(unittest.TestCase):
    def setUp(self):
        self.ch = fresh_chain()

    def test_mining_pays_reward(self):
        extend(self.ch, MINER, 3)
        self.assertEqual(self.ch.height, 3)
        self.assertEqual(self.ch.bal[MINER], 3 * 45 * INX // 10)
        self.assertEqual(sum(self.ch.bal.values()), C.FOUNDER_ALLOC + C.mined_supply_through(3))

    def rejects(self, block, text=None):
        before = (self.ch.height, dict(self.ch.bal), dict(self.ch.nonce))
        with self.assertRaises(C.ConsensusError) as cm:
            self.ch.add_block(block)
        if text:
            self.assertIn(text, str(cm.exception))
        self.assertEqual(before, (self.ch.height, dict(self.ch.bal), dict(self.ch.nonce)), "состояние не должно меняться")

    def test_reward_too_big(self):
        self.rejects(build_block(self.ch, MINER, cb_extra=1), "награда")

    def test_wrong_links(self):
        self.rejects(build_block(self.ch, MINER, prev="22" * 32), "не продолжает")
        self.rejects(build_block(self.ch, MINER, height=5, target=self.ch.expected_target(1)), "высота")

    def test_pow_and_target(self):
        t = self.ch.expected_target(1)
        self.rejects(build_block(self.ch, MINER, avoid=True), "proof-of-work")
        self.rejects(build_block(self.ch, MINER, target=t * 2), "сложност")

    def test_merkle(self):
        self.rejects(build_block(self.ch, MINER, merkle="33" * 32), "Merkle")

    def test_tampered_content_after_mining(self):
        b = build_block(self.ch, MINER)
        b["txs"][0]["to"] = BOB
        self.rejects(b)

    def test_time_rules(self):
        extend(self.ch, MINER, 12)
        mtp = self.ch.mtp(13)
        self.rejects(build_block(self.ch, MINER, t=mtp), "медиан")
        self.rejects(build_block(self.ch, MINER, t=int(time.time()) + C.MAX_FUTURE_DRIFT + 100), "будущем")

    def test_schema(self):
        b = build_block(self.ch, MINER)
        b["extra"] = 1
        self.rejects(b, "структура")
        b = build_block(self.ch, MINER)
        b["txs"][0]["amount"] = float(b["txs"][0]["amount"])
        self.rejects(b)
        b = build_block(self.ch, MINER)
        b["txs"] = []
        self.rejects(b)

    def test_second_coinbase_rejected(self):
        cb1 = {"type": "coinbase", "to": MINER, "amount": C.block_reward(1), "height": 1}
        cb2 = {"type": "coinbase", "to": MINER, "amount": 1, "height": 1}
        txs = [cb1, cb2]
        merkle = C.merkle_root([C.txid(x) for x in txs])
        b = solve(1, self.ch.tip["hash"], merkle, self.ch.tip["time"] + 60, self.ch.expected_target(1), txs)
        self.rejects(b)


class Transfers(unittest.TestCase):
    def setUp(self):
        self.ch = fresh_chain()
        extend(self.ch, ALICE, 3)           # у Alice 135 INX

    def block_with(self, *txs, miner=MINER):
        return build_block(self.ch, miner, list(txs))

    def test_transfer_moves_money_and_fee(self):
        tx = transfer(self.ch, ALICE_PRIV, BOB, 1 * INX, fee=20_000)
        self.ch.add_block(self.block_with(tx))
        self.assertEqual(self.ch.bal[BOB], 1 * INX)
        self.assertEqual(self.ch.bal[ALICE], 135 * INX // 10 - 1 * INX - 20_000)
        self.assertEqual(self.ch.bal[MINER], 45 * INX // 10 + 20_000, "комиссию получает майнер")
        self.assertEqual(self.ch.nonce[ALICE], 1)
        self.assertEqual(sum(self.ch.bal.values()), C.FOUNDER_ALLOC + C.mined_supply_through(self.ch.height))

    def rejects(self, tx, text):
        before = (dict(self.ch.bal), dict(self.ch.nonce), self.ch.height)
        with self.assertRaises(C.ConsensusError) as cm:
            self.ch.add_block(self.block_with(tx))
        self.assertIn(text, str(cm.exception))
        self.assertEqual(before, (dict(self.ch.bal), dict(self.ch.nonce), self.ch.height))

    def test_bad_signature(self):
        tx = transfer(self.ch, ALICE_PRIV, BOB, 10 * INX)
        tx["amount"] += 1
        self.rejects(tx, "подпись")

    def test_someone_elses_key(self):
        tx = transfer(self.ch, BOB_PRIV, MINER, 1 * INX)         # у Bob ничего нет
        self.rejects(tx, "недостаточно")
        tx = transfer(self.ch, ALICE_PRIV, MINER, 1 * INX)
        tx["from_pub"] = C.pubkey_from_priv(BOB_PRIV).hex()      # подмена отправителя
        self.rejects(tx, "подпись")

    def test_replay_on_other_network_rejected(self):
        tx = transfer(self.ch, ALICE_PRIV, BOB, 1 * INX, chain_id="ab" * 32)
        self.rejects(tx, "подпись")

    def test_nonce_rules(self):
        self.rejects(transfer(self.ch, ALICE_PRIV, BOB, 1 * INX, nonce=1), "nonce")
        tx = transfer(self.ch, ALICE_PRIV, BOB, 1 * INX)
        self.ch.add_block(self.block_with(tx))
        self.rejects(tx, "nonce")                                # повтор той же подписи в новом блоке

    def test_double_spend_in_one_block(self):
        a = transfer(self.ch, ALICE_PRIV, BOB, 100 * INX, nonce=0)
        b = transfer(self.ch, ALICE_PRIV, MINER, 100 * INX, nonce=1)
        self.rejects_two = None
        with self.assertRaises(C.ConsensusError):
            self.ch.add_block(self.block_with(a, b))
        self.assertEqual(self.ch.bal.get(BOB, 0), 0)

    def test_overspend_and_fee_rules(self):
        self.rejects(transfer(self.ch, ALICE_PRIV, BOB, 135 * INX), "недостаточно")        # без места под комиссию
        self.rejects(transfer(self.ch, ALICE_PRIV, BOB, INX, fee=C.MIN_FEE - 1), "комисси")
        self.rejects(transfer(self.ch, ALICE_PRIV, ALICE, INX), "самому себе")
        self.rejects(transfer(self.ch, ALICE_PRIV, "INXnotanaddress", INX), "адрес")

    def test_duplicate_tx_in_block(self):
        tx = transfer(self.ch, ALICE_PRIV, BOB, INX)
        with self.assertRaises(C.ConsensusError):
            self.ch.add_block(self.block_with(tx, tx))

    def test_sequential_transfers_same_block(self):
        a = transfer(self.ch, ALICE_PRIV, BOB, 5 * INX, nonce=0)
        b = transfer(self.ch, ALICE_PRIV, BOB, 5 * INX, nonce=1)
        self.ch.add_block(self.block_with(a, b))
        self.assertEqual(self.ch.bal[BOB], 10 * INX)

    def test_int_only_amounts(self):
        tx = transfer(self.ch, ALICE_PRIV, BOB, INX)
        tx["amount"] = float(tx["amount"])
        self.rejects(tx, "сумма")


class Vesting(unittest.TestCase):
    """Доля основателя заморожена: потратить можно только уже размороженную часть."""

    def setUp(self):
        self.ch = fresh_chain(make_genesis(age_days=20))
        self.now = int(time.time())

    def spendable(self, t):
        return C.FOUNDER_ALLOC - self.ch.params.locked(FOUNDER, t)

    def test_cannot_spend_locked_part(self):
        free = self.spendable(self.now)
        self.assertTrue(0 < free < C.FOUNDER_ALLOC // 10, "за 20 дней из 730 разморожено около 2.7%")
        too_much = transfer(self.ch, FOUNDER_PRIV, BOB, free + 100 * INX)
        with self.assertRaises(C.ConsensusError) as cm:
            self.ch.add_block(build_block(self.ch, MINER, [too_much], t=self.now))
        self.assertIn("заморожена", str(cm.exception))

    def test_can_spend_unlocked_part(self):
        free = self.spendable(self.now) - 10 * INX
        ok = transfer(self.ch, FOUNDER_PRIV, BOB, free)
        self.ch.add_block(build_block(self.ch, MINER, [ok], t=self.now))
        self.assertEqual(self.ch.bal[BOB], free)

    def test_cannot_dodge_lock_by_old_block_time(self):
        """Майнер не может поставить в блок более раннее время, чтобы «обмануть» заморозку: время ограничено медианой."""
        free = self.spendable(self.now)
        tx = transfer(self.ch, FOUNDER_PRIV, BOB, free + 50_000 * INX)
        with self.assertRaises(C.ConsensusError):
            self.ch.add_block(build_block(self.ch, MINER, [tx], t=self.ch.tip["time"] + 1))

    def test_unlock_over_time(self):
        gt, v = self.ch.params.genesis_time, self.ch.params.vest_seconds
        later = self.ch.params.locked(FOUNDER, gt + v // 2)
        self.assertEqual(later, C.FOUNDER_ALLOC // 2)

    def test_incoming_coins_to_founder_are_not_locked_beyond_alloc(self):
        extend(self.ch, ALICE, 2)
        tx = transfer(self.ch, ALICE_PRIV, FOUNDER, 1 * INX)
        self.ch.add_block(build_block(self.ch, MINER, [tx], t=self.now))
        self.assertEqual(self.ch.bal[FOUNDER], C.FOUNDER_ALLOC + 1 * INX)
        # нижняя граница баланса по-прежнему locked(now): 1 INX сверху можно потратить, если они сверх замороженной части
        free = self.ch.bal[FOUNDER] - self.ch.params.locked(FOUNDER, self.now)
        self.assertGreaterEqual(free, 1 * INX)


class Retarget(unittest.TestCase):
    def run_window(self, ch, spacing):
        """Майним ровно до высоты, где пересчитывается сложность, с заданным интервалом между блоками."""
        while (ch.height + 1) % C.RETARGET_INTERVAL != 0:
            extend(ch, MINER, 1, spacing=spacing)

    def test_target_changes_and_is_enforced(self):
        ch = fresh_chain()
        pow_limit = ch.params.pow_limit
        t0 = int(ch.tip["target"], 16)
        self.run_window(ch, 15)                                  # блоки в 4 раза быстрее нормы
        expect = max(1, min(pow_limit, t0 * (C.RETARGET_INTERVAL * C.BLOCK_TIME // 4) // (C.RETARGET_INTERVAL * C.BLOCK_TIME)))
        self.assertEqual(ch.expected_target(ch.height + 1), expect)
        self.assertEqual(expect, t0 // 4, "быстрые блоки: сложность вырастает в 4 раза (предел)")
        bad = build_block(ch, MINER, target=t0)                  # старая лёгкая цель недопустима
        with self.assertRaises(C.ConsensusError):
            ch.add_block(bad)
        extend(ch, MINER, 1)                                     # блок с новой целью принимается
        self.assertEqual(int(ch.tip["target"], 16), t0 // 4)

    def test_slow_blocks_ease_but_never_beyond_limit(self):
        ch = fresh_chain()
        t0 = int(ch.tip["target"], 16)
        self.run_window(ch, 15)
        extend(ch, MINER, 1)
        self.run_window(ch, 600)                                 # теперь в 10 раз медленнее нормы
        self.assertEqual(ch.expected_target(ch.height + 1), min(ch.params.pow_limit, (t0 // 4) * 4))
        extend(ch, MINER, 1)
        self.run_window(ch, 600)
        self.assertEqual(ch.expected_target(ch.height + 1), ch.params.pow_limit, "легче начальной сложности быть не может")

    def test_on_target_speed_stays_almost_same(self):
        ch = fresh_chain()
        t0 = int(ch.tip["target"], 16)
        self.run_window(ch, C.BLOCK_TIME)
        new = ch.expected_target(ch.height + 1)
        self.assertTrue(t0 * 0.98 < new <= t0)


class ReorgAndRollback(unittest.TestCase):
    def setUp(self):
        g = make_genesis()
        self.a, self.b = fresh_chain(g), fresh_chain(g)
        extend(self.a, ALICE, 3)
        extend(self.b, ALICE, 3)                                  # общая часть: 3 блока

    def snapshot(self, ch):
        return (ch.height, ch.tip["hash"], dict(ch.bal), dict(ch.nonce), dict(ch.txindex),
                {k: list(v) for k, v in ch.addr_txs.items()}, dict(ch.hindex), list(ch.work))

    def test_rollback_restores_everything(self):
        base = self.snapshot(self.a)
        tx = transfer(self.a, ALICE_PRIV, BOB, 5 * INX)
        self.a.add_block(build_block(self.a, MINER, [tx]))
        extend(self.a, MINER, 2)
        self.assertNotEqual(base, self.snapshot(self.a))
        self.a.rollback_to(3)
        self.assertEqual(base, self.snapshot(self.a))
        self.a.rollback_to(0)
        self.assertEqual(self.a.bal, {FOUNDER: C.FOUNDER_ALLOC})
        self.assertEqual(self.a.nonce, {})
        self.assertEqual(len(self.a.txindex), 1)

    def test_reorg_to_heavier_branch(self):
        tx = transfer(self.a, ALICE_PRIV, BOB, 5 * INX)
        self.a.add_block(build_block(self.a, MINER, [tx]))        # ветка A: 4 блока, с переводом
        extend(self.b, BOB, 3)                                    # ветка B: 6 блоков, без перевода
        tail = [copy.deepcopy(x) for x in self.b.blocks[4:]]
        old = self.a.reorg(3, [copy.deepcopy(x) for x in self.b.blocks[4:]])
        self.assertEqual(len(old), 1)
        self.assertEqual(self.snapshot(self.a), self.snapshot(self.b))
        self.assertEqual(self.a.bal.get(BOB, 0), 3 * 45 * INX // 10, "перевод из старой ветки отменён")

    def test_lighter_or_equal_branch_rejected_and_state_kept(self):
        extend(self.a, MINER, 2)
        extend(self.b, BOB, 2)                                    # столько же работы
        before = self.snapshot(self.a)
        with self.assertRaises(C.ConsensusError):
            self.a.reorg(3, [copy.deepcopy(x) for x in self.b.blocks[4:]])
        self.assertEqual(before, self.snapshot(self.a))

    def test_invalid_block_inside_heavier_branch_leaves_chain_unchanged(self):
        extend(self.b, BOB, 4)
        blocks = [copy.deepcopy(x) for x in self.b.blocks[4:]]
        blocks[2]["txs"][0]["amount"] += 1                        # испорчен третий блок ветки
        before = self.snapshot(self.a)
        with self.assertRaises(C.ConsensusError):
            self.a.reorg(3, blocks)
        self.assertEqual(before, self.snapshot(self.a))
        self.a.add_block(build_block(self.a, MINER))              # цепочка осталась рабочей
        self.assertEqual(self.a.height, 4)


class Determinism(unittest.TestCase):
    def test_two_chains_same_blocks_same_state(self):
        g = make_genesis()
        a, b = fresh_chain(g), fresh_chain(g)
        extend(a, ALICE, 4)
        tx = transfer(a, ALICE_PRIV, BOB, 7 * INX)
        a.add_block(build_block(a, MINER, [tx]))
        for blk in a.blocks[1:]:
            b.add_block(copy.deepcopy(blk), check_future=False)
        self.assertEqual((a.bal, a.nonce, a.tip["hash"], a.work), (b.bal, b.nonce, b.tip["hash"], b.work))


if __name__ == "__main__":
    unittest.main(verbosity=2)
