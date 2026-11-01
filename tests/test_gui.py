"""Проверяет логику окна без настоящего tkinter (его нет на сервере тестов): виджеты заменены заглушками.
Сам вид окна эти тесты не проверяют: его нужно один раз открыть глазами."""
import os
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

from testutil import C  # noqa: F401


class Var:
    def __init__(self, value=""):
        self.v = value

    def get(self):
        return self.v

    def set(self, x):
        self.v = x


def fake_tk():
    tk = mock.MagicMock(name="tkinter")
    tk.StringVar = Var
    ttk, mb, fd = mock.MagicMock(name="ttk"), mock.MagicMock(name="messagebox"), mock.MagicMock(name="filedialog")
    mb.askyesno.return_value = True
    tk.ttk, tk.messagebox, tk.filedialog = ttk, mb, fd
    return tk, ttk, mb, fd


class GuiLogic(unittest.TestCase):
    def setUp(self):
        self.tk, self.ttk, self.mb, self.fd = fake_tk()
        self.patch = mock.patch.dict(sys.modules, {"tkinter": self.tk, "tkinter.ttk": self.ttk,
                                                    "tkinter.messagebox": self.mb, "tkinter.filedialog": self.fd})
        self.patch.start()
        sys.modules.pop("inx_gui", None)
        import inx_app as A
        self.A = A
        self.tmp = tempfile.TemporaryDirectory()
        A.HOME_DIR = os.path.join(self.tmp.name, ".inexion")
        A.SETTINGS = os.path.join(A.HOME_DIR, "app.json")
        import inx_gui
        self.G = inx_gui
        self.state = A.State("http://127.0.0.1:1")
        self.gui = inx_gui.GUI(mock.MagicMock(), self.state)

    def tearDown(self):
        self.state.lock_wallet()
        self.patch.stop()
        sys.modules.pop("inx_gui", None)
        self.tmp.cleanup()

    def pump(self, n=1, timeout=10):
        """Ждёт n фоновых задач и разбирает все, что успело прийти следом (например, обновление баланса)."""
        end, got, quiet = time.time() + timeout, 0, None
        while time.time() < end:
            if not self.gui.q.empty():
                self.gui._pump()
                got, quiet = got + 1, time.time() + 0.4
            else:
                if got >= n and time.time() > quiet:
                    return
                time.sleep(0.05)
        self.assertGreaterEqual(got, n, "фоновая задача не завершилась")

    def test_formats(self):
        self.assertEqual(self.G.fmt(0), "0")
        self.assertEqual(self.G.fmt(450000000), "4.5")
        self.assertEqual(self.G.fmt(100000000), "1")
        self.assertEqual(self.G.fmt(1), "0.00000001")
        self.assertEqual(self.G.fmt(1000 * 10 ** 8), "1000")

    def test_wallet_flow(self):
        g, v = self.gui, self.gui.v
        self.assertEqual(g.current, "login")
        v["cpass"].set("short")
        v["cpass2"].set("short")
        g.do_create()
        self.pump()
        self.assertIn("короткий", v["cmsg"].get())
        v["cpass"].set("long-enough-pass")
        v["cpass2"].set("long-enough-pass")
        g.do_create()
        self.pump()
        self.assertEqual(g.current, "rec")
        code = v["reccode"].get()
        self.assertTrue(len(code) > 50)
        g.rec_done()
        self.pump()                                     # обновление баланса: узла нет, окно не падает
        self.assertEqual(g.current, "main")
        self.assertEqual(v["bal"].get(), "нет связи")
        addr = self.state.address
        self.assertEqual(v["addr"].get(), addr)
        g.do_lock()
        self.assertEqual(g.current, "login")
        self.assertFalse(self.state.unlocked())
        path = self.state.last_file
        v["lpath"].set(path)
        v["lpass"].set("wrong-password-1")
        g.do_unlock()
        self.pump()
        self.assertIn("пароль", v["lmsg"].get())
        self.assertFalse(self.state.unlocked())
        v["lpass"].set("long-enough-pass")
        g.do_unlock()
        self.pump()
        self.assertEqual(g.current, "main")
        self.assertEqual(self.state.address, addr)
        # показать код восстановления
        v["xpass"].set("nope-nope-nope")
        g.do_recovery()
        self.pump()
        self.assertIn("пароль", v["xmsg"].get())
        v["xpass"].set("long-enough-pass")
        g.do_recovery()
        self.pump()
        self.tk.Toplevel.assert_called()                # окно с кодом открылось

    def test_send_validation_and_mining_buttons(self):
        g, v = self.gui, self.gui.v
        v["cpass"].set("long-enough-pass")
        v["cpass2"].set("long-enough-pass")
        g.do_create()
        self.pump()
        g.rec_done()
        self.pump()
        v["sto"].set("INXbad")
        v["samt"].set("1")
        g.do_send()
        self.pump()
        self.assertIn("неверный", v["smsg"].get())
        self.mb.askyesno.return_value = False           # пользователь отказался
        v["smsg"].set("")
        g.do_send()
        self.assertEqual(v["smsg"].get(), "")
        v["mthr"].set("1")
        g.do_mine()                                     # запуск: узла нет, майнер должен жить и останавливаться
        self.assertTrue(self.state.miner.running())
        g.update_mining()
        self.assertEqual(v["mst"].get(), "идёт")
        g.do_mine()
        for _ in range(60):
            if not self.state.miner.running():
                break
            time.sleep(0.2)
        self.assertFalse(self.state.miner.running())
        g.update_mining()
        self.assertEqual(v["mst"].get(), "остановлен")

    def test_node_setting_and_idle_lock(self):
        g, v = self.gui, self.gui.v
        v["nurl"].set("ftp://bad")
        g.do_node()
        self.assertIn("http", v["nmsg"].get())
        v["cpass"].set("long-enough-pass")
        v["cpass2"].set("long-enough-pass")
        g.do_create()
        self.pump()
        g.rec_done()
        self.pump()
        self.state.touched -= 16 * 60
        g._tick()
        self.assertEqual(g.current, "login")            # автоблокировка


if __name__ == "__main__":
    unittest.main()
