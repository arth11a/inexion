"""
inx_gui.py: окно приложения INEXION (tkinter, входит в Python для Mac и Windows).
Запускается из inx_app.py. Вся логика (кошелёк, переводы, майнинг) общая с версией в браузере: inx_app.api().
Сетевые вызовы идут в отдельных потоках, чтобы окно не зависало.
"""
import os
import queue
import threading
import tkinter as tk
import urllib.error
from tkinter import filedialog, messagebox, ttk

import inx_app as A

PAD = 10


def fmt(n):
    """Целое число 1e-8 INX в текст без лишних нулей."""
    s = ("%.8f" % (n / 1e8)).rstrip("0").rstrip(".")
    return s or "0"


def errtext(e):
    if isinstance(e, ValueError):
        return str(e)
    if isinstance(e, (urllib.error.URLError, OSError)):
        return "Нет связи с узлом (%s)" % getattr(e, "reason", e)
    return "Ошибка приложения"


class GUI:
    def __init__(self, root, state):
        self.root, self.st = root, state
        self.q = queue.Queue()
        self.counter = 0
        root.title("INEXION")
        root.geometry("820x700")
        root.minsize(680, 560)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.v = {k: tk.StringVar() for k in (
            "lpath", "lpass", "cpass", "cpass2", "rcode", "rpass", "bal", "spend", "locked", "height", "addr",
            "sto", "samt", "sfee", "smsg", "mst", "mrate", "mblocks", "meng", "mthr", "nurl", "xpass", "wfile",
            "lmsg", "cmsg", "rmsg", "nmsg", "xmsg", "reccode")}
        self.v["sfee"].set("0.0001")
        self.v["bal"].set("…")
        self.frames = {}
        self._build_login()
        self._build_rec()
        self._build_main()
        self.show("login")
        self.refresh_login()
        root.after(100, self._pump)
        root.after(2000, self._tick)

    # ---------------------------------------------------------------- потоки
    def bg(self, fn, done):
        def work():
            try:
                r, e = fn(), None
            except Exception as ex:                      # noqa: BLE001  (в окно уходит понятный текст)
                r, e = None, ex
            self.q.put((done, r, e))
        threading.Thread(target=work, daemon=True).start()

    def _pump(self):
        while True:
            try:
                done, r, e = self.q.get_nowait()
            except queue.Empty:
                break
            done(r, e)
        self.root.after(100, self._pump)

    # ---------------------------------------------------------------- экраны
    def show(self, name):
        for k, f in self.frames.items():
            f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)
        self.current = name

    def _frame(self, name):
        f = ttk.Frame(self.root, padding=PAD)
        self.frames[name] = f
        return f

    def _row(self, parent, label, var, show=None, width=48):
        ttk.Label(parent, text=label).pack(anchor="w", pady=(PAD, 2))
        e = ttk.Entry(parent, textvariable=var, width=width, show=show) if show else ttk.Entry(parent, textvariable=var, width=width)
        e.pack(anchor="w", fill="x")
        return e

    def _build_login(self):
        f = self._frame("login")
        ttk.Label(f, text="INEXION", font=("Helvetica", 26, "bold")).pack(anchor="w")
        ttk.Label(f, text="Тестовая сеть: монеты ничего не стоят. Экспериментальное ПО без аудита.", foreground="#8a5a00").pack(anchor="w", pady=(2, PAD))
        nb = ttk.Notebook(f)
        nb.pack(fill="both", expand=True)
        # открыть
        a = ttk.Frame(nb, padding=PAD)
        nb.add(a, text="Открыть кошелёк")
        ttk.Label(a, text="Файл кошелька").pack(anchor="w")
        row = ttk.Frame(a)
        row.pack(fill="x")
        self.lbox = ttk.Combobox(row, textvariable=self.v["lpath"], width=56)
        self.lbox.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Обзор…", command=self.browse).pack(side="left", padx=(6, 0))
        e = self._row(a, "Пароль", self.v["lpass"], show="•")
        e.bind("<Return>", lambda ev: self.do_unlock())
        ttk.Button(a, text="Открыть", command=self.do_unlock).pack(anchor="w", pady=PAD)
        ttk.Label(a, textvariable=self.v["lmsg"], foreground="#b3261e", wraplength=640).pack(anchor="w")
        # создать
        c = ttk.Frame(nb, padding=PAD)
        nb.add(c, text="Новый кошелёк")
        ttk.Label(c, text="Придумайте пароль (не короче 10 символов). Потом вы получите код восстановления: запишите его на бумагу.", wraplength=640).pack(anchor="w")
        self._row(c, "Пароль", self.v["cpass"], show="•")
        self._row(c, "Повторите пароль", self.v["cpass2"], show="•")
        ttk.Button(c, text="Создать кошелёк", command=self.do_create).pack(anchor="w", pady=PAD)
        ttk.Label(c, textvariable=self.v["cmsg"], foreground="#b3261e", wraplength=640).pack(anchor="w")
        # восстановить
        r = ttk.Frame(nb, padding=PAD)
        nb.add(r, text="Восстановить по коду")
        self._row(r, "Код восстановления", self.v["rcode"])
        self._row(r, "Новый пароль", self.v["rpass"], show="•")
        ttk.Button(r, text="Восстановить", command=self.do_restore).pack(anchor="w", pady=PAD)
        ttk.Label(r, textvariable=self.v["rmsg"], foreground="#b3261e", wraplength=640).pack(anchor="w")

    def _build_rec(self):
        f = self._frame("rec")
        ttk.Label(f, text="Код восстановления", font=("Helvetica", 20, "bold")).pack(anchor="w")
        ttk.Label(f, wraplength=700, text="Запишите этот код на бумагу и храните отдельно от компьютера. Без файла кошелька или этого кода монеты не вернуть, а с ним их может забрать любой.").pack(anchor="w", pady=PAD)
        e = ttk.Entry(f, textvariable=self.v["reccode"], width=80, state="readonly", font=("Menlo", 13))
        e.pack(anchor="w", fill="x", pady=PAD)
        row = ttk.Frame(f)
        row.pack(anchor="w")
        ttk.Button(row, text="Скопировать", command=lambda: self.copy(self.v["reccode"].get())).pack(side="left")
        ttk.Button(row, text="Я записал код", command=self.rec_done).pack(side="left", padx=PAD)

    def _stat(self, parent, title, var, col):
        b = ttk.Frame(parent, padding=PAD, relief="groove")
        b.grid(row=0, column=col, padx=(0, PAD), sticky="nsew")
        ttk.Label(b, text=title, foreground="#566678").pack(anchor="w")
        ttk.Label(b, textvariable=var, font=("Helvetica", 14, "bold")).pack(anchor="w")

    def _build_main(self):
        f = self._frame("main")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="INEXION", font=("Helvetica", 18, "bold")).pack(side="left")
        ttk.Label(top, textvariable=self.v["nurl"], foreground="#566678").pack(side="right")
        self.nb = ttk.Notebook(f)
        self.nb.pack(fill="both", expand=True, pady=(PAD, 0))
        # кошелёк
        w = ttk.Frame(self.nb, padding=PAD)
        self.nb.add(w, text="Кошелёк")
        ttk.Label(w, text="Баланс", foreground="#566678").pack(anchor="w")
        big = ttk.Frame(w)
        big.pack(anchor="w")
        ttk.Label(big, textvariable=self.v["bal"], font=("Helvetica", 32, "bold")).pack(side="left")
        ttk.Label(big, text="  INX", font=("Helvetica", 18)).pack(side="left", anchor="s")
        grid = ttk.Frame(w)
        grid.pack(fill="x", pady=PAD)
        self._stat(grid, "Можно потратить", self.v["spend"], 0)
        self._stat(grid, "Заморожено", self.v["locked"], 1)
        self._stat(grid, "Блоков в сети", self.v["height"], 2)
        ttk.Label(w, text="Ваш адрес (его можно показывать)", foreground="#566678").pack(anchor="w")
        ar = ttk.Frame(w)
        ar.pack(fill="x")
        ttk.Entry(ar, textvariable=self.v["addr"], state="readonly", font=("Menlo", 12)).pack(side="left", fill="x", expand=True)
        ttk.Button(ar, text="Скопировать", command=lambda: self.copy(self.v["addr"].get())).pack(side="left", padx=(6, 0))
        ttk.Label(w, text="История", font=("Helvetica", 14, "bold")).pack(anchor="w", pady=(PAD, 4))
        self.tree = ttk.Treeview(w, columns=("h", "k", "o", "a"), show="headings", height=10)
        for c, t, wd in (("h", "Блок", 70), ("k", "Что", 150), ("o", "Кто", 260), ("a", "Сумма", 120)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=wd, anchor="e" if c == "a" else "w")
        self.tree.pack(fill="both", expand=True)
        # отправить
        s = ttk.Frame(self.nb, padding=PAD)
        self.nb.add(s, text="Отправить")
        self._row(s, "Адрес получателя", self.v["sto"])
        self._row(s, "Сумма, INX", self.v["samt"], width=20)
        self._row(s, "Комиссия, INX", self.v["sfee"], width=20)
        self.bsend = ttk.Button(s, text="Отправить", command=self.do_send)
        self.bsend.pack(anchor="w", pady=PAD)
        self.lsmsg = ttk.Label(s, textvariable=self.v["smsg"], wraplength=700)
        self.lsmsg.pack(anchor="w")
        # майнинг
        m = ttk.Frame(self.nb, padding=PAD)
        self.nb.add(m, text="Майнинг")
        ttk.Label(m, text="Награда за блок идёт на адрес вашего кошелька. Окно должно оставаться открытым.", foreground="#566678").pack(anchor="w")
        g = ttk.Frame(m)
        g.pack(fill="x", pady=PAD)
        self._stat(g, "Состояние", self.v["mst"], 0)
        self._stat(g, "Скорость", self.v["mrate"], 1)
        self._stat(g, "Найдено блоков", self.v["mblocks"], 2)
        self._stat(g, "Способ", self.v["meng"], 3)
        tr = ttk.Frame(m)
        tr.pack(anchor="w")
        ttk.Label(tr, text="Потоков процессора:").pack(side="left")
        self.spin = ttk.Spinbox(tr, from_=1, to=(os.cpu_count() or 1), textvariable=self.v["mthr"], width=5)
        self.spin.pack(side="left", padx=6)
        self.bmine = ttk.Button(tr, text="Начать майнинг", command=self.do_mine)
        self.bmine.pack(side="left", padx=PAD)
        self.log = tk.Text(m, height=14, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, pady=PAD)
        # настройки
        x = ttk.Frame(self.nb, padding=PAD)
        self.nb.add(x, text="Настройки")
        self._row(x, "Адрес узла", self.v["nurl"])
        ttk.Button(x, text="Сохранить", command=self.do_node).pack(anchor="w", pady=PAD)
        ttk.Label(x, textvariable=self.v["nmsg"], wraplength=700).pack(anchor="w")
        ttk.Separator(x).pack(fill="x", pady=PAD)
        ttk.Label(x, text="Кошелёк сам блокируется через 15 минут без действий (во время майнинга не блокируется).", foreground="#566678", wraplength=700).pack(anchor="w")
        self._row(x, "Пароль, чтобы показать код восстановления", self.v["xpass"], show="•", width=30)
        row = ttk.Frame(x)
        row.pack(anchor="w", pady=PAD)
        ttk.Button(row, text="Показать код восстановления", command=self.do_recovery).pack(side="left")
        ttk.Button(row, text="Заблокировать кошелёк", command=self.do_lock).pack(side="left", padx=PAD)
        ttk.Label(x, textvariable=self.v["xmsg"], foreground="#b3261e", wraplength=700).pack(anchor="w")
        ttk.Label(x, text="Файл кошелька:", foreground="#566678").pack(anchor="w", pady=(PAD, 0))
        ttk.Label(x, textvariable=self.v["wfile"], wraplength=700).pack(anchor="w")

    # ---------------------------------------------------------------- действия
    def copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def refresh_login(self):
        try:
            st = A.api(self.st, "/api/state", None)
        except Exception:                                # noqa: BLE001
            return
        self.v["nurl"].set(st["node"])
        self.lbox["values"] = st["wallets"]
        if st.get("last_file"):
            self.v["lpath"].set(st["last_file"])
        elif st["wallets"]:
            self.v["lpath"].set(st["wallets"][0])
        self.cpu = st["cpu"]

    def browse(self):
        p = filedialog.askopenfilename(title="Файл кошелька", filetypes=[("Кошелёк", "*.json"), ("Все файлы", "*")])
        if p:
            self.v["lpath"].set(p)

    def do_unlock(self):
        self.v["lmsg"].set("")
        body = {"file": self.v["lpath"].get().strip(), "password": self.v["lpass"].get()}

        def done(r, e):
            if e:
                self.v["lmsg"].set(errtext(e))
                return
            self.v["lpass"].set("")
            self.enter_main()
        self.bg(lambda: A.api(self.st, "/api/unlock", body), done)

    def do_create(self):
        self.v["cmsg"].set("")
        body = {"password": self.v["cpass"].get(), "password2": self.v["cpass2"].get()}

        def done(r, e):
            if e:
                self.v["cmsg"].set(errtext(e))
                return
            self.v["cpass"].set("")
            self.v["cpass2"].set("")
            self.v["reccode"].set(r["recovery"])
            self.show("rec")
        self.bg(lambda: A.api(self.st, "/api/create", body), done)

    def rec_done(self):
        self.v["reccode"].set("")
        self.enter_main()

    def do_restore(self):
        self.v["rmsg"].set("")
        body = {"code": self.v["rcode"].get(), "password": self.v["rpass"].get()}

        def done(r, e):
            if e:
                self.v["rmsg"].set(errtext(e))
                return
            self.v["rcode"].set("")
            self.v["rpass"].set("")
            self.enter_main()
        self.bg(lambda: A.api(self.st, "/api/restore", body), done)

    def enter_main(self):
        self.v["addr"].set(self.st.address or "")
        self.v["wfile"].set(self.st.file or "")
        self.v["nurl"].set(self.st.node)
        if not self.v["mthr"].get():
            self.v["mthr"].set(str(max(1, (os.cpu_count() or 2) - 1)))
        self.show("main")
        self.refresh_account()

    def do_lock(self):
        A.api(self.st, "/api/lock", {})
        self.after_lock()

    def after_lock(self):
        self.v["bal"].set("…")
        self.show("login")
        self.refresh_login()

    def refresh_account(self):
        def done(r, e):
            if e:
                if "заблокирован" in str(e):
                    return self.after_lock()
                self.v["bal"].set("нет связи")
                return
            i = r["info"]
            self.v["bal"].set(fmt(i["balance"]))
            self.v["spend"].set(fmt(i["spendable"]))
            self.v["locked"].set(fmt(i["locked"]))
            self.v["height"].set(str(r["status"]["height"]))
            self.tree.delete(*self.tree.get_children())
            names = {"mined": "майнинг", "sent": "отправлено", "received": "получено", "founder": "доля основателя"}
            for h in i["history"]:
                other = h["other"] or "—"
                sign = "−" if h["kind"] == "sent" else "+"
                self.tree.insert("", "end", values=(h["height"], names.get(h["kind"], h["kind"]), other, sign + fmt(h["amount"])))
        self.bg(lambda: A.api(self.st, "/api/account", None), done)

    def do_send(self):
        to, amt, fee = self.v["sto"].get().strip(), self.v["samt"].get().strip(), self.v["sfee"].get().strip()
        if not messagebox.askyesno("Подтвердите перевод",
                                   "Отправить %s INX на адрес\n%s\nКомиссия: %s INX.\nПеревод нельзя отменить." % (amt, to, fee)):
            return
        self.v["smsg"].set("Отправляю…")
        self.bsend.configure(state="disabled")

        def done(r, e):
            self.bsend.configure(state="normal")
            if e:
                self.v["smsg"].set(errtext(e))
                self.lsmsg.configure(foreground="#b3261e")
                return
            self.v["smsg"].set("Перевод отправлен. Он подтвердится, когда попадёт в блок. ID: %s" % r["txid"])
            self.lsmsg.configure(foreground="#0a7a45")
            self.v["samt"].set("")
            self.refresh_account()
        self.bg(lambda: A.api(self.st, "/api/send", {"to": to, "amount": amt, "fee": fee}), done)

    def do_mine(self):
        run = self.st.miner.running()
        try:
            if run:
                A.api(self.st, "/api/mine/stop", {})
            else:
                A.api(self.st, "/api/mine/start", {"threads": int(self.v["mthr"].get() or 1)})
        except ValueError as e:
            messagebox.showerror("Майнинг", str(e))
        self.update_mining()

    def update_mining(self):
        m = A.api(self.st, "/api/mining", None)
        self.v["mst"].set("идёт" if m["running"] else "остановлен")
        r = m["rate"] if m["running"] else 0
        self.v["mrate"].set(("%.2f МХеш/с" % (r / 1e6)) if r >= 1e6 else ("%.1f кХеш/с" % (r / 1e3)))
        self.v["mblocks"].set(str(m["blocks"]))
        self.v["meng"].set(m["engine"] or "…")
        self.bmine.configure(text="Остановить" if m["running"] else "Начать майнинг")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("end", "\n".join(m["log"]) or "—")
        self.log.see("end")
        self.log.configure(state="disabled")

    def do_node(self):
        try:
            A.api(self.st, "/api/node", {"url": self.v["nurl"].get()})
            self.v["nmsg"].set("Сохранено.")
            self.refresh_account()
        except ValueError as e:
            self.v["nmsg"].set(str(e))

    def do_recovery(self):
        self.v["xmsg"].set("")
        body = {"password": self.v["xpass"].get()}

        def done(r, e):
            if e:
                self.v["xmsg"].set(errtext(e))
                return
            self.v["xpass"].set("")
            self.show_code(r["recovery"])
        self.bg(lambda: A.api(self.st, "/api/recovery", body), done)

    def show_code(self, code):
        win = tk.Toplevel(self.root)
        win.title("Код восстановления")
        var = tk.StringVar(value=code)
        ttk.Label(win, text="Запишите код на бумагу. Окно закроется само через 30 секунд.", padding=PAD).pack()
        ttk.Entry(win, textvariable=var, state="readonly", width=76, font=("Menlo", 12)).pack(padx=PAD, pady=PAD)
        ttk.Button(win, text="Закрыть", command=win.destroy).pack(pady=PAD)
        win.after(30000, lambda: win.winfo_exists() and win.destroy())

    # ---------------------------------------------------------------- таймер и выход
    def _tick(self):
        self.counter += 1
        self.st.check_idle()
        if self.current == "main":
            if not self.st.unlocked():
                self.after_lock()
            else:
                tab = self.nb.index(self.nb.select())
                if tab == 2:
                    self.update_mining()
                if tab == 0 and self.counter % 3 == 0:
                    self.refresh_account()
        self.root.after(2000, self._tick)

    def on_close(self):
        try:
            self.st.lock_wallet()
        finally:
            self.root.destroy()


def run(state):
    root = tk.Tk()
    GUI(root, state)
    root.mainloop()
