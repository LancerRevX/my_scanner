import tkinter as tk
import tkinter.commondialog
from tkinter import ttk

from my_scanner import scan_server

DEBUG = 0

WAIT_DIALOG_WIDTH = 200
WAIT_DIALOG_HEIGHT = 100


class MyScannerInterface(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title('Н.А.Киренков Оценка безопасности веб-приложения')

        self.sql_injection = tk.BooleanVar(self, True)
        self.xpath = tk.BooleanVar(self, True)
        self.xss = tk.BooleanVar(self, True)
        self.csp = tk.BooleanVar(self, True)
        self.xml = tk.BooleanVar(self, True)
        self.ssrf = tk.BooleanVar(self, True)
        self.csrf = tk.BooleanVar(self, True)
        self.url = tk.StringVar(self, 'http://localhost:8000/')

        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        vulnerabilities_menu = tk.Menu(self, tearoff=0)
        vulnerabilities_menu.add_checkbutton(label='SQL инъекции', variable=self.sql_injection)
        vulnerabilities_menu.add_checkbutton(label='Blind XPath Injection', variable=self.xpath)
        vulnerabilities_menu.add_checkbutton(label='Cross-site scripting', variable=self.xss)
        vulnerabilities_menu.add_checkbutton(label='Неверная конфигурация CSP', variable=self.csp)
        vulnerabilities_menu.add_checkbutton(label='XML External Entity', variable=self.xml)
        vulnerabilities_menu.add_checkbutton(label='Server-Side Request Forgery', variable=self.ssrf)
        vulnerabilities_menu.add_checkbutton(label='Cross-Site Request Forgery', variable=self.csrf)
        menu_bar.add_cascade(label='Уязвимости', menu=vulnerabilities_menu)

        url_frame = tk.Frame(self)
        tk.Label(url_frame, text='URL сервера').pack(side='left', padx=(10, 0))
        tk.Entry(url_frame, textvariable=self.url, width=60).pack(side='left', padx=5)
        tk.Button(
            url_frame,
            text='Провести сканирование',
            command=self.scan_server
        ).pack(side='left', padx=(0, 10))
        url_frame.pack(pady=10)

        tk.Label(self, text='Результат сканирования').pack()
        result_frame = tk.Frame(self)
        self.result_table = ttk.Treeview(result_frame, selectmode='browse')
        self.result_table.heading('#0', text='Найденные уязвимости')
        self.result_table.pack(side='left', expand=1, fill='both')
        result_scrollbar = tk.Scrollbar(result_frame, orient='vertical', command=self.result_table.yview)
        result_scrollbar.pack(side='left', fill='y')
        self.result_table.configure(yscrollcommand=result_scrollbar.set)
        result_frame.pack(expand=1, fill='both', padx=10, pady=(0, 10))

        tk.Button(self, text='Создать ТЗ на модернизацию', state='disabled').pack(pady=(0, 10))

        if DEBUG:
            self.update()
            self.scan_server()

    def scan_server(self):
        wait_dialog = tk.Toplevel(self)
        wait_dialog.title('')
        tk.Label(wait_dialog, text='Ждите...').pack(expand=1, fill='both')
        wait_dialog.geometry(f'{WAIT_DIALOG_WIDTH}x{WAIT_DIALOG_HEIGHT}')
        wait_dialog_x = self.winfo_x() + self.winfo_width() // 2 - WAIT_DIALOG_WIDTH // 2
        wait_dialog_y = self.winfo_y() + self.winfo_height() // 2 - WAIT_DIALOG_HEIGHT // 2
        wait_dialog.geometry(f'+{wait_dialog_x}+{wait_dialog_y}')
        wait_dialog.update()

        for i in self.result_table.get_children():
            self.result_table.delete(i)

        url = self.url.get()
        results = scan_server(
            url,
            sql_injection=self.sql_injection.get(),
            csp=self.csp.get()
        )
        print(results)

        for i, result in enumerate(results):
            self.result_table.insert('', 'end', iid=i, text=f'{result.type} {result.description}')
            for vulnerability in result.vulnerabilities:
                self.result_table.insert(i, 'end', text=f'{vulnerability[0]}: {vulnerability[1]}')
        wait_dialog.destroy()


if __name__ == '__main__':
    # params = find_params('http://192.168.1.72:8000/sql-injection/get-students-vulnerable')
    # print(params)
    MyScannerInterface().mainloop()