import tkinter as tk
import tkinter.commondialog
from tkinter import ttk

from my_scanner import scan_server

DEBUG = 1

WAIT_DIALOG_WIDTH = 200
WAIT_DIALOG_HEIGHT = 100


class MyScannerInterface(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title('Н.А.Киренков Оценка безопасности веб-приложения')

        self.sql_injection = tk.BooleanVar(self, True)
        self.url = tk.StringVar(self, 'http://localhost:8000/')

        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        vulnerabilities_menu = tk.Menu(self)
        vulnerabilities_menu.add_checkbutton(label='SQL инъекции', variable=self.sql_injection)
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
        self.result_table.heading('#0', text='Уязвимости')
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
            sql_injection=self.sql_injection.get()
        )
        print(len(results))

        for i, result in enumerate(results):
            self.result_table.insert('', 'end', iid=i, text=f'{result.type} {result.description}')
            for url in result.urls:
                self.result_table.insert(i, 'end', text=url)
        wait_dialog.destroy()


if __name__ == '__main__':
    # params = find_params('http://192.168.1.72:8000/sql-injection/get-students-vulnerable')
    # print(params)
    MyScannerInterface().mainloop()