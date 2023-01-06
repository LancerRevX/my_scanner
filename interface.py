import tkinter as tk
from tkinter import ttk
from arjun import find_params


class MyScannerInterface(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title('Н.А.Киренков Оценка безопасности веб-приложения')

        self.sql_injection = tk.BooleanVar(self, True)
        self.url = tk.StringVar(self, 'http://localhost:8000/get-students-vulnerable&name=Василий')

        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        vulnerabilities_menu = tk.Menu(self)
        vulnerabilities_menu.add_checkbutton(label='SQL инъекции', variable=self.sql_injection)
        menu_bar.add_cascade(label='Уязвимости', menu=vulnerabilities_menu)

        url_frame = tk.Frame(self)
        tk.Label(url_frame, text='URL веб-приложения').pack(side='left', padx=(10, 0))
        tk.Entry(url_frame, textvariable=self.url, width=60).pack(side='left', padx=5)
        tk.Button(url_frame, text='Провести сканирование').pack(side='left', padx=(0, 10))
        url_frame.pack(pady=10)

        tk.Label(self, text='Результат сканирования').pack()
        result_table = ttk.Treeview(self)
        result_table.config(columns=['vulnerability', 'result'])
        result_table.column('#0', width=0, stretch='no')
        result_table.heading('vulnerability', text='Уязвимость')
        result_table.heading('result', text='Результат')
        result_table.pack(expand=1, fill='both', padx=10, pady=(0, 10))

        result_table.insert(parent='', index='end', values=['SQL инъекции', 'Не обнаружено'])

        tk.Button(self, text='Создать ТЗ на модернизацию', state='disabled').pack(pady=(0, 10))


if __name__ == '__main__':
    # params = find_params('http://192.168.1.72:8000/sql-injection/get-students-vulnerable')
    # print(params)
    MyScannerInterface().mainloop()