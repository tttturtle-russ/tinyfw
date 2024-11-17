import tkinter as tk
from datetime import datetime

class LogText(tk.Text):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.config(state='disabled')

    @property
    def time(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def log(self, text):
        self.append(f"{self.time}: {text}\n")

    def append(self, text):
        self.config(state='normal')
        self.insert('end', text)
        self.config(state='disabled')
