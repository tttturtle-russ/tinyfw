from abc import abstractmethod
import tkinter as tk
from tkinter.filedialog import askopenfilename
from datetime import datetime

from log import LogText

class RuleButtonBase(tk.Button):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.config(command=self.command)

    @abstractmethod
    def command(self):
        pass

class AddRuleButton(RuleButtonBase):
    def __init__(self, master,log: LogText, **kwargs):
        super().__init__(master, **kwargs)
        self.log = log

    def command(self):
        file = askopenfilename()
        if file:
            self.log.log(f'Read Rule from {file}')

class DeleteRuleButton(RuleButtonBase):
    def __init__(self, master, log:LogText, **kwargs):
        super().__init__(master, **kwargs)
        self.log = log

    def command(self):
        self.log.log(f"Delete Rule")

class SaveRuleButton(RuleButtonBase):
    def __init__(self, master, log:LogText, **kwargs):
        super().__init__(master, **kwargs)
        self.log = log

    def command(self):
        self.log.log(f"Delete Rule")


class ClearRuleButton(RuleButtonBase):
    def __init__(self, master, log: LogText, **kwargs):
        super().__init__(master, **kwargs)
        self.log = log

    def command(self):
        self.log.log(f"Clear Rule")