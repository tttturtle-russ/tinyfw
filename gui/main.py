import tkinter as tk
from tkinter.filedialog import askopenfilename
from abc import abstractmethod

class LogText(tk.Text):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.config(state='disabled')

    def append(self, text):
        self.config(state='normal')
        self.insert('end', text)
        self.config(state='disabled')

class RuleButtonBase(tk.Button):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.config(command=self.command)

    @abstractmethod
    def command(self):
        pass

class AddRuleButton(RuleButtonBase):
    def __init__(self, master,log, **kwargs):
        super().__init__(master, **kwargs)
        self.log = log

    def command(self):
        file = askopenfilename()
        if file:
            self.log.append(f'Added Rule: {file}\n')

class DeleteRuleButton(RuleButtonBase):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

    def command(self):
        print('Delete Rule')


class MainApplication:
    def __init__(self, window_name) -> None:
        self.window = tk.Tk()
        self.window.title(window_name)
        self.window.focus()
        self.window.geometry('800x600')
        self.window.resizable(True, True)

        self.log_text = LogText(self.window)
        self.log_text.grid(row=1, column=0, columnspan=2)

        self.add_rule_btn = AddRuleButton(self.window,self.log_text, text='Add Rule')
        self.add_rule_btn.grid(row=0, column=0)

        self.delete_rule_btn = DeleteRuleButton(self.window, text='Delete Rule')
        self.delete_rule_btn.grid(row=0, column=1)
        

    def run(self):
        self.window.mainloop()

if __name__ == '__main__':
    app = MainApplication('Main Application')
    app.run()

    