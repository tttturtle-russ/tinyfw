import tkinter as tk
from log import LogText
from rule_btn import AddRuleButton, DeleteRuleButton, SaveRuleButton, ClearRuleButton

class MainApplication:
    def __init__(self, window_name) -> None:
        self.window = tk.Tk()
        self.window.title(window_name)
        self.window.focus()
        self.window.geometry('800x600')
        self.window.resizable(True, True)

        self.log_text = LogText(self.window)
        self.log_text.grid(row=1, column=0, columnspan=4)

        self.add_rule_btn = AddRuleButton(self.window,self.log_text, text='Add Rule')
        self.add_rule_btn.grid(row=0, column=0)

        self.delete_rule_btn = DeleteRuleButton(self.window,self.log_text, text='Delete Rule')
        self.delete_rule_btn.grid(row=0, column=1)

        self.save_rule_btm = SaveRuleButton(self.window,self.log_text, text='Save Rule')
        self.save_rule_btm.grid(row=0, column=2)

        self.clear_rule_btn = ClearRuleButton(self.window,self.log_text, text='Clear Rule')
        self.clear_rule_btn.grid(row=0, column=3)
        

    def run(self):
        self.window.mainloop()

if __name__ == '__main__':
    app = MainApplication('Main Application')
    app.run()

    