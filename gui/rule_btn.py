from abc import abstractmethod
import tkinter as tk
from tkinter.filedialog import askopenfilename
from tkinter import messagebox, ttk

from log import LogText
from rule import Rule

rules = {}

def is_valid_ip(ip: str) -> bool:
    """
    检测一个字符串是否是合法的 IPv4 地址。

    :param ip: 待检测的字符串
    :return: 如果是合法的 IPv4 地址，返回 True；否则返回 False
    """
    # 按 "." 分割字符串，IPv4 地址应由四部分组成
    parts = ip.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        # 检查每部分是否是数字
        if not part.isdigit():
            return False

        # 转换为整数并检查范围
        num = int(part)
        if num < 0 or num > 255:
            return False

        # 防止前导零的情况（如 "01" 不合法）
        if len(part) > 1 and part[0] == "0":
            return False

    return True


class RuleButtonBase(tk.Button):
    def __init__(self, master,log, **kwargs):
        super().__init__(master, **kwargs)
        self.config(command=self.command)
        self.logger = log

    def log(self,text):
        self.logger.log(text)

    @abstractmethod
    def command(self):
        pass

class AddRuleButton(RuleButtonBase):
    def __init__(self, master,log: LogText, **kwargs):
        super().__init__(master,log, **kwargs)

    def command(self):
        dialog = tk.Toplevel(self.master)
        dialog.title('Add Rule')

        tk.Label(dialog, text='src addr').grid(column=0, row=0)
        src_addr_input = tk.Entry(dialog, width=10)
        src_addr_input.grid(column=1,row=0)
        tk.Label(dialog, text='src mask').grid(column=2, row=0)
        src_mask_input = tk.Entry(dialog, width=10)
        src_mask_input.grid(column=3,row=0)
        tk.Label(dialog, text='src port min').grid(column=4,row=0)
        src_port_min_input = tk.Entry(dialog, width=10)
        src_port_min_input.grid(column=5,row=0)
        tk.Label(dialog, text='src port max').grid(column=6,row=0)
        src_port_max_input = tk.Entry(dialog, width=10)
        src_port_max_input.grid(column=7,row=0)

        tk.Label(dialog, text='dst addr').grid(column=0, row=1)
        dst_addr_input = tk.Entry(dialog, width=10)
        dst_addr_input.grid(column=1,row=1)
        tk.Label(dialog, text='dst mask').grid(column=2, row=1)
        dst_mask_input = tk.Entry(dialog, width=10)
        dst_mask_input.grid(column=3,row=1)
        tk.Label(dialog, text='dst port min').grid(column=4,row=1)
        dst_port_min_input = tk.Entry(dialog, width=10)
        dst_port_min_input.grid(column=5,row=1)
        tk.Label(dialog, text='dst port max').grid(column=6,row=1)
        dst_port_max_input = tk.Entry(dialog, width=10)
        dst_port_max_input.grid(column=7,row=1)

        tk.Label(dialog, text='name').grid(column=0,row=2)
        name_input = tk.Entry(dialog, width=10)
        name_input.grid(column=1,row=2)

        action_box = ttk.Combobox(dialog, values=["Accept", "Drop"], state='readonly')
        action_box.grid(row=2, column=3, columnspan=2)
        action_box.set("Choose Action")

        protocol_box = ttk.Combobox(dialog, values=['TCP','ICMP','UDP','ANY'], state='readonly')
        protocol_box.grid(row=2, column=5)
        protocol_box.set("Choose Protocol")

        def command():
            src_addr = src_addr_input.get()
            src_mask = src_mask_input.get()
            src_port_max = src_port_max_input.get()
            src_port_min = src_port_min_input.get()

            dst_addr = dst_addr_input.get()
            dst_mask = dst_mask_input.get()
            dst_port_max = dst_port_max_input.get()
            dst_port_min = dst_port_min_input.get()

            action = action_box.get()
            name = name_input.get()
            protocol = protocol_box.get()

            if not all([name, src_addr, src_mask, src_port_max, src_port_min, dst_addr, dst_mask, dst_port_max, dst_port_min, action, protocol]):
                messagebox.showwarning('Warn', 'Please fill all fields!')
                return
            if not is_valid_ip(src_addr) or not is_valid_ip(dst_addr):
                messagebox.showerror('Error', 'Please input the valid IP address!')
                return
            if int(dst_port_max) < int(dst_port_min) or int(src_port_max) < int(src_port_min):
                messagebox.showerror('Error', 'Please input the valid port range!')
                return
            
            rule = Rule(name,src_addr, src_mask, src_port_min, src_port_max, dst_addr,dst_mask,dst_port_min,dst_port_max,action,protocol)
            rules[name] = rule
        
            self.log(rule.dump())
            dialog.destroy()

        tk.Button(dialog, command=command, text='Add').grid(row=2, column=6, columnspan=2)


class DeleteRuleButton(RuleButtonBase):
    def __init__(self, master, log:LogText, **kwargs):
        super().__init__(master,log, **kwargs)

    def command(self):
        dialog = tk.Toplevel(self.master)
        dialog.title('Delete Rule')

        combobox = ttk.Combobox(dialog, values=list(rules.keys()), state='readonly')
        combobox.pack()

        def command():
            name = combobox.get()
            del rules[name]
            dialog.destroy()
            self.log("Delete rule: %s" % name)

        tk.Button(dialog, text='Delete', command=command).pack()
        

class SaveRuleButton(RuleButtonBase):
    def __init__(self, master, log:LogText, **kwargs):
        super().__init__(master,log, **kwargs)

    def command(self):
        self.log(f"Save Rule")


class ClearRuleButton(RuleButtonBase):
    def __init__(self, master, log: LogText, **kwargs):
        super().__init__(master,log, **kwargs)

    def command(self):
        rules.clear()
        self.log("Clearing all rules")