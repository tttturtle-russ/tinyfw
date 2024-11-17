# Makefile

# 内核模块对象文件
obj-m += tinywall.o tinywall_nl.o

# 用户程序编译命令
USER_CMD = ./user_cmd/tinywall_cmd.c
USER_BIN = ./fw

# 编译选项
CFLAGS += -Wall

# 默认目标
all: modules user_cmd

# 编译内核模块
modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# 编译用户程序
user_cmd:
	gcc $(CFLAGS) -o $(USER_BIN) $(USER_CMD)

# 清理内核模块和用户程序
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f $(USER_BIN)

# 安装内核模块
install:
	sudo insmod $(PWD)/tinywall.ko
	sudo insmod $(PWD)/tinywall_nl.ko

# 卸载内核模块
uninstall:
	sudo rmmod tinywall_nl
	sudo rmmod tinywall

# 快速操作：编译、卸载、安装
shot: all uninstall install

.PHONY: all modules user_cmd clean install uninstall shot