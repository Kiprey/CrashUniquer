#! python3
# encoding="utf-8"

from threading import Timer
import threading
import subprocess
import os
import re
import shutil
import socket
import sys
import time
import signal
import random
import json


class GdbTracer:
    def __init__(self):
        # 设置当前脚本所在的路径为工作路径。这样做可以避免各类相对路径的错误
        self.workspace = os.path.realpath(__file__)

        # 写入 cmd.gdb
        with open("{}/cmd.gdb".format(self.workspace), "w") as fp:
            fp.write(self.generate_gdb_cmd_file())

        # 读取config
        self.config = {}
        with open("{}/config.json".format(self.workspace), "r") as fp:
            self.config = json.loads(fp.read())

        # 创建 socket，等待 gdb 连接
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('127.0.0.1', int(self.config['gdb-port'])))
        self.server_sock.listen(1)

        # 显示声明其他成员变量
        self.target_status = None


    # 输出
    def log(self, data, is_debug=False):
        if is_debug and not self.config['is_debug']:
            return
        print(data, end="")


    # 创建 gdb 脚本
    def generate_gdb_cmd_file(self):
        data = ""
        data += "set confirm off\n"                 # 指明gdb所有要确认的地方全部为yes
        data += "set pagination off\n"              # 关闭分页显示功能
        data += "set auto-solib-add off\n"          # 跳过加载共享库中的所有调试信息
        data += "set disable-randomization on\n"    # 关闭ASLR
        data += "source gdb_script.py\n"            # 读取 gdb python script
        data += "run\n"                             # 开始执行
        return data


    # 获取 gdb 所保存的 target 信息
    def get_target_info(self):
        target_info = None
        with open("{}/target_info.json".format(self.workspace), "r") as fp:
            target_info = json.loads(fp.read())
        return target_info


    # 启动事件循环
    def run_eventloop(self):
        # root 表示当前正在访问的文件夹路径
        # files 表示该文件夹下的文件list
        for root, _, files in os.walk(self.config["crashes_input_path"]):
            # 遍历文件
            for f in files:
                # 准备输入语料
                cur_crash_path = os.path.join(root, f)
                self.log("[eventloop] reproducing crash " + cur_crash_path)
                shutil.copyfile(cur_crash_path, self.config["cur_input_path"])
                # 启动 gdb tracer
                hash = self.gdb_trace()
                # 检测输出
                if hash == "normal":
                    self.log("[eventloop] %s did not crash!\n" % cur_crash_path)
                elif hash == "timeout":
                    self.log("[eventloop] %s timeout!\n" % cur_crash_path)
                else:
                    self.log("[eventloop] %s crash hash: %s\n" % (cur_crash_path, hash))
                # 将crash复制至输出文件夹下
                shutil.copyfile(cur_crash_path, os.path.join(
                    self.config["crashes_output_path"], hash + "-" + f))


    # gdb 开始检测。该函数将会返回 backtrace hash
    def gdb_trace(self):
        command = "/usr/bin/gdb -q -x {}/cmd.gdb  --args {}".format(
            self.workspace, self.config["cmdline"])

        # 删除原始 target_info.json
        if os.path.exists('target_info.json'):
            os.remove('target_info.json')

        # 开始执行 gdb
        self.target_status = "normal"
        gdb_proc = subprocess.Popen(command, shell=True, cwd=self.workspace, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.log("[trace]: Running '%s'\n" % command, True)

        timer = Timer(int(self.config['target_timeout']), self.timeout_handler)
        try:
            # 尝试与 gdb 进行握手
            self.log("[trace]: Try handshake with gdb...", True)
            data = self.client_sock.recv(2)
            assert data == "ok"
            self.client_sock.sendall("next")
            self.log("done\n", True)
            # 启动定时器
            timer.start()
            # 等待gdb结束
            self.log("[trace] Waiting for gdb to exit...\n", True)
            self.target_status = self.client_sock.recv(100)
            self.log("done\n", True)
        except Exception as e:
            self.log("exception occured\n", True)
            self.log("[trace Exception]: %s\n" %  str(e))
        finally:
            timer.cancel()

        # gdb 执行完成
        gdb_proc.kill()
        gdb_proc.wait()
        self.log("[trace] gdb process was killed\n", True)

        # 过滤掉超时和正常退出的情况
        if self.target_status == "timeout":
            return "TIMEOUT"
        elif self.target_status == "normal":
            return "NORMAL"
        
        # 获取 crash 的栈回溯
        target_info = self.get_target_info()
        backtrace_msg = target_info["crash"]['backtrace']
        # 提取 crash hash        
        crash_hash = ""
        for l in backtrace_msg.split("\n"):
            self.log("[trace] Backtrace_msg: %s\n" % l, True)
            addr = re.findall("#\d+\s+(.*?)\s+in", l)
            if len(addr) >= 1:
                crash_hash += addr[0][-3:]
                self.log("[trace] Current tmp crash_hash : %s\n" % crash_hash, True)
        return crash_hash

    # 超时处理例程
    def timeout_handler(self):
        self.log("[trace] Timeout detected\n", True)
        target_info = self.get_target_info()
        self.target_status = "timeout"
        os.kill(target_info['target_pid'], signal.SIGINT)


    def quit(self):
        self.log("[trace] Try quit tracer...\n", True)
        target_info = self.get_target_info()
        os.kill(target_info['target_pid'], signal.SIGKILL)
        os.kill(target_info['gdb_pid'], signal.SIGKILL)

if __name__ == '__main__':
    tracer = GdbTracer()
    try:
        tracer.run_eventloop()
    except KeyboardInterrupt:
        tracer.quit()