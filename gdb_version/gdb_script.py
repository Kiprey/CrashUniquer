#! python3
# encoding="utf-8"
import gdb
import json
import socket
import os

# 配置文件
config = None
# target 信息
target_info = {}
# 与父进程通信的 socket
tracer_sock = None


# 更新 target 信息并且实时写入至配置文件
def dump_target_info(key, val):
    global target_info
    target_info[key] = val
    with open("target_info.json", "w") as fp:
        fp.write(json.dumps(target_info))


# 将可能的 crash 信息保存，并退出gdb
def save_data_and_exit(status):
    global tracer_sock, config
    if status == "crash":
        # 保存当前栈帧以及寄存器信息
        reg_info = gdb.execute("i r", to_string=True)
        bt = gdb.execute("bt " + str(config["stackframe_num"]), to_string=True)
        dump_target_info("crash", {'register_info': reg_info, 'backtrace': bt})
        print("backtrace:\n" + bt)
    # 输出信息，关闭通信端口并退出
    tracer_sock.send(status.encode())
    tracer_sock.close()
    gdb.execute("quit")


# gdb 检测到正常退出时所执行的处理例程
def exit_handler(event):
    print("EXIT event detected: (exit_code {})".format(event.exit_code))
    save_data_and_exit("normal")


# gdb 检测到停止事件时所执行的处理例程
def stop_handler(event):
    global tracer_sock
    if isinstance(event, gdb.SignalEvent):
        print("STOP signal: " + event.stop_signal)
        if event.stop_signal in ["SIGABRT", "SIGSEGV", "SIGILL"]:
            gdb.events.exited.disconnect(exit_handler)
            save_data_and_exit("crash")
        elif event.stop_signal in ["SIGINT", "SIGKILL"]:
            gdb.events.exited.disconnect(exit_handler)
            save_data_and_exit("normal")
    else:
        print("Unhandled event {}".format(event))


# gdb 检测到加载新文件时所执行的处理例程
def new_objfile_handler(event):
    if event.new_objfile.is_valid():
        print("NEW_OBJFILE detected: {}".format(event.new_objfile.filename))
    dump_target_info("target_pid", gdb.selected_inferior().pid)


# -------- 主逻辑开始 --------

# 读取配置文件
with open("config.json", "r") as fp:
    config = json.loads(fp.read())

# 尝试连接 Tracer
tracer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tracer_sock.connect(("127.0.0.1", int(config['gdb-port'])))
print("Connect %s:%s successfully." % ("127.0.0.1", config['gdb-port']))

# 尝试进行握手
tracer_sock.send(b"OK")
tracer_sock.recv(4)
print("Handshake successfully.")

# 注册 gdb 事件
gdb.events.exited.connect(exit_handler)
gdb.events.stop.connect(stop_handler)
gdb.events.new_objfile.connect(new_objfile_handler)

# 接下来等待触发 gdb 事件......
print("Waiting for triggering gdb events...")