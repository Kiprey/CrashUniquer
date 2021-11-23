# Crash Uniquer

## 一、简介

功能：将生成的大量 crash 根据 **触发路径的 hash** 自动分类。

由于 AFL 中的 crash 分类主要基于代码覆盖率，因此相同的 crash 触发路径可能会因为不同的代码覆盖率而错误分类，尤其是在大样本的 fuzz 中。

这里借鉴了 trapfuzz 的思路，将触发 crash 的栈回溯中，**选取最靠前几个的调用地址后三个十六进制来组成一串 hash**，用于区分不同 crash 的函数调用链。

## 二、使用方式

使用方式区别于版本。

### 1. C++ ptrace 版

（项目位于 `cpp_ptrace_version/` 文件夹下）

- 简单的编译方式

  ```bash
  gcc cpp_ptrace_version/main.cc -o main
  ```

- 类似于 AFL-fuzz 的使用方式
  
  > 参数带上 `@@` 表示将该参数替换为测试样例路径，没有该参数表示用 stdin 输入测试样例。

  ```text
  ./main [ options ] -- /path/to/fuzzed_app [ fuzzed_app_args ]

  Required parameters:
  -i dir        - input directory with test cases
  -o dir        - output directory for fuzzer findings

  Execution control settings:
  -t msec       - timeout for each run (ms)
  Hash settings:
  -f frames     - stack frame nums to calc crash-hash 
  ```

  以下是该项目自带的一个测试样例

  ```bash
  gcc cpp_ptrace_version/main.cc -o main

  pushd test/bin
  ./build.sh
  popd

  ./main -i test/test_input -o test/test_output -- test/bin/noasan_test @@
  ```

### 2. gdb 版

修改 `gdb_version/config.json`中的各个配置，缺一不可：

```json
{
    /* 是否启动调试输出 */
    "is_debug": false,
    /* 配置绑定的端口 */
    "gdb-port": 10000,
    /* 目标程序的命令行参数 */
    "cmdline": "/usr/class/CrashUniquer/test/bin/asan_test /usr/class/CrashUniquer/test/.cur_input",
    /* 目标程序输入语料的 .cur_input 路径，一定要与 cmdline 中对应的上 */
    "cur_input_path": "/usr/class/CrashUniquer/test/.cur_input",
    /* 存放待测试crashes的文件夹路径 */
    "crashes_input_path": "/usr/class/CrashUniquer/test/test_input",
    /* 存放添加上 hash 头的 crashes 的输出文件夹路径 */
    "crashes_output_path": "/usr/class/CrashUniquer/test/test_output",
    /* target 超时事件(s) */
    "target_timeout" : 5,
    /* 回溯栈帧层数 */
    "stackframe_num": 6
}
```

之后直接执行 `gdb_version/gdbtracer.py` 即可。

## 三、存在的问题

### 1. C++ ptrace 版

当前工具计算 crash hash 的方式，是通过 **遍历 rbp 寄存器串起的调用链中caller的返回地址** 来追踪函数调用链。

但若 crash 被 asan 捕获，则 asan 会修改 rbp 寄存器的指向，破坏调用链的追踪，因此无法区分开不同 asan 引发的 crash。

即当前工具可以区分开：

- 非 asan 编译条件下触发的 SIGILL、SIGSEGV、SIGABRT 的 crash
- asan 编译下的 SIGABRT 的 crash(因为 asan 不捕获 SIGABRT)

### 2. gdb 版

调试器 gdb 可以在 rbp 寄存器调用链破坏了情况下正常获取调用堆栈，同时还额外支持大量功能，因此 ptrace 版本中的问题在 gdb 版本中都可以迎刃而解。

美中不足的是执行效率可能会略微慢一点，不过这也无关紧要。

## 四、致敬

该项目内部有相当一部分思路与代码直接来自 AFL 和 trap-fuzz。

向 AFL 和 trap-fuzz 致敬 :-)
