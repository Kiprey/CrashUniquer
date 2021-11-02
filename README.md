# Crash Uniquer

## 一、简介

功能：使用 ptrace 将生成的大量 crash 根据 **触发路径的 hash** 自动分类。

由于 AFL 中的 crash 分类主要基于代码覆盖率，因此相同的 crash 触发路径可能会因为不同的代码覆盖率而错误分类，尤其是在大样本的 fuzz 中。

这里借鉴了 trapfuzz 的思路，将触发 crash 的栈回溯中，**选取最靠前几个的调用地址后三个十六进制来组成一串 hash**，用于区分不同 crash 的函数调用链。

## 二、使用方式

- 简单的编译方式

  ```bash
  gcc main.cc -o main
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
  gcc main.cc -o main

  pushd test/bin
  ./build.sh
  popd

  ./main -i test/test_input -o test/test_output -- test/bin/noasan_test @@
  ```

## 三、存在的问题

当前工具计算 crash hash 的方式，是通过 **遍历 rbp 寄存器串起的调用链中caller的返回地址** 来追踪函数调用链。

但若 crash 被 asan 捕获，则 asan 会修改 rbp 寄存器的指向，破坏调用链的追踪，因此无法区分开不同 asan 引发的 crash。

即当前工具可以区分开：
- 非 asan 编译条件下触发的 SIGILL、SIGSEGV、SIGABRT 的 crash
- asan 编译下的 SIGABRT 的 crash(因为 asan 不捕获 SIGABRT)

## 四、致敬

该项目内部有相当一部分代码直接来自 AFL, 向 AFL 致敬 :-)
 
思路来自 trap-fuzz。