# Crash Uniquer

## 简介

功能：使用 ptrace 将生成的大量 crash 根据 **触发路径的 hash** 自动分类。

由于 AFL 中的 crash 分类主要基于代码覆盖率，因此相同的 crash 触发路径可能会因为不同的代码覆盖率而错误分类，尤其是在大样本的 fuzz 中。

这里借鉴了 trapfuzz 的思路，将触发 crash 的栈回溯中，**选取最靠前几个的调用地址后三个十六进制来组成一串 hash**，用于区分不同 crash 的函数调用链。

## 致敬

该项目内部有相当一部分代码直接来自 AFL, 向 AFL 致敬 :-)
 
思路来自 trap-fuzz。