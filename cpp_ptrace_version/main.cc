#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// 信息输出
#define cRST "\x1b[0m"      // 终端红色字体代码
#define cLRD "\x1b[1;91m"   // 终端重置字体颜色代码
#define cYEL "\x1b[1;93m"   // 终端黄色字体代码
#define cBRI "\x1b[1;97m"   // 终端加粗白色字体代码
#define cLBL "\x1b[1;94m"   // 终端蓝色字体代码

#define INFO(x...) do { \
    fprintf(stdout, cLBL "[*] " cRST x); \
    fprintf(stdout, cRST "\n"); \
    fflush(stdout);    \
  } while (0)

#define WARN(x...) do { \
    fprintf(stderr, cYEL "[!] " cBRI "WARNING: " cRST x); \
    fprintf(stderr, cRST "\n");    \
    fflush(stderr);    \
  } while (0)

#define FATAL(x...) do { \
    fprintf(stderr, cRST cLRD "[-] PROGRAM ABORT : " cBRI x); \
    fprintf(stderr, cLRD "\n         Location : " cRST "%s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    fflush(stderr);    \
    exit(1); \
  } while (0)

// 生成存储字符串
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    int _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = (char*)malloc(_len + 1); \
    snprintf(_tmp, _len + 1, _str); \
    _tmp; \
  })

// 输入输出文件夹
char *in_dir = NULL, *out_dir = NULL;
// 限制子进程资源
unsigned long long int exec_tmout = 0;
pid_t child_pid = 0;
// 信号处理相关
bool is_child_timeout = false;
bool stop_soon = false;
// 追踪栈回溯层数
unsigned int framenum = 6;
// 子进程参数
char** child_args = NULL;
int child_inputarg_idx = -1;
// 输出文件夹
int out_dir_fd = -1;

// 子进程执行情况
enum ExecStatus { FAULT_NONE, FAULT_TMOUT, FAULT_CRASH};

// 输出帮助信息
void usage(char* procname) {
    INFO("%s [ options ] -- /path/to/fuzzed_app [ fuzzed_app_args ]\n\n"

            "Required parameters:\n"
            "  -i dir        - input directory with test cases\n"
            "  -o dir        - output directory for fuzzer findings\n\n"

            "Execution control settings:\n"
            "  -t msec       - timeout for each run (ms)\n"

            "Hash settings:\n"
            "  -f frames     - stack frame nums to calc crash-hash \n\n",
        procname);
    
    exit(1);
}

// 处理参数
void parse_args(int argc, char** argv) {
    int opt;
    while ((opt = getopt(argc, argv, "+i:o:t:f:")) > 0) {
        switch(opt) {
        case 'i':
            if (in_dir) FATAL("Multiple -i options not supported");
            in_dir = optarg;
            break;
        case 'o':
            if (out_dir) FATAL("Multiple -o options not supported");
            out_dir = optarg;
            break;
        case 't': {
            char suffix = 0;

            if (sscanf(optarg, "%llu%c", &exec_tmout, &suffix) < 1 ||
                optarg[0] == '-') FATAL("Bad syntax used for -t");

            if (exec_tmout < 5) FATAL("Dangerously low value of -t");

            break;

        }
        case 'f':
            if (sscanf(optarg, "%u", &framenum) < 1 || optarg[0] == '-') 
                FATAL("Bad syntax used for -f");

            if (framenum > 10) WARN("Dangerously large value of -f");

            break;
        default:
            usage(argv[0]);
        }
    }
    if(optind == argc || !in_dir || !out_dir)
        usage(argv[0]);
    if (!strcmp(in_dir, out_dir))
        FATAL("Input and output directories can't be the same");

    // 保存子进程的参数
    child_args = (char**)malloc((sizeof(char*)) * (argc - optind + 1));
    
    int i;
    for(i = 0; i < argc - optind; i++) {
        child_args[i] = alloc_printf("%s", argv[optind + i]);
        // 查找输入参数的位置
        if(!strcmp(child_args[i], "@@"))
            child_inputarg_idx = i;
    }
    child_args[i] = NULL;

    // 将获取到的参数输出
    INFO("Input dir: %s", in_dir);
    INFO("Output dir: %s", out_dir);
    if(exec_tmout > 0)
        INFO("Child exec timeout: %lld ms", exec_tmout);
    INFO("Traced stack frame num: %d", framenum);
    
    char* child_cmd = alloc_printf("%s", child_args[0]);;
    for(i = 1; i < argc - optind; i++) {
        char* tmp = alloc_printf("%s %s", child_cmd, child_args[i]);
        free(child_cmd);
        child_cmd = tmp;
    }

    INFO("Child cmdline: %s", child_cmd);
    free(child_cmd);

    if(child_inputarg_idx > 0)
        INFO("  - Input arg: %d th", child_inputarg_idx);
    else
        INFO("  - Cannot detecte child input arg, stdin used");
}

// 处理停止信号
void handle_stop_sig(int sig) {
  stop_soon = true; 
  if (child_pid > 0) 
    kill(child_pid, SIGKILL);
    INFO("Handling STOP SIG, child pid %d killed.", child_pid);
    child_pid = 0;
}

// 处理超时信号
void handle_timeout(int sig) {
  if (child_pid > 0) {
    is_child_timeout = true;
    kill(child_pid, SIGKILL);
    INFO("Handling timeout, child pid %d killed.", child_pid);
    child_pid = 0;
  }
}

// 注册信号处理程序
void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */
  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */
  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Things we don't care about. */
  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
}

// 创建文件夹
void setup_outdir_fds()
{
    if (mkdir(out_dir, 0700))
        if (errno != EEXIST) 
            FATAL("Unable to create '%s'", out_dir);

    out_dir_fd = open(out_dir, O_RDONLY | O_CLOEXEC);

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
        FATAL("Unable to flock() output directory.");
}

// 在退出程序前回收垃圾（不回收也行其实）
void clean_res() {
    close(out_dir_fd);

    for(int i = 0; child_args[i]; ++i)
        free(child_args[i]);
    free(child_args);

    if(child_pid > 0) {
        WARN("UNREACHABLE in clean_res");
        kill(child_pid, SIGKILL);
        if (waitpid(child_pid, NULL, 0) <= 0)
            WARN("waitpid() failed (%s)", strerror(errno));
    }
}

bool get_memory_from_child(uint64_t address, uint64_t* data) {
    assert(child_pid > 0);
    // 必须手动清空 errno 以检测 ptrace 错误
    errno = 0;
    // 即便读取失败，依然会设置 data 为 -1
    *data = ptrace(PTRACE_PEEKDATA, child_pid, address, nullptr);
    return errno == 0;
}

// 开始运行
ExecStatus run_target(char* args[], char** hash, char* in_fn) {
    assert(child_inputarg_idx > 0 || in_fn); // child_inputarg_idx < 0 -> in_fn
    // 如果当前不是使用 stdin 输入，则构造子进程参数
    int out_fd = -1;
    if(child_inputarg_idx < 0) {
        out_fd = open(in_fn, O_RDONLY | O_CLOEXEC, 0600);
        if (out_fd < 0) 
            FATAL("Unable to create '%s'", in_fn);
    }

    child_pid = fork();

    if (child_pid < 0) 
        FATAL("fork() failed");
    else if (child_pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        setsid();

        int dev_null_fd = open("/dev/null", O_RDWR);

        dup2(dev_null_fd, 1);
        dup2(dev_null_fd, 2);

        if (out_fd < 0) {
            dup2(dev_null_fd, 0);
        } else {
            dup2(out_fd, 0);
            close(out_fd);
        }

        close(dev_null_fd);
        close(out_dir_fd);
        /* Set sane defaults for ASAN if nothing else specified. */

        setenv("ASAN_OPTIONS", "abort_on_error=1:"
                                "detect_leaks=0:"
                                "symbolize=0:"
                                "allocator_may_return_null=1", 0);

        execv(args[0], args);

        exit(0);
    }
    close(out_fd);
    
    // 等待到 ptrace 在 execv 时产生的 SIGTRAP 信号
    wait(NULL);
    // 设置子进程继续执行
    if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0)
        FATAL("PTRACE_CONT error. %s", strerror(errno));

    // 启动计时器
    is_child_timeout = 0;

    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec = (exec_tmout / 1000);
    it.it_value.tv_usec = (exec_tmout % 1000) * 1000;
    if(setitimer(ITIMER_REAL, &it, NULL))
        WARN("set-setitimer fail: %s", strerror(errno));

    // 开始循环等待子进程结束
    while(child_pid > 0) 
    {
        int status = 0;
        
        // 阻塞等待
        if (waitpid(child_pid, &status, 0) <= 0) 
            WARN("waitpid() failed: %s", strerror(errno));

        // 如果 waitpid 因为子进程暂停
        if (WIFSTOPPED(status)) 
        {
            // 如果 tracer 只是追踪到了 signal-delivery-stop 
            // 则检测信号是否是我们所关心的信号 SIGILL SIGABRT SIGSEGV 
            int stp_sig = WSTOPSIG(status);
            if(stp_sig == SIGILL || stp_sig == SIGABRT || stp_sig == SIGSEGV)
            {
                // 捕获 crash，设置 hash
                assert(child_pid > 0);
                user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) < 0)
                    FATAL("ptrace error: %s", strerror(errno));

                uint64_t bp = regs.rbp;

                /**
                 * 栈帧示意图
                 *  +------------------+
                 *  |                  | <- new rsp
                 *  |   callee frame   |
                 *  |                  |
                 *  +------------------+
                 *  |     old rbp      | <- new rbp
                 *  +------------------+
                 *  | caller ret addr  |
                 *  +------------------+
                 *  |                  | <- new rsp
                 *  |   caller frame   |
                 *  |                  |
                 *  +------------------+
                 *  |      .......     |
                 * 
                 */
                
                // 开始回溯栈内存
                char* tmp_hash = alloc_printf("");
                for(unsigned int i = 0; i < framenum; i++) {
                    uint64_t caller_ret_addr;
                    char* tmp_str = NULL;
                    if(get_memory_from_child(bp + 0x8, &caller_ret_addr))
                        tmp_str = alloc_printf("%03x%s", (uint32_t)(caller_ret_addr & 0xfff), tmp_hash);
                    else
                        tmp_str = alloc_printf("XXX%s", tmp_hash);

                    free(tmp_hash);
                    tmp_hash = tmp_str;

                    // 更新 base pointer
                    get_memory_from_child(bp, &bp);
                }

                // 删除可能已经设置过的 hash
                free(*hash);
                *hash = tmp_hash;
            }

            // 最后将信号转发回子进程，并设置子进程继续执行
            if (ptrace(PTRACE_CONT, child_pid, NULL, stp_sig) < 0)
                FATAL("PTRACE_CONT error. %s", strerror(errno));
        }
        // 如果 waitpid 不是因为子进程暂停，那么就是因为子进程退出了
        else
        {
            child_pid = 0;
            // 清空定时器
            memset(&it, 0, sizeof(it));
            if(setitimer(ITIMER_REAL, &it, NULL))
                WARN("clean-setitimer fail: %s", strerror(errno));

            // 这里我们只会捕获子进程的 SIGKILL SIGILL SIGABRT SIGSEGV 
            if (WIFSIGNALED(status) && !stop_soon) {
                int kill_signal = WTERMSIG(status);
                if (is_child_timeout && kill_signal == SIGKILL) 
                    return FAULT_TMOUT;
                else {
                    return FAULT_CRASH;
                }
            }
            // 如果子进程已经结束，则直接退出
            break;
        }
    }

    return FAULT_NONE;
}

// 批处理每个输入文件夹
void uniqueing_crashes() {
    // 读取每个文件
    struct dirent **nl;
    int nl_cnt = scandir(in_dir, &nl, NULL, alphasort);
    if (nl_cnt < 0)
        FATAL("Unable to open '%s' (%s)", in_dir, strerror(errno));
    
    for (int i = 0; i < nl_cnt; i++) {
        struct stat st;

        char* in_fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    
        if (lstat(in_fn, &st) || access(in_fn, R_OK))
            FATAL("Unable to access '%s' (%s)", in_fn, strerror(errno));

        /* This also takes care of . and .. */
        if (S_ISREG(st.st_mode) && st.st_size) {
            INFO("Running %s ...", in_fn);
            
            // 如果当前不是使用 stdin 输入，则构造子进程参数
            char* hash = NULL;
            ExecStatus ret;

            if(child_inputarg_idx > 0) {
                char* tmp_inputarg = child_args[child_inputarg_idx];
                child_args[child_inputarg_idx] = in_fn;
                ret = run_target(child_args, &hash, NULL); // 传个 NULL 表示第三个参数无用
                child_args[child_inputarg_idx] = tmp_inputarg;
            } 
            else
                ret = run_target(child_args, &hash, in_fn);
            
            // 如果用户手动终止进程
            if(stop_soon) {
                WARN("****** Stop by user ******");
                for (int j = i; j < nl_cnt; j++)
                    free(nl[j]); 
                free(in_fn);
                return;
            }
            
            switch(ret) {
            case FAULT_NONE:  
                WARN("Cannot get crashed from %s !", in_fn); 
                break;
            case FAULT_TMOUT: 
                WARN("Timeout from %s !", in_fn);
                break;
            case FAULT_CRASH: {
                // 通过子进程返回的 hash 字符串，将 crash 分类
                assert(strlen(hash) == 3*framenum);
                // 创建文件夹
                if (mkdirat(out_dir_fd, hash, 0700))
                    if (errno != EEXIST) 
                        FATAL("Unable to create '%s'", out_dir);

                // 复制文件
                char* cmd = alloc_printf("cp %s %s/%s/%s", in_fn, out_dir, hash, nl[i]->d_name);
                if(system(cmd))
                    WARN("system(%s) failed", cmd);
                free(cmd);
                break;
            }
            }
        }
        free(nl[i]); 
        free(in_fn);
    }
}

int main(int argc, char**argv)
{
    // 准备参数
    parse_args(argc, argv);
    // 设置信号处理    
    setup_signal_handlers();
    // 创建并锁定 outdir
    setup_outdir_fds();
    // 开始处理传入的 crashes
    uniqueing_crashes();
    // 退出前清理
    clean_res();

    return 0;
}