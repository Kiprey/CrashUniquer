#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
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
bool is_child_timeout = false;
pid_t child_pid = 0;
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

// 开始运行
ExecStatus run_target(char* args[], char** hash, char* in_fn) {
    // 如果当前不是使用 stdin 输入，则构造子进程参数
    char* tmp_inputarg = NULL;
    if(child_inputarg_idx > 0) {
        tmp_inputarg = child_args[child_inputarg_idx];
        child_args[child_inputarg_idx] = in_fn;
    }

    ExecStatus ret_status = FAULT_NONE;

    // TODO
    
    
    // 记得恢复回去，以免出现 double free
    if(child_inputarg_idx > 0)
        child_args[child_inputarg_idx] = tmp_inputarg;

    return ret_status;
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

            // 调用子进程并追踪 crash
            char* hash = NULL;
            ExecStatus ret = run_target(child_args, &hash, in_fn);

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