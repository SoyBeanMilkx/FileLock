#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include "file.h"
#include <syscall.h>



KPM_NAME("File_Guard");
KPM_VERSION("1.21.51");
KPM_AUTHOR("yuuki & shapaozidex");
KPM_DESCRIPTION("Prevent your phone from being maliciously formatted");

static hook_err_t hook_err = HOOK_NOT_HOOK;

static struct file *(*do_filp_open)(int dfd, struct filename *pathname, const struct open_flags *op);
static int (*do_unlinkat)(void *mnt_userns, struct inode *dir, struct dentry *dentry, bool force);
static int (*do_rmdir)(int dfd, struct filename *name);
static int (*do_renameat2)(int olddfd, struct filename *oldname,int newdfd, struct filename *newname,unsigned int flags);

char *(*dentry_path_raw)(const struct dentry *dentry, char *buf, int buflen) = NULL;


static char protected_directories[MAX_PATHS][PATH_MAX];
static int path_count = 0;
// 不要问为什么定义了这么多日志级别，但却只用INFO，问就是都删了，不删看着麻烦
// 定义日志级别
typedef enum
{
    LOG_LEVEL_ALL,
    LOG_LEVEL_DEVELOPER,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_NO
} log_level_t;

// 当前日志级别
static log_level_t current_log_level = LOG_LEVEL_INFO;

// 日志输出宏
#define LOG(level, fmt, ...)                                \
    do                                                      \
    {                                                       \
        if (current_log_level <= level)                     \
        {                                                   \
            if (level == LOG_LEVEL_ALL)                     \
            {                                               \
                pr_info("[ALL] " fmt, ##__VA_ARGS__);       \
            }                                               \
            else if (level == LOG_LEVEL_DEVELOPER)          \
            {                                               \
                pr_info("[DEVELOPER] " fmt, ##__VA_ARGS__); \
            }                                               \
            else if (level == LOG_LEVEL_DEBUG)              \
            {                                               \
                pr_info("[DEBUG] " fmt, ##__VA_ARGS__);     \
            }                                               \
            else if (level == LOG_LEVEL_INFO)               \
            {                                               \
                pr_info("[INFO] " fmt, ##__VA_ARGS__);      \
            }                                               \
        }                                                   \
    } while (0)








static void do_unlinkat_before(hook_fargs4_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    char path_buf[PATH_MAX];

    // 默认放行
    args->skip_origin = false;
    args->ret = 0;

    // 更严格的路径检查
    if (!pathname || IS_ERR(pathname) || !pathname->name) {
        return;
    }

    // 初始化缓冲区
    memset(path_buf, 0, PATH_MAX);
    strncpy(path_buf, pathname->name, PATH_MAX - 1);

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++) {
        if (strstr(path_buf, protected_directories[i]) != NULL) {
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] do_unlinkat_before: 拦截删除文件操作: %s\n", path_buf);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}





static void do_rmdir_before(hook_fargs2_t *args, void *udata)
{
    struct filename* pathname = (struct filename*)args->arg1;
    char path_buf[PATH_MAX];

    // 默认放行
    args->skip_origin = false;
    args->ret = 0;

    // 更严格的路径检查
    if (!pathname || IS_ERR(pathname) || !pathname->name) {
        return;
    }

    // 初始化缓冲区
    memset(path_buf, 0, PATH_MAX);
    strncpy(path_buf, pathname->name, PATH_MAX - 1);

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++) {
        if (strstr(path_buf, protected_directories[i]) != NULL) {
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] do_rmdir_before: 拦截删除目录操作: %s\n", path_buf);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}

static void do_renameat2_before(hook_fargs5_t* args, void* udata) {
    struct filename* oldname = (struct filename*)args->arg1;
    struct filename* newname = (struct filename*)args->arg3;
    char old_path[PATH_MAX];
    char new_path[PATH_MAX];

    // 默认放行
    args->skip_origin = false;
    args->ret = 0;

    // 检查路径有效性
    if (!oldname || IS_ERR(oldname) || !oldname->name ||
        !newname || IS_ERR(newname) || !newname->name) {
        return;
    }

    // 获取源路径和目标路径
    memset(old_path, 0, PATH_MAX);
    memset(new_path, 0, PATH_MAX);
    strncpy(old_path, oldname->name, PATH_MAX - 1);
    strncpy(new_path, newname->name, PATH_MAX - 1);

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++) {
        if (strstr(old_path, protected_directories[i]) != NULL || 
            strstr(new_path, protected_directories[i]) != NULL) {
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] do_renameat2_before: 拦截重命名操作: %s -> %s\n", old_path, new_path);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}



static void do_filp_open_before(hook_fargs3_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    const struct open_flags *op = (const struct open_flags *)args->arg2;
    char path_buf[PATH_MAX];
    
    // 默认放行
    args->skip_origin = false;
    args->ret = 0;
    
    
    // 只在写入和创建时进行保护
    if (!(op->open_flag & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC ))) {
        args->skip_origin = false;
        args->ret = 0;
        return;
    }

    // 更严格的路径检查
    if (!pathname || IS_ERR(pathname) || !pathname->name) {
        return;
    }

    // 初始化缓冲区
    memset(path_buf, 0, PATH_MAX);
    strncpy(path_buf, pathname->name, PATH_MAX - 1);

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++) {
        if (strstr(path_buf, protected_directories[i]) != NULL) {
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] do_filp_open_before: 拦截文件操作: %s\n", path_buf);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}

static inline bool installHook()
{
    // 如果已经安装了hook，直接返回true
    if (hook_err == HOOK_NO_ERR) {
        return true;
    }

    // 定义需要安装的hook结构
    struct hook_info {
        const char *name;           // hook名称
        void *func;                 // 被hook的函数
        int args_num;              // 参数数量
        void *before_func;         // hook前的处理函数
        hook_err_t *err;           // 错误状态
    } hooks[] = {
        {"do_unlinkat", do_unlinkat, 4, do_unlinkat_before, &hook_err},
        {"do_rmdir", do_rmdir, 2, do_rmdir_before, &hook_err},
        {"do_renameat2", do_renameat2, 5, do_renameat2_before, &hook_err},
        {"do_filp_open", do_filp_open, 3, do_filp_open_before, &hook_err}
    };

    // 安装所有hook
    bool success = true;
    for (int i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
        if (!hooks[i].func) {
            *hooks[i].err = HOOK_BAD_ADDRESS;
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] %s: hook失败 - 地址无效: 0x%llx\n", 
                hooks[i].name, (unsigned long long)hooks[i].func);
            success = false;
            continue;
        }

        *hooks[i].err = hook_wrap(hooks[i].func, hooks[i].args_num, hooks[i].before_func, NULL, NULL);
        if (*hooks[i].err != HOOK_NO_ERR) {
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] %s: hook失败 - 地址: 0x%llx, 错误: %d\n", 
                hooks[i].name, (unsigned long long)hooks[i].func, *hooks[i].err);
            success = false;
            continue;
        }

        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] %s: hook成功 - 地址: 0x%llx\n", 
            hooks[i].name, (unsigned long long)hooks[i].func);
    }

    if (success) {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] Hook 安装成功\n");
    } else {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] Hook 安装失败\n");
    }

    return success;
}








static inline bool uninstallHook()
{
    if (hook_err == HOOK_NO_ERR)
    {
        unhook((void *)do_rmdir);
        unhook((void *)do_renameat2);
        unhook((void *)do_unlinkat);
        unhook((void *)do_filp_open);
        hook_err = HOOK_NOT_HOOK;
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] hook 卸载成功...\n");
    }
    else
    {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] Maybe it's not hooked, skipping...\n");
    }
    return true;
}








static inline bool control_internal(bool enable)
{
    return enable ? installHook() : uninstallHook();
}



static long mod_init(const char *args, const char *event, void *__user reserved) {
    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] Initializing...\n");
    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] ARGS = %s\n", args);

    // 定义需要查找的内核函数结构
    struct kernel_symbol {
        const char *name;        // 内核函数的符号名
        void **func_ptr;        // 用于存储函数指针的地址
        const char *err_msg;     // 查找失败时的错误信息
    } symbols[] = {
        {"do_filp_open", (void **)&do_filp_open, "do_filp_open"},
        {"do_unlinkat", (void **)&do_unlinkat, "do_unlinkat"},
        {"do_rmdir", (void **)&do_rmdir, "do_rmdir"},
        {"do_renameat2", (void **)&do_renameat2, "do_renameat2"},
        {"dentry_path_raw", (void **)&dentry_path_raw, "dentry_path_raw"}
    };

    // 查找所有需要的内核函数
    for (int i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        *symbols[i].func_ptr = (void *)kallsyms_lookup_name(symbols[i].name);
        if (!*symbols[i].func_ptr) {
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] kernel func: '%s' does not exist!\n", 
                symbols[i].err_msg);
            return -1;
        }
    }

    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] Kernel Version: %x\n", kver);
    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] Kernel Patch Version: %x\n", kpver);
    
    return 0;
}

// 添加目录到保护列表
static bool add_protected_directory(const char *path) {
    if (!path || !*path) {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 add: 未提供路径\n");
        return false;
    }

    if (path_count >= MAX_PATHS) {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 add: 达到上限 %d\n", path_count);
        return false;
    }

    // 检查重复
    for (int i = 0; i < path_count; i++) {
        if (strncmp(protected_directories[i], path, PATH_MAX) == 0) {
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 add: %s 已存在\n", path);
            return false;
        }
    }

    // 添加目录
    if (path[0] != '/') {
        protected_directories[path_count][0] = '/';
        strncpy(protected_directories[path_count] + 1, path, PATH_MAX - 2);
    } else {
        strncpy(protected_directories[path_count], path, PATH_MAX - 1);
    }
    protected_directories[path_count][PATH_MAX - 1] = '\0';
    
    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 add: 添加成功 %s\n", 
        protected_directories[path_count]);
    path_count++;
    return true;
}

// 从保护列表中移除目录
static bool remove_protected_directory(const char *path) {
    if (!path || !*path || path_count <= 0) {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 remove: 无效参数\n");
        return false;
    }

    for (int i = 0; i < path_count; i++) {
        if (strncmp(protected_directories[i], path, PATH_MAX) == 0) {
            memmove(protected_directories[i], protected_directories[i + 1], 
                   (path_count - i - 1) * PATH_MAX);
            path_count--;
            LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 remove: 删除成功 %s\n", path);
            return true;
        }
    }

    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 remove: %s 不存在\n", path);
    return false;
}

// 出所有受保护的目录
static void list_protected_directories(void) {
    if (path_count == 0) {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 ls: 无保护目录\n");
        return;
    }

    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 ls:\n");
    for (int i = 0; i < path_count; i++) {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] %d: %s 地址: 0x%llx\n", i + 1, protected_directories[i]);
    }
}

// 添加预设保护路径函数
static void add_default_protected_paths(void) {
    const char *default_paths[] = {
        "/storage/spzcc",
        // "/data",
        // "/system",s
        // "/vendor",
        // "/product"
    };
    
    for (int i = 0; i < sizeof(default_paths) / sizeof(default_paths[0]); i++) {
        if (add_protected_directory(default_paths[i])) {
            // LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0 add: %s - 0x%llx\n", default_paths[i], (unsigned long long)default_paths[i]);
        }
    }
}

// 主控制函数
static long mod_control0(const char *args, char *__user out_msg, int outlen) {
    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0: 收到命令: %s\n", args);

    if (strncmp(args, "rm -rf", 6) == 0) {
        add_default_protected_paths();
        control_internal(true);
    }
    else if (strncmp(args, "add", 3) == 0) {
        // 不管 add_protected_directory 返回什么结果，都认为是有效命令
        if (add_protected_directory(args + 4)) {
            control_internal(true);
        }
    }
    else if (strncmp(args, "remove", 6) == 0) {
        remove_protected_directory(args + 7);
    }
    else if (strncmp(args, "unhook", 6) == 0) {
        path_count = 0;
        control_internal(false);
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0: 卸载保护\n");
    }
    else if (strncmp(args, "ls", 2) == 0) {
        list_protected_directories();
    }
    else {
        LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_control0: 未知命令 %s\n", args);
    }

    return 0;
}


static long mod_exit(void *__user reserved)
{
    path_count = 0;
    control_internal(false);
    LOG(LOG_LEVEL_INFO, "[yuuki&shapaozidex] mod_exit, uninstalled hook.\n");
    return 0;
}



KPM_INIT(mod_init);
KPM_CTL0(mod_control0);
KPM_EXIT(mod_exit);
