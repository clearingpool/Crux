// +build ignore
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

typedef unsigned int u32;
typedef unsigned long long u64;

struct inode { long unsigned int i_ino; };
struct dentry { struct inode *d_inode; };
struct path { struct dentry *dentry; };
struct file { struct path f_path; };
struct mm_struct { struct file *exe_file; };

// Полное объявление структуры task_struct для CO-RE
struct task_struct { 
    struct mm_struct *mm;
    struct task_struct *real_parent;
    int pid; 
};

// Контекст обычного сисколла kill для трейспоинта
struct trace_event_raw_sys_enter_kill {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int id;
    long int pid; // PID процесса, который хотят убить
    long int sig; // Сигнал (например, 9 или 15)
};

// Описание контекста сисколла execve для трейспоинта
struct trace_event_raw_sys_enter_execve {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int id;
    long unsigned int args; // Первый аргумент execve — это указатель на путь к файлу
};

typedef struct event_t {
    u32 pid;
    u32 ppid;
	u32 uid;
    char filename[128];
    char comm[16];
} event_t_me;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// МАПА ДЛЯ Модуля Самозащиты (Self-Defense)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);   // Ключ: 0
    __type(value, u32); // Значение: PID нашего Go-агента
} my_pid_map SEC(".maps");

struct event_t *unused_event_t_ptr __attribute__((unused));

// РУБЕЖ 1: ПЕРЕХВАТ И АВТОМАТИЗАЦИЯ SOAR
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    struct event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, pid);

    // ИСПРАВЛЕНО: Безопасно читаем путь запускаемого бинаря из правильной структуры контекста
    const char *filename_ptr = (const char *)ctx->args;
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// РУБЕЖ 2: АБСОЛЮТНАЯ ИЗЯЩНАЯ САМОЗАЩИТА (SELF-DEFENSE)
SEC("tracepoint/syscalls/sys_enter_kill")
int tracepoint__syscalls__sys_enter_kill(struct trace_event_raw_sys_enter_kill *ctx) {
    u32 key = 0;
    u32 *edr_pid = bpf_map_lookup_elem(&my_pid_map, &key);
    
    if (!edr_pid) {
        return 0;
    }

    // Если хакер шлёт опасный сигнал (sig > 0) конкретно нашему EDR
    if (ctx->pid == *edr_pid && ctx->sig > 0) {
        // Замораживаем процесс хакера (SIGSTOP), не давая ему завершить сисколл kill
        bpf_send_signal(19); 
    }

    return 0;
}
