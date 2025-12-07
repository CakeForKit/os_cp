/*
 * Модуль мониторинга активности kswapd с привязкой к процессам
 * Автор: [Ваше имя]
 * Дата: [Дата]
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/vmalloc.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/sched/task.h>

#define MODULE_NAME "kswapd_monitor"
#define MAX_EVENTS 1000
#define PROC_FILENAME "kswapd_stats"
#define MEM_THRESHOLD_MB 100  // Порог для "тяжелых" процессов (100 МБ)

/* Структура для хранения события kswapd */
struct kswapd_event {
    ktime_t timestamp;           // Время события
    int order;                  // Порядок (размер) запрошенной памяти
    unsigned long free_pages;   // Свободных страниц в зоне
    pid_t pid;                  // PID процесса в момент вызова
    char comm[TASK_COMM_LEN];   // Имя процесса
    gfp_t gfp_flags;            // Флаги выделения памяти
    int zone_idx;               // Индекс зоны
    unsigned long vm_size;      // Размер виртуальной памяти процесса (в страницах)
    unsigned long rss;          // RSS процесса (в страницах)
};

/* Структура для статистики по процессам */
struct process_stats {
    pid_t pid;                  // PID процесса
    char comm[TASK_COMM_LEN];   // Имя процесса
    unsigned int wakeup_count;  // Количество пробуждений kswapd при активном процессе
    unsigned long total_vm;     // Суммарный размер виртуальной памяти
    unsigned long total_rss;    // Суммарный RSS
    ktime_t first_seen;         // Время первого обнаружения
    ktime_t last_seen;          // Время последнего обнаружения
};

/* Структура данных модуля */
struct kswapd_monitor_data {
    struct kswapd_event events[MAX_EVENTS]; // Кольцевой буфер событий
    struct process_stats *proc_stats;       // Статистика по процессам
    int event_index;                        // Текущий индекс в буфере
    int num_procs;                          // Количество отслеживаемых процессов
    spinlock_t lock;                        // Спинлок для синхронизации
    struct proc_dir_entry *proc_entry;      // /proc entry
};

static struct kswapd_monitor_data *mon_data;
static struct kprobe kp;

/* Вспомогательная функция для получения RSS процесса */
static unsigned long get_process_rss(struct task_struct *task)
{
    unsigned long rss = 0;
    
    if (task->mm) {
        rss = get_mm_rss(task->mm);
    }
    return rss;
}

/* Вспомогательная функция для получения VM size процесса */
static unsigned long get_process_vm_size(struct task_struct *task)
{
    unsigned long vm_size = 0;
    
    if (task->mm) {
        vm_size = task->mm->total_vm;
    }
    return vm_size;
}

/* Поиск статистики по PID */
static struct process_stats *find_proc_stats(pid_t pid)
{
    int i;
    
    for (i = 0; i < mon_data->num_procs; i++) {
        if (mon_data->proc_stats[i].pid == pid) {
            return &mon_data->proc_stats[i];
        }
    }
    return NULL;
}

/* Добавление нового процесса в статистику */
static struct process_stats *add_proc_stats(pid_t pid, const char *comm)
{
    struct process_stats *stats;
    
    /* Увеличиваем массив статистики */
    mon_data->proc_stats = krealloc(mon_data->proc_stats,
                                    (mon_data->num_procs + 1) * sizeof(struct process_stats),
                                    GFP_KERNEL);
    if (!mon_data->proc_stats) {
        return NULL;
    }
    
    stats = &mon_data->proc_stats[mon_data->num_procs];
    memset(stats, 0, sizeof(struct process_stats));
    
    stats->pid = pid;
    strncpy(stats->comm, comm, TASK_COMM_LEN - 1);
    stats->comm[TASK_COMM_LEN - 1] = '\0';
    stats->first_seen = ktime_get();
    stats->last_seen = stats->first_seen;
    
    mon_data->num_procs++;
    return stats;
}

/* Обработчик kprobe для wakeup_kswapd */
static int kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
    printk(KERN_INFO "%s: KPROBE TRIGGERED! Current: %s[%d]\n",
           MODULE_NAME, current->comm, current->pid);
    struct kswapd_event *event;
    struct process_stats *pstats;
    struct zone *zone;
    struct task_struct *task = current;
    unsigned long free_pages = 0;
    int order;
    gfp_t gfp_flags;
    enum zone_type zone_idx;
    
    /* Получаем параметры из регистров (для x86_64) */
#if defined(CONFIG_X86_64)
    zone = (struct zone *)regs->di;
    gfp_flags = (gfp_t)regs->si;
    order = (int)regs->dx;
    zone_idx = (enum zone_type)regs->cx;
#elif defined(CONFIG_X86)
    /* Для 32-битного x86 параметры передаются на стеке */
    /* Здесь нужна более сложная логика для получения параметров */
    zone = NULL;
    gfp_flags = 0;
    order = 0;
    zone_idx = 0;
#else
    /* Для других архитектур */
    zone = NULL;
    gfp_flags = 0;
    order = 0;
    zone_idx = 0;
#endif
    
    /* Получаем количество свободных страниц в зоне */
    if (zone) {
        free_pages = zone_page_state(zone, NR_FREE_PAGES);
    }
    
    spin_lock(&mon_data->lock);
    
    /* Записываем событие */
    event = &mon_data->events[mon_data->event_index];
    event->timestamp = ktime_get();
    event->order = order;
    event->free_pages = free_pages;
    event->pid = task->pid;
    strncpy(event->comm, task->comm, TASK_COMM_LEN - 1);
    event->comm[TASK_COMM_LEN - 1] = '\0';
    event->gfp_flags = gfp_flags;
    event->zone_idx = zone_idx;
    event->vm_size = get_process_vm_size(task);
    event->rss = get_process_rss(task);
    
    /* Обновляем индекс буфера */
    mon_data->event_index = (mon_data->event_index + 1) % MAX_EVENTS;
    
    /* Обновляем статистику по процессу */
    pstats = find_proc_stats(task->pid);
    if (!pstats) {
        pstats = add_proc_stats(task->pid, task->comm);
    }
    
    if (pstats) {
        pstats->wakeup_count++;
        pstats->total_vm += event->vm_size;
        pstats->total_rss += event->rss;
        pstats->last_seen = event->timestamp;
    }
    
    spin_unlock(&mon_data->lock);
    
    /* Логируем в системный журнал для отладки */
    printk(KERN_INFO "%s: kswapd wakeup by %s[%d], order=%d, free=%lu pages, RSS=%lu pages\n",
           MODULE_NAME, task->comm, task->pid, order, free_pages, event->rss);
    
    return 0;
}

/* Функция для сканирования всех процессов и поиска "тяжелых" */
static void scan_memory_hogs(void)
{
    struct task_struct *task;
    unsigned long vm_size, rss;
    
    printk(KERN_INFO "%s: Scanning for memory hogs...\n", MODULE_NAME);
    
    rcu_read_lock();
    for_each_process(task) {
        vm_size = get_process_vm_size(task);
        rss = get_process_rss(task);
        
        /* Проверяем только процессы с памятью больше порога */
        if (vm_size * PAGE_SIZE / 1024 / 1024 > MEM_THRESHOLD_MB) {
            struct process_stats *pstats;
            
            spin_lock(&mon_data->lock);
            pstats = find_proc_stats(task->pid);
            if (!pstats) {
                pstats = add_proc_stats(task->pid, task->comm);
            }
            if (pstats) {
                pstats->total_vm = vm_size;
                pstats->total_rss = rss;
            }
            spin_unlock(&mon_data->lock);
            
            printk(KERN_INFO "%s: Memory hog: %s[%d], VM=%lu MB, RSS=%lu MB\n",
                   MODULE_NAME, task->comm, task->pid,
                   vm_size * PAGE_SIZE / 1024 / 1024,
                   rss * PAGE_SIZE / 1024 / 1024);
        }
    }
    rcu_read_unlock();
}

/* Функции для /proc интерфейса */

/* Вывод статистики по событиям */
static int proc_show_events(struct seq_file *m, void *v)
{
    int i, start_idx;
    struct timespec64 ts;
    
    seq_printf(m, "Last %d kswapd wakeup events:\n", MAX_EVENTS);
    seq_printf(m, "%-20s %-6s %-16s %-8s %-10s %-10s %-6s\n",
               "Timestamp", "PID", "Process", "Order", "Free Pages", "VM Pages", "RSS");
    seq_printf(m, "%-20s %-6s %-16s %-8s %-10s %-10s %-6s\n",
               "-------------------", "------", "----------------", "------",
               "----------", "----------", "------");
    
    spin_lock(&mon_data->lock);
    start_idx = (mon_data->event_index + MAX_EVENTS - 10) % MAX_EVENTS;
    if (start_idx < 0) start_idx = 0;
    
    for (i = 0; i < 10; i++) {
        int idx = (start_idx + i) % MAX_EVENTS;
        struct kswapd_event *event = &mon_data->events[idx];
        
        if (event->timestamp == 0) continue;
        
        ts = ktime_to_timespec64(event->timestamp);
        seq_printf(m, "%lld.%09ld %-6d %-16s %-8d %-10lu %-10lu %-6lu\n",
                   (long long)ts.tv_sec, ts.tv_nsec,
                   event->pid, event->comm, event->order,
                   event->free_pages, event->vm_size, event->rss);
    }
    spin_unlock(&mon_data->lock);
    
    return 0;
}

/* Вывод статистики по процессам */
static int proc_show_procs(struct seq_file *m, void *v)
{
    int i;
    
    seq_printf(m, "Process statistics (top by kswapd wakeups):\n");
    seq_printf(m, "%-6s %-16s %-10s %-12s %-12s %-20s %-20s\n",
               "PID", "Process", "Wakeups", "Avg VM(MB)", "Avg RSS(MB)",
               "First Seen", "Last Seen");
    seq_printf(m, "%-6s %-16s %-10s %-12s %-12s %-20s %-20s\n",
               "------", "----------------", "----------", "------------",
               "------------", "--------------------", "--------------------");
    
    spin_lock(&mon_data->lock);
    
    /* Сортируем процессы по количеству пробуждений (простая сортировка) */
    for (i = 0; i < mon_data->num_procs - 1; i++) {
        int j;
        for (j = i + 1; j < mon_data->num_procs; j++) {
            if (mon_data->proc_stats[j].wakeup_count > 
                mon_data->proc_stats[i].wakeup_count) {
                struct process_stats tmp = mon_data->proc_stats[i];
                mon_data->proc_stats[i] = mon_data->proc_stats[j];
                mon_data->proc_stats[j] = tmp;
            }
        }
    }
    
    /* Выводим топ-10 процессов */
    for (i = 0; i < min(10, mon_data->num_procs); i++) {
        struct process_stats *stats = &mon_data->proc_stats[i];
        struct timespec64 first_ts, last_ts;
        unsigned long avg_vm = 0, avg_rss = 0;
        
        if (stats->wakeup_count > 0) {
            avg_vm = stats->total_vm / stats->wakeup_count;
            avg_rss = stats->total_rss / stats->wakeup_count;
        }
        
        first_ts = ktime_to_timespec64(stats->first_seen);
        last_ts = ktime_to_timespec64(stats->last_seen);
        
        seq_printf(m, "%-6d %-16s %-10u %-12lu %-12lu %lld.%09ld %lld.%09ld\n",
                   stats->pid, stats->comm, stats->wakeup_count,
                   avg_vm * PAGE_SIZE / 1024 / 1024,
                   avg_rss * PAGE_SIZE / 1024 / 1024,
                   (long long)first_ts.tv_sec, first_ts.tv_nsec,
                   (long long)last_ts.tv_sec, last_ts.tv_nsec);
    }
    
    spin_unlock(&mon_data->lock);
    
    return 0;
}

/* Объединенный вывод */
static int proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "=== KSWAPD Monitor Statistics ===\n\n");
    proc_show_events(m, v);
    seq_printf(m, "\n");
    proc_show_procs(m, v);
    
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Инициализация модуля */
static int __init kswapd_monitor_init(void)
{
    int ret;
    
    printk(KERN_INFO "%s: Initializing module\n", MODULE_NAME);
    
    /* Выделяем память для данных */
    mon_data = kzalloc(sizeof(struct kswapd_monitor_data), GFP_KERNEL);
    if (!mon_data) {
        printk(KERN_ERR "%s: Failed to allocate memory\n", MODULE_NAME);
        return -ENOMEM;
    }
    
    /* Инициализируем спинлок */
    spin_lock_init(&mon_data->lock);
    
    /* Инициализируем буфер событий */
    memset(mon_data->events, 0, sizeof(mon_data->events));
    mon_data->event_index = 0;
    mon_data->num_procs = 0;
    mon_data->proc_stats = NULL;
    
    /* Настраиваем kprobe */
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "wakeup_kswapd";
    kp.pre_handler = kprobe_handler;
    
    /* Регистрируем kprobe */
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "%s: Failed to register kprobe: %d\n", MODULE_NAME, ret);
        kfree(mon_data);
        return ret;
    }
    
    /* Создаем /proc entry */
    mon_data->proc_entry = proc_create(PROC_FILENAME, 0444, NULL, &proc_fops);
    if (!mon_data->proc_entry) {
        printk(KERN_ERR "%s: Failed to create /proc entry\n", MODULE_NAME);
        unregister_kprobe(&kp);
        kfree(mon_data);
        return -ENOMEM;
    }
    
    /* Сканируем процессы на старте */
    scan_memory_hogs();
    
    printk(KERN_INFO "%s: Module initialized successfully\n", MODULE_NAME);
    printk(KERN_INFO "%s: Statistics available at /proc/%s\n", 
           MODULE_NAME, PROC_FILENAME);
    
    return 0;
}

/* Выход из модуля */
static void __exit kswapd_monitor_exit(void)
{
    printk(KERN_INFO "%s: Unloading module\n", MODULE_NAME);
    
    /* Удаляем /proc entry */
    if (mon_data->proc_entry) {
        proc_remove(mon_data->proc_entry);
    }
    
    /* Удаляем kprobe */
    unregister_kprobe(&kp);
    
    /* Освобождаем память */
    if (mon_data->proc_stats) {
        kfree(mon_data->proc_stats);
    }
    kfree(mon_data);
    
    printk(KERN_INFO "%s: Module unloaded\n", MODULE_NAME);
}

module_init(kswapd_monitor_init);
module_exit(kswapd_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("KSWAPD Monitor with process tracking");
MODULE_VERSION("1.0");