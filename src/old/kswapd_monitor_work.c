#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kathrine");
MODULE_DESCRIPTION("Monitor kswapd and free pages in zones with process binding");

#define DIRNAME "memory_info"
#define FILENAME "kswapd_status"
#define SYMNAME "meminfo"
#define BUF_SIZE 4096

static struct proc_dir_entry *dir;
static struct proc_dir_entry *file;
static struct proc_dir_entry *sym;

static char monitor_buf[BUF_SIZE];
static int target_pid = -1;

#define PARSE_SIZE 16


// Упрощенная функция для получения информации о процессе
static void get_simple_process_info(struct task_struct *task, char *buf, size_t *offset, size_t size)
{
    if (!task)
        return;
    
    *offset += snprintf(buf + *offset, size - *offset,
                       "Name:           %s\n", task->comm);
    *offset += snprintf(buf + *offset, size - *offset,
                       "PID:            %d\n", task->pid);
    *offset += snprintf(buf + *offset, size - *offset,
                       "State:          %u\n", task->__state);
    *offset += snprintf(buf + *offset, size - *offset,
                       "Flags:          %#x\n", task->flags);
    
    // Попробуем получить информацию о памяти через /proc (симулируем)
    *offset += snprintf(buf + *offset, size - *offset,
                       "Memory info:    [Use 'ps aux' for detailed memory info]\n");
    
    if (task->mm) {
        unsigned long rss_pages = get_mm_rss(task->mm);
        *offset += snprintf(buf + *offset, size - *offset,
                           "RSS (approx):   %lu pages (%lu MB)\n",
                           rss_pages, pages_to_mb(rss_pages));
    }
}

// Получение информации о памяти (упрощенная версия для WSL2)
static void get_memory_info(char *buf, size_t size, size_t *offset)
{
    struct sysinfo si;
    
    *offset += snprintf(buf + *offset, size - *offset, 
                       "\n=== Memory Information ===\n");
    
    // Используем si_meminfo для получения информации о памяти
    si_meminfo(&si);
    
    *offset += snprintf(buf + *offset, size - *offset,
                       "Total RAM:      %lu pages (%lu MB)\n",
                       si.totalram, pages_to_mb(si.totalram));
    *offset += snprintf(buf + *offset, size - *offset,
                       "Free RAM:       %lu pages (%lu MB)\n",
                       si.freeram, pages_to_mb(si.freeram));
    *offset += snprintf(buf + *offset, size - *offset,
                       "Used RAM:       %lu pages (%lu MB)\n",
                       si.totalram - si.freeram, 
                       pages_to_mb(si.totalram - si.freeram));
    
    if (si.totalram > 0) {
        *offset += snprintf(buf + *offset, size - *offset,
                           "Memory Usage:   %lu%%\n",
                           ((si.totalram - si.freeram) * 100) / si.totalram);
    }
}

// Получение информации о kswapd
static void get_kswapd_info(char *buf, size_t size, size_t *offset)
{
    struct task_struct *task;
    int kswapd_found = 0;
    
    *offset += snprintf(buf + *offset, size - *offset,
                       "\n=== KSWAPD Information ===\n");
    
    // Находим kswapd задачу
    rcu_read_lock();
    for_each_process(task) {
        if (task->flags & PF_KSWAPD) {
            kswapd_found = 1;
            break;
        }
    }
    rcu_read_unlock();
    
    if (kswapd_found && task) {
        *offset += snprintf(buf + *offset, size - *offset,
                           "kswapd PID:     %d\n", task->pid);
        *offset += snprintf(buf + *offset, size - *offset,
                           "kswapd Name:    %s\n", task->comm);
        *offset += snprintf(buf + *offset, size - *offset,
                           "kswapd State:   %u\n", task->__state);
        *offset += snprintf(buf + *offset, size - *offset,
                           "kswapd Flags:   %#x (PF_KSWAPD set)\n", task->flags);
    } else {
        *offset += snprintf(buf + *offset, size - *offset,
                           "kswapd: Not found or not running\n");
        *offset += snprintf(buf + *offset, size - *offset,
                           "Note: kswapd may not be needed in WSL2\n");
    }
}

// Получение списка процессов (упрощенное)
static void get_process_list(char *buf, size_t size, size_t *offset)
{
    struct task_struct *task;
    int count = 0;
    const int max_processes = 15;
    
    *offset += snprintf(buf + *offset, size - *offset,
                       "\n=== Active Processes (top %d) ===\n", max_processes);
    *offset += snprintf(buf + *offset, size - *offset,
                       "%-8s %-20s %-12s\n",
                       "PID", "Name", "State");
    *offset += snprintf(buf + *offset, size - *offset,
                       "-----------------------------------\n");
    
    rcu_read_lock();
    for_each_process(task) {
        if (count++ >= max_processes)
            break;
        
        *offset += snprintf(buf + *offset, size - *offset,
                           "%-8d %-20s %-12u\n",
                           task->pid,
                           task->comm,
                           task->__state);
    }
    rcu_read_unlock();
}

static ssize_t monitor_read(struct file *filp, char __user *buf, 
                           size_t count, loff_t *offset)
{
    struct task_struct *target_task = NULL;
    size_t len;
    size_t buf_offset = 0;
    
    printk(KERN_INFO " + kswapd_monitor read: offset=%lld, count=%zu\n", 
           *offset, count);
    
    if (*offset > 0) {
        return 0;
    }
    
    if (count >= BUF_SIZE) {
        count = BUF_SIZE - 1;
    }
    
    // Очищаем буфер
    memset(monitor_buf, 0, BUF_SIZE);
    
    // Заголовок
    buf_offset += snprintf(monitor_buf + buf_offset, BUF_SIZE - buf_offset,
                          "=== Memory and KSWAPD Monitor ===\n");
    buf_offset += snprintf(monitor_buf + buf_offset, BUF_SIZE - buf_offset,
                          "Module: kswapd_monitor (WSL2 compatible)\n\n");
    
    // Если указан PID, показываем информацию о конкретном процессе
    if (target_pid > 0) {
        target_task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
        if (target_task) {
            buf_offset += snprintf(monitor_buf + buf_offset, BUF_SIZE - buf_offset,
                                  "=== Process %d Information ===\n", target_pid);
            get_simple_process_info(target_task, monitor_buf, &buf_offset, BUF_SIZE);
        } else {
            buf_offset += snprintf(monitor_buf + buf_offset, BUF_SIZE - buf_offset,
                                  "\nProcess with PID %d not found\n", target_pid);
        }
    }
    
    // Получаем информацию о памяти
    get_memory_info(monitor_buf, BUF_SIZE, &buf_offset);
    
    // Информация о kswapd
    get_kswapd_info(monitor_buf, BUF_SIZE, &buf_offset);
    
    // Список процессов (только если не выбран конкретный PID)
    if (target_pid <= 0) {
        get_process_list(monitor_buf, BUF_SIZE, &buf_offset);
    }
    
    buf_offset += snprintf(monitor_buf + buf_offset, BUF_SIZE - buf_offset,
                          "\n=== Usage ===\n");
    buf_offset += snprintf(monitor_buf + buf_offset, BUF_SIZE - buf_offset,
                          "To monitor specific process: echo PID > /proc/%s/%s\n", 
                          DIRNAME, FILENAME);
    buf_offset += snprintf(monitor_buf + buf_offset, BUF_SIZE - buf_offset,
                          "To show all info: echo -1 > /proc/%s/%s\n", 
                          DIRNAME, FILENAME);
    
    len = buf_offset < count ? buf_offset : count;
    
    if (copy_to_user(buf, monitor_buf, len)) {
        return -EFAULT;
    }
    
    *offset += len;
    return len;
}

static ssize_t monitor_write(struct file *filp, const char __user *buf, 
                            size_t count, loff_t *offset)
{
    char ubuf[PARSE_SIZE];
    
    printk(KERN_INFO " + kswapd_monitor write: offset=%lld, count=%zu\n", 
           *offset, count);
    
    if (*offset > 0) {
        return 0;
    }
    
    if (count > PARSE_SIZE - 1) {
        count = PARSE_SIZE - 1;
    }
    
    if (copy_from_user(ubuf, buf, count)) {
        return -EFAULT;
    }
    
    ubuf[count] = '\0';
    
    if (kstrtoint(ubuf, 10, &target_pid)) {
        // Если не число, сбрасываем target_pid
        target_pid = -1;
        printk(KERN_INFO " + kswapd_monitor: Reset target PID\n");
    } else {
        printk(KERN_INFO " + kswapd_monitor: Set target PID to %d\n", target_pid);
    }
    
    return count;
}

static int proc_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "+ kswapd_monitor open\n");
    return 0;
}

static int proc_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "+ kswapd_monitor release\n");
    return 0;
}

static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_release = proc_release,
    .proc_read = monitor_read,
    .proc_write = monitor_write,
};

static int __init kswapd_monitor_init(void)
{
    printk(KERN_INFO "+ kswapd_monitor init\n");
    
    // Создаем директорию в /proc
    dir = proc_mkdir(DIRNAME, NULL);
    if (dir == NULL) {
        printk(KERN_ERR "+ proc_mkdir failed\n");
        return -ENOMEM;
    }
    
    // Создаем файл в директории
    file = proc_create(FILENAME, 0666, dir, &proc_fops);
    if (file == NULL) {
        printk(KERN_ERR "+ proc_create failed\n");
        proc_remove(dir);
        return -ENOMEM;
    }
    
    // // Создаем символическую ссылку
    // sym = proc_symlink(SYMNAME, NULL, DIRNAME "/" FILENAME);
    // if (sym == NULL) {
    //     printk(KERN_ERR "+ proc_symlink failed\n");
    //     proc_remove(file);
    //     proc_remove(dir);
    //     return -ENOMEM;
    // }
    
    printk(KERN_INFO "+ kswapd_monitor module loaded successfully\n");
    printk(KERN_INFO "+ Access via: /proc/%s/%s or /proc/%s\n", 
           DIRNAME, FILENAME, SYMNAME);
    
    return 0;
}

static void __exit kswapd_monitor_exit(void)
{
    printk(KERN_INFO "+ kswapd_monitor exit\n");
    
    // Удаляем proc entries
    proc_remove(sym);
    proc_remove(file);
    proc_remove(dir);
    
    printk(KERN_INFO "+ kswapd_monitor module unloaded\n");
}

module_init(kswapd_monitor_init);
module_exit(kswapd_monitor_exit);