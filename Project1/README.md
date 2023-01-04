# Linux Project 1

## 目標
1. 寫一個 system call 從 kernel space 找出指定 process(task) 的 code(text) 段的位址
2. user 段程式利用 system call 傳入 pid 並取得結果放至 user space 的 buffer 上，再輸出至 terminal 上。
>https://hackmd.io/t2tM_VFoTkyike6zlCmLWA?view
## 先備知識

asmlinkage與SYSCALL_DEFINEn(巨集)都是讓function call與底層溝通的syscall，差異在asmlinkage偏向於特製化syscall功能，編譯速度快但是開發速度較慢，而SYSCALL_DEFINEn算是提供function call一個泛用的syscall功能，給予該巨集function name跟parameter對該function做類似的system call功能，在開發速度上會比較快但編譯速度比較慢。

## 實驗

#### 程式碼
```clike=
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/syscalls.h>

struct data_segment
{
        unsigned long start_code;
        unsigned long end_code;
};


SYSCALL_DEFINE2(pass_kernel_data, pid_t, user_pid,  void*, __user user_address){


        struct data_segment my_data_segment;
        struct task_struct *task;
        for_each_process(task)
        {
                if(task->pid == user_pid)
                {

                        my_data_segment.start_code = task->mm->start_code;
                        my_data_segment.end_code = task->mm->end_code;
                        copy_to_user(user_address, &my_data_segment, sizeof(struct data_segment));
                        break;
                }
        }

        return 0;
}
```

```clike=
#include<syscall.h>
#include<sys/types.h>
#include<stdio.h>
#include<unistd.h>
#include<time.h>

struct data_segment{

        unsigned long start_code;
        unsigned long end_code;

};

#define __NR_pass_kernel_data 443


int main(){

        struct data_segment my_data_segment;
        //用system call 從 kernel space 中傳出這個process的 code段的起始與結束address
        int a = syscall(__NR_pass_kernel_data,  getpid(), (void*)&my_data_segment);

        printf("Start: %lx\nEnd: %lx\n", my_data_segment.start_code, my_data_segment.end_code);

        return 0;
}
```

印出code segment的virtual address
![](https://i.imgur.com/PBNqgmB.png)
