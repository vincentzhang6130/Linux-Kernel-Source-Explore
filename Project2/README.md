# Linux Project 2 

## 目標
1. 實作一個 system call ，功能是將複數個 virtual address 轉為 physical address。
2. 利用這個 system call 來檢查不同的 thread/process 的哪些 segment 會共用 memory。

>https://staff.csie.ncu.edu.tw/hsufh/COURSES/FALL2021/linux_project_2.html
 
## 先備知識

- Paging 機制是由硬體實現，kernel 啟動
> 維基百科 Wiki 的解釋
> Depending on the memory model, paged memory functionality is usually hardwired into a CPU/MCU by using a Memory Management Unit (MMU) or Memory Protection Unit (MPU) and ==separately enabled 啟用 by privileged system code in the operating system's kernel==.

- 為何需要Paging
> 為了解決==分割法 partitioning==所會導致的fragmentation，實現只要虛擬記憶體連續，並有辦法都對應到實體記憶體上，那在分配實體記憶體給Process時，就沒有一定得分配連續的實體記憶體給Process，也就不會有fragmentation。

- 為什麼需要multi-level paging
> 可以只載入部分的page table，就能存取到需要的physical address，不用載入整個page table，有助於減少記憶體用量。
![](https://i.imgur.com/GfGLgbU.png)

- VMA (Virtual Memory Allocation)
可以說是process在管理虛擬記憶體更高階的方式，

`strace` 指令把用到的system call都印出來

## Code Trace

fork
clone
mmap


## 實驗

- 實驗一，使用create了3個thread進行位址的轉換，了解有哪些位址是共用的。
- 我們宣告了使用不同segment(分段)的變數。
- 全域變數，放在data segment。
- 讀出main()的address，這是放在code segment
- Thread 的區域變數放在stack segment
- 未初始化的變數會放在BSS segment
- 動態記憶體分配的變數放在heap segment
- 共用的函式庫放在Memory Mapping Segment
```c==
unsigned long get_shr_mem_addr() {

        void *fHandle;
        fHandle = dlopen("/lib/x86_64-linux-gnu/libc-2.27.so",RTLD_LAZY);

        void (*func)(); //This a function pointer //point to a function which will return void
        unsigned long addr;
        if(!fHandle){
                fprintf(stderr,"%s\n", dlerror());
                return 0;

        }
        func = (void(*)())dlsym(fHandle,"printf"); // (void(*)()) 用來轉型成會回傳void的函式的function pointer
        addr = func;
        return addr;
}

```
- TLS ，用`__thread`來修飾變量，使每一個線程有一份獨立實體，各個線程的值互不幹擾。可以用來修飾那些帶有全局性且值可能變，但是又不值得用全局變量保護的變量，避免race condition，可用其修飾全域變數。
```c==
__thread int var = 1;
```

編譯 project2.c
```bash=
gcc project2.c -g -ldl -lpthread -o project2
```


|                    | Thread 1         | Thread 2         | Thread 3         |
|:------------------ |:---------------- |:---------------- |:---------------- |
| Code Virtual       | ==559fcc95dfa7== | ==559fcc95dfa7== | ==559fcc95dfa7== |
| Code Physical      | ==151207fa7==    | ==151207fa7==    | ==151207fa7==    |
| Data Virtual       | ==559fccb5f010== | ==559fccb5f010== | ==559fccb5f010== |
| Data Physical      | ==15fc41010==    | ==15fc41010==    | ==15fc41010==    |
| BSS Virtual        | 7f820b190d78     | 7f820a98fd78     | 7f820a18ed78     |
| BSS Physical       | 15fc46d78        | 152320d78        | 183f9dd78        |
| Heap Virtual       | 7f8204000f30     | 7f8204001000     | 7f8204001020     |
| Heap Physical      | 151e2df30        | 150c94000        | 150c94020        |
| Stack Virtual      | 7f820b190d74     | 7f820a98fd74     | 7f820a18ed74     |
| Stack Physical     | 15fc46d74        | 152320d74        | 183f9dd74        |
| TLS Virtual        | 7f820b1916fc     | 7f820a9906fc     | 7f820a18f6fc     |
| TLS Physical       | 15fc486fc        | 1517816fc        | 151c1b6fc        |
| Share Lib Virtual  | ==7f820b1f6e40== | ==7f820b1f6e40== | ==7f820b1f6e40== |
| Share Lib Physical | ==1b9f6ee40==    | ==1b9f6ee40==    | ==1b9f6ee40==    |

- 共用情形是否正確?，進一步思考thread 與process的差異
>From the perspective of the Linux kernel, thread and process are not treated differently.
We know that the system call fork() function can create a new child process. And the function pthread() can create a new thread. But both thread and process are represented by the task_struct structure. ==The only difference is the shared data area.==

![](https://i.imgur.com/hNZRDBv.jpg)

在 Linux 當中 process 和 thread 都是以 task_struct 結構描述，而兩者皆以 clone 系統呼叫建立，區別在於資源的管理。
task_struct 的 process address space 則是以 mm_struct 結構管理，以 task_struct->mm 方式呼叫。 process 和 thread 差別在於 threads 之間的 task_struct 會是指向同個 mm_struct 。

> https://hackmd.io/@linD026/Linux-kernel-COW-content/https%3A%2F%2Fhackmd.io%2F%40linD026%2FLinux-kernel-COW-memory-region
> 