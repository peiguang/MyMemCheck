#include "addr2sym.hpp"              // 包含地址到符号名转换的头文件
#include "plot_actions.hpp"          // 包含内存操作绘图相关函数的头文件
#include <atomic>                    // 包含原子操作支持
#include <cerrno>                    // 包含错误码 errno 定义
#include <chrono>                    // 包含时间测量相关类（如 high_resolution_clock）
#include <cstdlib>                   // 包含 C 标准库函数（如 malloc/free）
#include <deque>                     // 包含双端队列容器 deque
#include <fstream>                   // 包含文件流操作，用于写入导出文件
#include <mutex>                     // 包含互斥锁，用于线程同步
#include <new>                       // 包含 C++ new/delete 操作符及异常（如 std::bad_alloc）
#include <thread>                    // 包含多线程支持
#include <vector>                    // 包含向量容器 vector

#if __unix__
# include <sys/mman.h>              // Unix 系统下包含内存映射相关函数（如 mmap）
# include <unistd.h>                // Unix 系统下包含系统调用函数（如 gettid）
# define MALLOCVIS_EXPORT          // Unix 下导出宏，此处为空
#elif _WIN32
# include <windows.h>               // Windows 系统下包含 Windows API 函数（如 VirtualAlloc）
# define MALLOCVIS_EXPORT          // Windows 下导出宏，可定义为 __declspec(dllexport)（此处为空）
#endif

#if __cplusplus >= 201703L || __cpp_lib_memory_resource
# include <memory_resource>         // 如果 C++17 或更高版本支持，则包含 polymorphic memory resource 头文件
#endif
#if __cpp_lib_memory_resource
# define PMR std::pmr            // 定义 PMR 别名为 std::pmr
# define PMR_RES(x) \
     { x }                       // 用于在容器构造时传递内存资源
# define HAS_PMR 1               // 表示支持 PMR
#else
# define PMR std                // 不支持 PMR 则直接使用 std 命名空间
# define PMR_RES(x)             // 空定义
# define HAS_PMR 0              // 表示不支持 PMR
#endif
#include "alloc_action.hpp"         // 包含内存分配操作记录 AllocAction 的定义

// 开启一个匿名命名空间，防止内部符号被外部链接
namespace {

// 获取当前线程的唯一标识符（跨平台实现）
uint32_t get_thread_id() {
#if __unix__
    return gettid();              // 在 Unix 系统中调用 gettid() 获取线程ID
#elif _WIN32
    return GetCurrentThreadId();  // 在 Windows 系统中调用 GetCurrentThreadId() 获取线程ID
#else
    return 0;                     // 其他平台返回 0
#endif
}

// 定义每个线程独立的数据结构，按 64 字节对齐以避免伪共享
struct alignas(64) PerThreadData {
#if HAS_PMR
    size_t const bufsz = 64 * 1024 * 1024;  // 定义 64MB 的缓冲区大小，用于 PMR 内存资源
# if __unix__
    void *buf = mmap(nullptr, bufsz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // Unix 下使用 mmap 分配内存
# elif _WIN32
    void *buf =
        VirtualAlloc(nullptr, bufsz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); // Windows 下使用 VirtualAlloc 分配内存
# else
    static char buf[bufsz];      // 其他平台使用静态数组作为缓冲区
# endif
    // 利用缓冲区创建单调内存资源，后续所有 PMR 内存分配都从这里分配
    std::pmr::monotonic_buffer_resource mono{buf, bufsz};
    // 基于单调内存资源创建一个无锁内存池，用于后续容器内存分配
    std::pmr::unsynchronized_pool_resource pool{&mono};
#endif

    std::recursive_mutex lock;     // 递归互斥锁，保护下面的日志容器 actions
    PMR::deque<AllocAction> actions PMR_RES(&pool); // 日志队列，存储每次内存操作记录；如果支持 PMR，则使用自定义内存池
    bool enable = false;           // 标记是否启用日志记录，默认关闭
};

// 全局数据结构，用于管理所有线程的日志数据及导出操作
struct GlobalData {
//    std::mutex lock;             // 注释掉的全局锁（未使用）

    static inline size_t const kPerThreadsCount = 8;  // 定义预设的线程数据槽数为 8
    PerThreadData per_threads[kPerThreadsCount];      // 定义 8 个线程数据槽
    bool export_plot_on_exit = true;                  // 是否在程序退出时导出绘图
#if HAS_THREADS
    std::thread export_thread;    // 可选的导出线程对象
#endif
    std::atomic<bool> stopped{false}; // 用于标记导出线程是否应该停止（原子操作）

    // GlobalData 构造函数
    GlobalData() {
#if HAS_THREADS
        if (0) {  // 目前该功能被禁用（if(0)），如果启用则启动一个后台导出线程
            std::string path = "malloc.fifo";
            export_thread = std::thread([this, path] {
                get_per_thread(get_thread_id())->enable = false; // 禁用当前线程的记录
                export_thread_entry(path);                      // 进入导出线程入口函数
            });
            export_plot_on_exit = false;  // 关闭退出时自动绘图，因为后台线程会处理
        }
#endif
        // 启动时默认启用每个线程数据槽的记录功能
        for (size_t i = 0; i < kPerThreadsCount; ++i) {
            per_threads[i].enable = true;
        }
    }

    // 根据当前线程ID返回对应的 PerThreadData 数据槽（简单的哈希映射）
    PerThreadData *get_per_thread(uint32_t tid) {
        return per_threads + ((size_t)tid * 17) % kPerThreadsCount;
    }

#if HAS_THREADS
    // 导出线程的入口函数，将所有线程的日志记录写入指定的文件中
    void export_thread_entry(std::string const &path) {
# if HAS_PMR
        size_t const bufsz = 64 * 1024 * 1024; // 分配 64MB 内存缓冲区
#  if __unix__
        void *buf = mmap(nullptr, bufsz, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // Unix 下使用 mmap
#  elif _WIN32
        void *buf = VirtualAlloc(nullptr, bufsz, MEM_RESERVE | MEM_COMMIT,
                                 PAGE_READWRITE); // Windows 下使用 VirtualAlloc
#  else
        static char buf[bufsz];  // 其他平台使用静态数组
#  endif
        // 使用缓冲区创建单调内存资源和内存池
        std::pmr::monotonic_buffer_resource mono{buf, bufsz};
        std::pmr::unsynchronized_pool_resource pool{&mono};
# endif

        std::ofstream out(path, std::ios::binary); // 打开二进制输出文件
        PMR::deque<AllocAction> actions PMR_RES(&pool); // 创建一个临时日志队列
        while (!stopped.load(std::memory_order_acquire)) { // 循环直到收到停止信号
            // 遍历每个线程的数据槽
            for (auto &per_thread: per_threads) {
                std::unique_lock<std::recursive_mutex> guard(per_thread.lock); // 锁定当前线程数据槽
                auto thread_actions = std::move(per_thread.actions); // 移动该线程所有日志记录
                guard.unlock(); // 解锁
                // 将当前线程的日志记录追加到总队列中
                actions.insert(actions.end(), thread_actions.begin(),
                               thread_actions.end());
            }
            // 如果有日志记录，则写入文件
            if (!actions.empty()) {
                for (auto &action: actions) {
                    out.write((char const *)&action, sizeof(AllocAction));
                }
                actions.clear(); // 写入后清空队列
            }
            // 休眠 1 毫秒以降低 CPU 占用
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        // 循环结束前，采集一次所有线程剩余的日志记录
        for (auto &per_thread: per_threads) {
            std::unique_lock<std::recursive_mutex> guard(per_thread.lock);
            auto thread_actions = std::move(per_thread.actions);
            guard.unlock();
            actions.insert(actions.end(), thread_actions.begin(),
                           thread_actions.end());
        }
        if (!actions.empty()) {
            for (auto &action: actions) {
                out.write((char const *)&action, sizeof(AllocAction));
            }
            actions.clear();
        }
    }
#endif

    // GlobalData 析构函数，在程序退出时进行清理和导出日志（或绘图）
    ~GlobalData() {
        // 先禁用所有线程的数据槽，不再记录日志
        for (size_t i = 0; i < kPerThreadsCount; ++i) {
            per_threads[i].enable = false;
        }
        // 如果导出线程正在运行，则发送停止信号并等待其结束
        if (export_thread.joinable()) {
            stopped.store(true, std::memory_order_release);
            export_thread.join();
        }
        // 如果设置了在退出时导出绘图，则收集所有日志记录并调用绘图函数
        if (export_plot_on_exit) {
            std::vector<AllocAction> actions;
            for (size_t i = 0; i < kPerThreadsCount; ++i) {
                auto &their_actions = per_threads[i].actions;
                actions.insert(actions.end(), their_actions.begin(),
                               their_actions.end());
            }
            // 调用绘图函数，将收集到的内存分配操作传递过去
            mallocvis_plot_alloc_actions(std::move(actions));
        }
    }
};

GlobalData *global = nullptr;         // 定义一个全局 GlobalData 指针，初始为空

// EnableGuard 类用于在内存分配函数中临时禁用日志记录，防止递归调用
struct EnableGuard {
    uint32_t tid;                 // 当前线程 ID
    bool was_enable;              // 保存进入前日志记录是否启用的状态
    PerThreadData *per_thread;    // 指向当前线程对应的日志数据结构

    // 构造函数：获取当前线程数据，并禁用日志记录
    EnableGuard()
        : tid(get_thread_id()),
          per_thread(global ? global->get_per_thread(tid) : nullptr) {
        if (!per_thread) {
            was_enable = false; // 如果未获取到线程数据，则认为记录未启用
        } else {
            per_thread->lock.lock();  // 加锁保护数据
            was_enable = per_thread->enable; // 保存原来的 enable 状态
            per_thread->enable = false;      // 禁用日志记录，防止递归调用
        }
    }

    // 重载 bool 转换运算符，用于判断是否原本启用了日志记录
    explicit operator bool() const {
        return was_enable;
    }

    // on() 方法：在内存操作发生时记录一条日志记录
    void on(AllocOp op, void *ptr, size_t size, size_t align,
            void *caller) const {
        if (ptr) {  // 如果指针有效
            // 获取当前高精度时间点，并计算从 epoch 开始的纳秒数
            auto now = std::chrono::high_resolution_clock::now();
            int64_t time = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               now.time_since_epoch())
                               .count();
            // 将一次内存操作记录（包含操作类型、线程ID、指针、大小、对齐、调用者返回地址和时间戳）加入日志队列
            per_thread->actions.push_back(
                AllocAction{op, tid, ptr, size, align, caller, time});
        }
    }

    // 析构函数：在作用域结束时恢复 enable 状态并解锁
    ~EnableGuard() {
        if (per_thread) {
            per_thread->enable = was_enable;  // 恢复进入前的 enable 状态
            per_thread->lock.unlock();          // 解锁
        }
    }
};

} // 结束匿名命名空间

// 以下部分根据不同编译器设置真实内存分配函数和返回地址获取方式

#if __GNUC__
extern "C" void *__libc_malloc(size_t size) noexcept; // 声明 GNU libc 的 malloc
extern "C" void __libc_free(void *ptr) noexcept;       // 声明 GNU libc 的 free
extern "C" void *__libc_calloc(size_t nmemb, size_t size) noexcept; // 声明 calloc
extern "C" void *__libc_realloc(void *ptr, size_t size) noexcept;     // 声明 realloc
extern "C" void *__libc_reallocarray(void *ptr, size_t nmemb,
                                     size_t size) noexcept;         // 声明 reallocarray
extern "C" void *__libc_valloc(size_t size) noexcept;    // 声明 valloc
extern "C" void *__libc_memalign(size_t align, size_t size) noexcept;  // 声明 memalign
# define REAL_LIBC(name) __libc_##name                  // 定义 REAL_LIBC 宏为 GNU libc 对应函数
# ifndef MAY_OVERRIDE_MALLOC
#  define MAY_OVERRIDE_MALLOC 1                        // 允许重写 malloc
# endif
# ifndef MAY_OVERRIDE_MEMALIGN
#  define MAY_SUPPORT_MEMALIGN 1                       // 允许支持 memalign 重写
# endif
# undef RETURN_ADDRESS
# ifdef __has_builtin
#  if __has_builtin(__builtin_return_address)
#   if __has_builtin(__builtin_extract_return_addr)
#    define RETURN_ADDRESS \
        __builtin_extract_return_addr(__builtin_return_address(0))  // 使用内建函数提取返回地址
#   else
#    define RETURN_ADDRESS __builtin_return_address(0)
#   endif
#  endif
# elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)
#  define RETURN_ADDRESS __builtin_return_address(0)
# endif
# ifndef RETURN_ADDRESS
#  define RETURN_ADDRESS ((void *)0)   // 如果无法获取返回地址则返回 0
#  pragma message("Cannot find __builtin_return_address")
# endif
# define CSTDLIB_NOEXCEPT noexcept      // 定义异常规范为 noexcept
#elif _MSC_VER
// Microsoft Visual C++ 实现
static void *msvc_malloc(size_t size) noexcept {
    return HeapAlloc(GetProcessHeap(), 0, size); // 使用 HeapAlloc 分配内存
}

static void *msvc_calloc(size_t nmemb, size_t size) noexcept {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nmemb * size); // 分配并初始化为 0
}

static void msvc_free(void *ptr) noexcept {
    HeapFree(GetProcessHeap(), 0, ptr); // 使用 HeapFree 释放内存
}

static void *msvc_realloc(void *ptr, size_t size) noexcept {
    return HeapReAlloc(GetProcessHeap(), 0, ptr, size); // 使用 HeapReAlloc 重新分配内存
}

static void *msvc_reallocarray(void *ptr, size_t nmemb, size_t size) noexcept {
    return msvc_realloc(ptr, nmemb * size); // 根据元素个数和大小计算总大小重新分配内存
}

# define REAL_LIBC(name) msvc_##name     // 定义 REAL_LIBC 为 msvc_ 前缀函数
# ifndef MAY_OVERRIDE_MALLOC
#  define MAY_OVERRIDE_MALLOC 0         // MSVC 下通常不重写 malloc
# endif
# ifndef MAY_OVERRIDE_MEMALIGN
#  define MAY_SUPPORT_MEMALIGN 0        // MSVC 下不支持重写 memalign
# endif

# include <intrin.h>                    // 包含内置函数头文件

# pragma intrinsic(_ReturnAddress)      // 声明 _ReturnAddress 为内置函数
# define RETURN_ADDRESS _ReturnAddress() // 使用 _ReturnAddress() 获取返回地址
# define CSTDLIB_NOEXCEPT               // 定义空的异常规范
#else
# define REAL_LIBC(name) name           // 其他编译器直接使用标准函数名
# ifndef MAY_OVERRIDE_MALLOC
#  define MAY_OVERRIDE_MALLOC 0
# endif
# ifndef MAY_OVERRIDE_MEMALIGN
#  define MAY_SUPPORT_MEMALIGN 0
# endif
# define RETURN_ADDRESS ((void *)1)     // 返回地址占位值
# define CSTDLIB_NOEXCEPT
#endif

// 如果允许重写 malloc，则下面重载一系列内存分配函数
#if MAY_OVERRIDE_MALLOC
MALLOCVIS_EXPORT extern "C" void *malloc(size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                    // 进入 malloc 时构造 EnableGuard 对象，临时禁用记录
    void *ptr = REAL_LIBC(malloc)(size);                // 调用真实的 malloc 分配内存
    if (ena) {                                         // 如果原本允许记录
        ena.on(AllocOp::Malloc, ptr, size, kNone, RETURN_ADDRESS); // 记录一次 malloc 操作
    }
    return ptr;                                        // 返回分配得到的内存指针
}

MALLOCVIS_EXPORT extern "C" void free(void *ptr) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::Free, ptr, kNone, kNone, RETURN_ADDRESS); // 记录 free 操作
    }
    REAL_LIBC(free)(ptr);                              // 调用真实的 free 释放内存
}

MALLOCVIS_EXPORT extern "C" void *calloc(size_t nmemb,
                                         size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(calloc)(nmemb, size);          // 调用真实的 calloc 分配内存
    if (ena) {
        ena.on(AllocOp::Malloc, ptr, nmemb * size, kNone, RETURN_ADDRESS); // 记录分配操作（使用 Malloc 记录）
    }
    return ptr;                                        // 返回分配得到的内存指针
}

MALLOCVIS_EXPORT extern "C" void *realloc(void *ptr,
                                          size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *new_ptr = REAL_LIBC(realloc)(ptr, size);       // 调用真实的 realloc 重新分配内存
    if (ena) {
        ena.on(AllocOp::Malloc, new_ptr, size, kNone, RETURN_ADDRESS); // 记录新内存分配操作
        if (new_ptr) {
            ena.on(AllocOp::Free, ptr, kNone, kNone, RETURN_ADDRESS);  // 如果成功，记录原内存释放操作
        }
    }
    return new_ptr;                                    // 返回新内存指针
}

MALLOCVIS_EXPORT extern "C" void *reallocarray(void *ptr, size_t nmemb,
                                               size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *new_ptr = REAL_LIBC(reallocarray)(ptr, nmemb, size); // 调用 reallocarray 重新分配内存
    if (ena) {
        ena.on(AllocOp::Malloc, new_ptr, nmemb * size, kNone, RETURN_ADDRESS); // 记录分配操作
        if (new_ptr) {
            ena.on(AllocOp::Free, ptr, kNone, kNone, RETURN_ADDRESS); // 记录释放操作
        }
    }
    return new_ptr;                                    // 返回新内存指针
}

# if MAY_SUPPORT_MEMALIGN
MALLOCVIS_EXPORT extern "C" void *valloc(size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(valloc)(size);               // 调用 valloc 分配内存
    if (ena) {
#  if __unix__
        size_t pagesize = sysconf(_SC_PAGESIZE);       // Unix 下获取页面大小
#  elif _WIN32
        SYSTEM_INFO info;
        info.dwPageSize = kNone;
        GetSystemInfo(&info);                           // Windows 下获取系统页面大小
        size_t pagesize = info.dwPageSize;
#  else
        size_t pagesize = 0;
#  endif
        ena.on(AllocOp::Malloc, ptr, size, pagesize, RETURN_ADDRESS); // 记录分配操作，同时记录页面对齐信息
    }
    return ptr;                                        // 返回分配得到的内存指针
}

MALLOCVIS_EXPORT extern "C" void *memalign(size_t align,
                                           size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(memalign)(align, size);        // 调用 memalign 分配对齐内存
    if (ena) {
        ena.on(AllocOp::Malloc, ptr, size, align, RETURN_ADDRESS); // 记录分配操作，记录对齐信息
    }
    return ptr;
}

MALLOCVIS_EXPORT extern "C" void *aligned_alloc(size_t align,
                                                size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(memalign)(align, size);        // 使用 memalign 实现 aligned_alloc
    if (ena) {
        ena.on(AllocOp::Malloc, ptr, size, align, RETURN_ADDRESS); // 记录分配操作
    }
    return ptr;
}

MALLOCVIS_EXPORT extern "C" int posix_memalign(void **memptr, size_t align,
                                               size_t size) CSTDLIB_NOEXCEPT {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(memalign)(align, size);        // 调用 memalign 分配内存
    if (ena) {
        ena.on(AllocOp::Malloc, *memptr, size, align, RETURN_ADDRESS); // 记录操作
    }
    int ret = 0;
    if (!ptr) {
        ret = errno;                                   // 如果分配失败，则返回 errno 错误码
    } else {
        *memptr = ptr;                                 // 分配成功则将指针赋值给输出参数
    }
    return ret;                                        // 返回错误码（0 表示成功）
}
# endif
#endif

// 重载 C++ 的 delete 操作符
MALLOCVIS_EXPORT void operator delete(void *ptr) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::Delete, ptr, kNone, kNone, RETURN_ADDRESS); // 记录 delete 操作
    }
    REAL_LIBC(free)(ptr);                              // 调用真实的 free 释放内存
}

MALLOCVIS_EXPORT void operator delete[](void *ptr) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::DeleteArray, ptr, kNone, kNone, RETURN_ADDRESS); // 记录数组 delete 操作
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void operator delete(void *ptr,
                                      std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::Delete, ptr, kNone, kNone, RETURN_ADDRESS);
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void operator delete[](void *ptr,
                                        std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::DeleteArray, ptr, kNone, kNone, RETURN_ADDRESS);
    }
    REAL_LIBC(free)(ptr);
}

// 重载 C++ 的 new 操作符
MALLOCVIS_EXPORT void *operator new(size_t size) noexcept(false) {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(malloc)(size);               // 调用真实的 malloc 分配内存
    if (ena) {
        ena.on(AllocOp::New, ptr, size, kNone, RETURN_ADDRESS); // 记录 new 操作
    }
    if (ptr == nullptr) {
        throw std::bad_alloc();                        // 分配失败则抛出 bad_alloc 异常
    }
    return ptr;                                        // 返回分配的内存指针
}

MALLOCVIS_EXPORT void *operator new[](size_t size) noexcept(false) {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(malloc)(size);               // 分配数组内存
    if (ena) {
        ena.on(AllocOp::NewArray, ptr, size, kNone, RETURN_ADDRESS); // 记录 new 数组操作
    }
    if (ptr == nullptr) {
        throw std::bad_alloc();
    }
    return ptr;
}

MALLOCVIS_EXPORT void *operator new(size_t size,
                                    std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(malloc)(size);               // 分配内存，不抛异常
    if (ena) {
        ena.on(AllocOp::New, ptr, size, kNone, RETURN_ADDRESS);
    }
    return ptr;
}

MALLOCVIS_EXPORT void *operator new[](size_t size,
                                      std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(malloc)(size);               // 分配数组内存，不抛异常
    if (ena) {
        ena.on(AllocOp::NewArray, ptr, size, kNone, RETURN_ADDRESS);
    }
    return ptr;
}

#if (__cplusplus >= 201402L || _MSC_VER >= 1916)
MALLOCVIS_EXPORT void operator delete(void *ptr, size_t size) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::Delete, ptr, size, kNone, RETURN_ADDRESS); // 记录带 size 的 delete 操作
    }
    REAL_LIBC(free)(ptr);                              // 释放内存
}

MALLOCVIS_EXPORT void operator delete[](void *ptr, size_t size) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::DeleteArray, ptr, size, kNone, RETURN_ADDRESS); // 记录带 size 的数组 delete 操作
    }
    REAL_LIBC(free)(ptr);
}
#endif

#if (__cplusplus > 201402L || defined(__cpp_aligned_new))
# if MAY_SUPPORT_MEMALIGN
MALLOCVIS_EXPORT void operator delete(void *ptr,
                                      std::align_val_t align) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::Delete, ptr, kNone, (size_t)align, RETURN_ADDRESS); // 记录带对齐信息的 delete 操作
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void operator delete[](void *ptr,
                                        std::align_val_t align) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::DeleteArray, ptr, kNone, (size_t)align, RETURN_ADDRESS);
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void operator delete(void *ptr, size_t size,
                                      std::align_val_t align) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::Delete, ptr, size, (size_t)align, RETURN_ADDRESS);
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void operator delete[](void *ptr, size_t size,
                                        std::align_val_t align) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::DeleteArray, ptr, size, (size_t)align, RETURN_ADDRESS);
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void operator delete(void *ptr, std::align_val_t align,
                                      std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::Delete, ptr, kNone, (size_t)align, RETURN_ADDRESS);
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void operator delete[](void *ptr, std::align_val_t align,
                                        std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    if (ena) {
        ena.on(AllocOp::DeleteArray, ptr, kNone, (size_t)align, RETURN_ADDRESS);
    }
    REAL_LIBC(free)(ptr);
}

MALLOCVIS_EXPORT void *operator new(size_t size,
                                    std::align_val_t align) noexcept(false) {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(memalign)((size_t)align, size); // 使用 memalign 分配对齐内存
    if (ena) {
        ena.on(AllocOp::New, ptr, size, (size_t)align, RETURN_ADDRESS);
    }
    if (ptr == nullptr) {
        throw std::bad_alloc();
    }
    return ptr;
}

MALLOCVIS_EXPORT void *operator new[](size_t size,
                                      std::align_val_t align) noexcept(false) {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(memalign)((size_t)align, size);
    if (ena) {
        ena.on(AllocOp::NewArray, ptr, size, (size_t)align, RETURN_ADDRESS);
    }
    if (ptr == nullptr) {
        throw std::bad_alloc();
    }
    return ptr;
}

MALLOCVIS_EXPORT void *operator new(size_t size, std::align_val_t align,
                                    std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(memalign)((size_t)align, size);
    if (ena) {
        ena.on(AllocOp::New, ptr, size, (size_t)align, RETURN_ADDRESS);
    }
    return ptr;
}

MALLOCVIS_EXPORT void *operator new[](size_t size, std::align_val_t align,
                                      std::nothrow_t const &) noexcept {
    EnableGuard ena;                                   // 构造 EnableGuard 对象
    void *ptr = REAL_LIBC(memalign)((size_t)align, size);
    if (ena) {
        ena.on(AllocOp::NewArray, ptr, size, (size_t)align, RETURN_ADDRESS);
    }
    return ptr;
}
# endif
#endif

#if MANUAL_GLOBAL_INIT
alignas(GlobalData) static char global_buf[sizeof(GlobalData)]; // 定义对齐后的全局缓冲区，用于手动初始化 GlobalData

// 以下初始化/销毁函数可通过构造/析构属性自动调用（此处被注释掉了）
// # if __has_attribute(__constructor__) && __has_attribute(__destructor__)
// #  define GLOBAL_INIT_PRIORITY 101
// # endif

// __attribute__((__constructor__(GLOBAL_INIT_PRIORITY)))
void mallocvis_init() {
    global = new (&global_buf) GlobalData();          // 在全局缓冲区上构造 GlobalData 对象
}

// __attribute__((__destructor__(GLOBAL_INIT_PRIORITY)))
void mallocvis_deinit() {
    if (global) {
        global->~GlobalData();                          // 显式调用析构函数清理 GlobalData 对象
        global = nullptr;
    }
}
#else
static GlobalData global_buf;                           // 使用静态全局变量自动初始化 GlobalData
static int global_init_helper = (global = &global_buf, 0); // 初始化全局指针 global 指向 global_buf
#endif