#include <iostream> // 引入输入输出流库
#include <thread> // 引入线程库

using namespace std::chrono_literals; // 使用chrono字面量

int main() {
    // 创建并启动线程t1
    std::thread t1([] {
        for (int i = 0; i < 10; ++i) {
            std::cout << "Thread 1: " << i << std::endl; // 输出线程1的计数值
            std::this_thread::sleep_for(10ms); // 休眠10毫秒
        }
    });

    // 创建并启动线程t2
    std::thread t2([] {
        for (int i = 0; i < 10; ++i) {
            std::cout << "Thread 2: " << i << std::endl; // 输出线程2的计数值
            std::this_thread::sleep_for(10ms); // 休眠10毫秒
        }
    });

    t1.join(); // 等待线程t1执行完毕
    t2.join(); // 等待线程t2执行完毕
    return 0; // 返回0，表示程序正常结束
}
