#pragma once
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

class ThreadPool {
   public:
    ThreadPool(int threadNumbers);

    template <class T, class R = std::result_of_t<T()>>
    std::future<R> addTask(T&& task) {
        if (isAborted || isNeedToShutDown) return {};

        std::future<R> taskFuture;
        {
            std::lock_guard lock(tasksMutex);
            auto wrappedTask = std::packaged_task<R()>(std::forward<T>(task));
            taskFuture = wrappedTask.get_future();
            pendingTasks.emplace_back(move(wrappedTask));
        }

        taskExistsCondition.notify_one();

        return taskFuture;
    }

    void restart(int threadNumbers);
    void abortNow();
    void abortWaitPendingTasks();
    ~ThreadPool();

   private:
    void workerFunc(int num);
    void addWorkers(int threadNumbers);

   private:
    std::mutex tasksMutex;
    std::condition_variable taskExistsCondition;
    std::deque<std::packaged_task<void()>> pendingTasks;
    std::vector<std::thread> workers;
    std::atomic_bool isAborted = ATOMIC_VAR_INIT(false);
    std::atomic_bool isNeedToShutDown = ATOMIC_VAR_INIT(false);
};
