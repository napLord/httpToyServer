#include "threadpool.h"

ThreadPool::ThreadPool(int threadNumbers) { addWorkers(threadNumbers); }


void ThreadPool::restart(int threadNumbers) {
    abortWaitPendingTasks();

    assert(workers.empty());

    isAborted = false;
    isNeedToShutDown = false;

    addWorkers(threadNumbers);
}

void ThreadPool::abortNow() {
    isAborted = true;
    taskExistsCondition.notify_all();

    {
        std::lock_guard l(tasksMutex);
        pendingTasks.clear();
    }

    for (auto& worker : workers) worker.join();

    workers.clear();
}

void ThreadPool::abortWaitPendingTasks() {
    isNeedToShutDown = true;
    taskExistsCondition.notify_all();

    for (auto& worker : workers) worker.join();

    assert(pendingTasks.empty());

    workers.clear();
}

ThreadPool::~ThreadPool() { abortWaitPendingTasks(); }

void ThreadPool::workerFunc(int num) {
    while (true) {
        std::decay_t<decltype(pendingTasks.front())> taskToDo;
        {
            std::unique_lock lock(tasksMutex);
            if (!isNeedToShutDown)
                taskExistsCondition.wait(lock, [this] {
                    return !pendingTasks.empty() || isAborted ||
                           isNeedToShutDown;
                });

            if (isAborted || (pendingTasks.empty() && isNeedToShutDown)) return;

            taskToDo = std::move(pendingTasks.front());
            pendingTasks.pop_front();
        }
        
        std::cout << "thread #" << num << " is starting working" << std::endl;

        taskToDo();

        std::cout << "thread #" << num << " is ending working" << std::endl;
    }
}

void ThreadPool::addWorkers(int threadNumbers) {
    for (int i = 0; i < threadNumbers; ++i) {
        auto thr = std::thread(&ThreadPool::workerFunc, this, i);
        workers.push_back(move(thr));
    }
}
