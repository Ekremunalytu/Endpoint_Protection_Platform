#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <QThreadPool>
#include <QRunnable>
#include <QDebug>
#include <QThread>
#include <QtConcurrent>
#include <functional>
#include <memory>

// Task sınıfı - QRunnable'dan türetilen ve bir fonksiyonu çalıştıran sınıf
class Task : public QRunnable {
public:
    using TaskFunction = std::function<void()>;
    using Callback = std::function<void()>;

    Task(TaskFunction function, Callback onComplete = nullptr)
        : m_function(function), m_onComplete(onComplete) {
        setAutoDelete(true);
    }

    void run() override {
        try {
            m_function();
            if (m_onComplete) {
                m_onComplete();
            }
        } catch (const std::exception& e) {
            qCritical() << "Exception in thread task:" << e.what();
        } catch (...) {
            qCritical() << "Unknown exception in thread task";
        }
    }

private:
    TaskFunction m_function;
    Callback m_onComplete;
};

// ThreadPool sınıfı - QThreadPool'u yöneten bir singleton sınıf
// QObject'ten türetmeyi kaldırıyoruz, Q_OBJECT makrosu da yok artık 
class ThreadPool {
public:
    // Singleton instance getter - thread-safe in C++11
    static ThreadPool* getInstance() {
        static ThreadPool instance; // Magic static - C++11 thread-safe
        return &instance;
    }

    // Bir görevi asenkron olarak çalıştır
    void runAsync(const std::function<void()>& task, const std::function<void()>& onComplete = nullptr) {
        Task* runnable = new Task(task, onComplete);
        QThreadPool::globalInstance()->start(runnable);
    }

    // Bir görevi asenkron olarak çalıştır ve sonuç döndür (QFuture ile)
    template <typename ResultType>
    QFuture<ResultType> runAsyncWithResult(const std::function<ResultType()>& task) {
        return QtConcurrent::run(QThreadPool::globalInstance(), task);
    }

    // Thread pool'un büyüklüğünü ayarla
    void setMaxThreadCount(int count) {
        QThreadPool::globalInstance()->setMaxThreadCount(count);
    }

    // Aktif thread sayısını al
    int activeThreadCount() const {
        return QThreadPool::globalInstance()->activeThreadCount();
    }

    // Maksimum thread sayısını al
    int maxThreadCount() const {
        return QThreadPool::globalInstance()->maxThreadCount();
    }

private:
    // Private constructor - singleton pattern
    ThreadPool() {
        // İsteğe bağlı olarak thread pool'u yapılandır
        int optimalThreadCount = QThread::idealThreadCount();
        QThreadPool::globalInstance()->setMaxThreadCount(optimalThreadCount);
        
        qDebug() << "Thread pool initialized with" << optimalThreadCount << "threads";
    }
    
    // Private destructor
    ~ThreadPool() {
        QThreadPool::globalInstance()->waitForDone();
        qDebug() << "Thread pool destroyed";
    }

    // Singleton için copy/move constructorları ve operatörleri engelle
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;
};

#endif // THREADPOOL_H