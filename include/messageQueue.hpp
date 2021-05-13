#ifndef SGXDEDUP_MESSAGEQUEUE_HPP
#define SGXDEDUP_MESSAGEQUEUE_HPP

#include "configure.hpp"
#include "dataStructure.hpp"
#include <boost/atomic.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

template <class T>
class messageQueue {
    boost::lockfree::spsc_queue<T, boost::lockfree::capacity<5000>> lockFreeQueue_;

public:
    boost::atomic<bool> done_;
    messageQueue()
    {
        done_ = false;
    }
    ~messageQueue()
    {
    }
    bool push(T& data)
    {
        while (!lockFreeQueue_.push(data))
            ;
        return true;
    }
    bool pop(T& data)
    {
        return lockFreeQueue_.pop(data);
    }
    bool isEmpty()
    {
        return lockFreeQueue_.empty();
    }
};

#endif //SGXDEDUP_MESSAGEQUEUE_HPP