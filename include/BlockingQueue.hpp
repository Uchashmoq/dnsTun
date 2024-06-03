#ifndef DNS_BLOCKINGQUEUE_HPP
#define DNS_BLOCKINGQUEUE_HPP
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace ucsmq{
    enum pop_result{
        POP_SUCCESSFULLY=1,POP_INVALID=-1,POP_TIMEOUT=-2
    };
    template <typename T>
    class BlockingQueue {
    private:
        std::queue<T> queue;
        std::mutex mutex;
        std::condition_variable cv;
        std::atomic<bool> shouldBlock;
        bool cvSatisfied() const {
            if(shouldBlock.load()){
                return !queue.empty();
            }else{
                return true;
            }
        }
    public:
        BlockingQueue(){shouldBlock.store(true);}
        BlockingQueue(const BlockingQueue& )=delete;
        void unblock(){
            shouldBlock.store(false);
            cv.notify_all();
        }
        bool isBlockingQueue(){return shouldBlock.load();}
        ~BlockingQueue(){unblock();}
        void push(const T& value) {
            {
                std::unique_lock<std::mutex> lock(mutex);
                queue.push(value);
            }
            cv.notify_all();
        }
        void push(T&& value) {
            {
                std::unique_lock<std::mutex> lock(mutex);
                queue.push(std::move(value));
            }
            cv.notify_all();
        }

        pop_result pop(T& out,int timeout=0){
            std::unique_lock<std::mutex> lock(mutex);
            if (timeout>0) {
                if(!cv.wait_for(lock,std::chrono::seconds(timeout),[this] { return cvSatisfied();})){
                    return POP_TIMEOUT;
                }
            }else{
                cv.wait(lock,[this] { return cvSatisfied();});
            }
            if(queue.empty()){
                return POP_INVALID;
            }
            out=std::move(queue.front());
            queue.pop();
            return POP_SUCCESSFULLY;
        }


        size_t size(){
            std::unique_lock<std::mutex> lock(mutex);
            return queue.size();
        }


    };
}

#endif
