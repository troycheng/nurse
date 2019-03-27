#ifndef __HEALTH_STATE_HPP__
#define __HEALTH_STATE_HPP__

#include <cstdlib>
#include <cstdio>
#include <mutex>
#include <time.h>

class HealthState {
    private:
        bool       is_healthy;
        int        recover_latency;
        int        interval;

        int        head;
        int        rear;
        int        ring_buf_size;
        long int   *ring_buf;

        //std::mutex      mtx;

    public:
        HealthState(int fail_cnt = 3, int fail_interval = 5) {
            //循环队列相关初始化
            fail_cnt = fail_cnt < 3 ? 3 : fail_cnt;
            interval = fail_interval < fail_cnt ? fail_cnt : fail_interval;
            ring_buf_size = fail_cnt + 1;
            ring_buf = (long int*)calloc(ring_buf_size, sizeof(long int));
            if (!ring_buf) {
                fprintf(stderr, "create ring_buf with size %d failed\n", fail_cnt);
                ring_buf = NULL;
            }
            head = 0;
            rear = 0;

            //初始化状态
            is_healthy = true;
            recover_latency = 0;
        }

        ~HealthState() {
            if (!ring_buf) {
                free(ring_buf);
            }
        }

        bool healthy() const {
            return is_healthy;
        }

        void print() {
            int pos = head;
            fprintf(stderr, "recover: %d | ", recover_latency);
            for (int i = 0; i < ring_buf_size; ++i) {
                int idx = pos % ring_buf_size;
                if (idx != rear) {
                    fprintf(stderr, "%ld |", ring_buf[idx]);
                    ++pos;
                    continue;
                }
                fprintf(stderr, " |");
                break;
            }
            fprintf(stderr, "\n");
        }

        bool st_change_on_success() {
            //std::lock_guard<std::mutex> lock(this->mtx);
            if (recover_latency > 0) {
                --recover_latency;
            }

            // 成功时，循环链表为空说明没有失败状态，无需任何处理
            // 如果不为空，说明之前有失败状态，需要剔除最早的失败状态
            // 处于失败恢复过程的话，需要根据失败计数更新健康状态
            if (head != rear) {
                head = (head + 1) % ring_buf_size;
            }
            if (!is_healthy && head == rear && recover_latency == 0) {
                is_healthy = true;
                return true;
            }

            return false;
        }

        bool st_change_on_fail() {
            //std::lock_guard<std::mutex> lock(this->mtx);

            // 失败时，记录当前时间，并且后移尾指针
            // 如果循环链表写满，需要判断是否是检查区间内，是的话标记健康状态为失败
            // 循环链表写满时需要后移头指针剔除最早的状态
            struct timespec _cur_ts;
            clock_gettime(CLOCK_MONOTONIC_RAW, &_cur_ts);
            ring_buf[rear] = _cur_ts.tv_sec;
            rear = (rear + 1) % ring_buf_size;
            if (rear == head) {
                head = (head + 1) % ring_buf_size;
            }
            if ((rear + 1) % ring_buf_size == head) {
                if (is_healthy && (_cur_ts.tv_sec - ring_buf[head]) <= interval) {
                    is_healthy = false;
                    recover_latency = 2 * interval;
                    return true;
                }
            }

            return false;
        }
};

#endif
