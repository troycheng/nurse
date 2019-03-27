#include "health_state.hpp"
#include "thread_pool.hpp"
#include "host_prob.hpp"

#include <cstring>
#include <unordered_map>
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <curl/curl.h>
#include <exception>

#define MAX_MESG_THREAD 2
#define MAX_EVENTS 10

int get_hosts(const char* f, std::vector<struct host_addr> &hosts, std::unordered_map<std::string, std::string> &serv_dict) {
    FILE* fp = fopen(f, "r");
    if (!fp) return 0;

    int cnt = 0;
    while (!feof(fp)) {
        char _ip[INET_ADDRSTRLEN] = {'\0', };
        int  _port = 0;
        char _service[128] = {'\0', };
        if (fscanf(fp, "%16[0-9.]:%d %[^\r\n]%*c", _ip, &_port, _service) != 3) {
            continue;
        }

        host_addr _host(_ip, _port);

        if (!_host.valid || _port < 1 || _port > 65535) {
            fprintf(stderr, "WARNING: Invliad host rec:%s, ip:%s, port:%d, srv: %s\n", _host.to_str().c_str(), _host.ip, _host.port, _service);
            continue;
        }

        hosts.emplace_back(_host);
        serv_dict[_host.to_str()] = std::string(_service);
        ++cnt;
    }

    fclose(fp);
    return cnt;
}

inline long int get_cur_ms() {
    struct timespec _cur_ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &_cur_ts);
    return _cur_ts.tv_sec*1000 + _cur_ts.tv_nsec/1000000;
}

int http_post(const std::string &url, const std::string &body, long timeout_ms) {
    CURL* curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json;charset=utf-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "%s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    fprintf(stderr, "DEBUG: Curl post success\n");

    return res;
}

int main(int argc, char* argv[]) {
    // 解析选项
    std::string data_file = "", dingding_robot = "";
    int opt = 0;
    while ((opt = getopt(argc, argv, "f:r:h")) != -1) {
        switch(opt) {
            case 'f':
                data_file = optarg;
                break;
            case 'r':
                dingding_robot = optarg;
                break;
            case 'h':
            case '?':
            default:
                fprintf(stderr, "Usage: %s -[frh]\n",argv[0]);
                fprintf(stderr, "\t-f\tfile contains detect target with format:[ip:port\\tserv_name], ie.: 192.168.0.1:80\ttest\n");
                fprintf(stderr, "\t-r\tdingding robot url\n");
                fprintf(stderr, "\t-h\tprint these help info\n");
                fprintf(stderr, "For any questions pls feel free to contact frostmourn716@gmail.com\n");
                exit(0);
                break;
        }
    }
    if (access(data_file.c_str(), R_OK) != 0) {
        fprintf(stderr, "Error: can't read file %s\n", data_file.c_str());
        exit(1);
    }
    if (dingding_robot.empty()) {
        fprintf(stderr, "Error: empty robot url\n");
        exit(1);
    }

    // 全局初始化 curl
    curl_global_init(CURL_GLOBAL_ALL);

    // 创建探测对象
    host_prob *prob = nullptr;
    try {
        prob = new host_prob();
    } catch (std::exception &e) {
        fprintf(stderr, "ERROR: Init host prob failed, %s\n", e.what());
        exit(1);
    }

    // 创建 epoll 对象, 创建监听 socket 并绑定事件
    int epoll_fd = -1;
    if ((epoll_fd = epoll_create1(0)) < 0 ) {
        fprintf(stderr, "ERROR: Create epoll fd failed\n");
        exit(2);
    }

    struct epoll_event event;
    event.events  = EPOLLIN;
    event.data.fd = prob->get_recv_fd();
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event.data.fd, &event)) {
        fprintf(stderr, "ERROR: Faild to add file descriptor to epollfd\n");
        exit(3);
    }

    // 定义发送消息的线程池
    ThreadPool mesg_pool(MAX_MESG_THREAD);

    // 定义健康检查的数据存储结构
    std::unordered_map<std::string, HealthState> health_states;
    int report_interval = 60;
    int counter = 0;

    // 开始探测循环
    struct epoll_event recv_events[MAX_EVENTS];
    while (true) {
        long int start_ms = get_cur_ms();

        std::vector<struct host_addr> host_vec;
        std::unordered_map<std::string, std::string> detect_flag;
        int rec_cnt = get_hosts(data_file.c_str(), host_vec, detect_flag);

        fprintf(stderr, "\nNOTICE: Read %d hosts, start to send detect datagram...\n", rec_cnt);

        // 扔进探测队列探测
        // 对于每次探测，先将所有目标标记为失败，再将收到回复的标记为成功
        // 那些请求未发送成功和未在指定时间收到回复的，就自然标记为失败
        for (size_t i = 0; i < host_vec.size(); ++i) {
            std::string str_host = host_vec[i].to_str();
            if (health_states.find(str_host) == health_states.end()) {
                health_states.insert({str_host, {3, 5}});
            }

            prob->detect(host_vec[i]);
        }
        long int detect_cost_ms = get_cur_ms() - start_ms;
        fprintf(stderr, "NOTICE: Detect finish. cost: %ld ms\n", detect_cost_ms);

        std::vector<std::string> recover_hosts;
        std::vector<std::string> down_hosts;
        std::vector<std::string> need_report;

        // 在限定时间范围内接收返回结果，对于收到结果的 target，判断是否恢复
        int recv_cnt = 0;
        while (true) {
            int event_cnt = epoll_wait(epoll_fd, recv_events, MAX_EVENTS, 100);
            if (event_cnt < 0) {
                fprintf(stderr, "ERROR: Epoll failed with errno: %d\n", errno);
                exit(3);
            }
            for (int i = 0; i < event_cnt; ++i) {
                while (true) {
                    std::string str_host = prob->capture();
                    if (str_host.empty()) {
                        break;
                    }

                    if (health_states[str_host].st_change_on_success()) {
                        std::string content = std::string("服务: ") + detect_flag[str_host] + "  地址: " + str_host + "\n";
                        recover_hosts.emplace_back(content);
                        fprintf(stderr, "DEBUG: On Sccess Host %s -> ", str_host.c_str());
                        health_states[str_host].print();
                    }

                    detect_flag.erase(str_host);
                    ++recv_cnt;
                }
            }
            if (get_cur_ms() - start_ms >= 900) break;
        }
        fprintf(stderr, "DEBUG: Totally recv ack %d\n", recv_cnt);

        // 超出时间范围仍然没有收到结果的，判定为失败
        for (auto _pair : detect_flag) {
            if (health_states[_pair.first].st_change_on_fail()) {
                std::string content = std::string("服务: ") + _pair.second + "  地址: " + _pair.first;
                down_hosts.emplace_back(content);
            }
            if (!health_states[_pair.first].healthy()) {
                std::string content = std::string("服务: ") + _pair.second + "  地址: " + _pair.first;
                need_report.emplace_back(content);
            }
            fprintf(stderr, "DEBUG: On Fail Host %s -> ", _pair.first.c_str());
            health_states[_pair.first].print();
        }

        // 对产生变化的 hosts 发送消息通知
        if (!recover_hosts.empty() || !down_hosts.empty()) {
            mesg_pool.enqueue([&recover_hosts, &down_hosts, &dingding_robot]() {
                std::string text = "### 探活状态变动\n";
                if (!recover_hosts.empty()) {
                    text += "##### 恢复正常\n";
                    for (auto item : recover_hosts) {
                        text += "> " + item + "  \n";
                    }
                }
                if (!down_hosts.empty()) {
                    text += "##### 探活失败\n";
                    for (auto item : down_hosts) {
                        text += "> " + item + "  \n";
                    }
                }
                std::string body = "{\"msgtype\": \"markdown\",\"markdown\": {\"title\":\"探活状态变动\",\"text\":\""+text+"\"},\"at\":{\"atMobiles\":[\"13811626017\"], \"isAtAll\": false}}";
                http_post(dingding_robot, body, 1000);
            });
        }

        // 固定间隔汇报处于探活失败状态的机器
        if (++counter == report_interval) {
            counter = 0;
            if (!need_report.empty()) {
                mesg_pool.enqueue([need_report, &dingding_robot]() {
                    std::string text = "### 失活机器汇总\n";
                    for (auto item : need_report) {
                        text += "> " + item + "  \n";
                    }
                    std::string body = "{\"msgtype\": \"markdown\",\"markdown\": {\"title\":\"失活机器汇总\",\"text\":\""+text+"\"},\"at\":{\"atMobiles\":[\"13811626017\"], \"isAtAll\": false}}";
                    http_post(dingding_robot, body, 1000);
                });
            }
        }

        // 如果还有时间，等待
        long int rest_time = 1000 - (get_cur_ms() - start_ms);
        fprintf(stderr, "NOTICE: Recv finish. will sleep: %ld ms\n", rest_time);
        if (rest_time > 0) {
            usleep(rest_time * 1000);
        }
    }

    curl_global_cleanup();
    return 0;
}
