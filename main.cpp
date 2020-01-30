#include "server.h"
#include "threadpool.h"

const int THREAD_NUMBER = 5; // number of threads in threadpool at start

void parseArguments(int argc, char** argv, char*& h, char*& p, char*& d) {
    int rez = 0;
    while ((rez = getopt(argc, argv, "p:h:d:")) != -1) {
        switch (rez) {
            case 'h':
                h = optarg;
                break;
            case 'p':
                p = optarg;
                break;
            case 'd':
                d = optarg;
                break;
        }
    }
}

int main(int argc, char** argv) {
    char *h = nullptr, *p = nullptr, *d = nullptr;
    parseArguments(argc, argv, h, p, d);
    if (h == nullptr || p == nullptr || d == nullptr) {
        std::cerr << "usage: server -h <ip> -p <port> -d <directory>\n";
        exit(1);
    }

    chroot(d);
    chdir(d);

    NetworkManager manager(h, p);

    ThreadPool pool(THREAD_NUMBER);

    while (true) {
        auto client = manager.waitClient();

        auto serveFunc = [cli = std::move(client)]() mutable {
            int ret = cli.getRequest();
            if (ret >= 0) cli.giveResponse();
        };

        pool.addTask(std::move(serveFunc));
    }

    return 0;
}
