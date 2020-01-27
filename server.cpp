#include "picohttpparser.h"

#include <array>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <chrono>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <algorithm>
#include <csignal>
#include <iostream>
#include <istream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/file.h>
#include <unordered_map>

#define BACKLOG 32

inline int guard(int n, const char *msg, bool throwError = 0) {
    if (n < 0) {
        perror(msg);
        if (throwError)
            throw std::logic_error(strerror(errno));
    }

    return n;
}

int setUserTimeOut(int fd, int millisecs) {
        return guard(setsockopt(fd, SOL_TCP, TCP_USER_TIMEOUT, &millisecs, sizeof(int)), "setsockoput setusertimeout");
}

class HTTPClient {
   public:
    HTTPClient(int clientSocket, sockaddr_in clientAdress,
               socklen_t adressLength)
        : cliSock(clientSocket),
          clientAdr(clientAdress),
          clientAdrLen(adressLength) {
         std::cout << "got connection from " << inet_ntoa(clientAdr.sin_addr) << std::endl;
         setUserTimeOut(clientSocket, 30000);
    }

    int getRequest() {
        while (true) {
            int len;
            while ((len = recv(cliSock, &buff[ofs], buff.size() - ofs, MSG_NOSIGNAL)) == -1 && errno == EINTR) {
                continue;
            }

            if (len == 0) {
                std::cout << "cient disconnected" << std::endl;
                return -1;
            }
            if (len < 0) {
                std::cout << "recv error " << strerror(errno) << std::endl;
                return -1;
            }

            lastofs = ofs;
            ofs += len;

            int parseRet;
            headersCnt = sizeof(headers) / sizeof(headers[0]);
            parseRet = phr_parse_request(buff.data(), ofs, &method, &methodLen,
                                               &path, &pathLen, &version,
                                               headers.data(), &headersCnt, lastofs);

            if (ofs == sizeof(buff)) {
                std::cerr << "request is too big for inner buffer" << std::endl;
                return -1;
            }

            if (parseRet > 0) {                 //read all the headers, but possibly not full body
                bodyStart = parseRet;
                return readToTheEnd(parseRet);  //read full body
            }

            if (parseRet == -2) {               //http resp is not fully read yet
                continue;
            }

            if (parseRet == -1) {               //error
                return -1;
            }
        }
    }

    void giveResponse() {
        std::cout << "message read and ready to response.\nSTARTMESSAGE\n" <<
            std::basic_string(buff.data(), ofs) <<
            "ENDMESSAGE" << std::endl;

        if (version != 0) {
            std::ostringstream resp;
            int status = 505;
            resp << "HTTP/1.0" << status << "\n";
            resp << "Content-length: " << 0 << " \n";
            resp << "Content-Type: text/html\n";
            resp << "\n";

            sendStr(resp.str());
            return;
        }

        std::string_view met(method, methodLen);

        if (met == "GET") {
            httpGET();
        }
        else if (met == "POST") {
            httpPOST();
        }
        else {
            std::ostringstream resp;
            int status = 405;
            resp << "HTTP/1.0" << status << "\n";
            resp << "Content-length: " << 0 << " \n";
            resp << "Content-Type: text/html\n";
            resp << "\n";

            sendStr(resp.str());
            return;
        }
    }

    ~HTTPClient() {
        std::cout << "response given" << std::endl;
        close(cliSock);
    }

   private:
    void httpGET() {
        struct stat fileStat;
        std::ostringstream resp;

        int status = 200;

        std::string pathBuf(path, pathLen);

        int filefd;
        guard(filefd = open(pathBuf.c_str(), O_RDWR), "open Error");

        guard(fstat(filefd, &fileStat), "fstat error");

        if (filefd < 0 || !S_ISREG(fileStat.st_mode)) {
            status = 404;

            resp << "HTTP/1.0 " << status << "\n";
            resp << "Content-length: " << 0 << " \n";
        } else {
            resp << "HTTP/1.0 " << status << "\n";
            resp << "Content-length: " << size_t(fileStat.st_size) << " \n";
        }

        resp << "Content-Type: text/html\n";
        resp << "\n";

        sendStr(resp.str());
        sendFile(filefd, fileStat);

        close(filefd);
    }

    void httpPOST() {
        std::ostringstream resp;
        int filefd;
        std::string pathBuf(path, pathLen);
        guard(filefd = open(pathBuf.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666), "httpPost open error");

        bool writeSuccess = true;
        if (filefd >= 0) {
            int needToWrite = ofs - bodyStart;
            int written = 0;

            flock(filefd, LOCK_EX);
            while (needToWrite > 0) {
                int len;
                guard(len = write(filefd, &buff[written + bodyStart], needToWrite), "httpPost write error");
                if (len == -1) {
                    writeSuccess = false;
                    break;
                }

                written += len;
                needToWrite -= len;
            }
            flock(filefd, LOCK_UN);
        }

        int status = 200;
        if(filefd < 0) {
            status = 409;
            resp << "HTTP/1.0 " << status << " already exists or incorrect path"  << "\r\n";
        } 
        else if (!writeSuccess) {
            status = 500;
            resp << "HTTP/1.0 " << status << "\r\n";
        } 
        else {
            status = 201;
            resp << "HTTP/1.0 " << status << " file created successfuly" << "\r\n";
            //need to add location header
        }

        resp << "Content-length: " << 0 << "\r\n";

        sendStr(resp.str());
        close(filefd);
    }

    int sendStr(std::string msg) {
        int sendCode;
        while (guard(sendCode = send(cliSock, msg.c_str(), msg.size(),
                                     MSG_NOSIGNAL),
                     "senderror") == -1 &&
               errno == EINTR) {
            continue;
        }

        return sendCode;
    }

    int sendFile(int filefd, const struct stat &fileStat) {
        if (!S_ISREG(fileStat.st_mode) || filefd < 0) return -1;

        off_t fileOff = 0;
        size_t byteSent = 0, totalLeft = (fileStat.st_size);
        bool error = 0;

        flock(filefd, LOCK_SH);
        while (totalLeft > 0) {
            guard(byteSent = sendfile(cliSock, filefd, &fileOff, 2e9),
                  "sendfile");  // possible errors
            if (byteSent == -1) {
                error = true;
                break;
            }
            totalLeft -= byteSent;
        }
        flock(filefd, LOCK_UN);

        return error ? -1 : byteSent;
    }

    int readToTheEnd(size_t bodyStart) {
        int bodyLen = 0;
        for (int i = 0; i < headersCnt; ++i) {
            if (std::string_view(headers[i].name, headers[i].name_len) == "Content-Length")
                bodyLen = atoi(headers[i].value);
        }

        int bodyUnreadBytes = (bodyLen + bodyStart) - ofs;
        if (bodyLen <= 0 || bodyUnreadBytes <= 0) {
            return ofs;
        }
        else {
            int len = 0;
            while (bodyUnreadBytes > 0) {
                while ((len = recv(cliSock, &buff[ofs], buff.size() - ofs, MSG_NOSIGNAL)) == -1 && errno == EINTR) {
                    continue; }

                if (len == 0) {
                    std::cout << "cient disconnected" << std::endl;
                    return -1;
                }
                if (len < 0) {
                    std::cout << "recv error " << strerror(errno) << std::endl;
                    return -1;
                }

                ofs += len;
                bodyUnreadBytes -= len;

                if (ofs == buff.size()) {
                    std::cerr << "request is too big" << std::endl;
                    return -1;
                }
            }
        }
        return ofs;
    }

    class TopResponsePart {
        public:
            void addStatus (int newStatus, std::string reason) {
                status = newStatus;
                reasonPhrase = reason;
            }

            void addHeader(std::string_view key, std::string_view value) {
                headers[static_cast<std::string>(key)] = static_cast<std::string>(value);
            }

            void addHeader(std::string_view key, int value) {
                headers[static_cast<std::string>(key)] = std::to_string(value);
            }

            std::string getStr() {
                std::string response = "HTTP/1.0 ";
                response += std::to_string(status) + " " + reasonPhrase + "\r\n";
                for (auto &i : headers) {
                    response += i.first + ": " + i.second + "\r\n";
                }

                return response;
            }

        private:
            std::unordered_map<std::string, std::string> headers;
            std::string reasonPhrase = "OK";
            int status = 200;
    };

   private:
    int cliSock;
    sockaddr_in clientAdr;
    socklen_t clientAdrLen;

    std::array<char, 40000> buff;
    std::array<phr_header, 32> headers;
    const char *method, *path;
    size_t buflen = 0, ofs = 0, methodLen = 0, pathLen = 0, headersCnt = 0, bodyStart = 0;
    int lastofs = 0, version;
};

class NetworkManager {
   public:
    NetworkManager(const char *adress, const char *port) {
        addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        guard(getaddrinfo(adress, port, &hints, &myAdr), "getaddrError", 1);

        guard(mSock = socket(myAdr->ai_family, myAdr->ai_socktype,
                             myAdr->ai_protocol),
              "socketError", 1);

        int yes = 1;
        if (setsockopt(mSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
             std::cerr << "setsockopt   " << strerror(errno) << std::endl;

        guard(bind(mSock, myAdr->ai_addr, myAdr->ai_addrlen), "bindError", 1);

        guard(listen(mSock, BACKLOG), "listenError", 1);

        std::cout << "listening on " << adress << ":" << port << std::endl;
    }

    HTTPClient waitClient() {
        while (true) {
            sockaddr_in clientAdr;
            socklen_t clientAdrLen = sizeof(clientAdr);
            int cliSock;

            guard(cliSock =
                      accept(mSock, (sockaddr *)(&clientAdr), &clientAdrLen),
                  "acceptError");

            if (cliSock > 0) {
                guard(
                    getpeername(cliSock, (sockaddr *)&clientAdr, &clientAdrLen),
                    "getpeername");
                return HTTPClient(cliSock, clientAdr, clientAdrLen);
            } else {
                continue;
            }
        }
    }

    ~NetworkManager() {
        freeaddrinfo(myAdr);
        close(mSock);
    }

   private:
    int mSock;
    addrinfo *myAdr;
};

void killChildHandler(int signal, siginfo_t *info, void *ptr) {
    if (info->si_code == CLD_EXITED || info->si_code == CLD_DUMPED ||
        info->si_code == CLD_KILLED) {
        waitpid(-1, nullptr, 0);
        // std::cerr << "killed " << std::endl;
    }
}

void setZombieKiller() {
    struct sigaction act;
    act.sa_flags = SA_SIGINFO | SA_RESTART;
    act.sa_sigaction = &killChildHandler;
    sigaction(SIGCHLD, &act, nullptr);
}

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

int main(int argc, char **argv) {
    setZombieKiller();

    char *h = nullptr, *p = nullptr, *d = nullptr;
    parseArguments(argc, argv, h, p ,d);
    if (h == nullptr || p == nullptr || d == nullptr) {
        std::cerr << "usage: server -h <ip> -p <port> -d <directory>\n";
        exit(1);
    }

    chroot(d);

    NetworkManager manager(h, p);

    while (true) {
        auto client = manager.waitClient();

        if (!fork()) {
            if (client.getRequest() != -1) client.giveResponse();

            return 0;
        }
    }

    return 0;
}
