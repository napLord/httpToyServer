#include "picohttp/picohttpparser.h"  //!!!!!11

#include <asm-generic/errno-base.h>
#include <linux/falloc.h>
#include <netinet/in.h>
#include <iostream>
#include <istream>
#include <memory>
#include <ostream>
#include <sstream>
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

#define PORT "80"
#define BACKLOG 32

inline int guard(int n, const char *msg) {
    if (n < 0) perror(msg);

    return n;
}

void response(int cliFd, const char *method, size_t methodLen, const char *path,
              size_t pathLen, int version) {
    std::ostringstream resp;

    int status = 200;

    char *pathBuf = new char[pathLen + 2];
    memcpy(pathBuf + 1, path, pathLen);
    pathBuf[0] = '.';
    pathBuf[pathLen + 1] = '\0';
    std::unique_ptr<char> realPath(pathBuf);

    int filefd;
    guard(filefd = open(realPath.get(), O_RDONLY), "open Error");
    std::cerr << "filefd " << filefd << std::endl;

    if (version != 0) {
        status = 505;

        resp << "HTTP/1.0 " << status << " \n";
        resp << "Content-length: " << 0 << " \n";
        resp << "Content-Type: text/html\n";
        resp << "\n";
        goto RESP;
    }

    if (filefd < 0) {
        status = 404;

        resp << "HTTP/1.0 " << status << " not found"
             << "\n";
        resp << "Content-length: " << 0 << " \n";
        resp << "Content-Type: text/html\n";
        resp << "\n";
        goto RESP;
    }

    struct stat fileStat;
    guard(fstat(filefd, &fileStat), "fstat error");

    resp << "HTTP/1.0 " << status << "\n";
    resp << "Content-length: " << size_t(fileStat.st_size) << " \n";
    resp << "Content-Type: text/html\n";
    resp << "\n";
    goto RESP;

RESP:
    std::flush(resp);
    // std::cout << "response " << resp.str() << std::endl;
    // std::cout << "response " << resp.str().c_str() << std::endl;

    int sendCode;
    while (guard(sendCode = send(cliFd, resp.str().c_str(),
                                 strlen(resp.str().c_str()), MSG_NOSIGNAL),
                 "senderror") == -1 &&
           errno == EINTR) {
        continue;
    }

    if (sendCode == -1) {
        std::cout << "send message error " << strerror(errno) << std::endl;
    } else {
        std::cout << "response " << resp.str().c_str() << std::endl;
    }

    if (filefd) {
        off_t fileOff = 0;
        size_t byteSent = 0, totalLeft = (fileStat.st_size);
        while (totalLeft > 0) {
            guard(byteSent = sendfile(cliFd, filefd, &fileOff, 2e9),
                  "sendfile");  // possible errors
            if (byteSent == -1) break;
            totalLeft -= byteSent;
        }
    }

    close(filefd);
}

class HTTPClient {
   public:
    HTTPClient(int clientSocket, std::unique_ptr<sockaddr_in> clientAdress,
               socklen_t adressLength)
        : cliSock(clientSocket),
          clientAdr(std::move(clientAdress)),
          clientAdrLen(adressLength) {
        std::cout << "got connection from " << inet_ntoa(clientAdr->sin_addr)
                  << std::endl;
    }

    void getRequest() {
        while (true) {
            int len;
            while ((len = recv(cliSock, buff + ofs, sizeof(buff) - ofs,
                               MSG_NOSIGNAL)) == -1 &&
                   errno == EINTR) {
                continue;
            }

            if (len == 0) {
                std::cout << "disconnected" << std::endl;
                break;
            }
            if (len < 0) {
                std::cout << "recv error " << strerror(errno) << std::endl;
            }

            lastofs = ofs;
            ofs += len;

            headersCnt = sizeof(headers) / sizeof(headers[0]);

            int parseRet;
            guard(parseRet = phr_parse_request(buff, ofs, &method, &methodLen,
                                               &path, &pathLen, &version,
                                               headers, &headersCnt, lastofs),
                  "phr_parse_req_error");
            std::cerr << parseRet << std::endl;
            if (parseRet > 0) {
                break;
            }

            if (parseRet == -2) {
                continue;
            }

            if (ofs == sizeof(buff)) {
                break;
            }
        }

        printf("buffer is %s\n", buff);
        printf("method is %.*s\n", (int)methodLen, method);
        printf("path is %.*s\n", (int)pathLen, path);
        printf("HTTP version is 1.%d\n", version);
        printf("headers:\n");
        for (int i = 0; i != headersCnt; ++i) {
            printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
                   (int)headers[i].value_len, headers[i].value);
        }
    }

    void giveResponse() {
            response(cliSock, method, methodLen, path, pathLen, version);
    }

   private:
    int cliSock;

    std::unique_ptr<sockaddr_in> clientAdr;
    socklen_t clientAdrLen;

    char buff[4096];
    const char *method, *path;
    size_t buflen = 0, ofs = 0, methodLen = 0, pathLen = 0, headersCnt = 0;
    int lastofs = 0, version;
    phr_header headers[24];
};

class A {
   public:
    A() {
        addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        guard(getaddrinfo(nullptr, PORT, &hints, &myAdr),
              "getaddrError");  // leak?

        guard(mSock = socket(myAdr->ai_family, myAdr->ai_socktype,
                             myAdr->ai_protocol),
              "socketError");

        int yes = 1;
        if (setsockopt(mSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) ==
            -1)
            std::cerr << "setsockopt   " << strerror(errno) << std::endl;

        guard(bind(mSock, myAdr->ai_addr, myAdr->ai_addrlen), "bindError");

        guard(listen(mSock, BACKLOG), "listenError");

        std::cout << "listening" << std::endl;
    }

    HTTPClient waitClient() {
        auto clientAdr = std::make_unique<sockaddr_in>();
        socklen_t clientAdrLen;
        int cliSock;

        while (true) {
            guard(cliSock = accept(
                      mSock, reinterpret_cast<sockaddr *>(clientAdr.get()),
                      &clientAdrLen),
                  "acceptError");

            if (cliSock != -1) {
                std::cout << "got connection from "
                          << inet_ntoa(clientAdr->sin_addr) << std::endl;
                continue;
            } else {
                return HTTPClient(cliSock, std::move(clientAdr), clientAdrLen);
            }
        }
    }

    ~A() {
        // clean myAdr
        close(mSock);
    }

   private:
    int mSock;
    addrinfo *myAdr;
};


int main() {
    addrinfo *myAdr, hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    guard(getaddrinfo(nullptr, PORT, &hints, &myAdr), "getaddrError");

    int mSock;

    guard(mSock =
              socket(myAdr->ai_family, myAdr->ai_socktype, myAdr->ai_protocol),
          "socketError");

    int yes = 1;
    if (setsockopt(mSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        std::cerr << "setsockopt   " << strerror(errno) << std::endl;

    guard(bind(mSock, myAdr->ai_addr, myAdr->ai_addrlen), "bindError");

    guard(listen(mSock, BACKLOG), "listenError");

    std::cout << "listening" << std::endl;

    while (true) {
        sockaddr_in clientAdr;
        socklen_t clientArdlen;

        int cliSock;
        guard(cliSock = accept(mSock, reinterpret_cast<sockaddr *>(&clientAdr),
                               &clientArdlen),
              "acceptError");
        if (cliSock != -1) {
            std::cout << "got connection from " << inet_ntoa(clientAdr.sin_addr)
                      << std::endl;

            char buff[4096];
            const char *method, *path;
            size_t buflen = 0, ofs = 0, methodLen = 0, pathLen = 0,
                   headersCnt = 0;
            int lastofs = 0, version;
            phr_header headers[24];

            while (true) {
                int len;
                while ((len = recv(cliSock, buff + ofs, sizeof(buff) - ofs,
                                   MSG_NOSIGNAL)) == -1 &&
                       errno == EINTR) {
                    continue;
                }

                if (len == 0) {
                    std::cout << "disconnected" << std::endl;
                    break;
                }
                if (len < 0) {
                    std::cout << "recv error " << strerror(errno) << std::endl;
                }

                lastofs = ofs;
                ofs += len;

                headersCnt = sizeof(headers) / sizeof(headers[0]);

                int parseRet;
                guard(parseRet = phr_parse_request(
                          buff, ofs, &method, &methodLen, &path, &pathLen,
                          &version, headers, &headersCnt, lastofs),
                      "phr_parse_req_error");
                std::cerr << parseRet << std::endl;
                if (parseRet > 0) {
                    break;
                }

                if (parseRet == -2) {
                    continue;
                }

                if (ofs == sizeof(buff)) {
                    break;
                }
            }

            printf("buffer is %s\n", buff);
            printf("method is %.*s\n", (int)methodLen, method);
            printf("path is %.*s\n", (int)pathLen, path);
            printf("HTTP version is 1.%d\n", version);
            printf("headers:\n");
            for (int i = 0; i != headersCnt; ++i) {
                printf("%.*s: %.*s\n", (int)headers[i].name_len,
                       headers[i].name, (int)headers[i].value_len,
                       headers[i].value);
            }

            response(cliSock, method, methodLen, path, pathLen, version);

            close(cliSock);

        } else {
            continue;
        }
    }

    close(mSock);

    return 0;
}
