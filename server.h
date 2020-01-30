#pragma once
#include "picohttpparser.h"

#include <asm-generic/errno-base.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <functional>
#include <iostream>
#include <istream>
#include <memory>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>
#include <unordered_map>

class HTTPClient {
   public:
    HTTPClient(int clientSocket, sockaddr_in clientAdress, socklen_t adressLength);
    HTTPClient(const HTTPClient&) = delete;
    HTTPClient(HTTPClient&& other);
    HTTPClient& operator=(const HTTPClient&) = delete;
    HTTPClient& operator=(HTTPClient&& other);
    int getRequest();
    void giveResponse() const;
    ~HTTPClient();

   private:
    void httpGET() const;
    void httpPOST() const;
    int sendStr(std::string msg) const;
    int sendFile(int filefd, const struct stat& fileStat) const;
    int readToTheEnd(size_t bodyStart);

    class TopResponsePart;

   private:
    int cliSock;
    sockaddr_in clientAdr;
    socklen_t clientAdrLen;

    std::vector<char> buff;
    std::vector<phr_header> headers;
    //const char *method, *path;
    size_t buflen = 0, ofs = 0, methodLen = 0, pathLen = 0, headersCnt = 0,
           bodyStart = 0;
    int lastofs = 0, version, methodOfs, pathOfs;
};

class NetworkManager {
   public:
    NetworkManager(const char* adress, const char* port);
    NetworkManager(const NetworkManager&) = delete;
    NetworkManager(NetworkManager&& other);
    NetworkManager& operator=(const NetworkManager&) = delete;
    NetworkManager& operator=(NetworkManager&& other);
    HTTPClient waitClient() const;
    ~NetworkManager();

   private:
    int mSock;
    addrinfo* myAdr;
};

class HTTPClient::TopResponsePart {
   public:
    void addStatus(int newStatus, std::string_view reason) {
        status = newStatus;
        reasonPhrase = static_cast<std::string>(reason);
    }

    void addHeader(std::string_view key, std::string_view value) {
        headers[static_cast<std::string>(key)] =
            static_cast<std::string>(value);
    }

    void addHeader(std::string_view key, int value) {
        headers[static_cast<std::string>(key)] = std::to_string(value);
    }

    std::string str() const {
        std::string response = "HTTP/1.0 ";
        response += std::to_string(status) + " " + reasonPhrase + "\r\n";
        for (auto& i : headers) {
            response += i.first + ": " + i.second + "\r\n";
        }
        response += "\n";

        return response;
    }

   private:
    std::unordered_map<std::string, std::string> headers;
    std::string reasonPhrase = "OK";
    int status = 200;
};
