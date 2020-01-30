#include "server.h"
#include "picohttp/picohttpparser.h"

static int BACKLOG =  32;          //  max clients in line to connect
static int USER_TIMEOUT = 30000;  //  how long we can wait for users tcp responses
static int CLIENT_BUFFER_SIZE = 64;  //  starting buffer size for client request
static int MAX_CLIENT_HEADERS_COUNT = 30;  //  maximum amount of headers request can have

inline int errGuard(int n, const char* msg, bool throwError = 0) {
    if (n < 0) {
        perror(msg);
        if (throwError) throw std::logic_error(strerror(errno));
    }

    return n;
}

int setUserTimeOut1(int fd, int millisecs) {
    return errGuard(
        setsockopt(fd, SOL_TCP, TCP_USER_TIMEOUT, &millisecs, sizeof(int)),
        "setsockoput setusertimeout");
}

HTTPClient::HTTPClient(int clientSocket, sockaddr_in clientAdress,
                       socklen_t adressLength)
    : cliSock(clientSocket),
      clientAdr(clientAdress),
      clientAdrLen(adressLength),
      buff(CLIENT_BUFFER_SIZE),
      headers(MAX_CLIENT_HEADERS_COUNT) {
    std::cout << "got connection from " << inet_ntoa(clientAdr.sin_addr)
              << std::endl;
    setUserTimeOut1(clientSocket, USER_TIMEOUT);
}

HTTPClient::HTTPClient(HTTPClient&& other) { *this = std::move(other); }

HTTPClient& HTTPClient::operator=(HTTPClient&& other) {
    buff = std::move(other.buff);
    headers = std::move(other.headers);
    methodOfs = other.methodOfs;
    pathOfs = other.pathOfs;
    buflen = other.buflen;
    ofs = other.ofs;
    methodLen = other.methodLen;
    pathLen = other.pathLen;
    headersCnt = other.headersCnt;
    bodyStart = other.bodyStart;
    lastofs = other.lastofs;
    version = other.version;

    cliSock = other.cliSock;
    other.cliSock = -1;

    return *this;
}

int HTTPClient::getRequest() {
    std::cout << "getreq" << std::endl;
    const char *method = nullptr, *path = nullptr;
    while (true) {
        int len;
        while ((len = recv(cliSock, &buff[ofs], buff.size() - ofs,
                           MSG_NOSIGNAL)) == -1 &&
               errno == EINTR) {
            continue;
        }
        std::cout << "len " << len << std::endl;

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
        headersCnt = headers.size();
        parseRet = phr_parse_request(buff.data(), ofs, &method, &methodLen,
                                     &path, &pathLen, &version, headers.data(),
                                     &headersCnt, lastofs);
        if (method) { 
            methodOfs = method - buff.data(); // set offset for where is http method starts
        }

        if (path) { 
            pathOfs = path - buff.data(); // set offset for where is http path starts
        }

        if (ofs == buff.size()) {
            std::cerr << "buff resize when reading headers  prev:" << buff.size() << std::endl;
            buff.resize(buff.size() * 2);
            std::cerr << "  next: " << buff.size() << std::endl;
        }

        if (parseRet > 0) {  // read all the headers, but possibly not full body
            bodyStart = parseRet;
            return readToTheEnd(parseRet);  // read full body
        }

        if (parseRet == -2) {  // http resp is not fully read yet
            continue;
        }

        if (parseRet == -1) {  // error
            std::cout << "parseError" << std::endl;
            return -1;
        }
    }
}

void HTTPClient::giveResponse() const {
    std::cout << "message read and ready to response.\nSTARTMESSAGE\n"
              << std::basic_string(buff.data(), ofs) << "ENDMESSAGE"
              << std::endl;

    TopResponsePart response;

    if (version != 0) {
        response.addStatus(505, "version is not supported");
        response.addHeader("Content-Length", "0");

        sendStr(response.str());
        return;
    }

    std::string_view met(buff.data() + methodOfs, methodLen);
    std::string_view pt(buff.data() + pathOfs, pathLen);

    std::cout << "method is " <<  met << std::endl;
    std::cout << "path is " <<  pt << std::endl;

    if (met == "GET") {
        httpGET();
    } else if (met == "POST") {
        httpPOST();
    } else {
        response.addStatus(405, "method is not allowed");
        response.addHeader("Content-Length", "0");
        sendStr(response.str());
        return;
    }
}

HTTPClient::~HTTPClient() { close(cliSock); }

void HTTPClient::httpGET() const {
    struct stat fileStat;
    TopResponsePart response;

    std::string pathBuf(buff.data() + pathOfs, pathLen);

    int filefd;
    errGuard(filefd = open(pathBuf.c_str(), O_RDWR), "open Error");

    errGuard(fstat(filefd, &fileStat), "fstat error");

    if (filefd < 0 || !S_ISREG(fileStat.st_mode)) {
        response.addStatus(404, "not found");
        response.addHeader("Content-Length", "0");
    } else {
        response.addStatus(200, "OK");
        response.addHeader("Content-Length", size_t(fileStat.st_size));
        response.addHeader("Content-Type", "text/html");
    }

    sendStr(response.str());
    sendFile(filefd, fileStat);

    close(filefd);
}

void HTTPClient::httpPOST() const {
    TopResponsePart response;
    int filefd;
    std::string pathBuf(buff.data() + pathOfs, pathLen);
    errGuard(filefd = open(pathBuf.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666),
             "httpPost open error");

    bool writeSuccess = true;
    if (filefd >= 0) {
        int needToWrite = ofs - bodyStart;
        int written = 0;

        while (flock(filefd, LOCK_EX) == -1 && errno == EINTR) continue;
        ;
        while (needToWrite > 0) {
            int len;
            errGuard(
                len = write(filefd, &buff[written + bodyStart], needToWrite),
                "httpPost write error");
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
    if (filefd < 0) {
        response.addStatus(409,
                           "page already exists or incorrect path provided");
    } else if (!writeSuccess) {
        response.addStatus(500, "internal server error");
    } else {
        response.addStatus(201, "page created successfuly");
        response.addHeader("Location", pathBuf);
    }

    response.addHeader("Content-Length", "0");

    sendStr(response.str());
    close(filefd);
}

int HTTPClient::sendStr(std::string msg) const {
    int sendCode;
    int needToSend = msg.size(), alreadySent = 0;

    while (needToSend > 0) {
        while (errGuard( sendCode = send(cliSock, msg.c_str() + alreadySent, msg.size() - alreadySent , MSG_NOSIGNAL),
                   "senderror") == -1 && errno == EINTR) {
            continue;
        }
        if (sendCode == -1) {
            return -1;
        } else {
            needToSend -= sendCode;
            alreadySent += sendCode;
        }
    }

    return alreadySent;
}

int HTTPClient::sendFile(int filefd, const struct stat& fileStat) const {
    if (!S_ISREG(fileStat.st_mode) || filefd < 0) return -1;

    off_t fileOff = 0;
    size_t byteSent = 0, totalLeft = (fileStat.st_size);
    bool error = 0;

    while (flock(filefd, LOCK_SH) == -1 && errno == EINTR) continue;
    while (totalLeft > 0) {
        errGuard(byteSent = sendfile(cliSock, filefd, &fileOff, 2e9),
                 "sendfile");  // possible errors
        if (byteSent == -1) {
            error = true;
            break;
        }
        totalLeft -= byteSent;
        static int cnt = 0;
        ++cnt;
    }
    flock(filefd, LOCK_UN);

    return error ? -1 : byteSent;
}

int HTTPClient::readToTheEnd(size_t bodyStart) {
    int bodyLen = 0;
    for (int i = 0; i < headersCnt; ++i) {
        if (std::string_view(headers[i].name, headers[i].name_len) ==
            "Content-Length")
            bodyLen = atoi(headers[i].value);
    }

    int bodyUnreadBytes = (bodyLen + bodyStart) - ofs;
    if (bodyLen <= 0 || bodyUnreadBytes <= 0) {
        return ofs;
    } else {
        int len = 0;
        while (bodyUnreadBytes > 0) {
            while ((len = recv(cliSock, &buff[ofs], buff.size() - ofs,
                               MSG_NOSIGNAL)) == -1 &&
                   errno == EINTR) {
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

            ofs += len;
            bodyUnreadBytes -= len;

            if (ofs == buff.size()) {
                buff.resize(buff.size() + bodyUnreadBytes);
                std::cerr << "request is too big" << std::endl;
                //return -1;
            }
        }
    }
    return ofs;
}

NetworkManager::NetworkManager(const char* adress, const char* port) {
    addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    errGuard(getaddrinfo(adress, port, &hints, &myAdr), "getaddrError", 1);

    errGuard(mSock = socket(myAdr->ai_family, myAdr->ai_socktype,
                            myAdr->ai_protocol),
             "socketError", 1);

    int yes = 1;
    if (setsockopt(mSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        std::cerr << "setsockopt   " << strerror(errno) << std::endl;

    errGuard(bind(mSock, myAdr->ai_addr, myAdr->ai_addrlen), "bindError", 1);

    errGuard(listen(mSock, BACKLOG), "listenError", 1);

    std::cout << "listening on " << adress << ":" << port << std::endl;
}

NetworkManager::NetworkManager(NetworkManager&& other) {
    *this = std::move(other);
}

NetworkManager& NetworkManager::operator=(NetworkManager&& other) {
    myAdr = other.myAdr;
    other.myAdr = nullptr;
    mSock = other.mSock;
    other.mSock = -1;

    return *this;
}

HTTPClient NetworkManager::waitClient() const {
    while (true) {
        sockaddr_in clientAdr;
        socklen_t clientAdrLen = sizeof(clientAdr);
        int cliSock;

        errGuard(
            cliSock = accept(mSock, (sockaddr*)(&clientAdr), &clientAdrLen),
            "acceptError");

        if (cliSock > 0) {
            errGuard(getpeername(cliSock, (sockaddr*)&clientAdr, &clientAdrLen),
                     "getpeername");
            return HTTPClient(cliSock, clientAdr, clientAdrLen);
        } else {
            continue;
        }
    }
}

NetworkManager::~NetworkManager() {
    freeaddrinfo(myAdr);
    close(mSock);
}
