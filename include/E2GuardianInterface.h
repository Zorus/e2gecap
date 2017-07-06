#pragma once

#include <HTTPHeader.hpp>
#include <DataBuffer.hpp>
#include <OptionContainer.hpp>
#include <ConnectionHandler.hpp>

#include <string>

class E2GuardianInterface {
public:
    E2GuardianInterface();

    bool onRequest(HTTPHeader& header, std::string clientIp, bool isMitm); // false = block; true = pass

    void onResponse(HTTPHeader& header, DataBuffer& body);

private:
    static ConnectionHandler ch;

    static OptionContainer o;

    static std::shared_ptr<LOptionContainer> ldl;

    int filterGroup;
};
