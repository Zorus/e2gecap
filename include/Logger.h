#pragma once

#include <libecap/common/log.h>
#include <string>
#include <fstream>

#define E2GE_LOG_FILE_NAME "/var/log/Zorus/e2ge.log"

using libecap::ilNormal;
using libecap::ilCritical;
using libecap::flXaction;
using libecap::flApplication;

class Logger {
public:
    static void writeLine(std::string msg);

    static void write(std::string msg);

    static std::fstream out;
};
