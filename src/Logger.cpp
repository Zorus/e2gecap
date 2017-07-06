#include <Logger.h>

std::fstream Logger::out = std::fstream(E2GE_LOG_FILE_NAME, std::ios::out | std::ios::trunc);

void Logger::write(std::string msg) {
    Logger::out << msg;
}

void Logger::writeLine(std::string msg) {
    Logger::out << msg << std::endl;
}