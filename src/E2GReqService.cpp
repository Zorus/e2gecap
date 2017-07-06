#include <E2GReqService.h>
#include <E2GReqXaction.h>
#include <Logger.h>

std::string Adapter::E2GReqService::uri() const {
    Logger::writeLine("E2GReqService::uri()");
    return "ecap://zorustech.com/ecap/services/e2guardian";
}

std::string Adapter::E2GReqService::tag() const {
    Logger::writeLine("E2GReqService::tag()");
    return PACKAGE_VERSION;
}

void Adapter::E2GReqService::describe(std::ostream &os) const {
    Logger::writeLine("E2GReqService::describe()");
    os << "An adapter from " << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

void Adapter::E2GReqService::configure(const libecap::Options &) {
    Logger::writeLine("E2GReqService::configure()");
    // this service is not configurable
}

void Adapter::E2GReqService::reconfigure(const libecap::Options &) {
    Logger::writeLine("E2GReqService::reconfigure()");
    // this service is not configurable
}

void Adapter::E2GReqService::start() {
    libecap::adapter::Service::start();

    Logger::writeLine("E2GReqService::start()");
    // custom code would go here, but this service does not have one
}

void Adapter::E2GReqService::stop() {
    // custom code would go here, but this service does not have one
    Logger::writeLine("E2GReqService::stop()");

    libecap::adapter::Service::stop();
}

void Adapter::E2GReqService::retire() {
    // custom code would go here, but this service does not have one
    Logger::writeLine("E2GReqService::retire()");

    libecap::adapter::Service::stop();
}

bool Adapter::E2GReqService::wantsUrl(const char *url) const {
    Logger::writeLine("E2GReqService::wantsUrl()");
    return true; // minimal adapter is applied to all messages
}

libecap::adapter::Service::MadeXactionPointer Adapter::E2GReqService::makeXaction(libecap::host::Xaction *hostx) {
    Logger::writeLine("E2GReqService::makeXaction()");
    return MadeXactionPointer(new Adapter::E2GReqXaction(std::tr1::static_pointer_cast<E2GReqService>(self), hostx));
}
