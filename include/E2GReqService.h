#pragma once

#include <iostream>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>

#define PACKAGE_VERSION "1"
#define PACKAGE_NAME "e2guardian"

namespace Adapter {
    class E2GReqService : public libecap::adapter::Service {
        public:
            // About
            virtual std::string uri() const; // unique across all vendors
            virtual std::string tag() const; // changes with version and config
            virtual void describe(std::ostream &os) const; // free-format info

            // Configuration
            virtual void configure(const libecap::Options &cfg);

            virtual void reconfigure(const libecap::Options &cfg);

            // Lifecycle
            virtual void start(); // expect makeXaction() calls
            virtual void stop(); // no more makeXaction() calls until start()
            virtual void retire(); // no more makeXaction() calls

            // Scope (XXX: this may be changed to look at the whole header)
            virtual bool wantsUrl(const char *url) const;

            // Work
            virtual libecap::adapter::Service::MadeXactionPointer makeXaction(libecap::host::Xaction *hostx);
    };
}