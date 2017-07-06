#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/common/named_values.h>
#include <libecap/host/host.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>
#include "E2GuardianInterface.h"

namespace Adapter {
    class E2GReqXaction: public libecap::adapter::Xaction {
    public:
        E2GReqXaction(libecap::shared_ptr<E2GReqService> s, libecap::host::Xaction *x);

        virtual ~E2GReqXaction();

        // meta-information for the host transaction
        virtual const libecap::Area option(const libecap::Name &name) const;

        virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

        // lifecycle
        virtual void start();

        virtual void stop();

        // adapted body transmission control
        virtual void abDiscard();

        virtual void abMake();

        virtual void abMakeMore();

        virtual void abStopMaking();

        // adapted body content extraction and consumption
        virtual libecap::Area abContent(libecap::size_type offset, libecap::size_type size);

        virtual void abContentShift(libecap::size_type size);

        // virgin body state notification
        virtual void noteVbContentDone(bool atEnd);

        virtual void noteVbContentAvailable();

        // libecap::Callable API, via libecap::host::E2GReqXaction
        virtual bool callable() const;

    protected:
        libecap::host::Xaction *lastHostCall(); // clears hostx

    private:
        libecap::host::Xaction *hostx; // Host transaction rep

        typedef enum {
            opUndecided,
            opOn,
            opComplete,
            opNever
        } OperationState;

        OperationState receivingVb;
        OperationState sendingAb;

        E2GuardianInterface e2gInterface;
    };
}