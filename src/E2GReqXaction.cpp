#include <E2GReqService.h>
#include <E2GReqXaction.h>
#include <Logger.h>
#include <HTTPHeader.hpp>

Adapter::E2GReqXaction::E2GReqXaction(libecap::shared_ptr<E2GReqService> s, libecap::host::Xaction *x): hostx(x) {
}

Adapter::E2GReqXaction::~E2GReqXaction() {
    if (libecap::host::Xaction *x = hostx) {
        hostx = 0;
        x->adaptationAborted();
    }
}

const libecap::Area Adapter::E2GReqXaction::option(const libecap::Name &) const {
    return libecap::Area(); // this transaction has no meta-information
}

void Adapter::E2GReqXaction::visitEachOption(libecap::NamedValueVisitor &) const {
    // this transaction has no meta-information to pass to the visitor
}

void Adapter::E2GReqXaction::start() {
    Logger::writeLine("E2GReqXaction::start()");

    Must(hostx);

    // Receive vb
    if (hostx->virgin().body()) {
        receivingVb = opOn;
        hostx->vbMake(); // ask host to supply virgin body
    } else {
        receivingVb = opNever;
    }

    // Clone vb for adaptation
    libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
    Must(adapted != nullptr);

    HTTPHeader header;
    header.ecapIn(adapted->header());

    libecap::Area clientIp = hostx->option(libecap::Name("metaClientIp"));
    bool send = e2gInterface.onRequest(header, std::string(clientIp.start, clientIp.size), false);

    header.ecapOut(adapted->header());

    // Delete content length header, squid doesnt modify the content length for us as it should..
    // WARNING: unknown length may have performance implications for the host
    // adapted->header().removeAny(libecap::headerContentLength);

    // Add a test header
    static const libecap::Name name("X-Ecap");
    const libecap::Header::Value value = libecap::Area::FromTempString(libecap::MyHost().uri());
    adapted->header().add(name, value);

    // Send adapted
    if(send) {
        if (!adapted->body()) {
            sendingAb = opNever; // there is nothing to send
            lastHostCall()->useAdapted(adapted);
        } else {
            hostx->useAdapted(adapted);
        }
    } else {
        hostx->blockVirgin();
    }
}

void Adapter::E2GReqXaction::stop() {
    Logger::writeLine("E2GReqXaction::stop()");

    hostx = 0;
    // the caller will delete
}

void Adapter::E2GReqXaction::abDiscard()
{
    Must(sendingAb == opUndecided); // have not started yet
    sendingAb = opNever;
}

void Adapter::E2GReqXaction::abMake()
{
    Must(sendingAb == opUndecided); // have not yet started or decided not to send
    Must(hostx->virgin().body()); // that is our only source of ab content

    // we are or were receiving vb
    Must(receivingVb == opOn || receivingVb == opComplete);

    sendingAb = opOn;
    hostx->noteAbContentAvailable();
}

void Adapter::E2GReqXaction::abMakeMore()
{
    Must(receivingVb == opOn); // a precondition for receiving more vb
    hostx->vbMakeMore();
}

void Adapter::E2GReqXaction::abStopMaking()
{
    sendingAb = opComplete;
    // we may still continue receiving
}

libecap::Area Adapter::E2GReqXaction::abContent(libecap::size_type offset, libecap::size_type size)
{
    Must(sendingAb == opOn);
    return hostx->vbContent(offset, size);
}

void Adapter::E2GReqXaction::abContentShift(libecap::size_type size)
{
    Must(sendingAb == opOn);
    hostx->vbContentShift(size);
}


void Adapter::E2GReqXaction::noteVbContentDone(bool atEnd)
{
    Must(receivingVb == opOn);
    receivingVb = opComplete;
    hostx->noteAbContentDone(atEnd);
}

void Adapter::E2GReqXaction::noteVbContentAvailable()
{
    Must(receivingVb == opOn);
    if (sendingAb == opOn)
        hostx->noteAbContentAvailable();
}


bool Adapter::E2GReqXaction::callable() const {
    return hostx != 0; // no point to call us if we are done
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
libecap::host::Xaction *Adapter::E2GReqXaction::lastHostCall() {
    libecap::host::Xaction *x = hostx;
    Must(x);
    hostx = 0;
    return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered = (libecap::RegisterVersionedService(new Adapter::E2GReqService), true);
