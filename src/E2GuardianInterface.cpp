#include <E2GuardianInterface.h>
#include <Logger.h>

ConnectionHandler E2GuardianInterface::ch;

OptionContainer E2GuardianInterface::o;

std::shared_ptr<LOptionContainer> E2GuardianInterface::ldl = o.currentLists();

E2GuardianInterface::E2GuardianInterface() : filterGroup(0) {

}

bool E2GuardianInterface::onRequest(HTTPHeader &header, std::string clientIp, bool isMitm) {
    // Set timeout
    header.setTimeout(o.pcon_timeout);

    // Flags
    bool wasChecked = false;
    bool wasRequested = false;
    bool isException = false;
    bool isOurWebserver = false;
    bool wasclean = false;
    bool cacheHit = false;
    bool isBypass = false;
    bool isCookieBypass = false;
    bool isVirusBypass = false;
    bool isScanBypass = false;
    bool isPostBlock = false;
    bool pausedTooBig = false;
    bool wasInfected = false;
    bool wasScanned = false;
    bool contentModified = false;
    bool urlModified = false;
    bool headerModified = false;
    bool headerAdded = false;
    bool isConnect;
    bool isHead;
    bool scanError;
    bool isMitmCandidate = false;
    bool doMitm = false;
    bool isSsl = false;
    int bypassTimestamp = 0;
    bool urlRedirect = false;
    bool logged = false; // Remove some results from log: eg: 302 requests
    bool dohash = false;
    bool useXForwardedFor = false;
    bool isBannedUser = false;
    int gmode = 0;
    bool authed = false;
    NaughtyFilter checkMe;

    bool matchedIp;
    std::string room;
    std::string clientUser;
    std::string *clientHost = NULL;
    std::string urlParams;
    std::list<postinfo> postParts;
    String lastCategory;

    // 0=none, 1=first line, 2=all
    int headerSent = 0;
    int messageNo = 0;

    // Content scanners for post request
    std::deque<CSPlugin *> reqScanners;
    std::deque<CSPlugin *> respScanners;

    std::string mimeType("-");

    String url;
    String logUrl;
    String urld;
    String urlDomain;

    std::string exceptionReason; // to hold the reason for not blocking
    std::string exceptionCat;

    off_t docSize = 0;

    // Scan
    url = header.getUrl(false, isMitm);
    logUrl = header.getLogUrl(false, isMitm);
    urld = header.decode(url);
    urlDomain = url.getHostname();
    isSsl = header.requestType().startsWith("CONNECT");

    // TODO: We don't need xforward...

    // Check for bad urls
    if (header.malformedURL(url)) {
        messageNo = 200;
        return false;
    }

    // TODO: No idea what the point was here...
    // if(urlDomain == "internal.test.e2guardian.org") {
    //    return false;
    // }

    // Total block list checking
    if (o.use_total_block_list && o.inTotalBlockList(urld)) {
        // TODO: there was some custom messages here for ssl and not...
        return false;
    }

    bool persistentOutgoing = header.isPersistent();
    bool overridePersistent = false;
    // TODO: auth plugin stuff should goe here this will have to be done differently w/ ecap... line 755 e2g ch

    gmode = ldl->fg[filterGroup]->group_mode;

#ifdef __SSLMITM
    // Set if candidate MITM (exceptions will not go to MITM)
    isMitmCandidate = isSsl && ldl->fg[filterGroup]->ssl_mitm && (header.port == 443);
#endif

    // Check if user is banned
    isBannedUser = (gmode == 0);

    // Check if machine is banned
    bool isBannedIp = ldl->inBannedIPList(&clientIp, clientHost);
    bool partBanned;
    if (isBannedIp) {
        matchedIp = clientHost == NULL;
    } else {
        if (ldl->inRoom(clientIp, room, clientHost, &isBannedIp, &partBanned, &isException, urld)) {
            if (isBannedIp) {
                matchedIp = clientHost == NULL;
            }
            if (isException) {
                // do reason codes etc
                exceptionReason = o.language_list.getTranslation(630);
                exceptionReason.append(room);
                exceptionReason.append(o.language_list.getTranslation(631));
                messageNo = 632;
            }
        }
    }

    // TODO: Orig IP

    // TODO: "start of by pass" line 1089
    if ((ldl->fg[filterGroup]->bypass_mode != 0) || (ldl->fg[filterGroup]->bypass_mode != 0)) {
        if (header.isScanBypassURL(&logUrl, ldl->fg[filterGroup]->magic.c_str(), clientIp.c_str())) {
            isScanBypass = true;
            isBypass = true;
            exceptionReason = o.language_list.getTranslation(608);
        } else {
            if (ldl->fg[filterGroup]->bypass_mode != 0)
                bypassTimestamp = header.isBypassURL(&logUrl, ldl->fg[filterGroup]->magic.c_str(), clientIp.c_str(),
                                                     NULL);
            if ((bypassTimestamp == 0) && (ldl->fg[filterGroup]->infection_bypass_mode != 0))
                bypassTimestamp = header.isBypassURL(&logUrl, ldl->fg[filterGroup]->imagic.c_str(), clientIp.c_str(),
                                                     &isVirusBypass);
            if (bypassTimestamp > 0) {
                header.chopBypass(logUrl, isVirusBypass);
                if (bypassTimestamp > 1) { // not expired
                    isBypass = true;
                    // checkme: need a TR string for virus bypass
                    exceptionReason = o.language_list.getTranslation(606);
                }
            } else if (ldl->fg[filterGroup]->bypass_mode != 0) {
                if (header.isBypassCookie(urlDomain, ldl->fg[filterGroup]->cookie_magic.c_str(), clientIp.c_str())) {
                    isCookieBypass = true;
                    isBypass = true;
                    isException = true;
                    exceptionReason = o.language_list.getTranslation(607);
                }
            }
        }

        bool is_ip = ch.isIPHostnameStrip(urld);
        char *nopass;

        if (((*ldl->fg[filterGroup]).inBannedSiteListwithbypass(url, true, is_ip, isSsl, lastCategory)) != NULL) {
            isException = false;
            isBypass = false;
            isPostBlock = true;
        }

        // Start of scan bypass
//        if (isScanBypass) {
//            //we need to decode the URL and send the temp file with the
//            //correct header to the client then delete the temp file
//            String tempfilename(url.after("GSBYPASS=").after("&N="));
//            String tempfilemime(tempfilename.after("&M="));
//            String tempfiledis(header.decode(tempfilemime.after("&D="), true));
//
//            String rtype(header.requestType());
//            tempfilemime = tempfilemime.before("&D=");
//            tempfilename = o.download_dir + "/tf" + tempfilename.before("&M=");
//            try {
//                docSize = sendFile(&peerconn, tempfilename, tempfilemime, tempfiledis, url);
//                header.chopScanBypass(url);
//                url = header.getLogUrl();
//                doLog(clientuser, clientip, logurl, header.port, exceptionreason,
//                      rtype, docsize, NULL, false, 0, isexception, false, &thestart,
//                      cachehit, 200, mimetype, wasinfected, wasscanned, 0, filtergroup,
//                      &header);
//
//                if (o.delete_downloaded_temp_files) {
//                    unlink(tempfilename.toCharArray());
//                }
//            } catch (std::exception &e) {
//                persistProxy = false;
//                proxysock.close(); // close connection to proxy
//                break;
//            }
//        }
    }

    char *retchar;

    if (!(isBannedUser || isBannedIp || isBypass || isException)) {
        //bool is_ssl = header.requestType() == "CONNECT";
        bool is_ip = ch.isIPHostnameStrip(urld);
        if ((gmode == 2)) { // admin user
            isException = true;
            exceptionReason = o.language_list.getTranslation(601);
            messageNo = 601;
            // Exception client user match.
        } else if (ldl->inExceptionIPList(&clientIp, clientHost)) { // admin pc
            matchedIp = clientHost == NULL;
            isException = true;
            exceptionReason = o.language_list.getTranslation(600);
            // Exception client IP match.
        }
        if (!isException && (*ldl->fg[filterGroup]).enable_local_list) {

            if (isSsl && (!isMitmCandidate) &&
                ((retchar = ldl->fg[filterGroup]->inLocalBannedSSLSiteList(urld, false, is_ip, isSsl, lastCategory)) !=
                 NULL)) { // blocked SSL site
                checkMe.whatIsNaughty = o.language_list.getTranslation(580); // banned site
                messageNo = 580;
                checkMe.whatIsNaughty += retchar;
                checkMe.whatIsNaughtyLog = checkMe.whatIsNaughty;
                checkMe.isItNaughty = true;
                checkMe.whatIsNaughtyCategories = lastCategory.toCharArray();
            } else if (ldl->fg[filterGroup]->inLocalExceptionSiteList(urld, false, is_ip, isSsl,
                                                                      lastCategory)) { // allowed site
                if (ldl->fg[0]->isOurWebserver(url)) {
                    isOurWebserver = true;
                } else {
                    isException = true;
                    exceptionReason = o.language_list.getTranslation(662);
                    messageNo = 662;
                    // Exception site match.
                    exceptionCat = lastCategory.toCharArray();
                }
            } else if (ldl->fg[filterGroup]->inLocalExceptionURLList(urld, false, is_ip, isSsl,
                                                                     lastCategory)) { // allowed url
                isException = true;
                exceptionReason = o.language_list.getTranslation(663);
                messageNo = 663;
                // Exception url match.
                exceptionCat = lastCategory.toCharArray();
            } else if ((!isSsl) && ch.embededRefererChecks(&header, &urld, &url,
                                                                           filterGroup)) { // referer exception
                isException = true;
                exceptionReason = o.language_list.getTranslation(620);
                messageNo = 620;
            }
            // end of local lists exception checking
        }
    }

    if ((*ldl->fg[filterGroup]).enable_local_list) {
        if (authed && !(isException || isOurWebserver)) {
            // check if this is a search request
            if (!isSsl)
                checkMe.isSearch = header.isSearch(ldl->fg[filterGroup]);
            // add local grey and black checks
            if (!isMitmCandidate || ldl->fg[filterGroup]->only_mitm_ssl_grey) {
                ch.requestLocalChecks(&header, &checkMe, &urld, &url, &clientIp, &clientUser,
                                                      filterGroup, isBannedUser, isBannedIp, room);
                messageNo = checkMe.message_no;
            } else {
                String lc;
                if (ldl->fg[filterGroup]->inLocalBannedSiteList(urld, false, false, true, lc) != NULL) {
                    checkMe.isGrey = true;
                }
            }
        }
    }

    // Orginal section only now called if local list not matched
    if (authed && (!(isBannedUser || isBannedIp || isBypass || isException || checkMe.isGrey || checkMe.isItNaughty ||
                     ldl->fg[filterGroup]->use_only_local_allow_lists))) {
        //bool is_ssl = header.requestType() == "CONNECT";
        bool is_ip = ch.isIPHostnameStrip(urld);
        if (isSsl && (!isMitmCandidate) &&
            ((retchar = ldl->fg[filterGroup]->inBannedSSLSiteList(urld, false, is_ip, isSsl, lastCategory)) !=
             NULL)) { // blocked SSL site
            checkMe.whatIsNaughty = o.language_list.getTranslation(520); // banned site
            messageNo = 520;
            checkMe.whatIsNaughty += retchar;
            checkMe.whatIsNaughtyLog = checkMe.whatIsNaughty;
            checkMe.isItNaughty = true;
            checkMe.whatIsNaughtyCategories = lastCategory.toCharArray();
        }

        int rc;
        if (ldl->fg[filterGroup]->inExceptionSiteList(urld, true, is_ip, isSsl, lastCategory)) // allowed site
        {
            if (ldl->fg[0]->isOurWebserver(url)) {
                isOurWebserver = true;
            } else {
                isException = true;
                exceptionReason = o.language_list.getTranslation(602);
                messageNo = 602;
                // Exception site match.
                exceptionCat = lastCategory.toCharArray();
            }
        } else if (ldl->fg[filterGroup]->inExceptionURLList(urld, true, is_ip, isSsl, lastCategory)) { // allowed url
            isException = true;
            exceptionReason = o.language_list.getTranslation(603);
            messageNo = 603;
            // Exception url match.
            exceptionCat = lastCategory.toCharArray();
        } else if ((rc = ldl->fg[filterGroup]->inExceptionRegExpURLList(urld, lastCategory)) > -1) {
            isException = true;
            // exception regular expression url match:
            exceptionReason = o.language_list.getTranslation(609);
            messageNo = 609;
            exceptionReason += ldl->fg[filterGroup]->exception_regexpurl_list_source[rc].toCharArray();
            exceptionCat = lastCategory.toCharArray();
        } else if (!(*ldl->fg[filterGroup]).enable_local_list) {
            if (ch.embededRefererChecks(&header, &urld, &url, filterGroup)) { // referer exception
                isException = true;
                exceptionReason = o.language_list.getTranslation(620);
                messageNo = 620;
            }
        }
    }
    // if banned with regex blank ban and exception check nevertheless
    if ((*ldl->fg[filterGroup]).enable_regex_grey && isException && (!(isBypass || isBannedUser || isBannedIp))) {
        ch.requestChecks(&header, &checkMe, &urld, &url, &clientIp, &clientUser, filterGroup,
                                         isBannedUser, isBannedIp, room);
        // Debug deny code //
        // syslog(LOG_ERR, "code: %d", checkme.message_no); //
        if (checkMe.message_no == 503 || checkMe.message_no == 508) {
            isException = false;
            messageNo = checkMe.message_no;
        }
    }

    String reqtype(header.requestType());
    isConnect = reqtype[0] == 'C';
    isHead = reqtype[0] == 'H';

    // Query request and response scanners to see which is interested in scanning data for this request
    // TODO - Should probably block if willScanRequest returns error
    bool multipart = false;
    if (!isBannedIp && !isBannedUser && !isConnect && !isHead
        && (ldl->fg[filterGroup]->disable_content_scan != 1)
        && !(isException && !o.content_scan_exceptions)) {
        for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i) {
            int csrc = ((CSPlugin *) (*i))->willScanRequest(header.getUrl(), clientUser.c_str(), ldl->fg[filterGroup],
                                                            clientIp.c_str(), false, false, isException, isBypass);
            if (csrc > 0)
                respScanners.push_back((CSPlugin *) (*i));
            else if (csrc < 0)
                Logger::writeLine("willScanRequest returned error: " + csrc);
        }

        // Only query scanners regarding outgoing data if we are actually sending data in the request
        if (header.contentLength() > 0) {
            // POST data log entry - fill in for single-part posts,
            // and fill in overall "guess" for multi-part posts;
            // latter will be overwritten with more detail about
            // individual parts, if part-by-part filtering occurs.
            String mtype(header.getContentType());
            postParts.push_back(postinfo());
            postParts.back().mimetype.assign(mtype);
            postParts.back().size = header.contentLength();

            if (mtype == "application/x-www-form-urlencoded" || (multipart = (mtype == "multipart/form-data"))) {
                // Don't bother if it's a single part POST and is above max_content_ramcache_scan_size
                if (!multipart && header.contentLength() > o.max_content_ramcache_scan_size) {

                } else {
                    for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i) {
                        int csrc = ((CSPlugin *) (*i))->willScanRequest(header.getUrl(), clientUser.c_str(),
                                                                        ldl->fg[filterGroup], clientIp.c_str(), true,
                                                                        !multipart, isException, isBypass);
                        if (csrc > 0)
                            reqScanners.push_back((CSPlugin *) (*i));
                        else if (csrc < 0)
                            Logger::writeLine("willScanRequest returned error: " + csrc);
                    }
                }
            }
        }
    }


    return (isException || isCookieBypass || isVirusBypass)
           // don't filter exception and local web server
           // Cookie bypass so don't need to add cookie so just CONNECT (unless should content scan)
           && !isBannedIp // bad users pc
           && !isBannedUser // bad user
           && reqScanners.empty() && respScanners.empty();

}

void E2GuardianInterface::onResponse(HTTPHeader &header, DataBuffer &body) {

}