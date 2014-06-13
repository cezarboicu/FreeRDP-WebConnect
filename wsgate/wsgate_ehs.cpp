/* vim: set et ts=4 sw=4 cindent:
*
* FreeRDP-WebConnect,
* A gateway for seamless access to your RDP-Sessions in any HTML5-compliant browser.
*
* Copyright 2012 Fritz Elfert <wsgate@fritz-elfert.de>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include "wsgate_ehs.hpp"

namespace wsgate {
    int nFormValue(HttpRequest *request, const string & name, int defval) {
        string tmp(request->FormValues(name).m_sBody);
        int ret = defval;
        if (!tmp.empty()) {
            try {
                ret = boost::lexical_cast<int>(tmp);
            }
            catch (const boost::bad_lexical_cast & e) { ret = defval; }
        }
        return ret;
    };
    ResponseCode WsGate::HandleWsgateRequest(HttpRequest *request, HttpResponse *response, std::string uri, std::string thisHost)
    {
        //FreeRDP Params
        string dtsize;
        string rdphost;
        string rdppcb;
        string rdpuser;
        int rdpport;
        string rdppass;
        WsRdpParams params;
        bool setCookie = true;

        if (boost::starts_with(uri, "/wsgate?token="))
        {
            // OpenStack console authentication
            setCookie = false;
            try
            {
                log::info << "Starting OpenStack token authentication" << endl;

                string tokenId = request->FormValues("token").m_sBody;

                nova_console_token_auth* token_auth = nova_console_token_auth_factory::get_instance();

                nova_console_info info = token_auth->get_console_info(m_sOpenStackAuthUrl, m_sOpenStackUsername,
                    m_sOpenStackPassword, m_sOpenStackTenantName,
                    tokenId);

                log::info << "Host: " << info.host << " Port: " << info.port
                    << " Internal access path: " << info.internal_access_path
                    << endl;

                rdphost = info.host;
                rdpport = info.port;
                rdppcb = info.internal_access_path;

                rdpuser = m_sHyperVHostUsername;
                rdppass = m_sHyperVHostPassword;
            }
            catch (exception& ex)
            {
                log::err << "OpenStack token authentication failed: " << ex.what() << endl;
                return HTTPRESPONSECODE_400_BADREQUEST;
            }
        }
        else
        {
            dtsize = request->FormValues("dtsize").m_sBody;
            rdphost = request->FormValues("host").m_sBody;
            rdppcb = request->FormValues("pcb").m_sBody;
            rdpuser = request->FormValues("user").m_sBody;
            istringstream(request->FormValues("port").m_sBody) >> rdpport;
            rdppass = base64_decode(request->FormValues("pass").m_sBody);
        }

        params =
        {
            rdpport,
            1024,
            768,
            m_bOverrideRdpPerf ? m_RdpOverrideParams.perf : nFormValue(request, "perf", 0),
            m_bOverrideRdpFntlm ? m_RdpOverrideParams.fntlm : nFormValue(request, "fntlm", 0),
            m_bOverrideRdpNotls ? m_RdpOverrideParams.notls : nFormValue(request, "notls", 0),
            m_bOverrideRdpNonla ? m_RdpOverrideParams.nonla : nFormValue(request, "nonla", 0),
            m_bOverrideRdpNowallp ? m_RdpOverrideParams.nowallp : nFormValue(request, "nowallp", 0),
            m_bOverrideRdpNowdrag ? m_RdpOverrideParams.nowdrag : nFormValue(request, "nowdrag", 0),
            m_bOverrideRdpNomani ? m_RdpOverrideParams.nomani : nFormValue(request, "nomani", 0),
            m_bOverrideRdpNotheme ? m_RdpOverrideParams.notheme : nFormValue(request, "notheme", 0),
        };

        CheckForPredefined(rdphost, rdpuser, rdppass);

        if (!ConnectionIsAllowed(rdphost)){
            LogInfo(request->RemoteAddress(), rdphost, "403 Denied by access rules");
            return HTTPRESPONSECODE_403_FORBIDDEN;
        }

        if (!dtsize.empty()) {
            try {
                vector<string> wh;
                boost::split(wh, dtsize, is_any_of("x"));
                if (wh.size() == 2) {
                    params.width = boost::lexical_cast<int>(wh[0]);
                    params.height = boost::lexical_cast<int>(wh[1]);
                }
            }
            catch (const exception &e) {
                params.width = 1024;
                params.height = 768;
            }
        }
        response->SetBody("", 0);

        int wsocketCheck = CheckIfWSocketRequest(request, response, uri, thisHost);
        if (wsocketCheck != 0)
        {
            //using a switch in case of new errors being thrown from the wsocket check
            switch (wsocketCheck)
            {
            case 400:
            {
                        return HTTPRESPONSECODE_400_BADREQUEST;
            };
            case 426:
            {
                        return HTTPRESPONSECODE_426_UPGRADE_REQUIRED;
            };
            }
        }

        string wskey(request->Headers("Sec-WebSocket-Key"));
        SHA1 sha1;
        uint32_t digest[5];
        sha1 << wskey.c_str() << ws_magic;
        if (!sha1.Result(digest))
        {
            LogInfo(request->RemoteAddress(), uri, "500 (Digest calculation failed)");
            return HTTPRESPONSECODE_500_INTERNALSERVERERROR;
        }
        // Handle endianess
        for (int i = 0; i < 5; ++i)
        {
            digest[i] = htonl(digest[i]);
        }
        MyRawSocketHandler *sh = dynamic_cast<MyRawSocketHandler*>(GetRawSocketHandler());
        if (!sh)
        {
            throw tracing::runtime_error("No raw socket handler available");
        }
        response->EnableIdleTimeout(false);
        response->EnableKeepAlive(true);
        try
        {
            if (!sh->Prepare(request->Connection(), rdphost, rdppcb, rdpuser, rdppass, params))
            {
                LogInfo(request->RemoteAddress(), uri, "503 (RDP backend not available)");
                response->EnableIdleTimeout(true);
                return HTTPRESPONSECODE_503_SERVICEUNAVAILABLE;
            }
        }
        catch (...)
        {
            log::info << "caught exception!" << endl;
        }

        //Use cookies only as standalone app
        if (setCookie)
            ManageCookies(request, response, rdphost, rdppcb, rdpuser, thisHost);
        else
            //openstack - wipe out any cookies
            ManageCookies(request, response, "", "", "", thisHost);
        response->RemoveHeader("Content-Type");
        response->RemoveHeader("Content-Length");
        response->RemoveHeader("Last-Modified");
        response->RemoveHeader("Cache-Control");

        string wsproto(request->Headers("Sec-WebSocket-Protocol"));
        if (0 < wsproto.length())
        {
            response->SetHeader("Sec-WebSocket-Protocol", wsproto);
        }
        response->SetHeader("Upgrade", "websocket");
        response->SetHeader("Connection", "Upgrade");
        response->SetHeader("Sec-WebSocket-Accept", base64_encode(reinterpret_cast<const unsigned char *>(digest), 20));

        LogInfo(request->RemoteAddress(), uri, "101");
        return HTTPRESPONSECODE_101_SWITCHING_PROTOCOLS;
    };
    ResponseCode WsGate::HandleRequest(HttpRequest *request, HttpResponse *response)
    {
        //Connection Params
        string uri = request->Uri();
        string thisHost = m_sHostname.empty() ? request->Headers("Host") : m_sHostname;

        //add new behaviour note:
        //those requests that have the same beggining have to be placed with an if else condition

        if (request->Method() != REQUESTMETHOD_GET)
            return HTTPRESPONSECODE_400_BADREQUEST;

        if (m_bRedirect && (!request->Secure()))
        {
            return HandleRedirectRequest(request, response, uri, thisHost);
        }

        if (boost::starts_with(uri, "/robots.txt"))
        {
            return HandleRobotsRequest(request, response, uri, thisHost);
        }
        if (boost::starts_with(uri, "/cur/"))
        {
            return HandleCursorRequest(request, response, uri, thisHost);
        }

        if (boost::starts_with(uri, "/wsgate?"))
        {
            return HandleWsgateRequest(request, response, uri, thisHost);
        }

        if (boost::starts_with(uri, "/connect?"))
        {
            //handle a direct connection via queryString here
            return HTTPRESPONSECODE_200_OK;
        }
        return HandleHTTPRequest(request, response);
    };

    HttpResponse *WsGate::HandleThreadException(ehs_threadid_t, HttpRequest *request, exception &ex)
    {
        HttpResponse *ret = NULL;
        string msg(ex.what());
        log::err << "##################### Catched " << msg << endl;
        log::err << "request: " << hex << request << dec << endl;
        tracing::exception *btx =
            dynamic_cast<tracing::exception*>(&ex);
        if (NULL != btx) {
            string tmsg = btx->where();
            log::err << "Backtrace:" << endl << tmsg;
            if (0 != msg.compare("fatal")) {
                ret = HttpResponse::Error(HTTPRESPONSECODE_500_INTERNALSERVERERROR, request);
                string body(ret->GetBody());
                tmsg.insert(0, "<br>\n<pre>").append(msg).append("</pre><p><a href=\"/\">Back to main page</a>");
                body.insert(body.find("</body>"), tmsg);
                ret->SetBody(body.c_str(), body.length());
            }
        }
        else {
            ret = HttpResponse::Error(HTTPRESPONSECODE_500_INTERNALSERVERERROR, request);
        }
        return ret;
    };

    void WsGate::CheckForPredefined(string& rdpHost, string& rdpUser, string& rdpPass)
    {
        if (m_bOverrideRdpHost)
            rdpHost.assign(m_sRdpOverrideHost);

        if (m_bOverrideRdpUser)
            rdpUser.assign(m_sRdpOverrideUser);

        if (m_bOverrideRdpPass)
            rdpPass.assign(m_sRdpOverridePass);
    };

    bool WsGate::ConnectionIsAllowed(string rdphost)
    {
        bool denied = true;
        vector<boost::regex>::iterator ri;
        if (m_bOrderDenyAllow) {
            denied = false;
            for (ri = m_deniedHosts.begin(); ri != m_deniedHosts.end(); ++ri) {
                if (regex_match(rdphost, *ri)) {
                    denied = true;
                    break;
                }
            }
            for (ri = m_allowedHosts.begin(); ri != m_allowedHosts.end(); ++ri) {
                if (regex_match(rdphost, *ri)) {
                    denied = false;
                    break;
                }
            }
        }
        else {
            for (ri = m_allowedHosts.begin(); ri != m_allowedHosts.end(); ++ri) {
                if (regex_match(rdphost, *ri)) {
                    denied = false;
                    break;
                }
            }
            for (ri = m_deniedHosts.begin(); ri != m_deniedHosts.end(); ++ri) {
                if (regex_match(rdphost, *ri)) {
                    denied = true;
                    break;
                }
            }
        }
        return true;
    };

    /* =================================== CURSOR HANDLING =================================== */
    ResponseCode WsGate::HandleCursorRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost)
    {
        string idpart(uri.substr(5));
        vector<string> parts;
        boost::split(parts, idpart, is_any_of("/"));
        SessionMap::iterator it = m_SessionMap.find(parts[0]);
        if (it != m_SessionMap.end()) {
            uint32_t cid = 0;
            try {
                cid = boost::lexical_cast<uint32_t>(parts[1]);
            }
            catch (const boost::bad_lexical_cast & e) { cid = 0; }
            if (cid) {
                RDP::cursor c = it->second->GetCursor(cid);
                time_t ct = c.get<0>();
                if (0 != ct) {
                    if (notModified(request, response, ct)) {
                        return HTTPRESPONSECODE_304_NOT_MODIFIED;
                    }
                    string png = c.get<1>();
                    if (!png.empty()) {
                        response->SetHeader("Content-Type", "image/cur");
                        response->SetLastModified(ct);
                        response->SetBody(png.data(), png.length());
                        LogInfo(request->RemoteAddress(), uri, "200 OK");
                        return HTTPRESPONSECODE_200_OK;
                    }
                }
            }
        }
        LogInfo(request->RemoteAddress(), uri, "404 Not Found");
        return HTTPRESPONSECODE_404_NOTFOUND;
    };

    /* =================================== REDIRECT REQUEST =================================== */
    ResponseCode WsGate::HandleRedirectRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost)
    {
        string dest(boost::starts_with(uri, "/wsgate?") ? "wss" : "https");
        //adding the sslPort to the dest Location
        if (m_pVm->count("ssl.port"))
        {
            stringstream sslPort;
            sslPort << (*m_pVm)["ssl.port"].as<uint16_t>();

            //Replace the http port with the ssl one
            string thisSslHost = thisHost.substr(0, thisHost.find(":")) + ":" + sslPort.str();

            //append the rest of the uri
            dest.append("://").append(thisSslHost).append(uri);
            response->SetHeader("Location", dest);
            LogInfo(request->RemoteAddress(), uri, "301 Moved permanently");
            return HTTPRESPONSECODE_301_MOVEDPERMANENTLY;
        }
        else
        {
            LogInfo(request->RemoteAddress(), uri, "404 Not found");
            return HTTPRESPONSECODE_404_NOTFOUND;
        }

    };

    /* =================================== HANDLE WSGATE REQUEST =================================== */
    int WsGate::CheckIfWSocketRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost)
    {
        if (0 != request->HttpVersion().compare("1.1"))
        {
            LogInfo(request->RemoteAddress(), uri, "400 (Not HTTP 1.1)");
            return 400;
        }

        string wshost(to_lower_copy(request->Headers("Host")));
        string wsconn(to_lower_copy(request->Headers("Connection")));
        string wsupg(to_lower_copy(request->Headers("Upgrade")));
        string wsver(request->Headers("Sec-WebSocket-Version"));
        string wskey(request->Headers("Sec-WebSocket-Key"));

        string wsproto(request->Headers("Sec-WebSocket-Protocol"));
        string wsext(request->Headers("Sec-WebSocket-Extension"));

        if (!MultivalHeaderContains(wsconn, "upgrade"))
        {
            LogInfo(request->RemoteAddress(), uri, "400 (No upgrade header)");

            return 400;
        }
        if (!MultivalHeaderContains(wsupg, "websocket"))
        {
            LogInfo(request->RemoteAddress(), uri, "400 (Upgrade header does not contain websocket tag)");
            return 400;
        }
        if (0 != wshost.compare(thisHost))
        {
            LogInfo(request->RemoteAddress(), uri, "400 (Host header does not match)");
            return 400;
        }
        string wskey_decoded(base64_decode(wskey));

        if (16 != wskey_decoded.length())
        {
            LogInfo(request->RemoteAddress(), uri, "400 (Invalid WebSocket key)");
            return 400;
        }

        if (!MultivalHeaderContains(wsver, "13"))
        {
            response->SetHeader("Sec-WebSocket-Version", "13");
            LogInfo(request->RemoteAddress(), uri, "426 (Protocol version not 13)");
            return 426;
        }

        return 0;
    };

    void WsGate::ManageCookies(HttpRequest *request, HttpResponse *response, string rdphost, string rdppcb, string rdpuser, string thisHost)
    {
        CookieParameters setcookie;
        setcookie["path"] = "/";
        setcookie["host"] = thisHost;
        setcookie["max-age"] = "864000";
        if (request->Secure()) {
            setcookie["secure"] = "";
        }
        CookieParameters delcookie;
        delcookie["path"] = "/";
        delcookie["host"] = thisHost;
        delcookie["max-age"] = "0";
        if (request->Secure()) {
            delcookie["secure"] = "";
        }
        if (rdppcb.empty()) {
            delcookie["name"] = "lastpcb";
            delcookie["value"] = "%20";
            response->SetCookie(delcookie);
        }
        else {
            setcookie["name"] = "lastpcb";
            setcookie["value"] = (rdppcb);
            response->SetCookie(setcookie);
        }
        if (rdphost.empty()) {
            delcookie["name"] = "lasthost";
            delcookie["value"] = "%20";
            response->SetCookie(delcookie);
        }
        else {
            setcookie["name"] = "lasthost";
            setcookie["value"] = (m_bOverrideRdpHost ? "<predefined>" : rdphost);
            response->SetCookie(setcookie);
        }
        if (rdpuser.empty()) {
            delcookie["name"] = "lastuser";
            delcookie["value"] = "%20";
            response->SetCookie(delcookie);
        }
        else {
            setcookie["name"] = "lastuser";
            setcookie["value"] = (m_bOverrideRdpUser ? "<predefined>" : rdpuser);
            response->SetCookie(setcookie);
        }
    };

    ResponseCode WsGate::HandleHTTPRequest(HttpRequest *request, HttpResponse *response, bool tokenAuth)
    {
        string uri(request->Uri());
        string thisHost(m_sHostname.empty() ? request->Headers("Host") : m_sHostname);

        // Regular (non WebSockets) request
        bool bDynDebug = m_bDebug;
        if (!bDynDebug) {
            // Enable debugging by using a custom UserAgent header
            if (iequals(request->Headers("X-WSGate-Debug"), "true")) {
                bDynDebug = true;
            }
        }
        if (0 != thisHost.compare(request->Headers("Host"))) {
            LogInfo(request->RemoteAddress(), uri, "404 Not found");
            return HTTPRESPONSECODE_404_NOTFOUND;
        }


        path p(m_sDocumentRoot);
        p /= uri;
        if (ends_with(uri, "/")) {
            p /= (bDynDebug ? "/index-debug.html" : "/index.html");
        }
        p.normalize();
        bool externalRequest = false;

        if (!exists(p)) {
            p = m_sDocumentRoot;
            p /= "index.html";
        }

        if (!is_regular_file(p)) {
            LogInfo(request->RemoteAddress(), uri, "403 Forbidden");
            log::warn << "Request from " << request->RemoteAddress()
                << ": " << uri << " => 403 Forbidden" << endl;

            p = m_sDocumentRoot;
            p /= "index.html";
        }

        // Handle If-modified-sice request header
        time_t mtime = last_write_time(p);
        if (notModified(request, response, mtime)) {
            return HTTPRESPONSECODE_304_NOT_MODIFIED;
        }
        response->SetLastModified(mtime);

        string body;
        StaticCache::iterator ci = m_StaticCache.find(p);
        if ((m_StaticCache.end() != ci) && (ci->second.get<0>() == mtime)) {
            body.assign(ci->second.get<1>());
        }
        else {
            fs::ifstream f(p, ios::binary);
            if (f.fail()) {
                log::warn << "Request from " << request->RemoteAddress()
                    << ": " << uri << " => 404 (file '" << p << "' unreadable)" << endl;
                return HTTPRESPONSECODE_404_NOTFOUND;
            }
            body.assign((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
            f.close();
            m_StaticCache[p] = cache_entry(mtime, body);
        }

#ifdef BOOST_FILESYSTEM_VERSION
# if (BOOST_FILESYSTEM_VERSION >= 3)
        string basename(p.filename().generic_string());
# else
        string basename(p.filename());
# endif
#else
        // Not defined at all: old API
        string basename(p.filename());
#endif

        MimeType mt = simpleMime(to_lower_copy(basename));
        if (HTML == mt) {
            ostringstream oss;

            oss << (request->Secure() ? "wss://" : "ws://") << thisHost << "/wsgate";

            replace_all(body, "%WSURI%", oss.str());
            replace_all(body, "%JSDEBUG%", (bDynDebug ? "-debug" : ""));
            string tmp;
            if (externalRequest)
            {
                string dtsize(request->FormValues("dtsize").m_sBody);
                string port(request->FormValues("port").m_sBody);

                replace_all(body, "%COOKIE_LASTUSER%", request->FormValues("user").m_sBody);
                replace_all(body, "%COOKIE_LASTPASS%", base64_decode(request->FormValues("pass").m_sBody)); // Passw0rd
                replace_all(body, "%COOKIE_LASTHOST%", request->FormValues("host").m_sBody);
                replace_all(body, "%COOKIE_LASTPCB%", request->FormValues("pcb").m_sBody);
                replace_all(body, "var externalConnection = false;", "var externalConnection = true;");
            }
            else
            {
                tmp.assign(m_bOverrideRdpUser ? "<predefined>" : request->Cookies("lastuser"));
                replace_all(body, "%COOKIE_LASTUSER%", tmp);
                tmp.assign(m_bOverrideRdpUser ? "disabled=\"disabled\"" : "");
                replace_all(body, "%DISABLED_USER%", tmp);
                tmp.assign(m_bOverrideRdpPass ? "SomthingUseless" : base64_decode(request->Cookies("lastpass")));
                replace_all(body, "%COOKIE_LASTPASS%", tmp);
                tmp.assign(m_bOverrideRdpPass ? "disabled=\"disabled\"" : "");
                replace_all(body, "%DISABLED_PASS%", tmp);

                tmp.assign(m_bOverrideRdpHost ? "<predefined>" : request->Cookies("lasthost"));
                replace_all(body, "%COOKIE_LASTHOST%", tmp);
                tmp.assign(m_bOverrideRdpHost ? "disabled=\"disabled\"" : "");
                replace_all(body, "%DISABLED_HOST%", tmp);

                tmp.assign(request->Cookies("lastpcb"));
                replace_all(body, "%COOKIE_LASTPCB%", tmp);
                tmp.assign("");
                replace_all(body, "%DISABLED_PCB%", tmp);
            }

            tmp.assign(VERSION).append(".").append(GITREV);
            replace_all(body, "%VERSION%", tmp);

            //The new Port Selector
            if (m_bOverrideRdpPort) {
                replace_all(body, "%DISABLED_PORT%", "disabled=\"disabled\"");
                replace_all(body, "%SELECTED_PORT0%", (0 == m_RdpOverrideParams.port) ? "selected" : "");
                replace_all(body, "%SELECTED_PORT1%", (1 == m_RdpOverrideParams.port) ? "selected" : "");
                replace_all(body, "%SELECTED_PORT2%", (2 == m_RdpOverrideParams.port) ? "selected" : "");
            }
            else {
                replace_all(body, "%DISABLED_PORT%", "");
                replace_all(body, "%SELECTED_PORT0%", "");
                replace_all(body, "%SELECTED_PORT1%", "");
                replace_all(body, "%SELECTED_PORT2%", "");
            }

            //The Desktop Resolution
            if (m_bOverrideRdpPerf) {
                replace_all(body, "%DISABLED_PERF%", "disabled=\"disabled\"");
                replace_all(body, "%SELECTED_PERF0%", (0 == m_RdpOverrideParams.perf) ? "selected" : "");
                replace_all(body, "%SELECTED_PERF1%", (1 == m_RdpOverrideParams.perf) ? "selected" : "");
                replace_all(body, "%SELECTED_PERF2%", (2 == m_RdpOverrideParams.perf) ? "selected" : "");
            }
            else {
                replace_all(body, "%DISABLED_PERF%", "");
                replace_all(body, "%SELECTED_PERF0%", "");
                replace_all(body, "%SELECTED_PERF1%", "");
                replace_all(body, "%SELECTED_PERF2%", "");
            }


            if (m_bOverrideRdpFntlm) {
                replace_all(body, "%DISABLED_FNTLM%", "disabled=\"disabled\"");
                replace_all(body, "%SELECTED_FNTLM0%", (0 == m_RdpOverrideParams.fntlm) ? "selected" : "");
                replace_all(body, "%SELECTED_FNTLM1%", (1 == m_RdpOverrideParams.fntlm) ? "selected" : "");
                replace_all(body, "%SELECTED_FNTLM2%", (2 == m_RdpOverrideParams.fntlm) ? "selected" : "");
            }
            else {
                replace_all(body, "%DISABLED_FNTLM%", "");
                replace_all(body, "%SELECTED_FNTLM0%", "");
                replace_all(body, "%SELECTED_FNTLM1%", "");
                replace_all(body, "%SELECTED_FNTLM2%", "");
            }
            if (m_bOverrideRdpNowallp) {
                tmp.assign("disabled=\"disabled\"").append((m_RdpOverrideParams.nowallp) ? " checked=\"checked\"" : "");
            }
            else {
                tmp.assign("");
            }
            replace_all(body, "%CHECKED_NOWALLP%", tmp);
            if (m_bOverrideRdpNowdrag) {
                tmp.assign("disabled=\"disabled\"").append((m_RdpOverrideParams.nowdrag) ? " checked=\"checked\"" : "");
            }
            else {
                tmp.assign("");
            }
            replace_all(body, "%CHECKED_NOWDRAG%", tmp);
            if (m_bOverrideRdpNomani) {
                tmp.assign("disabled=\"disabled\"").append((m_RdpOverrideParams.nomani) ? " checked=\"checked\"" : "");
            }
            else {
                tmp.assign("");
            }
            replace_all(body, "%CHECKED_NOMANI%", tmp);
            if (m_bOverrideRdpNotheme) {
                tmp.assign("disabled=\"disabled\"").append((m_RdpOverrideParams.notheme) ? " checked=\"checked\"" : "");
            }
            else {
                tmp.assign("");
            }
            replace_all(body, "%CHECKED_NOTHEME%", tmp);
            if (m_bOverrideRdpNotls) {
                tmp.assign("disabled=\"disabled\"").append((m_RdpOverrideParams.notls) ? " checked=\"checked\"" : "");
            }
            else {
                tmp.assign("");
            }
            replace_all(body, "%CHECKED_NOTLS%", tmp);
            if (m_bOverrideRdpNonla) {
                tmp.assign("disabled=\"disabled\"").append((m_RdpOverrideParams.nonla) ? " checked=\"checked\"" : "");
            }
            else {
                tmp.assign("");
            }
            replace_all(body, "%CHECKED_NONLA%", tmp);
        }
        switch (mt) {
        case TEXT:
            response->SetHeader("Content-Type", "text/plain");
            response->SetHeader("Cache-Control", "no-cache, private");
            break;
        case HTML:
            response->SetHeader("Content-Type", "text/html");
            response->SetHeader("Cache-Control", "no-cache, private");
            break;
        case PNG:
            response->SetHeader("Content-Type", "image/png");
            break;
        case ICO:
            response->SetHeader("Content-Type", "image/x-icon");
            break;
        case JAVASCRIPT:
            response->SetHeader("Content-Type", "text/javascript");
            break;
        case JSON:
            response->SetHeader("Content-Type", "application/json");
            break;
        case CSS:
            response->SetHeader("Content-Type", "text/css");
            break;
        case OGG:
            response->SetHeader("Content-Type", "audio/ogg");
            break;
        case CUR:
            response->SetHeader("Content-Type", "image/cur");
            break;
        case BINARY:
            response->SetHeader("Content-Type", "application/octet-stream");
            break;
        }
        response->SetBody(body.data(), body.length());

        LogInfo(request->RemoteAddress(), uri, "200 OK");
        return HTTPRESPONSECODE_200_OK;
    };

    bool WsGate::ReadConfig(wsgate::log *logger) {
        // config file options
        po::options_description cfg("");
        cfg.add_options()
            ("global.daemon", po::value<string>(), "enable/disable daemon mode")
            ("global.pidfile", po::value<string>(), "path of PID file in daemon mode")
            ("global.debug", po::value<string>(), "enable/disable debugging")
            ("global.enablecore", po::value<string>(), "enable/disable coredumps")
            ("global.hostname", po::value<string>(), "specify host name")
            ("global.port", po::value<uint16_t>(), "specify listening port")
            ("global.bindaddr", po::value<string>(), "specify bind address")
            ("global.redirect", po::value<string>(), "Flag: Always redirect non-SSL to SSL")
            ("global.logmask", po::value<string>(), "specify syslog mask")
            ("global.logfacility", po::value<string>(), "specify syslog facility")
            ("ssl.port", po::value<uint16_t>(), "specify listening port for SSL")
            ("ssl.bindaddr", po::value<string>(), "specify bind address for SSL")
            ("ssl.certfile", po::value<string>(), "specify certificate file")
            ("ssl.certpass", po::value<string>(), "specify certificate passphrase")
            ("threading.mode", po::value<string>(), "specify threading mode")
            ("threading.poolsize", po::value<int>(), "specify threading pool size")
            ("http.maxrequestsize", po::value<unsigned long>(), "specify maximum http request size")
            ("http.documentroot", po::value<string>(), "specify http document root")
            ("acl.allow", po::value<vector<string>>()->multitoken(), "Allowed destination hosts or nets")
            ("acl.deny", po::value<vector<string>>()->multitoken(), "Denied destination hosts or nets")
            ("acl.order", po::value<string>(), "Order (deny,allow or allow,deny)")
            ("rdpoverride.host", po::value<string>(), "Predefined RDP destination host")
            ("rdpoverride.port", po::value<uint16_t>(), "Predefined RDP port")
            ("rdpoverride.user", po::value<string>(), "Predefined RDP user")
            ("rdpoverride.pass", po::value<string>(), "Predefined RDP password")
            ("rdpoverride.performance", po::value<int>(), "Predefined RDP performance")
            ("rdpoverride.nowallpaper", po::value<string>(), "Predefined RDP flag: No wallpaper")
            ("rdpoverride.nofullwindowdrag", po::value<string>(), "Predefined RDP flag: No full window drag")
            ("rdpoverride.nomenuanimation", po::value<string>(), "Predefined RDP flag: No full menu animation")
            ("rdpoverride.notheming", po::value<string>(), "Predefined RDP flag: No theming")
            ("rdpoverride.notls", po::value<string>(), "Predefined RDP flag: Disable TLS")
            ("rdpoverride.nonla", po::value<string>(), "Predefined RDP flag: Disable NLA")
            ("rdpoverride.forcentlm", po::value<int>(), "Predefined RDP flag: Force NTLM")
            ("rdpoverride.size", po::value<string>(), "Predefined RDP desktop size")
            ("openstack.authurl", po::value<string>(), "OpenStack authentication URL")
            ("openstack.username", po::value<string>(), "OpenStack username")
            ("openstack.password", po::value<string>(), "OpenStack password")
            ("openstack.tenantname", po::value<string>(), "OpenStack tenant name")
            ("hyperv.hostusername", po::value<string>(), "Hyper-V username")
            ("hyperv.hostpassword", po::value<string>(), "Hyper-V user's password")
            ;

        m_pVm = new po::variables_map();
        try {
            ifstream f(m_sConfigFile.c_str());
            if (f.fail()) {
#ifdef _WIN32
                wsgate::log::err << "Could not read config file '" << m_sConfigFile << "'." << endl;
#endif
                cerr << "Could not read config file '" << m_sConfigFile << "'." << endl;
                return false;
            }
            po::store(po::parse_config_file(f, cfg, true), *m_pVm);
            po::notify(*m_pVm);

            try {
                // Examine values from config file

                if (m_pVm->count("global.daemon")) {
                    m_bDaemon = str2bool((*m_pVm)["global.daemon"].as<string>());
                }
                m_bDebug = false;
                if (m_pVm->count("global.debug")) {
                    m_bDebug = str2bool((*m_pVm)["global.debug"].as<string>());
                }
                m_bEnableCore = false;
                if (m_pVm->count("global.enablecore")) {
                    m_bEnableCore = str2bool((*m_pVm)["global.enablecore"].as<string>());
                }
                if (m_pVm->count("global.logmask")) {
                    if (NULL != logger) {
                        logger->setmaskByName(to_upper_copy((*m_pVm)["global.logmask"].as<string>()));
                    }
                }
                if (m_pVm->count("global.logfacility")) {
                    if (NULL != logger) {
                        logger->setfacilityByName(to_upper_copy((*m_pVm)["global.logfacility"].as<string>()));
                    }
                }
                if (0 == (m_pVm->count("global.port") + m_pVm->count("ssl.port"))) {
                    throw tracing::invalid_argument("No listening ports defined.");
                }
                if (0 == (m_pVm->count("http.documentroot"))) {
                    throw tracing::invalid_argument("No documentroot defined.");
                }
                m_sDocumentRoot.assign((*m_pVm)["http.documentroot"].as<string>());
                if (m_sDocumentRoot.empty()) {
                    throw tracing::invalid_argument("documentroot is empty.");
                }

                m_bRedirect = false;
                if (m_pVm->count("global.redirect")) {
                    m_bRedirect = str2bool((*m_pVm)["global.redirect"].as<string>());
                }

                if (m_pVm->count("acl.order")) {
                    setAclOrder((*m_pVm)["acl.order"].as<string>());
                }
                if (m_pVm->count("acl.allow")) {
                    setHostList((*m_pVm)["acl.allow"].as<vector <string>>(), m_allowedHosts);
                }
                if (m_pVm->count("acl.deny")) {
                    setHostList((*m_pVm)["acl.deny"].as<vector <string>>(), m_deniedHosts);
                }

                if (m_pVm->count("rdpoverride.host")) {
                    m_sRdpOverrideHost.assign((*m_pVm)["rdpoverride.host"].as<string>());
                    m_bOverrideRdpHost = true;
                }
                else {
                    m_bOverrideRdpHost = false;
                }
                if (m_pVm->count("rdpoverride.user")) {
                    m_sRdpOverrideUser.assign((*m_pVm)["rdpoverride.user"].as<string>());
                    m_bOverrideRdpUser = true;
                }
                else {
                    m_bOverrideRdpUser = false;
                }
                if (m_pVm->count("rdpoverride.pass")) {
                    m_sRdpOverridePass.assign((*m_pVm)["rdpoverride.pass"].as<string>());
                    m_bOverrideRdpPass = true;
                }
                else {
                    m_bOverrideRdpPass = false;
                }

                if (m_pVm->count("rdpoverride.port")) {
                    int n = (*m_pVm)["rdpoverride.port"].as<int>();
                    if ((0 > n) || (2 < n)) {
                        throw tracing::invalid_argument("Invalid port value.");
                    }
                    m_RdpOverrideParams.port = n;
                    m_bOverrideRdpPort = true;
                }
                else {
                    m_bOverrideRdpPort = false;
                }

                if (m_pVm->count("rdpoverride.performance")) {
                    int n = (*m_pVm)["rdpoverride.performance"].as<int>();
                    if ((0 > n) || (2 < n)) {
                        throw tracing::invalid_argument("Invalid performance value.");
                    }
                    m_RdpOverrideParams.perf = n;
                    m_bOverrideRdpPerf = true;
                }
                else {
                    m_bOverrideRdpPerf = false;
                }
                if (m_pVm->count("rdpoverride.forcentlm")) {
                    int n = (*m_pVm)["rdpoverride.forcentlm"].as<int>();
                    if ((0 > n) || (2 < n)) {
                        throw tracing::invalid_argument("Invalid forcentlm value.");
                    }
                    m_RdpOverrideParams.fntlm = n;
                    m_bOverrideRdpFntlm = true;
                }
                else {
                    m_bOverrideRdpFntlm = false;
                }
                if (m_pVm->count("rdpoverride.nowallpaper")) {
                    m_RdpOverrideParams.nowallp = str2bint((*m_pVm)["rdpoverride.nowallpaper"].as<string>());
                    m_bOverrideRdpNowallp = true;
                }
                else {
                    m_bOverrideRdpNowallp = false;
                }
                if (m_pVm->count("rdpoverride.nofullwindowdrag")) {
                    m_RdpOverrideParams.nowdrag = str2bint((*m_pVm)["rdpoverride.nofullwindowdrag"].as<string>());
                    m_bOverrideRdpNowdrag = true;
                }
                else {
                    m_bOverrideRdpNowdrag = false;
                }
                if (m_pVm->count("rdpoverride.nomenuanimation")) {
                    m_RdpOverrideParams.nomani = str2bint((*m_pVm)["rdpoverride.nomenuanimation"].as<string>());
                    m_bOverrideRdpNomani = true;
                }
                else {
                    m_bOverrideRdpNomani = false;
                }
                if (m_pVm->count("rdpoverride.notheming")) {
                    m_RdpOverrideParams.notheme = str2bint((*m_pVm)["rdpoverride.notheming"].as<string>());
                    m_bOverrideRdpNotheme = true;
                }
                else {
                    m_bOverrideRdpNotheme = false;
                }
                if (m_pVm->count("rdpoverride.notls")) {
                    m_RdpOverrideParams.notls = str2bint((*m_pVm)["rdpoverride.notls"].as<string>());
                    m_bOverrideRdpNotls = true;
                }
                else {
                    m_bOverrideRdpNotls = false;
                }
                if (m_pVm->count("rdpoverride.nonla")) {
                    m_RdpOverrideParams.nonla = str2bint((*m_pVm)["rdpoverride.nonla"].as<string>());
                    m_bOverrideRdpNonla = true;
                }
                else {
                    m_bOverrideRdpNonla = false;
                }
                if (m_pVm->count("global.hostname")) {
                    m_sHostname.assign((*m_pVm)["global.hostname"].as<string>());
                }
                else {
                    m_sHostname.clear();
                }
                if (m_pVm->count("openstack.authurl")) {
                    m_sOpenStackAuthUrl.assign((*m_pVm)["openstack.authurl"].as<string>());
                }
                else {
                    m_sOpenStackAuthUrl.clear();
                }
                if (m_pVm->count("openstack.username")) {
                    m_sOpenStackUsername.assign((*m_pVm)["openstack.username"].as<string>());
                }
                else {
                    m_sOpenStackUsername.clear();
                }
                if (m_pVm->count("openstack.password")) {
                    m_sOpenStackPassword.assign((*m_pVm)["openstack.password"].as<string>());
                }
                else {
                    m_sOpenStackPassword.clear();
                }
                if (m_pVm->count("openstack.tenantname")) {
                    m_sOpenStackTenantName.assign((*m_pVm)["openstack.tenantname"].as<string>());
                }
                else {
                    m_sOpenStackTenantName.clear();
                }
                if (m_pVm->count("hyperv.hostusername")) {
                    m_sHyperVHostUsername.assign((*m_pVm)["hyperv.hostusername"].as<string>());
                }
                else {
                    m_sHyperVHostUsername.clear();
                }
                if (m_pVm->count("hyperv.hostpassword")) {
                    m_sHyperVHostPassword.assign((*m_pVm)["hyperv.hostpassword"].as<string>());
                }
                else {
                    m_sHyperVHostPassword.clear();
                }
            }
            catch (const tracing::invalid_argument & e) {
                cerr << e.what() << endl;
                wsgate::log::err << e.what() << endl;
                wsgate::log::err << e.where() << endl;
                return false;
            }

        }
        catch (const po::error &e) {
            cerr << e.what() << endl;
            return false;
        }
        return true;
    };

}
