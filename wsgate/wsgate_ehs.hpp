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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#include <ehs.h>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <typeinfo>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/regex.hpp>

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "common.hpp"
#include "btexception.hpp"
#include "base64.hpp"
#include "sha1.hpp"
#include "logging.hpp"
#include "wsendpoint.hpp"
#include "wsgate.hpp"
#include "myrawsocket.hpp"
#include "nova_token_auth.hpp"

#ifdef _WIN32
#include <direct.h>
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <shlobj.h>
# include "NTService.hpp"
#endif

using namespace std;
using boost::algorithm::iequals;
using boost::algorithm::to_lower_copy;
using boost::algorithm::ends_with;
using boost::algorithm::replace_all;
using boost::algorithm::to_upper_copy;
using boost::algorithm::trim_right_copy_if;
using boost::algorithm::trim;
using boost::algorithm::is_any_of;
using boost::algorithm::split;
namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace pt = boost::posix_time;
using boost::filesystem::path;
// subclass of EHS that defines a custom HTTP response.
namespace wsgate {
    static const char * const ws_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    //disable two connections to the same host
    std::map<string, bool> activeConnections;

#ifndef _WIN32
    // Bind helper is not needed on win32, because win32 does not
    // have a concept of privileged ports.
    class MyBindHelper : public PrivilegedBindHelper {

    public:
        MyBindHelper() : mutex(pthread_mutex_t()) {
            pthread_mutex_init(&mutex, NULL);
        }

        bool BindPrivilegedPort(int socket, const char *addr, const unsigned short port) {
            bool ret = false;
            pid_t pid;
            int status;
            char buf[32];
            pthread_mutex_lock(&mutex);
            switch (pid = fork()) {
            case 0:
                sprintf(buf, "%08x%08x%04x", socket, inet_addr(addr), port);
                execl(BINDHELPER_PATH, buf, ((void *)NULL));
                exit(errno);
                break;
            case -1:
                break;
            default:
                if (waitpid(pid, &status, 0) != -1) {
                    ret = (0 == status);
                    if (0 != status) {
                        log::err << BINDHELPER_PATH << " reports: " << strerror(WEXITSTATUS(status)) << endl;
                        errno = WEXITSTATUS(status);
                    }
                }
                break;
            }
            pthread_mutex_unlock(&mutex);
            return ret;
        }

    private:
        pthread_mutex_t mutex;
    };
#endif

    class WsGate : public EHS
    {
    private:
        typedef enum {
            TEXT,
            HTML,
            PNG,
            ICO,
            JAVASCRIPT,
            JSON,
            CSS,
            OGG,
            CUR,
            BINARY
        } MimeType;

        typedef map<string, rdp_ptr> SessionMap;
        typedef boost::tuple<time_t, string> cache_entry;
        typedef map<path, cache_entry> StaticCache;

        MimeType simpleMime(const string & filename)
        {
            if (ends_with(filename, ".txt"))
                return TEXT;
            if (ends_with(filename, ".html"))
                return HTML;
            if (ends_with(filename, ".png"))
                return PNG;
            if (ends_with(filename, ".ico"))
                return ICO;
            if (ends_with(filename, ".js"))
                return JAVASCRIPT;
            if (ends_with(filename, ".json"))
                return JSON;
            if (ends_with(filename, ".css"))
                return CSS;
            if (ends_with(filename, ".cur"))
                return CUR;
            if (ends_with(filename, ".ogg"))
                return OGG;
            return BINARY;
        }

        // Non-copyable
        WsGate(const wsgate::WsGate&);
        WsGate & operator=(const wsgate::WsGate&);

    public:

        WsGate(EHS *parent = NULL, std::string registerpath = "")
            : EHS(parent, registerpath)
            , m_sHostname()
            , m_sDocumentRoot()
            , m_sPidFile()
            , m_bDebug(false)
            , m_bEnableCore(false)
            , m_SessionMap()
            , m_allowedHosts()
            , m_deniedHosts()
            , m_bOrderDenyAllow(true)
            , m_bOverrideRdpHost(false)
            , m_bOverrideRdpPort(false)
            , m_bOverrideRdpUser(false)
            , m_bOverrideRdpPass(false)
            , m_bOverrideRdpPerf(false)
            , m_bOverrideRdpNowallp(false)
            , m_bOverrideRdpNowdrag(false)
            , m_bOverrideRdpNomani(false)
            , m_bOverrideRdpNotheme(false)
            , m_bOverrideRdpNotls(false)
            , m_bOverrideRdpNonla(false)
            , m_bOverrideRdpFntlm(false)
            , m_sRdpOverrideHost()
            , m_sRdpOverrideUser()
            , m_sRdpOverridePass()
            , m_RdpOverrideParams()
            , m_sConfigFile()
            , m_pVm(NULL)
            , m_bDaemon(false)
            , m_bRedirect(false)
            , m_StaticCache()
        {
        }

        virtual ~WsGate()
        {
            if (!m_sPidFile.empty()) {
                unlink(m_sPidFile.c_str());
            }
            delete m_pVm;
            m_pVm = NULL;
        }

        HttpResponse *HandleThreadException(ehs_threadid_t, HttpRequest *request, exception &ex)
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
        }

        void CheckForPredefined(string& rdpHost, string& rdpUser, string& rdpPass)
        {
            if (m_bOverrideRdpHost)
                rdpHost.assign(m_sRdpOverrideHost);

            if (m_bOverrideRdpUser)
                rdpUser.assign(m_sRdpOverrideUser);

            if (m_bOverrideRdpPass)
                rdpPass.assign(m_sRdpOverridePass);
        }

        bool ConnectionIsAllowed(string rdphost)
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
        }

        void LogInfo(std::basic_string<char> remoteAdress, string uri, const char response[])
        {
            log::info << "Request FROM: " << remoteAdress << endl;
            log::info << "To URI: " << uri << " => " << response << endl;
        }

        ResponseCode HandleRobotsRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost)
        {
            response->SetHeader("Content-Type", "text/plain");
            response->SetBody("User-agent: *\nDisallow: /\n", 26);
            return HTTPRESPONSECODE_200_OK;
        }

        /* =================================== CURSOR HANDLING =================================== */
        ResponseCode HandleCursorRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost)
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
        }

        /* =================================== REDIRECT REQUEST =================================== */
        ResponseCode HandleRedirectRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost)
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

        }

        /* =================================== HANDLE WSGATE REQUEST =================================== */
        int CheckIfWSocketRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost)
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
        }

        void ManageCookies(HttpRequest *request, HttpResponse *response, string rdphost, string rdppcb, string rdpuser, string thisHost)
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
        }

        ResponseCode HandleWsgateRequest(HttpRequest *request, HttpResponse *response, std::string uri, std::string thisHost);

        // generates a page for each http request
        ResponseCode HandleRequest(HttpRequest *request, HttpResponse *response);

        ResponseCode HandleHTTPRequest(HttpRequest *request, HttpResponse *response, bool tokenAuth = false)
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
        }

        po::variables_map *GetConfig() {
            return m_pVm;
        }

        const string & GetConfigFile() {
            return m_sConfigFile;
        }

        bool GetEnableCore() {
            return m_bEnableCore;
        }

        bool SetConfigFile(const string &name) {
            if (name.empty()) {
#ifdef _WIN32
                wsgate::log::err << "Config filename is empty." << endl;
#endif
                cerr << "Config filename is empty." << endl;
                return false;
            }
            m_sConfigFile = name;
            return true;
        }

        bool ReadConfig(wsgate::log *logger = NULL) {
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
        }

    private:

        bool notModified(HttpRequest *request, HttpResponse *response, time_t mtime)
        {
            string ifms(request->Headers("if-modified-since"));
            if (!ifms.empty()) {
                pt::ptime file_time(pt::from_time_t(mtime));
                pt::ptime req_time;
                istringstream iss(ifms);
                iss.imbue(locale(locale::classic(),
                    new pt::time_input_facet("%a, %d %b %Y %H:%M:%S GMT")));
                iss >> req_time;
                if (file_time <= req_time) {
                    response->RemoveHeader("Content-Type");
                    response->RemoveHeader("Content-Length");
                    response->RemoveHeader("Last-Modified");
                    response->RemoveHeader("Cache-Control");
                    log::info << "Request from " << request->RemoteAddress()
                        << ": " << request->Uri() << " => 304 Not modified" << endl;
                    return true;
                }
            }
            return false;
        }

        int str2bint(const string &s) {
            string v(s);
            trim(v);
            if (!v.empty()) {
                if (iequals(v, "true")) {
                    return 1;
                }
                if (iequals(v, "yes")) {
                    return 1;
                }
                if (iequals(v, "on")) {
                    return 1;
                }
                if (iequals(v, "1")) {
                    return 1;
                }
                if (iequals(v, "false")) {
                    return 0;
                }
                if (iequals(v, "no")) {
                    return 0;
                }
                if (iequals(v, "off")) {
                    return 0;
                }
                if (iequals(v, "0")) {
                    return 0;
                }
            }
            throw tracing::invalid_argument("Invalid boolean value");
        }

        bool str2bool(const string &s) {
            return (1 == str2bint(s));
        }

        void wc2pat(string &wildcards) {
            boost::replace_all(wildcards, "\\", "\\\\");
            boost::replace_all(wildcards, "^", "\\^");
            boost::replace_all(wildcards, ".", "\\.");
            boost::replace_all(wildcards, "$", "\\$");
            boost::replace_all(wildcards, "|", "\\|");
            boost::replace_all(wildcards, "(", "\\(");
            boost::replace_all(wildcards, ")", "\\)");
            boost::replace_all(wildcards, "[", "\\[");
            boost::replace_all(wildcards, "]", "\\]");
            boost::replace_all(wildcards, "*", "\\*");
            boost::replace_all(wildcards, "+", "\\+");
            boost::replace_all(wildcards, "?", "\\?");
            boost::replace_all(wildcards, "/", "\\/");
            boost::replace_all(wildcards, "\\?", ".");
            boost::replace_all(wildcards, "\\*", ".*");
            wildcards.insert(0, "^").append("$");
        }

        void setHostList(const vector<string> &hosts, vector<boost::regex> &hostlist) {
            vector<string> tmp(hosts);
            vector<string>::iterator i;
            hostlist.clear();
            for (i = tmp.begin(); i != tmp.end(); ++i) {
                wc2pat(*i);
                boost::regex re(*i, boost::regex::icase);
                hostlist.push_back(re);
            }
        }

        void setAclOrder(const string &order) {
            vector<string> parts;
            boost::split(parts, order, is_any_of(","));
            if (2 == parts.size()) {
                trim(parts[0]);
                trim(parts[1]);
                if (iequals(parts[0], "deny") && iequals(parts[1], "allow")) {
                    m_bOrderDenyAllow = true;
                    return;
                }
                if (iequals(parts[0], "allow") && iequals(parts[1], "deny")) {
                    m_bOrderDenyAllow = false;
                    return;
                }
            }
            throw tracing::invalid_argument("Invalid acl order value.");
        }

    public:
        bool GetDaemon() {
            return m_bDaemon;
        }

        void SetPidFile(const string &name) {
            m_sPidFile = name;
        }

        void RegisterRdpSession(rdp_ptr rdp) {
            ostringstream oss;
            oss << hex << rdp.get();
            m_SessionMap[oss.str()] = rdp;
        }

        void UnregisterRdpSession(rdp_ptr rdp) {
            ostringstream oss;
            oss << hex << rdp.get();
            m_SessionMap.erase(oss.str());
        }

    private:
        string m_sHostname;
        string m_sDocumentRoot;
        string m_sPidFile;
        bool m_bDebug;
        bool m_bEnableCore;
        SessionMap m_SessionMap;
        vector<boost::regex> m_allowedHosts;
        vector<boost::regex> m_deniedHosts;
        bool m_bOrderDenyAllow;
        bool m_bOverrideRdpHost;
        bool m_bOverrideRdpPort;
        bool m_bOverrideRdpUser;
        bool m_bOverrideRdpPass;
        bool m_bOverrideRdpPerf;
        bool m_bOverrideRdpNowallp;
        bool m_bOverrideRdpNowdrag;
        bool m_bOverrideRdpNomani;
        bool m_bOverrideRdpNotheme;
        bool m_bOverrideRdpNotls;
        bool m_bOverrideRdpNonla;
        bool m_bOverrideRdpFntlm;
        string m_sRdpOverrideHost;
        string m_sRdpOverrideUser;
        string m_sRdpOverridePass;
        WsRdpParams m_RdpOverrideParams;
        string m_sConfigFile;
        po::variables_map *m_pVm;
        bool m_bDaemon;
        bool m_bRedirect;
        StaticCache m_StaticCache;
        string m_sOpenStackAuthUrl;
        string m_sOpenStackUsername;
        string m_sOpenStackPassword;
        string m_sOpenStackTenantName;
        string m_sHyperVHostUsername;
        string m_sHyperVHostPassword;
    };
}