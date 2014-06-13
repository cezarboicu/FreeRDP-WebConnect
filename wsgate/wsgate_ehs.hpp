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
#ifndef _WSGATE_EHS_H_
#define _WSGATE_EHS_H_

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

        HttpResponse *HandleThreadException(ehs_threadid_t, HttpRequest *request, exception &ex);

        void CheckForPredefined(string& rdpHost, string& rdpUser, string& rdpPass);

        bool ConnectionIsAllowed(string rdphost);

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

        ResponseCode HandleCursorRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost);

        ResponseCode HandleRedirectRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost);

        int CheckIfWSocketRequest(HttpRequest *request, HttpResponse *response, string uri, string thisHost);

        void ManageCookies(HttpRequest *request, HttpResponse *response, string rdphost, string rdppcb, string rdpuser, string thisHost);

        ResponseCode HandleWsgateRequest(HttpRequest *request, HttpResponse *response, std::string uri, std::string thisHost);

        // generates a page for each http request
        ResponseCode HandleRequest(HttpRequest *request, HttpResponse *response);

        ResponseCode HandleHTTPRequest(HttpRequest *request, HttpResponse *response, bool tokenAuth = false);

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

        bool ReadConfig(wsgate::log *logger = NULL);
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

#endif