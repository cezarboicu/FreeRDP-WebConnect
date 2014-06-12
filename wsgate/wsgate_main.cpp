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
#include "wsgate_ehs.h"

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

static bool g_signaled = false;
#ifdef _WIN32
static bool g_service_background = true;
#endif

static void terminate(int)
{
    g_signaled = true;
    signal(SIGINT, terminate);
    signal(SIGTERM, terminate);
}

#ifndef _WIN32
static wsgate::WsGate *g_srv = NULL;
static wsgate::WsGate *g_psrv = NULL;
static void reload(int)
{
    wsgate::log::info << "Got SIGHUP, reloading config file." << endl;
    if (NULL != g_srv) {
        g_srv->ReadConfig();
    }
    if (NULL != g_psrv) {
        g_psrv->ReadConfig();
    }
    signal(SIGHUP, reload);
}
#endif

#ifdef _WIN32
static int _service_main (int argc, char **argv)
#else
int main (int argc, char **argv)
#endif
{
    wsgate::logger log("wsgate");

    // commandline options
    po::options_description desc("Supported options");
    desc.add_options()
        ("help,h", "Show this message and exit.")
        ("version,V", "Show version information and exit.")
#ifndef _WIN32
        ("foreground,f", "Run in foreground.")
#endif
        ("config,c", po::value<string>()->default_value(DEFAULTCFG), "Specify config file");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error &e) {
#ifdef _WIN32
        wsgate::log::err << e.what() << endl << "Hint: Use --help option." << endl;
#endif
        cerr << e.what() << endl << "Hint: Use --help option." << endl;
        return -1;
    }

    if (vm.count("help")) {
        cout << desc << endl;
        return 0;
    }
    if (vm.count("version")) {
        cout << "wsgate v" << VERSION << "." << GITREV << endl << getEHSconfig() << endl;
        return 0;
    }
    wsgate::WsGate srv;
    if (vm.count("config")) {
        if (!srv.SetConfigFile(vm["config"].as<string>())) {
            return -1;
        }
    } else {
#ifdef _WIN32
        wsgate::log::err << "Mandatory option --config <filename> is missing." << endl;
#endif
        cerr << "Mandatory option --config <filename> is missing." << endl;
        return -1;
    }


    if (!srv.ReadConfig(&log)) {
        return -1;
    }
    po::variables_map *pvm = srv.GetConfig();
    if (NULL == pvm) {
        return -1;
    }

    int port = -1;
    bool https = false;
    bool need2 = false;
    if (pvm->count("ssl.port")) {
        port = (*pvm)["ssl.port"].as<uint16_t>();
        https = true;
        if (pvm->count("global.port")) {
            need2 = true;
        }
    } else if (pvm->count("global.port")) {
        port = (*pvm)["global.port"].as<uint16_t>();
    }

#ifndef _WIN32
    wsgate::MyBindHelper h;
    srv.SetBindHelper(&h);
#endif
    wsgate::MyRawSocketHandler sh(&srv);
    srv.SetRawSocketHandler(&sh);

    EHSServerParameters oSP;
    oSP["port"] = port;
    oSP["bindaddress"] = "0.0.0.0";
    oSP["norouterequest"] = 1;
    if (https) {
        if (pvm->count("ssl.bindaddr")) {
            oSP["bindaddress"] = (*pvm)["ssl.bindaddr"].as<string>();
        }
        oSP["https"] = 1;
        if (pvm->count("ssl.certfile")) {
            oSP["certificate"] = (*pvm)["ssl.certfile"].as<string>();
        }
        if (pvm->count("ssl.certpass")) {
            oSP["passphrase"] = (*pvm)["ssl.certpass"].as<string>();
        }
    } else {
        if (pvm->count("global.bindaddr")) {
            oSP["bindaddress"] = (*pvm)["global.bindaddr"].as<string>();
        }
    }
    if (pvm->count("http.maxrequestsize")) {
        oSP["maxrequestsize"] = (*pvm)["http.maxrequestsize"].as<unsigned long>();
    }
    bool sleepInLoop = true;
    if (pvm->count("threading.mode")) {
        string mode((*pvm)["threading.mode"].as<string>());
        if (0 == mode.compare("single")) {
            oSP["mode"] = "singlethreaded";
            sleepInLoop = false;
        } else if (0 == mode.compare("pool")) {
            oSP["mode"] = "threadpool";
            if (pvm->count("threading.poolsize")) {
                oSP["threadcount"] = (*pvm)["threading.poolsize"].as<int>();
            }
        } else if (0 == mode.compare("perrequest")) {
            oSP["mode"] = "onethreadperrequest";
        } else {
            cerr << "Invalid threading mode '" << mode << "'." << endl;
            return -1;
        }
    } else {
        oSP["mode"] = "onethreadperrequest";
    }
    if (pvm->count("ssl.certfile")) {
        oSP["certificate"] = (*pvm)["ssl.certfile"].as<string>();
    }
    if (pvm->count("ssl.certpass")) {
        oSP["passphrase"] = (*pvm)["ssl.certpass"].as<string>();
    }

#ifdef _WIN32
    bool daemon = (pvm->count("foreground")) ? false : g_service_background;
#else
    bool daemon = false;
    if (pvm->count("global.daemon") && (0 == pvm->count("foreground"))) {
        daemon = srv.GetDaemon();
        if (daemon) {
            pid_t pid = fork();
            switch (pid) {
                case 0:
                    // child
                    {
                        int nfd = open("/dev/null", O_RDWR);
                        dup2(nfd, 0);
                        dup2(nfd, 1);
                        dup2(nfd, 2);
                        close(nfd);
                        (void)chdir("/");
                        setsid();
                        if (pvm->count("global.pidfile")) {
                            const string pidfn((*pvm)["global.pidfile"].as<string>());
                            if (!pidfn.empty()) {
                                ofstream pidfile(pidfn.c_str());
                                pidfile << getpid() << endl;
                                pidfile.close();
                                srv.SetPidFile(pidfn);
                            }
                        }
                    }
                    break;
                case -1:
                    cerr << "Could not fork" << endl;
                    return -1;
                default:
                    return 0;
            }
        }
    }
#endif

#ifndef _WIN32
    g_srv = &srv;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, reload);
    if (srv.GetEnableCore()) {
        struct rlimit rlim;
        rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
        if (-1 == setrlimit(RLIMIT_CORE, &rlim)) {
            cerr << "Could not raise core dump limit: " << strerror(errno) << endl;
        }
    }
#endif
    signal(SIGINT, terminate);
    signal(SIGTERM, terminate);

    wsgate::WsGate *psrv = NULL;
    try {
        wsgate::log::info << "wsgate v" << VERSION << "." << GITREV << " starting" << endl;
        srv.StartServer(oSP);
        wsgate::log::info << "Listening on " << oSP["bindaddress"].GetCharString() << ":" << oSP["port"].GetInt() << endl;

        if (need2) {
            // Add second instance on insecure port
            psrv = new wsgate::WsGate();
#ifndef _WIN32
            psrv->SetBindHelper(&h);
#endif
            psrv->SetConfigFile(srv.GetConfigFile());
            psrv->ReadConfig();
            oSP["https"] = 0;
            oSP["port"] = (*pvm)["global.port"].as<uint16_t>();
            if (pvm->count("global.bindaddr")) {
                oSP["bindaddress"] = (*pvm)["global.bindaddr"].as<string>();
            }
            psrv->SetSourceEHS(srv);
            wsgate::MyRawSocketHandler *psh = new wsgate::MyRawSocketHandler(psrv);
            psrv->SetRawSocketHandler(psh);
            psrv->StartServer(oSP);
#ifndef _WIN32
            g_psrv = psrv;
#endif
            wsgate::log::info << "Listening on " << oSP["bindaddress"].GetCharString() << ":" << oSP["port"].GetInt() << endl;
        }

        if (daemon) {
            while (!(srv.ShouldTerminate() || (psrv && psrv->ShouldTerminate()) || g_signaled)) {
                if (sleepInLoop) {
                    usleep(50000);
                } else {
                    srv.HandleData(1000);
                    if (NULL != psrv) {
                        psrv->HandleData(1000);
                    }
                }
            }
        } else {
            wsgate::kbdio kbd;
            cout << "Press q to terminate ..." << endl;
            while (!(srv.ShouldTerminate()  || (psrv && psrv->ShouldTerminate()) || g_signaled || kbd.qpressed()))
            	{
                if (sleepInLoop)
					{
						usleep(1000);
					}
                else
					{
						srv.HandleData(1000);
						if (NULL != psrv)
							{
								psrv->HandleData(1000);
							}
					}
            }
        }
        wsgate::log::info << "terminating" << endl;
        srv.StopServer();
        if (NULL != psrv) {
            psrv->StopServer();
        }
    } catch (exception &e) {
        cerr << "ERROR: " << e.what() << endl;
        wsgate::log::err << e.what() << endl;
    }

    delete psrv;
    return 0;
}

#ifdef _WIN32
// Windows Service implementation

namespace wsgate {

    class WsGateService : public NTService {

        public:

            WsGateService() : NTService("FreeRDP-WebConnect", "FreeRDP WebConnect")
        {
            m_dwServiceStartupType = SERVICE_AUTO_START;
            m_sDescription.assign("RDP Web access gateway");
            AddDependency("Eventlog");
        }

        protected:

            bool OnServiceStop()
            {
                g_signaled = true;
                return true;
            }

            bool OnServiceShutdown()
            {
                g_signaled = true;
                return true;
            }

            void RunService()
            {
                g_signaled = false;
                // On Windows, always set out working dir to ../ relatively seen from
                // the binary's path.
                path p(m_sModulePath);
                string wdir(p.branch_path().branch_path().string());
                chdir(wdir.c_str());
                g_signaled = false;
                char *argv[] = {
                    strdup("wsgate"),
                    strdup("-c"),
                    strdup("etc/wsgate.ini"),
                    NULL
                };
                int r = _service_main(3, argv);
                if (0 != r) {
                    m_ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
                    m_ServiceStatus.dwServiceSpecificExitCode = r;
                }
                free(argv[0]);
                free(argv[1]);
                free(argv[2]);
            }

        public:

            bool ParseSpecialArgs(int argc, char **argv)
            {
                if (argc < 2) {
                    return false;
                }
                bool installed = false;
                try {
                    installed = IsServiceInstalled();
                } catch (const tracing::runtime_error &e) {
                    cerr << e.what() << endl;
                    return true;
                }
                if (0 == strcmp(argv[1], "--query")) {
                    // Report version of installed service
                    cout << "The service is " << (installed ? "currently" : "not")
                        << " installed." << endl;
                    return true;
                }
                if (0 == strcmp(argv[1], "--start")) {
                    // Start the service
                    try {
                        Start();
                    } catch (const tracing::runtime_error &e) {
                        cerr << "Failed to start " << m_sServiceName << endl;
                        cerr << e.what() << endl;
                    }
                    return true;
                }
                if (0 == strcmp(argv[1], "--stop")) {
                    // Start the service
                    try {
                        Stop();
                    } catch (const tracing::runtime_error &e) {
                        cerr << "Failed to stop " << m_sServiceName << endl;
                        cerr << e.what() << endl;
                    }
                    return true;
                }
                if (0 == strcmp(argv[1], "--install")) {
                    // Install the service
                    if (installed) {
                        cout << m_sServiceName << " is already installed." << endl;
                    } else {
                        try {
                            InstallService();
                            cout << m_sServiceName << " installed." << endl;
                        } catch (const tracing::runtime_error &e) {
                            cerr << "Failed to install " << m_sServiceName << endl;
                            cerr << e.what() << endl;
                        }
                    }
                    return true;
                }
                if (0 == strcmp(argv[1], "--remove")) {
                    // Remove the service
                    if (!installed) {
                        cout << m_sServiceName << " is not installed." << endl;
                    } else {
                        try {
                            UninstallService();
                            cout << m_sServiceName << " removed." << endl;
                        } catch (const tracing::runtime_error &e) {
                            cerr << "Failed to remove " << m_sServiceName << endl;
                            cerr << e.what() << endl;
                        }
                    }
                    return true;
                }
                return false;
            }

    };
}

int main (int argc, char **argv)
{
    wsgate::WsGateService s;
    if (!s.ParseSpecialArgs(argc, argv)) {
        try {
            if (!s.Execute()) {
                return _service_main(argc, argv);
            }
        } catch (const tracing::runtime_error &e) {
            cerr << "Failed to execute service" << endl;
            cerr << e.what() << endl;
        }
    }
    return s.ServiceExitCode();
}

#endif
