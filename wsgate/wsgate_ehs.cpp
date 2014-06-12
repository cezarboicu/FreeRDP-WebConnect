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
#include "wsgate_ehs.h"

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

}
