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
#include "myrawsocket.hpp"
#include "wsgate_ehs.h"
using namespace std;

namespace wsgate {
    class MyWsHandler : public wspp::wshandler
    {
    public:
        MyWsHandler(EHSConnection *econn, EHS *ehs, MyRawSocketHandler *rsh)
            : m_econn(econn)
            , m_ehs(ehs)
            , m_rsh(rsh)
        {}

        virtual void on_message(std::string hdr, std::string data) {
            if (1 == (hdr[0] & 0x0F)) {
                // A text message
                if (':' == data[1]) {
                    switch (data[0]) {
                    case 'D':
                        log::debug << "JS: " << data.substr(2) << endl;
                        break;
                    case 'I':
                        log::info << "JS: " << data.substr(2) << endl;
                        break;
                    case 'W':
                        log::warn << "JS: " << data.substr(2) << endl;
                        break;
                    case 'E':
                        log::err << "JS: " << data.substr(2) << endl;
                        break;
                    }
                }
                return;
            }
            // binary message;
            m_rsh->OnMessage(m_econn, data);
        }
        virtual void on_close() {
            log::debug << "GOT Close" << endl;
            ehs_autoptr<GenericResponse> r(new GenericResponse(0, m_econn));
            m_ehs->AddResponse(ehs_move(r));
        }
        virtual bool on_ping(const std::string & data) {
            log::debug << "GOT Ping: '" << data << "'" << endl;
            return true;
        }
        virtual void on_pong(const std::string & data) {
            log::debug << "GOT Pong: '" << data << "'" << endl;
        }
        virtual void do_response(const std::string & data) {
            ehs_autoptr<GenericResponse> r(new GenericResponse(0, m_econn));
            r->SetBody(data.data(), data.length());
            m_ehs->AddResponse(ehs_move(r));
        }

    private:
        // Non-copyable
        MyWsHandler(const MyWsHandler&);
        MyWsHandler& operator=(const MyWsHandler&);

        EHSConnection *m_econn;
        EHS *m_ehs;
        MyRawSocketHandler *m_rsh;
    };

    MyRawSocketHandler::MyRawSocketHandler(WsGate *parent)
        : m_parent(parent)
        , m_cmap(conn_map())
    { }

    bool MyRawSocketHandler::OnData(EHSConnection *conn, std::string data)
    {
        if (m_cmap.end() != m_cmap.find(conn)) {
            m_cmap[conn].get<0>()->AddRxData(data);
            return true;
        }
        return false;
    }

    void MyRawSocketHandler::OnConnect(EHSConnection * /* conn */)
    {
        log::debug << "GOT WS CONNECT" << endl;
    }

    void MyRawSocketHandler::OnDisconnect(EHSConnection *conn)
    {
        log::debug << "GOT WS DISCONNECT" << endl;
        m_parent->UnregisterRdpSession(m_cmap[conn].get<2>());
        m_cmap.erase(conn);
    }

    void MyRawSocketHandler::OnMessage(EHSConnection *conn, const std::string & data)
    {
        if (m_cmap.end() != m_cmap.find(conn)) {
            m_cmap[conn].get<2>()->OnWsMessage(data);
        }
    }

    bool MyRawSocketHandler::Prepare(EHSConnection *conn, const string host, const string pcb,
        const string user, const string pass, const WsRdpParams &params)
    {
        log::debug << "RDP Host:               '" << host << "'" << endl;
        log::debug << "RDP Pcb:               '" << pcb << "'" << endl;
        log::info << "RDP Port:               '" << params.port << "'" << endl;
        log::debug << "RDP User:               '" << user << "'" << endl;
        log::debug << "RDP Password:           '" << pass << "'" << endl;
        log::debug << "RDP Desktop size:       " << params.width << "x" << params.height << endl;
        log::debug << "RDP Performance:        " << params.perf << endl;
        log::debug << "RDP No wallpaper:       " << params.nowallp << endl;
        log::debug << "RDP No full windowdrag: " << params.nowdrag << endl;
        log::debug << "RDP No menu animation:  " << params.nomani << endl;
        log::debug << "RDP No theming:         " << params.nomani << endl;
        log::debug << "RDP Disable TLS:        " << params.notls << endl;
        log::debug << "RDP Disable NLA:        " << params.nonla << endl;
        log::debug << "RDP NTLM auth:          " << params.fntlm << endl;


        try
        {
            handler_ptr h(new MyWsHandler(conn, m_parent, this));
            conn_ptr c(new wspp::wsendpoint(h.get()));
            rdp_ptr r(new RDP(h.get()));
            m_cmap[conn] = conn_tuple(c, h, r);

            r->Connect(host, pcb, user, string() /*domain*/, pass, params);
            m_parent->RegisterRdpSession(r);
        }
        catch (...)
        {
            log::info << "Attemtped double connection to the same machine" << endl;
            return false;
        }
        return true;
    }
}