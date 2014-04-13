

namespace wsgate{
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

    void MyRawSocketHandler:: OnDisconnect(EHSConnection *conn)
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

        //log::info << "Reached the connection point >> wsgate_main:1249" << endl;

            r->Connect(host, pcb, user, string() /*domain*/, pass, params);
            m_parent->RegisterRdpSession(r);
        }
        catch(...)
        {
            log::info << "Attemtped double connection to the same machine" << endl;
            return false;
        }
        return true;
    }
}