// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_BSAP_H
#define ANALYZER_PROTOCOL_BSAP_H

#if __has_include(<zeek/zeek-version.h>)
#include <zeek/zeek-version.h>
#else
#include <zeek/zeek-config.h>
#endif

#include "events.bif.h"
#if ZEEK_VERSION_NUMBER >= 40100
#include <zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h>
#else
#include <zeek/analyzer/protocol/udp/UDP.h>
#endif
#include "bsap_pac.h"

namespace analyzer
{
    namespace BSAP
    {
        class BSAP_Analyzer : public zeek::analyzer::Analyzer
        {
            public:
                BSAP_Analyzer(zeek::Connection* conn);
                virtual ~BSAP_Analyzer();

                virtual void Done();

                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip, int caplen);

                static zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
                {
                    return new BSAP_Analyzer(conn);
                }

            protected:
                binpac::BSAP::BSAP_Conn* interp;
        };
    }
}

#endif