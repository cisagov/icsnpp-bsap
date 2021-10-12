## bsap.pac
##
## Binpac BSAP Protocol Analyzer
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%include zeek/binpac.pac
%include zeek/zeek.pac

%extern{
    #include "events.bif.h"
%}

analyzer BSAP withcontext {
    connection: BSAP_Conn;
    flow:       BSAP_Flow;
};

connection BSAP_Conn(zeek_analyzer: ZeekAnalyzer) {
    upflow   = BSAP_Flow(true);
    downflow = BSAP_Flow(false);
};

%include bsap-protocol.pac

flow BSAP_Flow(is_orig: bool) {
    datagram = BSAP_PDU(is_orig) withcontext(connection, this);
};

%include bsap-analyzer.pac
