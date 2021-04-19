## bsap.pac
##
## Binpac BSAP Protocol Analyzer
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
%}

analyzer BSAP withcontext {
    connection: BSAP_Conn;
    flow:       BSAP_Flow;
};

connection BSAP_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = BSAP_Flow(true);
    downflow = BSAP_Flow(false);
};

%include bsap-protocol.pac

flow BSAP_Flow(is_orig: bool) {
    datagram = BSAP_PDU(is_orig) withcontext(connection, this);
};

%include bsap-analyzer.pac
