##! main.zeek
##!
##! Binpac BSAP (BSAP) Analyzer - Contains the base script-layer functionality for 
##!                               processing events emitted from the analyzer.
##!                               For use with BSAP communication over serial 
##!                               using serial to ethernet tap, or for use with
##!                               BSAP communication over ethernet directly. 
##!
##!
##! Author:  Devin Vollmer
##! Contact: devin.vollmer@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved."

module Bsap;

export {
    redef enum Log::ID += { LOG_BSAP_IP, 
                            LOG_BSAP_IP_RDB, 
                            LOG_BSAP_IP_UNKNOWN,
                            LOG_BSAP_SERIAL_HEADER, 
                            LOG_BSAP_SERIAL_RDB, 
                            LOG_BSAP_SERIAL_RDB_EXT, 
                            LOG_BSAP_SERIAL_UNKNOWN};

    ###############################################################################################
    #############################  BSAP_IP_Header -> bsap_ip_header.log  ###########################
    ###############################################################################################
    type BSAP_IP_Header: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        id              : conn_id   &log;                   ## The connection's 4-tuple of endpoint addresses/ports.
        num_msg         : count     &log;                   ## Number of function calls in message packet
        type_name       : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_ip_header: event(rec: BSAP_IP_Header);

    ###############################################################################################
    ################################  BSAP_IP_RDB -> bsap_ip_rdb.log  ################################
    ###############################################################################################
    type BSAP_IP_RDB: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        header_size     : count     &log;                   ## The connection's 4-tuple of endpoint addresses/ports.
        mes_seq         : count     &log;
        res_seq         : count     &log;
        data_len        : count     &log;
        sequence        : count     &log;
        app_func_code   : string    &log;
        node_status     : count     &log;
        func_code       : string    &log;
        variable_count  : count     &log;
        variables       : string    &log;
        variable_value  : string    &log;
        #data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_ip_rdb: event(rec: BSAP_IP_RDB);

    ###############################################################################################
    ############################  BSAP_IP_UNKNOWN -> bsap_ip_unknown.log  ##########################
    ###############################################################################################
    type BSAP_IP_UNKNOWN: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_ip_unknown: event(rec: BSAP_IP_UNKNOWN);

    ###############################################################################################
    ###########################  BSAP_SERIAL_HEADER -> bsap_serial_header.log  ###########################
    ###############################################################################################

    type BSAP_SERIAL_HEADER: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        id              : conn_id   &log;                   ## The connection's 4-tuple of endpoint addresses/ports.
        ser             : count     &log;                   
        dadd            : count     &log;
        sadd            : count     &log;
        ctl             : count     &log;
        dfun            : string    &log;
        seq             : count     &log;
        sfun            : string    &log;
        nsb             : count     &log;
        type_name       : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_serial_header: event(rec: BSAP_SERIAL_HEADER);

    ###############################################################################################
    ##############################  BSAP_SERIAL_RDB -> bsap_serial_rdb.log  ##############################
    ###############################################################################################

    type BSAP_SERIAL_RDB: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        func_code       : string    &log;
        variable_count  : count     &log;
        variables       : string    &log;
        variable_value  : string    &log;
        #data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_serial_rdb: event(rec: BSAP_SERIAL_RDB);

    ###############################################################################################
    #########################  BSAP_SERIAL_RDB_EXT -> bsap_serial_rdb_ext.log  ###########################
    ###############################################################################################

    type BSAP_SERIAL_RDB_EXT: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        dfun            : string    &log;
        seq             : count     &log;
        sfun            : string    &log;
        nsb             : count     &log;
        extfun          : string    &log;
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_serial_rdb_ext: event(rec: BSAP_SERIAL_RDB_EXT);

    ###############################################################################################
    ##########################  BSAP_SERIAL_UNKNOWN -> bsap_serial_unknown.log  ##########################
    ###############################################################################################

    type BSAP_SERIAL_UNKNOWN: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_serial_unknown: event(rec: BSAP_SERIAL_UNKNOWN);
}

#port 1234,1235 are default port numbers used by BSAPIPDRV
const ports = { 1234/udp, 
                1235/udp
};

redef likely_server_ports += { ports };

###################################################################################################
########### Defines Log Streams for bsap_ip_header.log, bsapip_rdb.log, bsap_ip_unknown  ############
###################################################################################################
event zeek_init() &priority=5
    {
    Log::create_stream(Bsap::LOG_BSAP_IP, [$columns=BSAP_IP_Header, $ev=log_bsap_ip_header, $path="bsap_ip_header"]);
    Log::create_stream(Bsap::LOG_BSAP_IP_RDB, [$columns=BSAP_IP_RDB, $ev=log_bsap_ip_rdb, $path="bsap_ip_rdb"]);
    Log::create_stream(Bsap::LOG_BSAP_IP_UNKNOWN, [$columns=BSAP_IP_UNKNOWN, $ev=log_bsap_ip_unknown, $path="bsap_ip_unknown"]);

    Log::create_stream(Bsap::LOG_BSAP_SERIAL_HEADER, [$columns=BSAP_SERIAL_HEADER, $ev=log_bsap_serial_header, $path="bsap_serial_header"]);
    Log::create_stream(Bsap::LOG_BSAP_SERIAL_RDB, [$columns=BSAP_SERIAL_RDB, $ev=log_bsap_serial_rdb, $path="bsap_serial_rdb"]);
    Log::create_stream(Bsap::LOG_BSAP_SERIAL_RDB_EXT, [$columns=BSAP_SERIAL_RDB_EXT, $ev=log_bsap_serial_rdb_ext, $path="bsap_serial_rdb_ext"]);
    Log::create_stream(Bsap::LOG_BSAP_SERIAL_UNKNOWN, [$columns=BSAP_SERIAL_UNKNOWN, $ev=log_bsap_serial_unknown, $path="bsap_serial_unknown"]);

    # TODO: If you're using port-based DPD, uncomment this.
    Analyzer::register_for_ports(Analyzer::ANALYZER_BSAP, ports);
    }

###############################################################################################
################ Defines logging of bsap_ip_header event -> bsap_ip_header.log  #################
###############################################################################################
event bsap_ip_header(c: connection, is_orig: bool, id: count, Num_Messages: count, 
                    Message_Func: count)
    {
    local info: BSAP_IP_Header;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$num_msg = Num_Messages;
    info$type_name = msg_types[Message_Func];
    #info$mes_seq = message_seq;
    #info$res_seq = response_seq;
    #info$data_len = data_length;
    
    Log::write(Bsap::LOG_BSAP_IP, info);
    }   

###############################################################################################
############### Defines logging of bsap_ip_rdb_response event -> bsap_rdb.log  #################
###############################################################################################
event bsap_ip_rdb_response(c: connection, message_seq: count, response_seq: count, 
                           data_length: count, header_size: count, sequence: count, 
                           func_code: count, resp_status: count, variables: string, 
                           variable_value: string, variable_cnt: count, data: string)
    {
    local info: BSAP_IP_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$mes_seq = message_seq;
    info$res_seq = response_seq;
    info$data_len = data_length;
    info$header_size = header_size;
    info$sequence = sequence;
    info$app_func_code = "RDB";
    info$node_status = func_code;
    info$func_code = rdb_functions[func_code];
    info$variable_count = variable_cnt;
    info$variables = variables;
    info$variable_value = variable_value;
    #info$data = data;
    Log::write(Bsap::LOG_BSAP_IP_RDB, info);
    }   

###############################################################################################
################ Defines logging of bsap_ip_rdb_request event -> bsap_rdb.log  #################
###############################################################################################
event bsap_ip_rdb_request(c: connection, response_seq: count, message_seq: count, 
                        node_status: count, func_code: count, data_length: count, 
                        var_cnt: count, variables: string, variable_value: string, data: string)
    {
    local info: BSAP_IP_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$mes_seq = message_seq;
    info$res_seq = response_seq;
    info$data_len = data_length;
    info$app_func_code = "RDB";
    info$node_status = node_status;
    info$func_code = rdb_functions[func_code];
    info$variable_count = var_cnt;
    info$variables = variables;
    info$variable_value = variable_value;
    #info$data = data;
    Log::write(Bsap::LOG_BSAP_IP_RDB, info);
    }

###############################################################################################
############## Defines logging of bsap_ip_unknown event -> bsap_ip_unknown.log  ###############
###############################################################################################
event bsap_ip_unknown(c: connection, data: string)
    {
    local info: BSAP_IP_UNKNOWN;
    info$ts  = network_time();
    info$uid = c$uid;
    info$data = data;
    Log::write(Bsap::LOG_BSAP_IP_UNKNOWN, info);
    } 

###############################################################################################
############### Defines logging of bsap_local_header event -> bsap_header.log  ################
###############################################################################################
event bsap_serial_local_header(c: connection, SER: count, DFUN: count, SEQ: count, SFUN: count, NSB: count)
    {
    local info: BSAP_SERIAL_HEADER;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$ser = SER;
    info$dfun = app_functions[DFUN];
    info$seq = SEQ;
    info$sfun = app_functions[SFUN];
    info$nsb = NSB;
    info$type_name = "Local Message";
    
    Log::write(Bsap::LOG_BSAP_SERIAL_HEADER, info);
    }   

###############################################################################################
############## Defines logging of bsap_global_header event -> bsap_header.log  ################
###############################################################################################
event bsap_serial_global_header(c: connection, SER: count, DADD: count, SADD: count, CTL: count, DFUN: count,SEQ: count, 
                        SFUN: count, NSB: count)
    {
    local info: BSAP_SERIAL_HEADER;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$ser = SER;
    info$dadd = DADD;
    info$sadd = SADD;
    info$ctl = CTL;
    info$dfun = app_functions[DFUN];
    info$seq = SEQ;
    info$sfun = app_functions[SFUN];
    info$nsb = NSB;
    info$type_name = "Global Message";
    
    Log::write(Bsap::LOG_BSAP_SERIAL_HEADER, info);
    }   

###############################################################################################
############## Defines logging of bsap_rdb_response event -> bsap_cnv_rdb.log  ################
###############################################################################################
event bsap_serial_rdb_response(c: connection, func_code: count, 
                               variable_cnt: count, variables: string,
                               variable_value: string, data: string)
    {
    local info: BSAP_SERIAL_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$func_code = rdb_functions[func_code];
    info$variable_count = variable_cnt;
    info$variables = variables;
    info$variable_value = variable_value;
    #info$data = data;
    Log::write(Bsap::LOG_BSAP_SERIAL_RDB, info);
    }   

###############################################################################################
############### Defines logging of bsap_rdb_request event -> bsap_cnv_rdb.log  ################
###############################################################################################
event bsap_serial_rdb_request(c: connection, func_code: count,
                              variable_cnt: count, variables: string,
                              variable_value: string, data: string)
    {
    local info: BSAP_SERIAL_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$func_code = rdb_functions[func_code];
    info$variable_count = variable_cnt;
    info$variables = variables;
    info$variable_value = variable_value;
    #info$data = data;
    Log::write(Bsap::LOG_BSAP_SERIAL_RDB, info);
    }

###############################################################################################
############ Defines logging of bsap_rdb_extension event -> bsap_cnv_rdb_ext.log  #############
###############################################################################################
event bsap_serial_rdb_extension(c: connection, DFUN: count, SEQ: count, SFUN: count, NSB: count, XFUN: count, data: string)
    {
    local info: BSAP_SERIAL_RDB_EXT;
    info$ts  = network_time();
    info$uid = c$uid;
    info$dfun = app_functions[DFUN];
    info$seq = SEQ;
    info$sfun = app_functions[SFUN];
    info$nsb = NSB;
    info$extfun = rdb_ext_functions[XFUN];
    info$data = data;
    Log::write(Bsap::LOG_BSAP_SERIAL_RDB_EXT, info);
    }

###############################################################################################
################# Defines logging of bsap_unknown event -> bsap_unknown.log  ##################
###############################################################################################
event bsap_serial_unknown(c: connection, data: string)
    {

    local info: BSAP_SERIAL_UNKNOWN;
    info$ts  = network_time();
    info$uid = c$uid;
    info$data = data;
    Log::write(Bsap::LOG_BSAP_SERIAL_UNKNOWN, info);
    }     