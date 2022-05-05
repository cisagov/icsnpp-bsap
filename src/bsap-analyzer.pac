## bsap-analyzer.pac
##
## Binpac BSAP Protocol Analyzer - Defines BSAP analyzer events.
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%header{

     typedef struct RDB_Request {
        uint8 variable_cnt;
        uint8 err;
        zeek::VectorValPtr variable_value;
        zeek::VectorValPtr variables;

        RDB_Request(){
            variable_cnt = 0;
            err = 0;
            variable_value = NULL;
            variables = NULL;
        }
    } RDB_Request;

    extern string response_addr;
    extern uint8 FuncType;
    extern uint8 AppFuncCode;
    extern uint32 ResponseId;
    extern uint32 MessageId;
    extern uint32 req_len;
    string HexToString(const_bytestring data, uint16 len, uint16 pos);
    void setFunc(uint8 func);
    RDB_Request getRdb(uint8 req_resp, uint8 cnt, uint8 func,
                       uint8 proto_type, const_bytestring data);
    void setResponseId(uint8 function, uint32 ResponseSeqID,
                       uint32 MessageSeqID, uint32 MessageLen);
    uint32 checkResponse(uint32 Responder);
    uint32 getResponseID();
    uint32 getMessageID();
    uint8 getAppFunc();
%}

%code{
    uint8 variable_count = 0;
    uint8 FuncType = 0xFF;
    uint8 AppFuncCode = 0xFF;
    uint32 ResponseId = 0;
    uint32 MessageId = 0;
    uint32 req_len = 0;
    string response_addr;

    string HexToString(const_bytestring data, uint16 len, uint16 pos)
        {
        char buf[100];
        int offset = 0;
        int count = 0;
        if(len)
            {
            for(int i = pos; i < pos+len; i++)
                {
                if( ((data[i] & 0xF0) >> 4) > 0x09)
                    buf[count] = (((data[i] & 0xF0) >> 4) - 0x0A) + 0x41;
                else
                    buf[count] = ((data[i] & 0xF0) >> 4) + 0x30;

                if( ((data[i] & 0x0F)) > 0x09)
                    buf[count+1] = ((data[i] & 0x0F) - 0x0A) + 0x41;
                else
                    buf[count+1] = (data[i] & 0x0F) + 0x30;

                count += 2;
                }

            buf[count] = 0x00;

            string r_val;
            r_val += buf;
            return r_val;
            }
        return NULL;
        }

    void setFunc(uint8 func)
        {
        FuncType = func;
        }

    RDB_Request getRdb(uint8 req_resp, uint8 cnt, uint8 func,
                       uint8 proto_type, const_bytestring data)
        {
        RDB_Request rdb_request;
        auto variables = zeek::make_intrusive<zeek::VectorVal>(zeek::id::string_vec);
        auto variable_value = zeek::make_intrusive<zeek::VectorVal>(zeek::id::string_vec);
        uint16 z = 0;

        switch(func)
            {
            case READ_SIGNAL_BY_ADDRESS:

                break;
            case READ_LOGICAL_BY_ADDRESS:

                break;
            case READ_SIGNAL_BY_NAME:


                if(proto_type) // serial
                    {
                    if(req_resp)
                        rdb_request.variable_cnt = data[1];
                    else
                        {
                        rdb_request.variable_cnt = data[3];
                        }
                    }
                else // ip
                    {
                    if(req_resp)
                        rdb_request.variable_cnt = cnt;
                    else
                        rdb_request.variable_cnt = data[4];
                    }


                z = 0;

                if(req_resp)
                    {
                    if(!proto_type)
                        {
                        for(int i = 0; i < rdb_request.variable_cnt; i++)
                            {
                                if(data[z] > 0)
                                    {
                                        if(z < data.length())
                                            {
                                            rdb_request.err = data[z];
                                            z += 1;
                                            string vname;
                                            do{
                                                vname  = "Errdata 0x";
                                                vname += HexToString(data, 2, z);
                                                vname += " ";
                                                z += 2;

                                                vname += "Errdata 0x";
                                                vname += HexToString(data, 2, z);
                                                vname += " ";
                                                z += 2;

                                                vname += "Addr 0x";
                                                vname += HexToString(data, 2, z);
                                                variables->Assign(variables->Size(),
                                                                  zeek::make_intrusive<zeek::StringVal>(vname));
                                                z += 2;

                                                if((z > data.length() - 2))
                                                    break;

                                                }while(data[z] != 0x24 && data[z+1] != 0x77);
                                            }
                                    }
                                else
                                    {
                                        if(z < data.length())
                                            {
                                            string vname;
                                            do{
                                                vname  = "0x";
                                                vname += HexToString(data, 2, z);
                                                vname += " ";
                                                z += 2;

                                                vname += "Addr 0x";
                                                vname += HexToString(data, 2, z);
                                                variables->Assign(variables->Size(),
                                                                  zeek::make_intrusive<zeek::StringVal>(vname));
                                                z += 2;

                                                if((z > data.length() - 2))
                                                    break;
                                                }while(data[z] != 0x24 && data[z+1] != 0x77);
                                            }
                                    }
                                    z+=2;

                            }
                        }
                    else
                        {
                        z = 2;
                        uint8 errset = 0;
                        for(int i = 0; i < rdb_request.variable_cnt; i++)
                            {
                                uint8 testval;
                                string vval = "";
                                do
                                {
                                    testval = data[z];
                                    if(((testval & 0x10) >> 4 == 1) || ((testval & 0x20) >> 5 == 1) ||
                                       ((testval & 0x40) >> 6 == 1) || ((testval & 0x80) >> 7 == 1))
                                        {
                                            errset = 1;
                                            vval += "Errdata 0x";
                                            vval += HexToString(data, 1, z);
                                            vval += " ";

                                        }
                                    z++;

                                    if((z > data.length() - 2))
                                        break;
                                }while(data[z] != 0x10 && data[z+1] != 0x03);

                                if(!errset)
                                    {
                                    z = 2;
                                    do
                                    {
                                        vval += HexToString(data, 1, z);
                                        z++;
                                        if((z > data.length() - 2))
                                            break;
                                        }while(data[z] != 0x10 && data[z+1] != 0x03);
                                    }
                                variable_value->Assign(variable_value->Size(),
                                                       zeek::make_intrusive<zeek::StringVal>(vval));
                                errset = 0;
                            }
                        }
                    }
                else
                    {
                    if(proto_type)
                        z = 2;
                    for(int i = 0; i < rdb_request.variable_cnt; i++)
                        {
                        while(data[z] != '@' && z < data.length())
                        {
                            z++;

                        }

                        if(data[z] == '@')
                            {
                            string vname = "";
                            do{
                                vname += data[z];
                                z++;
                                if((z > data.length()))
                                    break;
                            }while(data[z] != 0x00);
                            variables->Assign(variables->Size(),
                                              zeek::make_intrusive<zeek::StringVal>(vname));
                            }
                        }
                    }

                break;
            case READ_LOGICAL_BY_NAME:

                break;
            case READ_SIGNAL_BY_LIST_START:

                break;
            case READ_SIGNAL_BY_LIST_CONTINUE:

                break;
            case READ_LOGICAL_BY_LIST_START:

                break;
            case READ_LOGICAL_BY_LIST_CONTINUE:

                break;
            case WRITE_SIGNAL_BY_ADDRESS:


                if(req_resp)
                {
                    if(data.length())
                        {
                        string vval = HexToString(data, 2, data.length());
                        variable_value->Assign(variable_value->Size(),
                                               zeek::make_intrusive<zeek::StringVal>(vval));
                        }
                    variables->Assign(variables->Size(),
                                      zeek::make_intrusive<zeek::StringVal>(response_addr));
                }
                else
                {
                    if(proto_type) // serial
                        {
                        rdb_request.variable_cnt = data[3];
                        z = 4;
                        }
                    else // ip
                        {
                        rdb_request.variable_cnt = data[3];
                        z = 4;
                        }

                    string vname = "";
                    string vval = "";
                    for(int i = 0; i < rdb_request.variable_cnt; i++)
                        {
                        vname += "Addr 0x";
                        vname += HexToString(data, 2, z);
                        vname += " ";
                        z += 2;
                        response_addr = vname;
                        vval += HexToString(data, 1, z);
                        z++;
                        if((z > data.length()))
                            break;
                        }
                    variables->Assign(variables->Size(),
                                      zeek::make_intrusive<zeek::StringVal>(vname));
                    variable_value->Assign(variable_value->Size(),
                                           zeek::make_intrusive<zeek::StringVal>(vval));
                }

                break;
            case WRITE_SIGNAL_BY_NAME:
                if(proto_type) // serial
                    {
                    if(req_resp)
                        {
                        rdb_request.variable_cnt = variable_count;
                        }
                    else
                        {
                        rdb_request.variable_cnt = data[1];
                        variable_count = rdb_request.variable_cnt;
                        }
                    }
                else // ip
                    {
                    if(req_resp)
                        rdb_request.variable_cnt = cnt;
                    else
                        rdb_request.variable_cnt = data[4];
                    }

                z = 0;

                if(req_resp)
                    {
                    if(!proto_type)
                        {
                        for(int i = 0; i < rdb_request.variable_cnt; i++)
                            {
                            z = 0;
                            uint8 errset = 0;

                            uint8 testval;
                            string vval = "";
                            do
                            {
                                testval = data[z];
                                if(((testval & 0x10) >> 4 == 1) || ((testval & 0x20) >> 5 == 1) ||
                                   ((testval & 0x40) >> 6 == 1) || ((testval & 0x80) >> 7 == 1))
                                    {
                                        errset = 1;
                                        vval += "Errdata 0x";
                                        vval += HexToString(data, 1, z);
                                        z++;
                                    }
                                z++;
                                if((z > data.length() - 2))
                                    break;
                            }while(data[z] != 0x24 && data[z+1] != 0x77);

                            if(!errset)
                                {
                                z = 0;
                                do
                                {
                                    vval += HexToString(data, 1, z);
                                    z++;
                                    if((z > data.length() - 2))
                                        break;
                                    }while(data[z] != 0x24 && data[z+1] != 0x77);
                                }
                            variable_value->Assign(variable_value->Size(),
                                                   zeek::make_intrusive<zeek::StringVal>(vval));
                            errset = 0;
                            }
                        }
                    else
                        {
                        z = 0;
                        uint8 errset = 0;

                        uint8 testval;
                        string vval = "";
                        do
                        {
                            testval = data[z];
                            if(((testval & 0x10) >> 4 == 1) || ((testval & 0x20) >> 5 == 1) ||
                               ((testval & 0x40) >> 6 == 1) || ((testval & 0x80) >> 7 == 1))
                                {
                                    errset = 1;
                                    vval += "Errdata 0x";
                                    vval += HexToString(data, 1, z);
                                    z++;
                                }
                            z++;
                            if((z > data.length() - 2))
                                break;
                        }while(data[z] != 0x10 && data[z+1] != 0x03);

                        if(!errset)
                            {
                            z = 0;
                            do
                            {
                                vval += HexToString(data, 1, z);
                                z++;
                                if((z > data.length() - 2))
                                    break;
                                }while(data[z] != 0x10 && data[z+1] != 0x03);
                            }
                        variable_value->Assign(variable_value->Size(),
                                               zeek::make_intrusive<zeek::StringVal>(vval));
                        errset = 0;

                        }
                    }
                else
                    {
                    if(proto_type)
                        z = 2;
                    for(int i = 0; i < rdb_request.variable_cnt; i++)
                        {
                        while(data[z] != '@' && z < data.length())
                        {
                            z++;

                        }

                        if(data[z] == '@')
                            {
                            string vname = "";
                            do{
                                vname += data[z];
                                z++;
                                if((z > data.length()))
                                    break;
                            }while(data[z] != 0x00);
                            variables->Assign(variables->Size(),
                                              zeek::make_intrusive<zeek::StringVal>(vname));
                            }
                        }
                    }

                break;
            case WRITE_SIGNAL_BY_LIST_START:

                break;
            case WRITE_SIGNAL_BY_LIST_CONTINUE:

                break;
            }

        rdb_request.variables = variables;
        rdb_request.variable_value = variable_value;
        return rdb_request;
        }

    void setResponseId(uint8 function, uint32 ResponseSeqID, uint32 MessageSeqID, uint32 MessageLen)
        {
        AppFuncCode = function;
        ResponseId = ResponseSeqID;
        MessageId = MessageSeqID;
        req_len = MessageLen;
        }

    uint32 checkResponse(uint32 Responder)
        {
        if(ResponseId == Responder)
            {
            MessageId = 0;
            ResponseId = 0;
            return FuncType + 0x50;
            }
        else
            {
            return ResponseId;
            }

        }

    uint32 getResponseID()
        {
        return ResponseId;
        }

    uint32 getMessageID()
        {
        return MessageId;
        }

    uint8 getAppFunc()
        {
        return AppFuncCode;
        }
%}

refine flow BSAP_Flow += {

    function proc_bsap_message(bsap_header: BSAP_PDU): bool
        %{
            return true;
        %}

    ###############################################################################################
    ###########################  Process data for bsapip_header event  ############################
    ###############################################################################################
    function proc_bsapip_ip_message(bsapip_header: BSAPIP_Ip): bool
       %{
            if( :: bsap_ip_header)
                {
                zeek::BifEvent::enqueue_bsap_ip_header(connection()->zeek_analyzer(),
                                                        connection()->zeek_analyzer()->Conn(),
                                                        is_orig(),
                                                        ${bsapip_header.header.Num_Messages},
                                                        ${bsapip_header.header.Num_Messages},
                                                        ${bsapip_header.header.Message_Func});
                }
            return true;
       %}

    ###############################################################################################
    ######################  Process data for proc_bsapip_request_header event  ######################
    ###############################################################################################
    function proc_bsapip_request_header(bsapip_request_header: BSAPIP_Request_Header): bool
       %{
            setResponseId(${bsapip_request_header.app_func_code},${bsapip_request_header.sequence},
                          ${bsapip_request_header.message_seq}, ${bsapip_request_header.data_length});

            if( :: bsap_ip_request_header)
            {
                zeek::BifEvent::enqueue_bsap_ip_request_header(connection()->zeek_analyzer(),
                                                                connection()->zeek_analyzer()->Conn(),
                                                                ${bsapip_request_header.response_seq},
                                                                ${bsapip_request_header.message_seq},
                                                                ${bsapip_request_header.data_length},
                                                                ${bsapip_request_header.header_size},
                                                                ${bsapip_request_header.sequence},
                                                                ${bsapip_request_header.app_func_code});
            }
            return true;
       %}

    ###############################################################################################
    ######################  Process data for proc_bsapip_rdb_request event  #######################
    ###############################################################################################
    function proc_bsapip_rdb_request(bsapip_rdb_request: BSAPIP_RDB_Request): bool
      %{
            uint32 message_id = 0, response_id = 0;
            RDB_Request rdb_request;

            setFunc(${bsapip_rdb_request.func_code});
            rdb_request = getRdb(0, 0, ${bsapip_rdb_request.func_code}, 0, ${bsapip_rdb_request.data});

            response_id = getResponseID();
            message_id = getMessageID();

            if( ::bsap_ip_rdb_request )
            {
                zeek::BifEvent::enqueue_bsap_ip_rdb_request(connection()->zeek_analyzer(),
                                                             connection()->zeek_analyzer()->Conn(),
                                                             response_id,
                                                             message_id,
                                                             ${bsapip_rdb_request.node_status},
                                                             ${bsapip_rdb_request.func_code},
                                                             req_len,
                                                             rdb_request.variable_cnt,
                                                             std::move(rdb_request.variables),
                                                             std::move(rdb_request.variable_value),
                                                             to_stringval(${bsapip_rdb_request.data}));
            }
            return true;
      %}

    ###############################################################################################
    ########################  Process data for proc_bsapip_response event  ########################
    ###############################################################################################
    function proc_bsapip_response(bsap_response: BSAPIP_Response): bool
       %{
            uint32 response_status = 0;
            uint32 app_code = 0;

            app_code = getAppFunc();
            response_status = checkResponse(${bsap_response.response_seq});

            RDB_Request rdb_request;
            rdb_request = getRdb(1, ${bsap_response.nme}, (response_status - 0x50), 0, ${bsap_response.data});

            switch(app_code)
            {
                case RDB:
                    if( ::bsap_ip_rdb_response )
                    {
                       zeek::BifEvent::enqueue_bsap_ip_rdb_response(connection()->zeek_analyzer(),
                                                                     connection()->zeek_analyzer()->Conn(),
                                                                     ${bsap_response.message_seq},
                                                                     ${bsap_response.response_seq},
                                                                     ${bsap_response.data_length},
                                                                     ${bsap_response.header_size},
                                                                     ${bsap_response.sequence},
                                                                     response_status,
                                                                     ${bsap_response.resp_status},
                                                                     std::move(rdb_request.variables),
                                                                     std::move(rdb_request.variable_value),
                                                                     ${bsap_response.nme},
                                                                     to_stringval(${bsap_response.data}));
                    }
                    break;
            }
            return true;
       %}

    ###############################################################################################
    ########################  Process data for proc_bsap_ip_unknown event  ########################
    ###############################################################################################
    function proc_bsap_ip_unknown(bsapip_unknown: BSAPIP_Unknown): bool
        %{
            if( ::bsap_ip_unknown )
            {
               zeek::BifEvent::enqueue_bsap_ip_unknown(connection()->zeek_analyzer(),
                                                        connection()->zeek_analyzer()->Conn(),
                                                        to_stringval(${bsapip_unknown.data}));
            }
            return true;
        %}



    ###############################################################################################
    ####################  Process data for proc_bsap_serial_local_header event  ###################
    ###############################################################################################
    function proc_bsap_serial_local_header(bsap_serial_local_header: BSAP_Serial_Local_Header): bool
      %{
            if( ::bsap_serial_local_header)
            {
                setResponseId(${bsap_serial_local_header.DFUN}, ${bsap_serial_local_header.SEQ}, 0, 0);

                zeek::BifEvent::enqueue_bsap_serial_local_header(connection()->zeek_analyzer(),
                                                                  connection()->zeek_analyzer()->Conn(),
                                                                  ${bsap_serial_local_header.SER},
                                                                  ${bsap_serial_local_header.DFUN},
                                                                  ${bsap_serial_local_header.SEQ},
                                                                  ${bsap_serial_local_header.SFUN},
                                                                  ${bsap_serial_local_header.NSB});
            }
            return true;
      %}
    ###############################################################################################
    #################  Process data for proc_bsap_serial_global_header event  #####################
    ###############################################################################################
    function proc_bsap_serial_global_header(bsap_serial_global_header: BSAP_Serial_Global_Header): bool
      %{
            if( ::bsap_serial_global_header)
            {
                zeek::BifEvent::enqueue_bsap_serial_global_header(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   ${bsap_serial_global_header.SER},
                                                                   ${bsap_serial_global_header.DADD},
                                                                   ${bsap_serial_global_header.SADD},
                                                                   ${bsap_serial_global_header.CTL},
                                                                   ${bsap_serial_global_header.DFUN},
                                                                   ${bsap_serial_global_header.SEQ},
                                                                   ${bsap_serial_global_header.SFUN},
                                                                   ${bsap_serial_global_header.NSB});
            }
            return true;
      %}

    ###############################################################################################
    ####################  Process data for proc_bsap_serial_rdb_request event  ####################
    ###############################################################################################
    function proc_bsap_serial_rdb_request(bsap_serial_rdb_request: BSAP_Serial_RDB_Request): bool
      %{

            RDB_Request rdb_request;
            setFunc(${bsap_serial_rdb_request.func_code});
            rdb_request = getRdb(0, 0, ${bsap_serial_rdb_request.func_code}, 1, ${bsap_serial_rdb_request.data});


            if( ::bsap_serial_rdb_request )
            {
                zeek::BifEvent::enqueue_bsap_serial_rdb_request(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 ${bsap_serial_rdb_request.func_code},
                                                                 rdb_request.variable_cnt,
                                                                 std::move(rdb_request.variables),
                                                                 std::move(rdb_request.variable_value),
                                                                 to_stringval(${bsap_serial_rdb_request.data}));
            }
            return true;
      %}

    ###############################################################################################
    ####################  Process data for proc_bsap_serial_response event  #######################
    ###############################################################################################
    function proc_bsap_serial_response(bsap_serial_response: BSAP_Serial_RDB_Response): bool
       %{
            uint32 response_status = 0;
            uint32 app_code = getResponseID();

            response_status = checkResponse(app_code);

            RDB_Request rdb_request;
            rdb_request = getRdb(1, 0, (response_status - 0x50), 1, ${bsap_serial_response.data});

            if( ::bsap_serial_rdb_response )
            {
               zeek::BifEvent::enqueue_bsap_serial_rdb_response(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 response_status,
                                                                 rdb_request.variable_cnt,
                                                                 std::move(rdb_request.variables),
                                                                 std::move(rdb_request.variable_value),
                                                                 to_stringval(${bsap_serial_response.data}));
            }
            return true;
       %}

    ###############################################################################################
    #################  Process data for proc_bsap_serial_rdb_extension event  #####################
    ###############################################################################################
    function proc_bsap_serial_rdb_extension(bsap_serial_rdb_extension: BSAP_Serial_RDB_Extension): bool
        %{
            if( ::bsap_serial_rdb_extension )
            {
               zeek::BifEvent::enqueue_bsap_serial_rdb_extension(connection()->zeek_analyzer(),
                                                                  connection()->zeek_analyzer()->Conn(),
                                                                  ${bsap_serial_rdb_extension.DFUN},
                                                                  ${bsap_serial_rdb_extension.SEQ},
                                                                  ${bsap_serial_rdb_extension.SFUN},
                                                                  ${bsap_serial_rdb_extension.NSB},
                                                                  ${bsap_serial_rdb_extension.XFUN},
                                                                  to_stringval(${bsap_serial_rdb_extension.data}));
            }
            return true;
       %}



    ###############################################################################################
    #####################  Process data for proc_bsap_serial_unknown event  #######################
    ###############################################################################################
    function proc_bsap_serial_unknown(bsap_serial_unknown: BSAP_Serial_Unknown): bool
        %{
            if( ::bsap_serial_unknown )
            {
               zeek::BifEvent::enqueue_bsap_serial_unknown(connection()->zeek_analyzer(),
                                                            connection()->zeek_analyzer()->Conn(),
                                                            to_stringval(${bsap_serial_unknown.data}));
            }
            return true;
        %}
};
