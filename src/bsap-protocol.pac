## BSAPIP-protocol.pac
##
## Binpac BSAP Protocol Analyzer - Defines BSAP Protocol Message Formats
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%include consts.pac

## --------------------------------------------BSAP-PDU--------------------------------------------
## Message Description:
##      Main BSAP PDU
## Message Format:
##      - header:                   BSAPIP_Header       -> See BSAPIP_Header
##      - body:                     GET_BSAP            -> GET_BSAP
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAPIP_Response or BSAPIP_Request parsing function.
## ------------------------------------------------------------------------------------------------
type BSAP_PDU(is_orig: bool) = record {
    msg_typ                 : BSAP_Type;
    body                    : TYPE_SWITCH(msg_typ);
} &byteorder=littleendian;

## -------------------------------------------BSAP_Type--------------------------------------------
## Message Description:
##      BSAP_Type
## Message Format:
##      - proto:                      uint16              -> Determines BSAP_IP vs BSAP_SERIAL
##
## Protocol Parsing:
##      Parses out protocol identifier for BSAP parser. 0x0210 == BSAP SERIAL, anything else
##      is BSAP_IP.
## ------------------------------------------------------------------------------------------------
type BSAP_Type = record {
    proto                   : uint16;
} &byteorder=littleendian;

## -----------------------------------------TYPE_SWITCH--------------------------------------------
## Message Description:
##      TYPE_SWITCH determines the correct protocol for the data to be passed to.
## Protocol Parsing:
##      Passes parsing to correct protocol target.
## ------------------------------------------------------------------------------------------------
type TYPE_SWITCH(msg_typ: BSAP_Type) = case msg_typ.proto of {

    BSAP_SERIAL                         -> bsapserial:             BSAP_Serial;
    default                             -> bsapip:                 BSAPIP_Ip;
} 

## ------------------------------------GET_BSAP_Serial_GLBL_LOCAL-----------------------------------
## Message Description:
##      BSAP GLBL LOCAL determines the BSAP header type if either local or global. 
## Message Format:
##      - LOCAL:                    local               -> see BSAP_Serial_Local
##      - GLOBAL:                   global              -> see BSAP_Serial_Global
##      - default:                  dflt                -> see BSAP_Serial_Local
## Protocol Parsing:
##      Passes processing to either BSAP_Serial_Local or BSAP_Serial_Global based off of header.ADDR
## ------------------------------------------------------------------------------------------------
type GET_BSAP_Serial_GLBL_LOCAL(header: BSAP_Serial_Header) = case (header.ADDR >> 7) of {
    LOCAL                               -> local:                   BSAP_Serial_Local;
    GLOBAL                              -> global:                  BSAP_Serial_Global;
    default                             -> dflt:                    BSAP_Serial_Local;
} 

## --------------------------------------------BSAP_Serial_Local-------------------------------------------
## Message Description:
##      BSAP_Serial_Local grabs local header and passes to GET_BSAP_Serial_LOCAL function to parse message
## Message Format:
##      - header:                   BSAP_Serial_Local_Header         -> See BSAP_Serial_Local_Header
##      - body:                     GET_BSAP_Serial_LOCAL            -> GET_BSAP_Serial_LOCAL
## Protocol Parsing:
##      Gets header for BSAP Local message and passes header data to function
##      GET_BSAP_Serial_LOCAL to determine the function to process the remaining data.
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_Local = record {
    header                     : BSAP_Serial_Local_Header;
    body                       : GET_BSAP_Serial_LOCAL(header);
} &byteorder=littleendian;

## --------------------------------------------BSAP_Serial_Global---------------------------------------
## Message Description:
##      BSAP_Serial_Global grabs local header and passes to GET_BSAP_Serial_GLOBAL 
##      function to parse message
## Message Format:
##      - header:                   BSAP_Serial_Global_Header         -> See BSAP_Serial_Global_Header
##      - body:                     GET_BSAP_Serial_GLOBAL            -> GET_BSAP_Serial_GLOBAL
## Protocol Parsing:
##      Gets header for BSAP Global message and passes header data to function
##      GET_BSAP_Serial_GLOBAL to determine the function to process the remaining data.
## -----------------------------------------------------------------------------------------------------
type BSAP_Serial_Global = record {
    header                     : BSAP_Serial_Global_Header;
    body                       : GET_BSAP_Serial_GLOBAL(header);
} &byteorder=littleendian;

## ------------------------------------BSAP_Serial_Local_Header-------------------------------------------
## Message Description:
##      BSAP Local header data 
## Message Format:
##      - SER:                      uint8               -> Message Serial Number
##      - DFUN:                     uint8               -> Destination Function
##      - SEQ:                      uint16              -> Message Sequence 
##      - SFUN:                     uint8               -> Source Function
##      - NSB:                      uint8               -> Node Status Byte        
##                                                                                                              
## Protocol Parsing:
##      Bsap Local header data to send to case statement for further processing     
## ------------------------------------------------------------------------------------------------------
type BSAP_Serial_Local_Header = record {
    SER                     : uint8;
    DFUN                    : uint8;
    SEQ                     : uint16;
    SFUN                    : uint8;
    NSB                     : uint8;
} &let {
    deliver: bool = $context.flow.proc_bsap_serial_local_header(this);
} &byteorder=littleendian;

## ------------------------------------BSAP_Serial_Global_Header------------------------------------------
## Message Description:
##      BSAP Global header data 
## Message Format:
##      - SER:                      uint8               -> Message Serial Number
##      - DADD:                     uint16              -> Destination Address
##      - SADD:                     uint16              -> Source Address
##      - CTL:                      uint8               -> Control Byte
##      - DFUN:                     uint8               -> Destination Function
##      - SEQ:                      uint16              -> Message Sequence
##      - SFUN:                     uint8               -> Source Function
##      - NSB:                      uint8               -> Node Status Byte
## Protocol Parsing:
##      Bsap Global header data to send to case statement for further processing
## ------------------------------------------------------------------------------------------------------
type BSAP_Serial_Global_Header = record {
    SER                     : uint8;
    DADD                    : uint16;
    SADD                    : uint16;
    CTL                     : uint8;
    DFUN                    : uint8;
    SEQ                     : uint16;
    SFUN                    : uint8;
    NSB                     : uint8;
}  &let {
    deliver: bool = $context.flow.proc_bsap_serial_global_header(this);
} &byteorder=littleendian;

## --------------------------------------------BSAP_Serial-----------------------------------------
## Message Description:
##      Main BSAP_Serial 
## Message Format:
##      - header:                   BSAP_Serial_Header         -> See BSAP_Serial_Header
##      - body:                     GET_BSAP_Serial_GLBL_LOCAL -> GET_BSAP_Serial_GLBL_LOCAL
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAP Local or BSAP Global message parsing depending on the ADDR value.
## ------------------------------------------------------------------------------------------------
type BSAP_Serial = record {
    header                  : BSAP_Serial_Header;
    body                    : GET_BSAP_Serial_GLBL_LOCAL(header);
} &byteorder=littleendian; 

## --------------------------------------BSAP_Serial_Header-----------------------------------------
## Message Description:
##      Main Ethernet/IP PDU
## Message Format:
##      - ADDR:                     uint8               -> Address of device 0x00-0x7F local addr
##                                                         localaddr+0x80  global msg
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAP Local or BSAP Global message parsing depending on the ADDR value.
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_Header = record {
    ADDR                    : uint8;
} &byteorder=littleendian;

## ----------------------------------------GET_BSAP_Serial_LOCAL------------------------------------------
## Message Description:
##      GET_BSAP_Serial_LOCAL determines the correct function to process the local message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Destination Function (DFUN) command
## ------------------------------------------------------------------------------------------------
type GET_BSAP_Serial_LOCAL(header: BSAP_Serial_Local_Header) = case header.DFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Serial_Unknown;
    PEI_PC                              -> pei_pc:                  BSAP_Serial_On_Line_PEI_PC_LOCAL(header);
    DIAG                                -> diag:                    BSAP_Serial_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Serial_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Serial_Unknown;
    RDB                                 -> remotedatabase:          BSAP_Serial_RDB_Request;
    RDB_EXTENSION                       -> remotedatabaseext:       BSAP_Serial_RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Serial_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Serial_Unknown;
    default                             -> poll:                    BSAP_Serial_Unknown;
} 

## ----------------------------------------BSAP_Serial_On_Line_PEI_PC_LOCAL------------------------------------
## Message Description:
##      GET_BSAP_Serial_GLOBAL determines the correct function to process the local message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Source Function (SFUN) command
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_On_Line_PEI_PC_LOCAL(header: BSAP_Serial_Local_Header) = case header.SFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Serial_Unknown;
    PEI_PC                              -> pei_pc:                  BSAP_Serial_Unknown;
    DIAG                                -> diag:                    BSAP_Serial_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Serial_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Serial_Unknown;
    RDB                                 -> remotedatabase:          BSAP_Serial_RDB_Response;
    RDB_EXTENSION                       -> remotedatabaseext:       BSAP_Serial_RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Serial_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Serial_Unknown;
    default                             -> poll:                    BSAP_Serial_Unknown;
}

## ----------------------------------------GET_BSAP_Serial_GLOBAL-----------------------------------------
## Message Description:
##      GET_BSAP_Serial_GLOBAL determines the correct function to process the global message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Destination Function (DFUN) command
## ------------------------------------------------------------------------------------------------
type GET_BSAP_Serial_GLOBAL(header: BSAP_Serial_Global_Header) = case header.DFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Serial_Unknown;
    PEI_PC                              -> pei_pc:                  BSAP_Serial_On_Line_PEI_PC_GLOBAL(header);
    DIAG                                -> diag:                    BSAP_Serial_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Serial_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Serial_Unknown;
    RDB                                 -> remotedatabase:          BSAP_Serial_RDB_Request;
    RDB_EXTENSION                       -> remotedatabaseext:       BSAP_Serial_RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Serial_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Serial_Unknown;
    default                             -> poll:                    BSAP_Serial_Unknown;
} 

## ----------------------------------------BSAP_Serial_On_Line_PEI_PC_GLOBAL-----------------------------------
## Message Description:
##      BSAP_Serial_On_Line_PEI_PC_GLOBAL determines the correct function to process the global message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Source Function (SFUN) command
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_On_Line_PEI_PC_GLOBAL(header: BSAP_Serial_Global_Header) = case header.SFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Serial_Unknown;
    PEI_PC                              -> pei_pc:                  BSAP_Serial_Unknown;
    DIAG                                -> diag:                    BSAP_Serial_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Serial_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Serial_Unknown;
    RDB                                 -> remotedatabase:          BSAP_Serial_RDB_Response;
    RDB_EXTENSION                       -> remotedatabaseext:       BSAP_Serial_RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Serial_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Serial_Unknown;
    default                             -> poll:                    BSAP_Serial_Unknown;
}

## --------------------------------------------BSAP_Serial_RDB_Request-----------------------------------------
## Message Description:
##      BSAP_Serial_RDB_Request is remote data base access for reading and writing RTU variables 
## Message Format:
##      func_code:                  uint8                   -> Function that will be called
##      data:                       bytestring &restofdata  -> data passed for function call
## Protocol Parsing:
##      Parses function code from message and stores rest of message in data to be 
##      stored in bsap_cnv_rdb.log file. 
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_RDB_Request = record {
    func_code               : uint8;
    data                    : bytestring &restofdata;        
} &let {
    deliver: bool = $context.flow.proc_bsap_serial_rdb_request(this);
} &byteorder=littleendian;

## ------------------------------------------BSAP_Serial_RDB_Extension-----------------------------------------
## Message Description:
##      BSAP_Serial_RDB_Extension is remote data base access request to (GFC 3308) devices.
## Message Format:
##      DFUN
##      SEQ
##      SFUN
##      NSB
##      XFUN
##      data
##      data:                       bytestring &restofdata  -> data returned to requester
## Protocol Parsing:
##      Parses data from response message and stores in bsap_cnv_rdb.log file
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_RDB_Extension = record {
    DFUN                    : uint8;
    SEQ                     : uint16;
    SFUN                    : uint8;
    NSB                     : uint8;
    XFUN                    : uint16;
    data                    : bytestring &restofdata;  
} &let {
    deliver: bool = $context.flow.proc_bsap_serial_rdb_extension(this);
} &byteorder=littleendian;

## -------------------------------------------BSAP_Serial_RDB_Response-----------------------------------------
## Message Description:
##      BSAP_Serial_RDB_Response is remote data base access response to the initiated request.
## Message Format:
##      data:                       bytestring &restofdata  -> data returned to requester
## Protocol Parsing:
##      Parses data from response message and stores in bsap_cnv_rdb.log file
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_RDB_Response = record {
    data                    : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.proc_bsap_serial_response(this);
} &byteorder=littleendian;

## -------------------------------------------BSAP_Serial_Unknown-----------------------------------------
## Message Description:
##      BSAP_Serial_Unknown is grabbing data that has BSAP comm but no structure defined
## Message Format:
##      data:                       bytestring &restofdata  -> data returned to requester
## Protocol Parsing:
##      Parses data from message and stores in bsap_unknown.log file
## ------------------------------------------------------------------------------------------------
type BSAP_Serial_Unknown = record {
    data                    : bytestring &restofdata;
} &byteorder=littleendian;


## -------------------------------------------BSAPIP_Header----------------------------------------
## Message Description:
##      BSAPIP_Header
## Message Format:
##      - Num_Messages:            uint16              -> This is either amount of functions per
##                                                        message or is standard vs poll message.
##
##      - Message_Func:            uint16              -> Determines message type
##
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAP Local or BSAP Global message parsing depending on the ADDR value.
## ------------------------------------------------------------------------------------------------
type BSAPIP_Header = record {
    Num_Messages            : uint16;
    Message_Func            : uint16;
} &byteorder=littleendian;

## -----------------------------------------GET_BSAPIP---------------------------------------------
## Message Description:
##      GET_BSAP determines the correct function to process the bsap message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Message_Func value
## ------------------------------------------------------------------------------------------------
type GET_BSAPIP(header: BSAPIP_Header) = case header.Message_Func of {
    CMD_REQUEST                         -> request:                 BSAPIP_Request;
    CMD_RESPONSE                        -> response:                BSAPIP_Response;
    CMD_RESPONSE_1                      -> response_1:              BSAPIP_Response;
    default                             -> unknown:                 BSAPIP_Unknown;
} 


## ------------------------------------------BSAPIP_Ip-----------------------------------------------
## Message Description:
##      BSAPIP_Ip main bsap ip parsing function
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on GET_BSAPIP 
## ------------------------------------------------------------------------------------------------
type BSAPIP_Ip = record{
    header                  : BSAPIP_Header;
    body                    : GET_BSAPIP(header);
} &let {
    deliver: bool = $context.flow.proc_bsapip_ip_message(this);
} &byteorder=littleendian;


## -----------------------------------------BSAPIP_Request-------------------------------------------
## Message Description:
##      BSAPIP_Request
## Message Format:
##      - header:                  BSAPIP_Request_Header -> See BSAPIP_Request_Header
##      - body:                    BSAPIP_Get_Request    -> See BSAPIP_Get_Request
##
## Protocol Parsing:
##      Parses BSAP request header data and passes the information to the 
##      correct function to finish parsing. 
## ------------------------------------------------------------------------------------------------
type BSAPIP_Request = record {
    header                  : BSAPIP_Request_Header;
    body                    : BSAPIP_Get_Request(header);
} &byteorder=littleendian;

## ----------------------------------BSAPIP_Request_Header------------------------------------------
## Message Description:
##      BSAPIP_Request_Header
## Message Format:
##      - response_seq:             uint32              -> Message Response Sequence
##      - message_seq:              uint32              -> Message Sequence
##      - data_length:              uint32              -> Message Length
##      - header_size:              uint8               -> Header Length
##      - sequence:                 uint32              -> Function sequence 
##      - app_func_code:            uint8               -> Application function code        
##                                                                                                              
## Protocol Parsing:
##      BSAP request header information    
## ------------------------------------------------------------------------------------------------
type BSAPIP_Request_Header = record {
    response_seq            : uint32;
    message_seq             : uint32;
    data_length             : uint32;
    header_size             : uint8;
    sequence                : uint32;
    app_func_code           : uint8;
}&let {
    deliver: bool = $context.flow.proc_bsapip_request_header(this);
} &byteorder=littleendian;

## ------------------------------------------BSAPIP_Get_Request------------------------------------
## Message Description:
##      BSAPIP_Get_Request determines the correct function to process the message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on app_func_code command.
##      If function isn't implemented we pass to Unknown to be logged.
## ------------------------------------------------------------------------------------------------
type BSAPIP_Get_Request(header: BSAPIP_Request_Header) = case header.app_func_code of {
    RDB                                 -> remotedatabase:          BSAPIP_RDB_Request;
    default                             -> dflt:                    BSAPIP_Unknown;
}

## --------------------------------------------BSAPIP_RDB_Request----------------------------------
## Message Description:
##      BSAPIP_RDB_Request is remote data base access for reading and writing RTU variables 
## Message Format:
##      node_status:                uint8                   -> Node status byte
##      func_code:                  uint8                   -> Function that will be called
##      data:                       bytestring &restofdata  -> data passed for function call
## Protocol Parsing:
##      Parses function code from message and stores rest of message in data to be 
##      stored in BSAPIP_cnv_rdb.log file. 
## ------------------------------------------------------------------------------------------------
type BSAPIP_RDB_Request = record {
    node_status             : uint8;
    func_code               : uint8;
    data                    : bytestring &restofdata;        
} &let {
    deliver: bool = $context.flow.proc_bsapip_rdb_request(this);
} &byteorder=littleendian;

## --------------------------------------------BSAPIP_Response-------------------------------------
## Message Description:
##      RDB_Response is remote data base access response to the initiated request.
## Message Format:
##      message_seq:                uint32                  -> Message Sequence
##      response_seq:               uint32                  -> Message Response Sequence
##      data_length:                uint32                  -> Message Length
##      header_size:                uint8                   -> Header Length
##      sequence:                   uint32                  -> Function sequence 
##      resp_status:                uint8                   -> Response Status
##      nme:                        uint8                   -> Number of message elements
##      data:                       bytestring &restofdata  -> data passed for response
## Protocol Parsing:
##      Parses function code from message and stores rest of message in data to be 
##      stored in BSAPIP_cnv_rdb.log file. 
## ------------------------------------------------------------------------------------------------
type BSAPIP_Response = record {
    message_seq             : uint32;
    response_seq            : uint32;
    data_length             : uint32;
    header_size             : uint8;
    sequence                : uint32;
    resp_status             : uint8;
    nme                     : uint8;
    data                    : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.proc_bsapip_response(this);
} &byteorder=littleendian;


type BSAPIP_Unknown = record {
    data                    : bytestring &restofdata;
} &byteorder=littleendian;


