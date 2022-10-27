## consts.pac
##
## Binpac BSAP Analyzer - Contains the constants definitions for BSAP
##
## Origanal Author: BYU CAPSTONE PROJECT
## Editing Author:   Devin Vollmer
## Contact:  devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#############################################################
#########           BSAP COMMAND CODES              #########
#########  These are values that are not in         #########
#########  bsap programmers reference guide.        #########
#########  They do make sense with data flow        #########
#########  from plc. These were implemented         #########
#########  by BYU-I students.                       #########
#############################################################
enum command_codes {
    CMD_POLL         = 0x0000,
    CMD_RESPONSE_1   = 0x0001,
    CMD_RESPONSE     = 0x0005,
    CMD_REQUEST      = 0x0006,
    CMD_REQUEST_1    = 0x0084,
    CMD_REQUEST_2    = 0x0086,
};

enum proto_define {
    BSAP_SERIAL      = 0x0210,  
};

enum func_header_type {
        LOCAL               = 0x00,
        GLOBAL              = 0x01,
    };
    
#############################################################
#########        BSAP PROTOCOL FUNC CODES           #########
#############################################################
enum protocol_function_codes {
    FUNC_DIAL_UP_ACK        = 0x81,     #response to first poll message
                                        #received following a slave initiated dial-up sequence.
                                        #(For use with Open BSI)

    FUNC_ACK                = 0x83,     #Message Discarded
    FUNC_POLL               = 0x85,     #Poll message
    FUNC_DOWN_TRNS_ACK      = 0x86,     #Down Transmit ACK, Slave ACKing message
    FUNC_ACK_NO_DATA        = 0x87,     #ACK No Data, in response to a Poll message
    FUNC_UP_ACK_W_POLL      = 0x8A,     #UP-ACK with poll (recognized by VSAT Slave)
    FUNC_UP_ACK_MSTR        = 0x8B,     #UP-ACK, Master ACKing message
    FUNC_NAK_NO_DATA        = 0x95,     #NAK, No buffer available for received data
}; 

#############################################################
#########           BSAP APPFUNC CODES              #########
#########  The application function codes are       ######### 
#########  referenced in the bsap reference         ######### 
#########  guide. Looking into the dll for          ######### 
#########  openBSI it looks like the RDB func       ######### 
#########  codes are the only ones that are         ######### 
#########  implemented.                             #########
#############################################################
enum app_function_codes {
    ILLEGAL                                     = 0x00,
    PEI_PC                                      = 0x03,
    PEI_RTU                                     = 0x40,
    DIAG                                        = 0x48,
    TRANSMITTER_REQ_3508                        = 0x50,
    TRANSMITTER_RESP_3508                       = 0x51,
    CBO                                         = 0x60,
    FLASH_DOWNLOAD                              = 0x68,
    FLASH_CONFIG                                = 0x6A,
    CMD_HANDLER_REQ                             = 0x70,
    CMD_HANDLER_RESP                            = 0x71,
    #Reserved                                   = 0x72, # (used internally only for EMaster)
    DOWNLOAD_REQ_MSG_FRAMES                     = 0x78,
    TS_NRT_MSG                                  = 0x88, # (for SLAVE ports only) 
    REQ_TS_NRT_MSG                              = 0x89,
    PS_PASSTHRU_TSK1                            = 0x98,
    PS_PASSTHRU_TSK2                            = 0x99,
    PS_PASSTHRU_TSK3                            = 0x9A,
    PS_PASSTHRU_TSK4                            = 0x9B,
    PS_PASSTHRU_TSK5                            = 0x9C,
    PS_PASSTHRU_TSK6                            = 0x9D,
    PS_PASSTHRU_TSK7                            = 0x9E,
    PS_PASSTHRU_TSK8                            = 0x9F,
    RDB                                         = 0xA0, # only implemented BSAP messaging over ETHERNET
    RDB_EXTENSION                               = 0xA1, # These extensions are supported only by the 3308 Accurate Gas Flow Computer 
                                                    # (GFC 3308) firmware under message exchange 0xA1
    RBE_FIRM                                    = 0xA2,
    RBE_MNGR                                    = 0xA3,
    ALARM_ACK                                   = 0xA8,
    ALARM_INIT                                  = 0xA9,
    ALARM_REPORT                                = 0xAA,
    #SPARE                                      = 0xAB, # (reserved for the Alarm system)
    P2P_MASTER                                  = 0xB0,
    P2P_SLAVE                                   = 0xB1,
    TUNNEL_REQUEST                              = 0xBF,
    IP_PROCESSING_TASK                          = 0xC0,
    PS_PASSTHRU_COM1                            = 0xC1,
    PS_PASSTHRU_COM2                            = 0xC2,
    CFE_TMPL_MANAGERREQ                         = 0xC2,
    PS_PASSTHRU_COM3                            = 0xC3,
    CFE_TMPL_MANAGERMULT                        = 0xC3,
    PS_PASSTHRU_COM4                            = 0xC4,
    PS_PASSTHRU_COM5                            = 0xC5,
    PS_PASSTHRU_COM6                            = 0xC6,
    PS_PASSTHRU_COM7                            = 0xC7,
    PS_PASSTHRU_COM8                            = 0xC8,
    PS_PASSTHRU_COM9                            = 0xC9,
    PS_PASSTHRU_COM10                           = 0xCA,
    PS_PASSTHRU_COM11                           = 0xCB,
};

#############################################################
#########        REMOTE DATABASE ACCESS             #########
#########  The rdb function codes are used to       ######### 
#########  read and write data to the PLC from      ######### 
#########  the HMI, or master PLC.                  #########
#############################################################
enum rdb_functions {
    READ_SIGNAL_BY_ADDRESS                      = 0x00,
    READ_LOGICAL_BY_ADDRESS                     = 0x02,
    READ_SIGNAL_BY_NAME                         = 0x04,
    READ_LOGICAL_BY_NAME                        = 0x06,
    READ_SIGNAL_BY_LIST_START                   = 0x0C,
    READ_SIGNAL_BY_LIST_CONTINUE                = 0x0D,
    READ_LOGICAL_BY_LIST_START                  = 0x0E,
    READ_LOGICAL_BY_LIST_CONTINUE               = 0x0F,
    WRITE_SIGNAL_BY_ADDRESS                     = 0x80,
    WRITE_SIGNAL_BY_NAME                        = 0x84,
    WRITE_SIGNAL_BY_LIST_START                  = 0x8C,
    WRITE_SIGNAL_BY_LIST_CONTINUE               = 0x8D,
};

enum rdb_ext_functions{
    RESET_SYSTEM                                = 0x0101,
    DIAGNOSTICS_RESET                           = 0x0102,
    READ_DATE_AND_TIME                          = 0x0201,
    READ_DATE                                   = 0x0202,
    READ_TIME                                   = 0x0203,
    WRITE_DATE_AND_TIME                         = 0x0281,
    CHANGE_LOCAL_NODE_ADDR                      = 0x0400,
};
