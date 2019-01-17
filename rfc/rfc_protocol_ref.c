#include "rfc_protocol_ref.h"

char * 
get_protocol_name (int proto_num)
{
    switch (proto_num)
    {
        case 0 : 
            return "Reserved";
        case 1 :
            return "ICMP";
        case 2 :
            return "Unassigned";
        case 3 :
            return "Gateway-to-Gateway";
        case 4 :
            return "CMCC Gateway Monitoring Message";
        case 5 :
            return "ST";
        case 6 :
            return "TCP";
        case 7 :
            return "UCL";
        case 8 :
            return "Unassigned";
        case 9 :
            return "Secure";
        case 10 :
            return "BBN RCC Monitoring";
        case 11 :
            return "NVP";
        case 12 :
            return "PUP";
        case 13 :
            return "Pluribus";
        case 14 :
            return "Telenet";
        case 15 :
            return "XNET";
        case 16 :
            return "Chaos";
        case 17 :
            return "User Datagram";
        case 18 :
            return "Multiplexing";
        case 19 :
            return "DCN";
        case 20 :
            return "TAC Monitoring";
        case 63 :
            return "any local network";
        case 64 :
            return "SATNET and Backroom EXPAK";
        case 65 :
            return "MIT Subnet Support";
        case 69 :
            return "SATNET Monitoring";
        case 71 :
            return "Internet Packet Core Utility";
        case 76 :
            return "Backroom SATNET Monitoring";
        case 78 :
            return "WIDEBAND Monitoring";
        case 79 :
            return "WIDEBAND EXPAK";
        case 255 :
            return "Reserved";
        default :
            return "Unassigned";
    }
}