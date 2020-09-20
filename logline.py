import csv
from datetime import datetime

import logline_enums

# this file implements the macro for V2 provided at
# https://support.symantec.com/us/en/article.tech100099.html

RECORD_DATA_HEADER = "Time,Event,Category,Logger,Computer,User,Virus,File,Wanted Action 1,Wanted Action 2,Real Action,Virus Type,Flags,Description,ScanID,New_Ext,Group ID,Event Data,VBin_ID,Virus ID,Quarantine Forward Status,Access,SND_Status,Compressed,Depth,Still Infected,Def Info,Def Sequence Number,Clean Info,Delete Info,Backup ID,Parent,GUID,Client Group,Address,Domain Name,NT Domain,MAC Address,Version,Remote Machine,Remote Machine IP,Action 1 Status,Action 2 Status,License Feature Name,License Feature Version,License Serial Number,License Fulfillment ID,License Start Date,License Expiration Date,License LifeCycle,License Seats Total,License Seats,Error Code,License Seats Delta,Status,Domain GUID,Log Session GUID,VBin Session ID,Login Domain,Event Data 2,Eraser Category ID,Dynamic Categoryset ID,Dynamic Subcategoryset ID,Display Name To Use,Reputation Disposition,Reputation Confidence,First Seen,Reputation Prevalence,Downloaded URL,Creator For Dropper,CIDS State,Behavior Risk Level,Detection Type,Acknowledge Text,VSIC State,Scan GUID,Scan Duration,Scan Start Time,TargetApp Type,Scan Command GUID"

def parse_datetime(datetime_str):
    year = 1970 + int(datetime_str[0:2], 16)
    month = int(datetime_str[2:4], 16) + 1
    day = int(datetime_str[4:6], 16)
    hour = int(datetime_str[6:8], 16)
    minute = int(datetime_str[8:10], 16)
    sec = int(datetime_str[10:12], 16)

    return datetime(year, month, day, hour, minute, sec)

def parse_flags(flag_val):
    flags = []

    if flag_val & 0x400000:
        flags.append("EB_ACCESS_DENIED")
    elif flag_val & 0x800000:
        flags.append("EB_NO_VDIALOG")
    elif flag_val & 0x1000000:
        flags.append("EB_LOG")
    elif flag_val & 0x2000000:
        flags.append("EB_REAL_CLIENT")
    elif flag_val & 0x4000000:
        flags.append("EB_ENDUSER_BLOCKED")
    elif flag_val & 0x8000000:
        flags.append("EB_AP_FILE_WIPED")
    elif flag_val & 0x10000000:
        flags.append("EB_PROCESS_KILLED")
    elif flag_val & 0x20000000:
        flags.append("EB_FROM_CLIENT")
    elif flag_val & 0x40000000:
        flags.append("EB_EXTRN_EVENT")
    
    if flag_val & 0x1FF:
        if flag_val & 0x1:
            flags.append("FA_SCANNING_MEMORY")
        elif flag_val & 0x2:
            flags.append("FA_SCANNING_BOOT_SECTOR")
        elif flag_val & 0x4:
            flags.append("FA_SCANNING_FILE")
        elif flag_val & 0x8:
            flags.append("FA_SCANNING_BEHAVIOR")
        elif flag_val & 0x10:
            flags.append("FA_SCANNING_CHECKSUM")
        elif flag_val & 0x20:
            flags.append("FA_WALKSCAN")
        elif flag_val & 0x40:
            flags.append("FA_RTSSCAN")
        elif flag_val & 0x80:
            flags.append("FA_CHECK_SCAN")
        elif flag_val & 0x100:
            flags.append("FA_CLEAN_SCAN")
    
    overlays = []
    if flag_val & 0x803FFE00:
        if flag_val & 0x200:
            overlays.append("N_OFFLINE")
        elif flag_val & 0x400:
            overlays.append("N_INFECTED")
        elif flag_val & 0x800:
            overlays.append("N_REPSEED_SCAN")
        elif flag_val & 0x1000:
            overlays.append("N_RTSNODE")
        elif flag_val & 0x2000:
            overlays.append("N_MAILNODE")
        elif flag_val & 0x4000:
            overlays.append("N_FILENODE")
        elif flag_val & 0x8000:
            overlays.append("N_COMPRESSED")
        elif flag_val & 0x10000:
            overlays.append("N_PASSTHROUGH")
        elif flag_val & 0x40000:
            overlays.append("N_DIRNODE")
        elif flag_val & 0x80000:
            overlays.append("N_ENDNODE")
        elif flag_val & 0x100000:
            overlays.append("N_MEMNODE")
        elif flag_val & 0x200000:
            overlays.append("N_ADMIN_REQUEST_REMEDIATION")
    
    out = " ".join(flags)

    if len(overlays):
        out += "EB_N_OVERLAYS ({})".format(" ".join(overlays))
    
    return out

key_enum_map = {
    "Event": logline_enums.event,
    "Category": logline_enums.category,
    "Logger": logline_enums.logger,
    "Wanted Action 1": logline_enums.action,
    "Wanted Action 2": logline_enums.action,
    "Real Action": logline_enums.action,
    "Virus Type": logline_enums.virus_type,
    "Dynamic Categoryset ID": logline_enums.dynamic_categoryset_id,
    "Display Name To Use": logline_enums.display_name,
    "Reputation Disposition": logline_enums.reputation_disposition,
    "Detection Type": logline_enums.detection_type,
    "TargetApp Type": logline_enums.targetapp_type
}

def parse_log_line(inp):
    reader = csv.DictReader([RECORD_DATA_HEADER, inp])
    out = {}
    
    row = reader.__next__()

    for key, value in row.items():
        if not value: continue
        
        if key in ["Time", "Scan Start Time"]:
            out[key] = parse_datetime(value)
        elif key in ["Computer", "User", "File"]:
            out[key] = value
        elif key == "Flags":
            out[key] = parse_flags(int(value))
        elif key in key_enum_map.keys():
            out[key] = key_enum_map[key].get(value, value)
        else:
            out[key] = value
    
    return out
