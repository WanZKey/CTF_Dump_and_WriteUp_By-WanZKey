#!/usr/bin/env python3
import json
import sys
try:
    from evtx import PyEvtxParser
except ImportError:
    print("[!] Install library dulu bro: pip install evtx")
    sys.exit(1)

def solve():
    file_path = "Security.evtx"
    print("[*] Parsing EVTX file, please wait...")
    
    try:
        parser = PyEvtxParser(file_path)
        for record in parser.records_json():
            record_str = record['data']
            
            # Hardcode
            if "4720" in record_str and "daya.aili" in record_str:
                data = json.loads(record_str)
                system = data.get('Event', {}).get('System', {})
                event_data = data.get('Event', {}).get('EventData', {})
                
                event_id = system.get('EventID')
                
                # Validasi ulang dari JSON parsed data
                if event_id == 4720:
                    print("\n[*] Match Found!")
                    
                    subject_domain = event_data.get('SubjectDomainName', '')
                    subject_user = event_data.get('SubjectUserName', '')
                    target_user = event_data.get('TargetUserName', '')
                    
                    print(f"[-] Target User Created: {target_user}")
                    print(f"[-] Created By Domain  : {subject_domain}")
                    print(f"[-] Created By User    : {subject_user}")
                    print(f"[-] Event ID           : {event_id}")
                    
                    # Build the flag
                    flag_domain = subject_domain.lower()
                    flag_user = subject_user.lower()
                    
                    flag = f"LKS{{{flag_domain}\\{flag_user}_{event_id}}}"
                    print(f"\n[*] Flag: {flag}")
                    return
                    
        print("[-] Target tidak ditemukan di dalam log.")
        
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == '__main__':
    solve()
