import vt
import os
import time
import json
import pefile

API_KEY = '0196010fd366852a1e939a0fe72a0ffdb96fcc08683a2b99755afbf864aeb62d'
folder_path = 'C:\\Users\\DELL\\Desktop\\BARBIER_PIERRE_V2\\src\\test'

def is_signed(file_path):
        pe = pefile.PE(file_path)
        for section in pe.sections :
            characteristics = getattr(section, 'Characteristics')
            if characteristics & 0x00000020 > 0 or characteristics & 0x20000000 > 0:
                return True
            return False

def scan_file(file_path):  
    with open(file_path, 'rb') as f:
        client = vt.Client(API_KEY)
        analysis = client.scan_file(f, wait_for_completion=True)
        analysis = client.get_object("/analyses/{}", analysis.id)
        
        if os.path.isfile(file_path) and os.access(file_path, os.X_OK) :
            if is_signed(file_path) :
                print("cette application posséde un certificat.")
            else :
                print("Cette application ne posséde pas de certificat.")
        
        sorted_results = json.dumps(analysis.results, sort_keys=True, indent=4)
        print(sorted_results)
        return analysis

for file_name in os.listdir(folder_path):
    file_path = os.path.join(folder_path, file_name)
    if os.path.isfile(file_path):
        print(f"Scanning {file_name}")
        analysis = scan_file(file_path)
        time.sleep(15)
