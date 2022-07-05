import json
import pandas as pd
import os
from apiSequence import all_api_count

file_list2 = []
dirs_positive_list = [""]
for root, dirs, files in os.walk(r'mal_reports/'):
    dirs[:] = [d for d in dirs if d in dirs_positive_list]
    for file in files:
        if file.endswith(".json"):
            file_list2.append(os.path.join(root, file))


file_list3 = []
dirs_positive_list = [""]
for root, dirs, files in os.walk(r'ben_reports/'):
    dirs[:] = [d for d in dirs if d in dirs_positive_list]
    for file in files:
        if file.endswith(".json"):
            file_list3.append(os.path.join(root, file))

Data = pd.DataFrame()



def check_empty(data):
    if data == "":
        return "0"
    return data

Features = [
    'Score',
    'ID',
    'Package',
    'Procmemory PID',
    'Url 1',
    'Url 2',
    'Url 3',
    'Target Category',
    'SHA1',
    'Name',
    'File Type',
    'SHA256',
    'File Url 1',
    'File Url 2',
    'File Url 3',
    'Size',
    'SHA512',
    'MD5',
    'Network Source',
    'Network Destination',
    'Signature Severity',
    'PDB Path',
    'PE Import 1',
    'PE Import 2',
    'PE Import 3',
    'BG Process Path 1',
    'BG Process Name 1',
    'BG Process Path 2',
    'BG Process Name 2',
    'BG Process Path 3',
    'BG Process Name 3',
    'Api Hit Count',
    'RegKey Read 1',
    'RegKey Read 2',
    'RegKey Read 3',
    'RegKey Read 4',
    'RegKey Read 5',
    'Malware/Legit'
]

Dataset = pd.DataFrame(columns=Features)


i = 1
def get_data(f, type):
    file = open(f, 'r') 
    data = file.read()
    try:
        data = json.loads(data)
    except:
        return 0
    
    score = ""

    id = ""

    package = ""

    procmemory_pid = ""

    proc_url_1 = ""

    proc_url_2 = ""

    proc_url_3 = ""


    target_category = ""

    sha1 = ""

    name = ""

    file_type = ""

    sha256 = ""

    file_url_1 = ""

    file_url_2 = ""

    file_url_3 = ""

    size = ""

    sha512 = ""

    md5 = ""

    network_src = ""

    network_dst = ""

    signature_severity = ""

    pdb_path = ""

    pe_import_1 = ""

    pe_import_2 = ""

    pe_import_3 = ""

    bg_process_path_1 = ""

    bg_process_name_1 = ""

    bg_process_path_2 = ""

    bg_process_name_2 = ""

    bg_process_path_3 = ""

    bg_process_name_3 = ""

    regkey_read_1 = ""

    regkey_read_2 = ""

    regkey_read_3 = ""

    regkey_read_4 = ""

    regkey_read_5 = ""

    api_hit_count = ""

    try:
        score = data['info']['score']
    except:
        pass

    try:
        id = data['info']['id']
    except:
        pass

    try:
        package = data['info']['package']
    except:
        pass

    try:
        procmemory_pid = data['procmemory'][0]['pid']
    except:
        pass

    try:
        proc_url_1 = data['procmemory'][0]['urls'][0]
    except:
        pass

    try:
        proc_url_2 = data['procmemory'][0]['urls'][1]
    except:
        pass

    try:
        proc_url_3 = data['procmemory'][0]['urls'][2]
    except:
        pass

    try:
        target_category = data['target']['category']
    except:
        pass

    try:
        sha1 = data['target']['file']['sha1']
    except:
        pass

    try:
        name = data['target']['file']['name']
    except:
        pass

    try:
        file_type = data['target']['file']['type']
    except:
        pass

    try:
        sha256 = data['target']['file']['sha256']
    except:
        pass

    try:
        file_url_1 = data['target']['file']['urls'][0]
    except:
        pass

    try:
        file_url_2 = data['target']['file']['urls'][1]
    except:
        pass

    try:
        file_url_3 = data['target']['file']['urls'][2]
    except:
        pass

    try:
        size = data['target']['file']['size']
    except:
        pass

    try:
        sha512 = data['target']['file']['sha512']
    except:
        pass

    try:
        md5 = data['target']['file']['md5']
    except:
        pass

    try:
        network_src = data['network']['udp'][0]['src']
    except:
        pass

    try:
        network_dst = data['network']['udp'][0]['dst']
    except:
        pass

    try:
        _severity = 0
        for x in data['signatures']:
            _severity += int(x['severity'])
        signature_severity = str(_severity)
    except:
        pass

    try:
        pdb_path = data['static']['pdb_path']
    except:
        pass

    try:
        pe_import_1 = data['static']['pe_imports'][0]['dll']
    except:
        pass

    try:
        pe_import_2 = data['static']['pe_imports'][1]['dll']
    except:
        pass

    try:
        pe_import_3 = data['static']['pe_imports'][2]['dll']
    except:
        pass

    try:
        bg_process_path_1 = data['behavior']['generic'][0]['process_path']
    except:
        pass

    try:
        bg_process_name_1 = data['behavior']['generic'][0]['process_name']
    except:
        pass

    try:
        bg_process_path_2 = data['behavior']['generic'][1]['process_path']
    except:
        pass

    try:
        bg_process_name_2 = data['behavior']['generic'][1]['process_name']
    except:
        pass

    try:
        bg_process_path_3 = data['behavior']['generic'][2]['process_path']
    except:
        pass

    try:
        bg_process_name_3 = data['behavior']['generic'][2]['process_name']
    except:
        pass

    try:
        api_hit_count = all_api_count(data['behavior']['apistats'])
    except:
        pass

    try:
        regkey_read_1 = data['behavior']['summary']['regkey_read'][0]
    except:
        pass

    try:
        regkey_read_2 = data['behavior']['summary']['regkey_read'][1]
    except:
        pass

    try:
        regkey_read_3 = data['behavior']['summary']['regkey_read'][2]
    except:
        pass

    try:
        regkey_read_4 = data['behavior']['summary']['regkey_read'][3]
    except:
        pass

    try:
        regkey_read_5 = data['behavior']['summary']['regkey_read'][4]
    except:
        pass

    score = check_empty(score)

    id = check_empty(id)

    package = check_empty(package)

    procmemory_pid = check_empty(procmemory_pid)

    proc_url_1 = check_empty(proc_url_1)

    proc_url_2 = check_empty(proc_url_2)

    proc_url_3 = check_empty(proc_url_3)

    target_category = check_empty(target_category)

    sha1 = check_empty(sha1)

    name = check_empty(name)

    file_type = check_empty(file_type)

    sha256 = check_empty(sha256)

    file_url_1 = check_empty(file_url_1)

    file_url_2 = check_empty(file_url_2)

    file_url_3 = check_empty(file_url_3)

    size = check_empty(size)

    sha512 = check_empty(sha512)

    md5 = check_empty(md5)

    network_src = check_empty(network_src)

    network_dst = check_empty(network_dst)
    
    signature_severity = check_empty(signature_severity)

    pdb_path = check_empty(pdb_path)

    pe_import_1 = check_empty(pe_import_1)

    pe_import_2 = check_empty(pe_import_2)

    pe_import_3 = check_empty(pe_import_3)

    bg_process_path_1 = check_empty(bg_process_path_1)

    bg_process_name_1 = check_empty(bg_process_name_1)

    bg_process_path_2 = check_empty(bg_process_path_2)

    bg_process_name_2 = check_empty(bg_process_name_2)

    bg_process_path_3 = check_empty(bg_process_path_3)

    bg_process_name_3 = check_empty(bg_process_name_3)

    api_hit_count = check_empty(api_hit_count)

    regkey_read_1 = check_empty(regkey_read_1)

    regkey_read_2 = check_empty(regkey_read_2)

    regkey_read_3 = check_empty(regkey_read_3)

    regkey_read_4 = check_empty(regkey_read_4)

    regkey_read_5 = check_empty(regkey_read_5)

    Dataset.loc[i] = [
        score,
        id,
        package,
        procmemory_pid,
        proc_url_1,
        proc_url_2,
        proc_url_3,
        target_category,
        sha1,
        name,
        file_type,
        sha256,
        file_url_1,
        file_url_2,
        file_url_3,
        size,
        sha512,
        md5,
        network_src,
        network_dst,
        signature_severity,
        pdb_path,
        pe_import_1,
        pe_import_2,
        pe_import_3,
        bg_process_path_1,
        bg_process_name_1,
        bg_process_path_2,
        bg_process_name_2,
        bg_process_path_3,
        bg_process_name_3,
        api_hit_count,
        regkey_read_1,
        regkey_read_2,
        regkey_read_3,
        regkey_read_4,
        regkey_read_5,
        type
    ]
    file.close()
    return 1

for f in file_list2:
    i += get_data(f, "1")


for f in file_list3:
    i += get_data(f, "0")


    
Dataset.to_csv('cuckoo-parsed.csv', escapechar='\\', index=False)
    

