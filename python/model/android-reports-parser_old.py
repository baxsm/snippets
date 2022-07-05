import json
from tabnanny import check
from unittest import signals
import pandas as pd
import os
from os import walk

from sklearn.utils import check_array

malware_list = []

# 0 - 11 , 1 so legit and malware reports are somewhat balanced
for i in range(1):
    dirs_positive_list = ["" + str(i) + "/"]
    for root, dirs, files in os.walk(r'malware_reports/' + str(i) + '/'):
        dirs[:] = [d for d in dirs if d in dirs_positive_list]
        for file in files:
            if file.endswith(".json"):
                malware_list.append(os.path.join(root, file))

legit_list = []
dirs_positive_list = [""]
for root, dirs, files in os.walk(r'legit_reports/'):
    dirs[:] = [d for d in dirs if d in dirs_positive_list]
    for file in files:
        if file.endswith(".json"):
            legit_list.append(os.path.join(root, file))


Data = pd.DataFrame()

Features = [
    'id',
    'Permission Requested 1',
    'Permission Requested 2',
    'Permission Requested 3',
    'Permission Checked 1',
    'Permission Checked 2',
    'Permission Checked 3',
    'Activities Started',
    'System Property Lookup',
    'Files Written 1',
    'Files Written 2',
    'Files Written 3',
    'Files Deleted 1',
    'Files Deleted 2',
    'Files Deleted 3',
    'Files Opened 1',
    'Files Opened 2',
    'Files Opened 3',
    'DNS Lookup',
    'Signals Hooked',
    'Signals Observed',
    'Invokes 1',
    'Invokes 2',
    'Invokes 3',
    'Services Started',
    'Malware/Legit'
]

Dataset = pd.DataFrame(columns=Features)


def parse_child(data):
    return str(data)

def check_empty(data):
    if data == "":
        return "0"
    return data


i = 1
def get_data(FILE_NAME, type):
    file = open(FILE_NAME, 'r')
    data = file.read()
    data = json.loads(data)

    id = ""
    permission_requested_1 = ""
    permission_requested_2 = ""
    permission_requested_3 = ""
    permission_checked_1 = ""
    permission_checked_2 = ""
    permission_checked_3 = ""
    activities_started = ""
    system_property_lookups = ""
    files_written_1 = ""
    files_written_2 = ""
    files_written_3 = ""
    dns_lookup = ""
    signals_hooked = ""
    files_deleted_1 = ""
    files_deleted_2 = ""
    files_deleted_3 = ""
    signals_observed = ""
    files_opened_1 = ""
    files_opened_2 = ""
    files_opened_3 = ""
    invokes_1 = ""
    invokes_2 = ""
    invokes_3 = ""
    services_started = ""
 
    try:
        _data = data['data']
    except:
        try:
            _data = data
        except:
            pass

    for key in _data:

        attributes = key['attributes']
        
        try:
            _id = key['id'].split('_')
            id = _id[0]
        except:
            pass

        try:
            permission_requested_1 = attributes['permissions_requested'][0].split(':')[0]
        except:
            pass

        try:
            permission_requested_2 = attributes['permissions_requested'][1].split(':')[0]
        except:
            pass

        try:
            permission_requested_3 = attributes['permissions_requested'][2].split(':')[0]
        except:
            pass

        try:
            permission_checked_1 = attributes['permissions_checked'][0]['permission']
        except:
            pass

        try:
            permission_checked_2 = attributes['permissions_checked'][1]['permission']
        except:
            pass

        try:
            permission_checked_3 = attributes['permissions_checked'][2]['permission']
        except:
            pass

        try:
            activities_started = attributes['activities_started'][0]
        except:
            pass

        try:
            system_property_lookups = attributes['system_property_lookups'][0]
        except:
            pass

        try:
            files_written_1 = attributes['files_written'][0]
        except:
            pass
        try:
            files_written_2 = attributes['files_written'][1]
        except:
            pass
        try:
            files_written_3 = attributes['files_written'][2]
        except:
            pass

        try:
            dns_lookup = attributes['dns_lookups'][0]['hostname']
        except:
            pass

        try:
            signals_hooked = attributes['signals_hooked'][0]
        except:
            pass

        try:
            files_deleted_1 = attributes['files_deleted'][0]
        except:
            pass
        try:
            files_deleted_2 = attributes['files_deleted'][1]
        except:
            pass
        try:
            files_deleted_3 = attributes['files_deleted'][2]
        except:
            pass

        try:
            signals_observed = attributes['signals_observed'][0]
        except:
            pass

        try:
            files_opened_1 = attributes['files_opened'][0]
        except:
            pass
        try:
            files_opened_2 = attributes['files_opened'][1]
        except:
            pass
        try:
            files_opened_3 = attributes['files_opened'][2]
        except:
            pass

        try:
            invokes_1 = attributes['invokes'][0]
        except:
            pass
        try:
            invokes_2 = attributes['invokes'][1]
        except:
            pass
        try:
            invokes_3 = attributes['invokes'][2]
        except:
            pass

        try:
            services_started = attributes['services_started'][0]
        except:
            pass



    id = check_empty(id)

    permission_requested_1 = check_empty(permission_requested_1)

    permission_requested_2 = check_empty(permission_requested_2)

    permission_requested_3 = check_empty(permission_requested_3)

    permission_checked_1 = check_empty(permission_checked_1)

    permission_checked_2 = check_empty(permission_checked_2)

    permission_checked_3 = check_empty(permission_checked_3)

    activities_started = check_empty(activities_started)

    system_property_lookups = check_empty(system_property_lookups)

    files_written_1 = check_empty(files_written_1)

    files_written_2 = check_empty(files_written_2)

    files_written_3 = check_empty(files_written_3)

    dns_lookup = check_empty(dns_lookup)

    signals_hooked = check_empty(signals_hooked)

    files_deleted_1 = check_empty(files_deleted_1)

    files_deleted_2 = check_empty(files_deleted_2)

    files_deleted_3 = check_empty(files_deleted_3)

    signals_observed = check_empty(signals_observed)

    files_opened_1 = check_empty(files_opened_1)

    files_opened_2 = check_empty(files_opened_2)

    files_opened_3 = check_empty(files_opened_3)

    invokes_1 = check_empty(invokes_1)

    invokes_2 = check_empty(invokes_2)

    invokes_3 = check_empty(invokes_3)

    services_started = check_empty(services_started)


    if id == "0":
        file.close()
        return 0
   
    Dataset.loc[i] = [
        id,
        permission_requested_1,
        permission_requested_2,
        permission_requested_3,
        permission_checked_1,
        permission_checked_2,
        permission_checked_3,
        activities_started,
        system_property_lookups,
        files_written_1,
        files_written_2,
        files_written_3,
        files_deleted_1,
        files_deleted_2,
        files_deleted_3,
        files_opened_1,
        files_opened_2,
        files_opened_3,
        dns_lookup,
        signals_hooked,
        signals_observed,
        invokes_1,
        invokes_2,
        invokes_3,
        services_started,
        type
    ]

    file.close()

    return 1

for file in malware_list:
    i += get_data(file, "1")

for file in legit_list:
    i += get_data(file, "0")


Dataset.to_csv('android-report.csv', index=False)
