#script to submit sample and get report
from virustotal_python import Virustotal
import sys
import json

NUMBER_OF_SAMPLES = 10

main_api_key = "63aa15b0de37b2f255661326aa96dbb73d7731c5d55500b2c6e75e5c4f036e4e"
vtotal = Virustotal(API_KEY = main_api_key, API_VERSION = "v3")

def virustotal(FILE_ID):
    response_virustotal = vtotal.request(f"files/{FILE_ID}/behaviours")
    json_report = str('virustotal/virustotal-reports/' + FILE_ID + '.json')
    with(open(json_report, 'w+')) as j:
        json.dump(response_virustotal.data, j)

hash_file = open('virustotal/sha256_dump.txt', 'r')
get_hashes = hash_file.readlines()

count = 0
for hash in get_hashes:
    virustotal(hash.strip())
    count += 1
    if count == NUMBER_OF_SAMPLES:
        sys.exit()
        
