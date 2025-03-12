import csv
import requests
import time
import hashlib

API_KEY = ''  # Replace with your VirusTotal API Key
API_URL = 'https://www.virustotal.com/api/v3/files/'

headers = {
    'x-apikey': API_KEY
}

def identify_hash_algorithm(file_hash):
    if len(file_hash) == 32:
        return 'MD5'
    elif len(file_hash) == 40:
        return 'SHA1'
    elif len(file_hash) == 64:
        return 'SHA256'
    else:
        return 'Unknown'

def get_hash_info(file_hash):
    response = requests.get(API_URL + file_hash, headers=headers)
    if response.status_code == 200:
        data = response.json()['data']['attributes']
        return {
            'detection_count': f"{data['last_analysis_stats'].get('malicious', 0)}/{sum(data['last_analysis_stats'].values())}",
            'md5': data.get('md5', 'N/A'),
            'sha1': data.get('sha1', 'N/A'),
            'sha256': data.get('sha256', 'N/A'),
            'file_type': data.get('type_description', 'N/A'),
            'magic': data.get('magic', 'N/A'),
            'creation_time': data.get('creation_date', 'N/A'),
            'signature_date': data.get('signature_date', 'N/A'),
            'first_seen': data.get('first_seen_itw_date', 'N/A'),
            'first_submission': data.get('first_submission_date', 'N/A'),
            'last_submission': data.get('last_submission_date', 'N/A'),
            'last_analysis': data.get('last_analysis_date', 'N/A'),
            'top_names': data.get('names', ['null', 'null', 'null'])[:3],
            'verdict': 'Malicious' if data['last_analysis_stats'].get('malicious', 0) > 0 else 'Benign'
        }
    else:
        return {
            'detection_count': 'N/A', 'md5': 'N/A', 'sha1': 'N/A', 'sha256': 'N/A',
            'file_type': 'N/A', 'magic': 'N/A', 'creation_time': 'N/A', 'signature_date': 'N/A',
            'first_seen': 'N/A', 'first_submission': 'N/A', 'last_submission': 'N/A',
            'last_analysis': 'N/A', 'top_names': ['null', 'null', 'null'], 'verdict': 'N/A'
        }

def format_date(timestamp):
    if isinstance(timestamp, int):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp))
    return 'N/A'

with open('part2.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    hashes = [row[0] for row in reader if row]

output_data = [['ID', 'Hashes', 'Algorithms', 'VirusTotal', '', '', '', 'Basic Properties', '', '', '', 'History', '', '', '', '', 'Names (top 3 names only, null if < 3 names)', '', '', ''],
               ['', '', '', 'Detection (sample: 4/69)', 'Hash-MD5', 'Hash-SHA1', 'Hash-SHA256', 'File Type', 'Magic', 'Creation Time', 'Signature Date', 'First Seen in the Wild', 'First Submission', 'Last Submission', 'Last Analysis', 'Name1', 'Name2', 'Name3', 'Verdict (Benign or Malicious)']]

for idx, file_hash in enumerate(hashes, start=1):
    result = get_hash_info(file_hash)
    top_names = result['top_names'] + ['null'] * (3 - len(result['top_names']))  # Ensure 3 name slots
    output_data.append([
        idx,
        file_hash,
        identify_hash_algorithm(file_hash),
        result['detection_count'],
        result['md5'],
        result['sha1'],
        result['sha256'],
        result['file_type'],
        result['magic'],
        format_date(result['creation_time']),
        format_date(result['signature_date']),
        format_date(result['first_seen']),
        format_date(result['first_submission']),
        format_date(result['last_submission']),
        format_date(result['last_analysis']),
        top_names[0],
        top_names[1],
        top_names[2],
        result['verdict']
    ])
    time.sleep(15)  # Respect rate limits for VirusTotal API

with open('output_info.csv', 'w', newline='', encoding='utf-8-sig') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(output_data)

print("Data collection complete. Output written to 'out2.csv'.")
