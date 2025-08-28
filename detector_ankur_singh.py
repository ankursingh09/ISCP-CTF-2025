import re
import csv
import json
import sys

# --------- Utility Masking Functions ---------------

def mask_phone(phone):
    v = str(phone)
    # Mask as 98XXXXXX10 (first 2 and last 2 digits only)
    return v[:2] + 'XXXXXX' + v[-2:]

def mask_aadhar(aadhar):
    v = str(aadhar)
    # Mask as 12XXXXXXXX34 (first 2 and last 2 digits only)
    return v[:2] + 'XXXXXXXX' + v[-2:]

def mask_passport(passport):
    # Mask as PXXXXXXX, only first character (the letter) remains
    v = str(passport)
    return v[0] + 'XXXXXXX' if len(v) == 8 else '[REDACTED_PASSPORT]'

def mask_upi(upi):
    # Mask everything before @ e.g. user123@paytm -> uXXX@paytm
    return re.sub(r'(.)(?:.*)(@.+)', lambda m: m.group(1) + 'XXX' + m.group(2), str(upi))

def mask_email(email):
    # Mask as joXXX@gmail.com (keep first 2 chars & domain)
    m = re.match(r'^([^@]{2})([^@]*)(@.+)$', email)
    if m:
        return m.group(1) + 'XXX' + m.group(3)
    else:
        return '[REDACTED_EMAIL]'

def mask_name(name):
    # Mask as JXXX SXXXX for two parts, else [REDACTED_NAME]
    parts = name.split()
    masked = []
    for part in parts:
        masked.append(part[0] + 'XXX' if len(part) > 1 else part)
    return ' '.join(masked)

def mask_address(address):
    return '[REDACTED_ADDRESS]'

def mask_device_id(device_id):
    return '[REDACTED_DEVICEID]'

def mask_ip(ip_addr):
    return '[REDACTED_IP]'

# ---------- PII Detection Functions ---------------

def is_phone(val):
    return isinstance(val, str) and re.fullmatch(r'\d{10}', val)

def is_aadhar(val):
    return isinstance(val, str) and re.fullmatch(r'\d{12}', val)

def is_passport(val):
    # Typical Indian format: one capital letter + 7 digits
    return isinstance(val, str) and re.fullmatch(r'[A-Z][0-9]{7}', val)

def is_upi(val):
    # UPI always contains an @
    return isinstance(val, str) and '@' in val

def is_email(val):
    # Simple email regex
    return isinstance(val, str) and re.fullmatch(r'[^@]+@[^@]+\.[^@]+', val)

def is_address(val):
    # Address heuristic: at least one comma, digit, or common address word
    return isinstance(val, str) and (
        ',' in val or 
        bool(re.search(r'\d', val)) or
        any(w in val.lower() for w in ['road', 'street', 'avenue', 'lane', 'block', 'sector'])
    )

def is_ip(val):
    return isinstance(val, str) and re.fullmatch(
        r'((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.|$)){4}', val + '.'
    )

def is_device_id(val):
    return isinstance(val, str) and (val.lower().startswith('dev') or val.lower().startswith('mob') or val.lower().startswith('tab') or len(val) >= 6)

def is_name(val):
    # Full name = must be 2+ words, all alpha (may allow for some Indian variations)
    return isinstance(val, str) and len(val.strip().split()) >= 2

# ----------- Main Row Processing ------------------

def detect_standalone_pii(js):
    """ Standalone PII: phone, aadhar, passport, upi_id """
    redacted = {}
    found = False
    if 'phone' in js and is_phone(js['phone']):
        redacted['phone'] = mask_phone(js['phone'])
        found = True
    if 'aadhar' in js and is_aadhar(js['aadhar']):
        redacted['aadhar'] = mask_aadhar(js['aadhar'])
        found = True
    if 'passport' in js and is_passport(js['passport']):
        redacted['passport'] = mask_passport(js['passport'])
        found = True
    if 'upi_id' in js and is_upi(js['upi_id']):
        redacted['upi_id'] = mask_upi(js['upi_id'])
        found = True
    return found, redacted

def detect_combinatorial_pii(js):
    """
    Combinatorial PII becomes PII if two or more exist:
    Candidates: name, email, address, device_id, ip_address
    """
    keys = []
    if 'name' in js and is_name(js['name']): keys.append('name')
    if 'email' in js and is_email(js['email']): keys.append('email')
    if 'address' in js and is_address(js['address']): keys.append('address')
    if 'device_id' in js and is_device_id(js['device_id']): keys.append('device_id')
    if 'ip_address' in js and is_ip(js['ip_address']): keys.append('ip_address')
    # At least two must be present
    if len(keys) >= 2:
        redacted = {}
        for k in keys:
            v = js[k]
            if k == 'name':
                redacted[k] = mask_name(v)
            elif k == 'email':
                redacted[k] = mask_email(v)
            elif k == 'address':
                redacted[k] = mask_address(v)
            elif k == 'device_id':
                redacted[k] = mask_device_id(v)
            elif k == 'ip_address':
                redacted[k] = mask_ip(v)
        return True, redacted
    return False, {}

# ----------- Process all rows from CSV ------------

def redact_obj(data_json):
    js = json.loads(data_json)
    output_js = dict(js)
    is_pii = False
    # Standalone
    st_pii, st_redacted = detect_standalone_pii(js)
    if st_pii:
        is_pii = True
        output_js.update(st_redacted)
    # Combinatorial
    comb_pii, comb_redacted = detect_combinatorial_pii(js)
    if comb_pii:
        is_pii = True
        output_js.update(comb_redacted)
    return output_js, is_pii

def main():
    if len(sys.argv) < 2:
        print('Usage: python3 detector_ankur_singh.py iscp_pii_dataset.csv')
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = 'redacted_output_ankur_singh.csv'

    with open(input_file, newline='', encoding='utf-8') as fin, \
         open(output_file, 'w', newline='', encoding='utf-8') as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
        writer.writeheader()
        for row in reader:
            recid = row['record_id']
            data_json = row['data_json']
            try:
                redacted_obj, is_pii = redact_obj(data_json)
                writer.writerow({
                    'record_id': recid,
                    'redacted_data_json': json.dumps(redacted_obj, ensure_ascii=False),
                    'is_pii': str(is_pii)
                })
            except Exception as e:
                writer.writerow({'record_id': recid, 'redacted_data_json': '{}', 'is_pii': 'False'})

if __name__ == '__main__':
    main()
