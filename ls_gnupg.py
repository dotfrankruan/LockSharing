import gnupg

def getkeyID(keytext):
    gpg = gnupg.GPG()
    gpg_key_content = keytext
    import_result = gpg.import_keys(gpg_key_content)
    keyid = gpg.list_keys(keys=[import_result.results[0]['fingerprint']])[0]['keyid']
    return keyid

def getUIDs(keytext):
    gpg = gnupg.GPG()
    gpg_key_content = keytext
    return gpg.list_keys(keys=[gpg.import_keys(gpg_key_content).results[0]['fingerprint']])[0]['uids']

def getAlgo(keytext):
    gpg = gnupg.GPG()
    gpg_key_content = keytext
    import_result = gpg.import_keys(gpg_key_content)
    keyid = gpg.list_keys(keys=[import_result.results[0]['fingerprint']])[0]['algo']

def getLength(keytext):
    gpg = gnupg.GPG()
    gpg_key_content = keytext
    import_result = gpg.import_keys(gpg_key_content)
    keyid = gpg.list_keys(keys=[import_result.results[0]['fingerprint']])[0]['length']

def getCreationDate(keytext):
    gpg = gnupg.GPG()
    gpg_key_content = keytext
    import_result = gpg.import_keys(gpg_key_content)
    keyid = gpg.list_keys(keys=[import_result.results[0]['fingerprint']])[0]['date']

    
