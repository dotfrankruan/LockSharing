#!/usr/bin/env python3
from flask import Flask, request, jsonify
import ls_gnupg as gpg

"""Main entrance"""

app = Flask(__name__)

@app.route('/pks/add', methods=['POST'])
def pks_add():
    keytext = request.form.get('keytext')
    keyID = gpg.getkeyID(keytext)
    uids = gpg.getUIDs(keytext)
    algo = gpg.getAlgo(keytext)
    length = gpg.getLength(keytext)
    creationdate = gpg.getCreationDate(keytext)
    # pub:<keyid>:<algorithm>:<keylen>:<creationdate>:<expirationdate>:<flags>:<version>
    retvalue = "pub:{}:{}:{}:{}".format(keyID, uids, str(algo), str(length), str(creationdate))
    return retvalue, 202

if __name__ == "__main__":
    app.run(debug=True, port=11371)