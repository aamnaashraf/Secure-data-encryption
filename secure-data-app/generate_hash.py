import hashlib
print('MASTER_PASS_HASH = "' + hashlib.sha256('Hayazahra123!'.encode()).hexdigest() + '"')