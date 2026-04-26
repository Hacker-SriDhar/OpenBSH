import re, ast, sys

PASS_S = '[PASS]'
FAIL_S = '[FAIL]'
results = []

def check(label, ok, detail=''):
    status = PASS_S if ok else FAIL_S
    msg = '  {}  {}'.format(status, label)
    if detail:
        msg += '  ({})'.format(detail)
    results.append((ok, msg))
    print(msg)

def read(path):
    return open(path, encoding='utf-8', errors='replace').read()

ROOT   = r'c:\Users\ELCOT\Downloads\OpenBSH server'
CLIENT = ROOT + r'\Client'
LINUX  = ROOT + r'\linux'

files = {
    'win_srv_svc'  : ROOT   + r'\bsh_server_service.py',
    'win_srv_proto': ROOT   + r'\bsh_protocol.py',
    'win_srv_crypt': ROOT   + r'\bsh_crypto.py',
    'lnx_srv_svc'  : LINUX  + r'\bsh_server_service.py',
    'lnx_srv_proto': LINUX  + r'\bsh_protocol.py',
    'lnx_srv_crypt': LINUX  + r'\bsh_crypto.py',
    'cli_proto'    : CLIENT + r'\bsh_protocol.py',
    'cli_crypt'    : CLIENT + r'\bsh_crypto.py',
    'cli_win'      : CLIENT + r'\bsh_client_windows.py',
    'cli_lnx'      : CLIENT + r'\bsh_client_linux.py',
}

src = {k: read(v) for k, v in files.items()}

print()
print('=' * 62)
print('  BSH FULL PROTOCOL SYNC VERIFICATION')
print('=' * 62)

# 1. Syntax
print('\n## 1. SYNTAX — all files valid Python')
for key, path in files.items():
    try:
        ast.parse(src[key])
        check(key, True, 'valid Python')
    except SyntaxError as e:
        check(key, False, str(e))

# 2. MessageType values
print('\n## 2. MessageType VALUES — 3 protocol files identical')
def get_types(text):
    return dict(re.findall(r'(MSG_\w+)\s*=\s*(0x[0-9A-Fa-f]+)', text))

ref = get_types(src['win_srv_proto'])
lnx = get_types(src['lnx_srv_proto'])
cli = get_types(src['cli_proto'])
check('Win-Server vs Linux-Server MessageType', ref == lnx,
      '{} values'.format(len(ref)) if ref == lnx else 'MISMATCH')
check('Win-Server vs Client MessageType', ref == cli,
      '{} values'.format(len(ref)) if ref == cli else 'MISMATCH')
print('  Known types:', sorted(ref.keys()))

# 3. SOF byte
print('\n## 3. SOF BYTE — 0xAA in all protocol files')
for key in ('win_srv_proto', 'lnx_srv_proto', 'cli_proto'):
    check('SOF=0xAA in ' + key, 'SOF = 0xAA' in src[key])

# 4. Checksum method name
print('\n## 4. CHECKSUM — _checksum not calculate_checksum')
for key in ('win_srv_proto', 'lnx_srv_proto', 'cli_proto'):
    has_new = 'def _checksum' in src[key]
    has_old = 'def calculate_checksum' in src[key]
    check('_checksum in ' + key, has_new)
    check('No calculate_checksum in ' + key, not has_old,
          'LEGACY PRESENT' if has_old else 'clean')

# 5. AES-GCM format
print('\n## 5. AES-256-GCM — IV[:12] + ct + tag[-16:]')
for key in ('win_srv_crypt', 'lnx_srv_crypt', 'cli_crypt'):
    iv  = 'encrypted[:12]'  in src[key]
    tag = 'encrypted[-16:]' in src[key]
    check('AES-GCM wire format ' + key, iv and tag,
          'ok' if (iv and tag) else 'iv={} tag={}'.format(iv, tag))

# 6. Bug 1 — server _recv_exact re-raises socket.timeout
print('\n## 6. BUG 1 — server _recv_exact re-raises socket.timeout')
for key in ('win_srv_svc', 'lnx_srv_svc'):
    m = re.search(r'def _recv_exact.*?(?=\ndef )', src[key], re.DOTALL)
    fn = m.group() if m else ''
    ok = 'except socket.timeout:' in fn and 'raise' in fn
    check('socket.timeout re-raised in ' + key + '._recv_exact', ok)

# 7. Bug 1 chain — start_shell_session has catch+continue
print('\n## 7. BUG 1 CHAIN — start_shell_session catches timeout with continue')
for key in ('win_srv_svc', 'lnx_srv_svc'):
    m = re.search(r'def start_shell_session.*?(?=\ndef )', src[key], re.DOTALL)
    fn = m.group() if m else ''
    ok = 'except socket.timeout:' in fn and 'continue' in fn
    check('except socket.timeout: continue in ' + key, ok)

# 8. Bug 3 — no dead auth messages in client protocol
print('\n## 8. BUG 3 — client protocol: no dead auth messages 0x04-0x06')
dead = ['MSG_AUTH_REQUEST', 'MSG_AUTH_CHALLENGE', 'MSG_AUTH_RESPONSE']
for msg in dead:
    present = msg + ' ' in src['cli_proto'] and '= 0x0' in src['cli_proto']
    # more precise: find actual enum assignment
    found = bool(re.search(msg + r'\s*=\s*0x0[456]', src['cli_proto']))
    check('No dead enum ' + msg + ' in cli_proto', not found,
          'FOUND!' if found else 'clean')

# 9. Bug 4 — Windows client PTY echo suppression
print('\n## 9. BUG 4 — Windows client PTY echo suppression')
check('_pty_server flag in cli_win',
      '_pty_server = self._server_os.lower()' in src['cli_win'])
check('if not _pty_server: guard on local echo',
      'if not _pty_server:' in src['cli_win'])
check('_server_os stored from MSG_HELLO in cli_win',
      "self._server_os   = hello_data.get('os'" in src['cli_win'] or
      "self._server_os = hello_data.get('os'" in src['cli_win'])

# 10. Bug 5 — correct SDP UUID
print('\n## 10. BUG 5 — Correct SDP UUID')
check('Correct UUID 0xB5E7DA7A in win client',
      '0xB5E7DA7A' in src['cli_win'])
check('Correct UUID 0x0B53 in win client',
      '0x0B53' in src['cli_win'])
check('Wrong UUID 0xBEA7DA7A absent from win client',
      '0xBEA7DA7A' not in src['cli_win'])
check('Correct UUID B5E7DA7A-0B53 in linux client',
      'B5E7DA7A-0B53' in src['cli_lnx'])

# 11. Bug 6 — Windows server handles MSG_WINDOW_SIZE
print('\n## 11. BUG 6 — Windows server handles MSG_WINDOW_SIZE')
m = re.search(r'def start_shell_session.*?(?=\ndef )', src['win_srv_svc'], re.DOTALL)
fn = m.group() if m else ''
check('MSG_WINDOW_SIZE in win_srv_svc.start_shell_session',
      'MSG_WINDOW_SIZE' in fn or 'MSG_WINDOW_RESIZE' in fn)

# 12. Bug 7 — Spanish log fixed
print('\n## 12. BUG 7 — Spanish log removed from Linux server')
check('Spanish log absent', 'usando shell impersonado' not in src['lnx_srv_svc'],
      'STILL PRESENT' if 'usando shell impersonado' in src['lnx_srv_svc'] else 'clean')
check('English log present', 'spawning impersonated shell' in src['lnx_srv_svc'])

# 13. Bug 8 — Linux client keepalive 0.5s
print('\n## 13. BUG 8 — Linux client keepalive every 0.5s')
check('No old 10x counter', '_ka_counter' not in src['cli_lnx'])
m = re.search(r'def keepalive_loop.*?(?=\ndef |\Z)', src['cli_lnx'], re.DOTALL)
fn = m.group() if m else ''
check('keepalive_loop waits 0.5s', 'wait(0.5)' in fn)

# 14. Client _recv_exact re-raises socket.timeout
print('\n## 14. CLIENT _recv_exact — socket.timeout re-raised')
for key in ('cli_win', 'cli_lnx'):
    m = re.search(r'def _recv_exact.*?(?=\ndef |\Z)', src[key], re.DOTALL)
    fn = m.group() if m else ''
    ok = 'except socket.timeout:' in fn and 'raise' in fn
    check('socket.timeout re-raised in ' + key, ok)

# 15. Auth flow ordering
print('\n## 15. AUTH FLOW — packet sequence')
lnx = src['lnx_srv_svc']
hello_pos  = lnx.index('create_hello_packet')
recv_pos   = lnx.index('receive_packet()')
check('Linux server sends HELLO before receiving client HELLO',
      hello_pos < recv_pos)

for key in ('win_srv_svc', 'lnx_srv_svc'):
    check(key + ' sends session_key in MSG_AUTH_SUCCESS',
          "session_key" in src[key] and "MSG_AUTH_SUCCESS" in src[key])

for key in ('cli_win', 'cli_lnx'):
    check(key + ' reads session_key from MSG_AUTH_SUCCESS',
          "bytes.fromhex" in src[key] and "session_key" in src[key])

# 16. Encryption symmetry
print('\n## 16. ENCRYPTION SYMMETRY — activated after MSG_AUTH_SUCCESS')
for key in ('win_srv_svc', 'lnx_srv_svc'):
    t = src[key]
    send_idx = t.rfind('MSG_AUTH_SUCCESS')
    enc_idx  = t.find('_encrypted = True', send_idx)
    check(key + ': _encrypted=True AFTER MSG_AUTH_SUCCESS', enc_idx > send_idx)

# 17. Hello packet fields
print('\n## 17. HELLO PACKET — servers send os + features + password')
for key in ('win_srv_svc', 'lnx_srv_svc'):
    check(key + " sends 'os' in hello",       "'os':" in src[key])
    check(key + " sends 'features' in hello", "'features':" in src[key])
    check(key + " includes 'password' feature", "'password'" in src[key])

# 18. Window size packet format
print('\n## 18. WINDOW SIZE — struct.pack(!HH) used')
for key in ('cli_win', 'cli_lnx', 'win_srv_svc', 'lnx_srv_svc'):
    ok = ("pack('!HH'" in src[key]) or ('create_window_size_packet' in src[key])
    check('Window size !HH in ' + key, ok)

# Summary
print()
print('=' * 62)
total  = len(results)
passed = sum(1 for ok, _ in results if ok)
failed = total - passed
print('  TOTAL : {}'.format(total))
print('  PASSED: {}'.format(passed))
print('  FAILED: {}'.format(failed))
if failed == 0:
    print()
    print('  *** ALL CHECKS PASSED ***')
    print('  *** CLIENTS AND SERVERS ARE FULLY IN SYNC ***')
else:
    print()
    print('  *** FAILURES DETECTED — SEE [FAIL] ABOVE ***')
    for ok, msg in results:
        if not ok:
            print(msg)
print('=' * 62)
sys.exit(0 if failed == 0 else 1)
