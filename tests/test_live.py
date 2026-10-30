import sys,os,json;H=os.path.dirname(os.path.abspath(__file__));sys.path.insert(0,os.path.join(H,'..','python'))
import receipt_verify as R
F=os.path.join(H,'..','fixtures','live-mainnet-guard-check-2026-10-30')
b=json.load(open(F+'.json'));tx=open(F+'.tx.b64').read().strip()
r=R.verify_receipt(b,tx_b64=tx);assert r['ok'],r
b['receipt']['event']['verdict']='NO_MATCH';assert not R.verify_receipt(b,tx_b64=tx)['ok']
print('live 2/2 passed')
