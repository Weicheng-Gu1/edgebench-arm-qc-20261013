"""Worker subprocess keeps the task key out of argv and command logs."""
import argparse,json,os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from crypto_transport import seal,open_safe
def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['encrypt','decrypt']);p.add_argument('source',type=Path);p.add_argument('destination',type=Path);p.add_argument('--aad',required=True);a=p.parse_args()
 key=bytes.fromhex(os.environ.pop('EDGEBENCH_ESA_BOUNDED_PHYSICS_NATIVE_R3_KEY'))
 result=seal(a.source,a.destination,key,a.aad.encode())if a.mode=='encrypt'else open_safe(a.source,a.destination,key,a.aad.encode())
 print(json.dumps({'transport_complete':True,**result}))
if __name__=='__main__':main()
