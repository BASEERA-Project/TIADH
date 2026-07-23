from db_helper import *



insert_honeypot("cowrie1",2222)



insert_honeypot("cowrie2",2223)



insert_honeypot("cowrie3",2224)



insert_attack(



"cowrie1",



"ABC123",



"2026-07-20",



"192.168.1.100",



"cowrie.login.failed",



"root",



"admin",



None



)



print("Success")
