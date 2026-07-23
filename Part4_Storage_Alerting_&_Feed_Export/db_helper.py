import sqlite3



DATABASE="cowrie.db"



def connect():

    return sqlite3.connect(DATABASE)

def insert_honeypot(name,port):



    conn=connect()



    cur=conn.cursor()



    cur.execute("""



    INSERT OR IGNORE INTO honeypots(name,port)



    VALUES (?,?)



    """,(name,port))



    conn.commit()



    conn.close()

def get_honeypot_id(name):



    conn=connect()



    cur=conn.cursor()



    cur.execute(



    "SELECT id FROM honeypots WHERE name=?",



    (name,)



    )



    row=cur.fetchone()



    conn.close()



    return row[0]

def insert_attack(



honeypot,



session,



timestamp,



src_ip,



eventid,



username,



password,



command



):



    honeypot_id=get_honeypot_id(honeypot)



    conn=connect()



    cur=conn.cursor()



    cur.execute("""



    INSERT INTO attacks(



    honeypot_id,



    session,



    timestamp,



    src_ip,



    eventid,



    username,



    password,



    command



    )



    VALUES(?,?,?,?,?,?,?,?)



    """,(



    honeypot_id,



    session,



    timestamp,



    src_ip,



    eventid,



    username,



    password,



    command



    ))



    conn.commit()



    conn.close()
