CREATE TABLE honeypots(



id INTEGER PRIMARY KEY AUTOINCREMENT,



name TEXT UNIQUE,



port INTEGER



);



CREATE TABLE attacks(



id INTEGER PRIMARY KEY AUTOINCREMENT,



honeypot_id INTEGER,



session TEXT,



timestamp TEXT,



src_ip TEXT,



eventid TEXT,



username TEXT,



password TEXT,



command TEXT,



FOREIGN KEY(honeypot_id) REFERENCES honeypots(id)



);
