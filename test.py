from hashlib import md5
from passlib.hash import md5_crypt
from argon2 import PasswordHasher
import argon2
ph = PasswordHasher()

def argon(password):
    password = ph.hash(password)
    return password

def md5_salted(password):
    password = md5_crypt.using(salt_size=8).hash(password)
    return password

def md5_classic(password):
    password = md5(password.encode()).hexdigest()
    return password

password = 'admin'
print(argon(password))
print(md5_salted(password))
print(md5_classic(password))


#INSERT INTO users (role_id, username, email, first_name, last_name, password) VALUES(1,'admin', 'admin@example.com', 'John', 'Doe', '$argon2id$v=19$m=65536,t=3,p=4$L3jNUzeRVWWiYP/u/mt2Ag$QYqf5Ayvr3H+XtD7QdOMh92Hf456DTpjmfzUq96lZgE');
#INSERT INTO users (role_id, username, email, first_name, last_name, password) VALUES(1,'admin', 'admin@example.com', 'John', 'Doe', '21232f297a57a5a743894a0e4a801fc3');
#INSERT INTO users (role_id, username, email, first_name, last_name, password) VALUES(1,'admin', 'admin@example.com', 'John', 'Doe', '$1$AdJoO/1c$/ofFs1UX.FLnstuVy.UBK0');
#INSERT INTO users (role_id, username, email, first_name, last_name, password) VALUES(1,'admin', 'admin@example.com', 'John', 'Doe', 'admin');

#$1$AdJoO/1c$/ofFs1UX.FLnstuVy.UBK0
#21232f297a57a5a743894a0e4a801fc3