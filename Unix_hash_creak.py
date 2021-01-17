# -*- coding: utf-8 -*-
# @Author  : 0x777
# @Time    : 2021/1/17 11:45
# @Function: Unix hash scan

from passlib.handlers.sha2_crypt import sha512_crypt

def testPass(cryptPass):
    salt  = cryptPass[0:2]
    dictFile = open('dictionary.txt','r')
    for word in dictFile.readline():
        word =word.split('\n')
        cryptWord = sha512_crypt.encrypt(word, salt=salt, rounds=5000)
        # cryptWord= crypt.crypt(word,salt)     ### only for unix (windows not,https://www.cnpython.com/qa/61413)
        try :
            if(cryptWord == cryptPass):
                print("[+] Found Password:"+str(word)+"\n")
                return
        except:
            print("[-] Password Not Found.\n")
            return

def main():
    passFile = open('password.txt','r')
    for line in passFile.readline():
        if ":" in line:
            user = line.split(':')[0]
            cryptPass =line.split(':')[1].split(' ')
            print("[*] Cracking Password For: " + str(user))
            testPass(cryptPass)


if __name__=='__main__':
    main()