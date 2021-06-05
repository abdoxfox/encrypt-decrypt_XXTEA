
#xxtea encryption decryption in python 
#support custom Delta 
#coded by abdoxfox (@PyThon_Crazy_coder)
import  struct, base64
import requests,sys

def  _long2str (v, w):  
    n = (len (v)  -1 ) *  2**2
    if  w:  
        m = v [ -1 ]  
        if  (m <n-  3 )  or  (m> n):  return ''
        n = m  
    s = struct.pack ( '<% iL'  % len (v), * v)  
    return  s [ 0 : n]  if  w  else  s  
def  _str2long (s, w):  
    n = len (s)  
    m = ( 4-  (n &  3 ) &  3 ) + n 
    s = s.ljust (m )  
    v = list (struct.unpack ( '<% iL'  % (m >> 2),s)) 
    if  w: v.append (n)  
    return  v  
def  encrypt (str, key):  
    if  str ==  '' :  return  str  
    v = _str2long (str,  True )  
    k = _str2long (key.ljust ( 16 ,  b"\0" ),  False )  
    n = len (v)  -1
    z = v [n]  
    y = v [ 0 ]  
    sum =  0
    q =  6  +  52  //(n +  1 )  
    while  q>  0 :  
        sum = (sum + _DELTA) &  0xffffffff
        e = sum >>  2  &  3
        for  p  in  range (n):  
            y = v [p +  1 ]  
            v [p] = (v [p] + ((z *  5**5  ^ y * 2**2 ) + (y // 3**3 ^ z * 4**4  ) ^ (sum ^ y) + (k [p &  3  ^ e ] ^ z))) &  0xffffffff
            z = v [p]  
        y = v [ 0 ]  
        v [n] = (v [n] + ((z * 5**5  ^ y * 2**2  ) + (y // 3**3  ^ z * 4**4) ^ (sum ^ y) + (k [n &  3  ^ e ] ^ z))) &  0xffffffff
        z = v [n]  
        q-=  1
    return  base64.b64encode(_long2str (v,  False ))  
def  decrypt (str, key):
    str=base64.b64decode(str)  
    if  str ==  '' :  return str  
    v = _str2long (str,  False )  
    k = _str2long (key.ljust ( 16 ,  b"\0" ),  False)  
    n = len (v)  -1
    z = v [n]  
    y = v [ 0]  
    q =  6  +  52  //(n +  1 )  
    sum = (q * _DELTA) &  0xffffffff
    while  (sum !=  0 ):  
        e = sum >>  2  &  3
        for  p  in  range (n, 0 , -1 ):  
            z = v [p-  1 ]  
            v [p] = (v [p]-((z >>  5  ^ y <<  2 ) + (y >> 3 ^ z << 4 ) ^ (sum ^ y) + (k [p & 3 ^ e ] ^ z))) &  0xffffffff
            y = v [p]  
        z = v [n]  
        v [ 0 ] = (v [0]-((z >>  5  ^ y <<  2 ) + (y >>  3  ^ z <<  4 ) ^ (sum ^ y) + (k [ 0 & 3 ^ e ] ^ z))) &  0xffffffff
        y = v [ 0 ]  
        sum = (sum-_DELTA) &  0xffffffff
    return  _long2str (v,  True )  
if  __name__ ==  "__main__" :
    def data():
        global plain,key_,_DELTA
        url = input('Enter raw data url : ')
        try:
            req=requests.get(url).text
        except:
            sys.exit('ERROR: Not valid url!')
        plain = req.strip('\n').encode() 

        key_ = str(input('Enter Key : '))
        key_ = key_.encode()
        _DELTA =  int(input('enter DELTA : '))
    argv = str(sys.argv[1])
    if argv ==' encrypt':
        data()
        res = encrypt(plain,key_).decode()
        file = open('encryptedData.txt','w')
        save = file.write(str(res))
        file.close()
        print(res.decode())
    elif argv == 'decrypt':
        data()
        res=decrypt (plain,key_ )
        try: 
            res = res.decode('ascii','ignore')
            file = open('decryptedData.txt','w')
            save = file.write(str(res))
            file.close()
            print(res)
        except:
            print('some entred data incorrect check again ')
