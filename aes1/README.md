
Designed to be incredibly user friendly. 

USAGE:  

aes [FLAGS] <input> <output>

./aes -e a.txt b.txt    will encrypt a.txt to file called b.txt

./aes -d b.txt c.txt    will decrypt b.txt to a file called c.txt

The key file is always key.key  in the same directory as the executable. 

When encrypting. if the key file is not found, it will make you a random key automatically - the file key.key will be made
in the directory of the executable. So you have to store the file key.key if you want to be able to decrypt later on. 





