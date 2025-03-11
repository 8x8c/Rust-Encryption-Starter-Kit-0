

# A series
xor.  used right, it is the most secure method known (One Time Pad) - although regular xor encryption without strictly following the OTP rules is not secure at all. For example, 2 cyphertexts can be xored to reveal information about the key- that is one of the reasons one can only use a xor otp key once.  


# B series

aes apps. aes is the hardest to get right, so for top security it is absolutely best to use pro apps, not home made. 

# C series

chacha20 / xchacha20-poly2305 apps. Chacha20 is simpler than aes and actually uses xor for some things, but it is just as secure as aes. chacha20 is easier to make home made apps with. In a way, it solves the issues with otp being so difficult to handle properly. The one time pad (properly used) is first place, in my opinion and for my uses, chacha20 is seckond place for sure. A great balance of security and ease of use, and it does not require special hardware to be its best like aes does. In other words, chacha20 runs easier on machines with less hardware. 

# k series

key makers. Deterministic keys aleays make the same key based on user input. Random key apps try to make the most random keys possible. 

# p series- 

password based apps

# T series- 

misc tools like key  analysis tools. 
