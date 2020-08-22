# RubyAES

* Ruby Implementation of AES written with just Ruby standard library

NOTE
-----
* The key for encryption always has to be base 16
* The text can be either hex or normal ascii string. You'll have to call corresponding class method for encryption
* The return value of encryption is always base 16 string. This is done because of the inability to print all 256 ascii characters
* In case the key is larger than the encryptionType(i.e 128,192,256 bits) , we'll only take the first k(=encryptionType) bits of the key

## Methods


*  `AES.encrypt_hex(text , key , encryptionType)` takes in text in hexadecimal form i.e each char is treated as hexadecimal value. Hence, if you put anything except hex values, Ruby will throw an error
* `AES.encrypt_ascii(text, key , encryptionType)` takes in a normal string and encrypts it.
* `AES.decrypt_hex(hexText, key, encryptionType) ` will take hex as input and decrypt to hex.
* `AES.decrypt_to_ascii(hexText, key, encryptionType) ` will decrypt the hexText and return the decrypted text as ascii string.