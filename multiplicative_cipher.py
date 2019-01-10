
# coding: utf-8

# In[1]:


#encription function
def mul_ciph_encrypt(plain_text, key):
    """Encrypt a stream of characters.
    
    Parameters
    ----------
    plain_text : string
               A single character or string of characters to be encrypted.
    key : int
        Encription key.
        This value is valid if and only if it has modular inverse over 128, 
        the total number of characters in ASCII.
        
    Returns
    -------
    cipher_text : string
                A single character or string of characters after encrypted.
                
    """
    
    cipher_text = ""
    for character in plain_text:
        temp_cipher = chr((ord(character) * key) % 128) 
        cipher_text = cipher_text + temp_cipher
        
    return cipher_text


# In[2]:


#decryption function
def mul_ciph_decrypt(cipher_text, key):
    """Decrypt a stream of characters.
    
    Parameters
    ----------
    cipher_text : string
                A single character or string of characters to be decrypted.
    key : int
        Decription key.
        This value is valid if and only if it has modular inverse over 128, 
        the total number of characters in ASCII.
        
    Returns
    -------
    plain_text : string
               A single character or string of characters after decrypted.
                
    """
    
    if modinv(key,128)==-1:
        print("INVALID KEY!!! --> %s" % key)
        return None
    plain_text = ""
    for character in cipher_text:
        temp_plain = chr(ord(character)*modinv(key,128) % 128)
        plain_text = plain_text + temp_plain
    
    return plain_text


# In[3]:


#modular inverse calculator
#source https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(int1, int2):
    if int1==0:
        return (int2, 0, 1)
    else:
        g,y,x = egcd(int2%int1, int1)
        return (g, x-(int2//int1)*y, y)
def modinv(int1, mod):
    g,x,y = egcd(int1,mod)
    if g!=1:
        return -1 
    else :
        return x%mod


# In[4]:


#file encrypting function
def encrypt_file(file_path, encrypted_file_name, key):
    """Encrypt a file.
    
    Parameters
    ----------
    file_path : string
              Path name of the file to be encrypted.
               
    encrypted_file_name : string
                        Path name of the file where the encrypted text will be written to.
    key : int
        Encription key.
        This value is valid if and only if it has modular inverse over 128, 
        the total number of characters in ASCII.
        
    Returns
    -------
    nothing returned
                
    """
    
    try :
        raw_file = open(file_path, "r")
        file_text = raw_file.read()

        encrypted_text = mul_ciph_encrypt(file_text, key)

        encrypted_file = open(encrypted_file_name, mode="w+")
        encrypted_file.write(encrypted_text)
        encrypted_file.close()
        
        print("FILE SUCCESSFULLY ENCRYPTED!!!")
        
    except Exception as e:
        print(e, "\n FILE ENCRYPTION FAILED!!!")


# In[5]:


#file decrypting function
def decrypt_file(file_path, decrypted_file_name, key):
    """Encrypt a file.
    
    Parameters
    ----------
    file_path : string
              Path name of the file to be decrypted.
               
    decrypted_file_name : string
                        Path name of the file where the decrypted text will be written to.
    key : int
        Decription key.
        This value is valid if and only if it has modular inverse over 128, 
        the total number of characters in ASCII.
        
    Returns
    -------
    nothing returned
                
    """
    
    try :
        raw_file = open(file_path, "r")
        file_text = raw_file.read()

        decrypted_text = mul_ciph_decrypt(file_text, key)

        decrypted_file = open(decrypted_file_name, mode="w+")
        decrypted_file.write(decrypted_text)
        decrypted_file.close()
        
        print("FILE SUCCESSFULLY DECRYPTED!!!")
        
    except Exception as e:
        print(e, "\n FILE DECRYPTION FAILED!!!")


# # Example

# In[6]:


encrypt_file("my_file.txt", "my_file_encrypted.txt", 7)


# In[7]:


decrypt_file("my_file_encrypted.txt", "my_file_decrypted.txt", 7)

