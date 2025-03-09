from Cipher import str_2_md5, file_2_md5


# test 1 

str = input("Add String: ")
print(str)
hash_result = str_2_md5(str)
print(f"MD5 Hash of '{str}': {hash_result}")

# test 2

file_path = "README.md"  
hash_result = file_2_md5(file_path)
print(f"MD5 Hash of '{file_path}': {hash_result}")