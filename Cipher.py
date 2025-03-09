import hashlib

def str_2_md5(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode('utf-8'))  
    return md5_hash.hexdigest()

def file_2_md5(file_path):
    md5_hash = hashlib.md5()
    try:
        with open(file_path, "rb") as f: 
            for chunk in iter(lambda: f.read(4096), b""): 
                md5_hash.update(chunk)  
        
        return md5_hash.hexdigest()  
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error: {e}"
