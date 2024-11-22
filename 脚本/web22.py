import hashlib

def check_md5_conditions(md5_hash):
    try:
        """检查MD5哈希值是否满足条件"""
        # 将MD5哈希值转换为十六进制字符串
        md5_hex = md5_hash.hexdigest()
        
        # 获取第2、15、18位字符
        char_2 = md5_hex[2]
        char_15 = md5_hex[14]
        char_18 = md5_hex[17]
        
        # 检查第2、15、18位是否相等
        if char_2 != char_15 or char_15 != char_18:
            return False
        
        # 将第2、15、18位字符转换为整数
        int_2 = int(char_2, 16)
        int_15 = int(char_15, 16)
        int_18 = int(char_18, 16)
        
        # 获取第32位字符并转换为整数
        char_32 = md5_hex[31]
        int_32 = int(char_32, 16)
        
        # 检查条件：(第2位 + 第15位 + 第18位) / 第2位 == 第32位
        if (int_2 + int_15 + int_18) // int_2 == int_32:
            return True
        else:
            return False
    except Exception as e:
        return False

def find_md5():
    """找到满足条件的MD5哈希值"""
    for i in range (1,100000):
        # 生成随机字符串
        random_string = str(i)
        # 计算MD5哈希值
        md5_hash = hashlib.md5(random_string.encode())
        print(md5_hash.hexdigest(),random_string)
        # 检查条件
        if check_md5_conditions(md5_hash):
            return (md5_hash.hexdigest(),random_string)

# 调用函数并打印结果
result,txt = find_md5()
print("满足条件的MD5哈希值是:", result,txt)