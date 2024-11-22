def get_oct(c):
    # 假设这是你的自定义函数，用于获取字符的八进制表示
    return oct(ord(c))[2:]

def common_otc(cmd):
    payload = '$\''
    for c in cmd:
        if c == ' ':
            payload += '\' $\''
        else:
            payload += '\\' + get_oct(c)
    payload += '\''
    return payload

if __name__ == "__main__":
    print(common_otc("ls"))