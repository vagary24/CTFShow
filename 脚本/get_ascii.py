# 生成所有ASCII字符并保存到文件

def generate_ascii_characters():
    # 创建一个空字符串，用于存储所有ASCII字符
    ascii_chars = ''
    
    # 遍历ASCII值从0到127（标准ASCII字符集的范围）
    for i in range(128):
        # 将每个字符添加到字符串中
        ascii_chars += chr(i)+"\n"
    
    # 返回包含所有ASCII字符的字符串
    return ascii_chars

def write_to_file(content, filename):
    # 打开文件，准备写入
    with open(filename, 'w', encoding='utf-8') as file:
        # 写入内容
        file.write(content)

# 主函数
def main():
    # 生成ASCII字符
    ascii_chars = generate_ascii_characters()
    
    # 定义输出文件名
    output_filename = 'ascii_characters.txt'
    
    # 将ASCII字符写入文件
    write_to_file(ascii_chars, output_filename)
    
    print(f'ASCII字符已成功写入到文件：{output_filename}')

# 运行主函数
if __name__ == '__main__':
    main()