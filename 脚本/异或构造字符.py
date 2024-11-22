valid = "1234567890!@$%^*(){}[];\'\",.<>/?-=_`~ "
# 定义一个包含所有ASCII字符的字符串
# valid = ''.join(chr(i) for i in range(128))

answer = "whoami"
tmp1, tmp2 = '', ''
for c in answer:
    flag=False
    for i in valid:
        for j in valid:
            if (ord(i) ^ ord(j) == ord(c)) and (ord(i) != ord(c) and ord(j) != ord(c)):
                print(ord(i),'^',ord(j),"=",c,' ',ord(c))
                tmp1 += i
                tmp2 += j
                flag=True
                break
            else:
                continue
        if flag:  # 检查是否已经找到异或值，如果是，则跳出外层循环
            break
print("tmp1为:",tmp1)
print("tmp2为:",tmp2)