# rsa_demo_for_dotNet
---
### 这是有关RSA加密的 C#/.Net的Demo项目

### 首先

1. 下载项目后添加到vs中
2. 编译代码，如果有报错的话解决一下（一般来说是引用的错误 重新引用就好）
3. 注意 extra dependency 包内的 bccrypto-csharp-1.8.2 这个项目，如果项目中没有引用成功，需要手动重新引用一下，因为这个是网友提供的C#的rsa加密和java的rsa加密转换用的工具类，不存在nuget包中

### 接着

- 找到rsatest.cshtml文件后开始debug（项目默认运行文件就是这货）

### 可能要踩的一些坑

这里可能会有几个坑

1. 页面运行不起来，控制台查看错误，尽量解决
2. 页面能运行起来，但是页面没有显示公钥的值
   * 检查项目下面有没有Resources文件夹，没有的话新建一个空的文件夹
   * 如果有Resources文件夹，检查 RSAHelper 类中间注明的私钥和公钥的储存地址是否能找到（这个可以自定义）
3. 页面终于跑起来了，公钥的值也在页面展示了，但是输入内容请求后没有反应了
   - **这个页面是没有响应的!!!!!!!!**
   - **这个页面是没有响应的!!!!!!!!**
   - **这个页面是没有响应的!!!!!!!!**
   - （重要的事情说三遍）
   * 浏览器打开console（控制台）查看是否有返回,如果有返回你输入的内容，说明通了
4. 另外会遇到怎么也跑不起来的情况，这种情况就默默把代码搬到你自己的项目中去重新尝试吧


## 提醒

RSA加密和解密的长度都是有上限的，加密的原数据长度是117，解密是128，如果超过这个长度上限有几种选择

1. 使用分段加(解)密,然后拼接
2. 换个加密方式
3. ...(还在研究中)

分端加密和解密的放在都已经分别加在jsencrypt.js文件和RSAHelper中了（由于备注说明都是英文的，为了格式统一我的备注也用了英文的）

.Net生成的RSA密钥不是PEM格式的，而JavaScript和Java都是使用PEM格式的密钥
在RSAHelper中已经写了.Net使用的xml格式密钥转换为PEM格式(base64编码)的方法

## 另外

在这里，我的请求方式与正常的请求方式有点区别
正常的请求方式是用json格式将数据请求到后端接口，这样至少一个参数（例如：{"data":"kajfdkjfhkdsvbalisugoaiwenfo"}），这样还是没有做到加密到底（至少截包后还是k能看到请求的参数data和请求数据（加过密的)
而我则是不使用请求参数，在请求的使用直接把加密的数据放在数据流中请求到后端接口，后端则写了一个ActionFilter拦截请求，再做数据解密（同时也可以做数据验证）

