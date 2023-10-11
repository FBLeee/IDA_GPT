# IDA_ChatGPT
利用讯飞星火认知大模型结合IDA，来解释IDA反汇编代码,每个手机号应该免费20w

## 1.注册讯飞星火认知大模型
[讯飞星火认知大模型官网](https://xinghuo.xfyun.cn/sparkapi)
![image](https://github.com/FBLeee/IDA_ChatGpt/assets/50468890/96b0b8df-9338-4aa6-b9a9-96a2d0268bc8)

## 2.设置

### 2.1 在控制台中寻找三个关键参数
![image](https://github.com/FBLeee/IDA_ChatGpt/assets/50468890/20436a1f-52cb-4422-8208-c31b3c7dd5d9)  



         
### 2.2 修改Gepetto_free.py代码
修改Gepetto_free.py代码中的关键参数
![image](https://github.com/FBLeee/IDA_ChatGpt/assets/50468890/0cecf507-ae9a-466c-a47a-730bcbd05b46)


### 2.3 放入ida
将gepetto-locales 和 Gepetto_free.py 、SparkApi.py脚本放到 IDA 插件文件夹 ( $IDAUSR/plugins)


## 3.使用
![274208313-8321cc7f-9d64-4183-84eb-5633e8630cb3](https://github.com/FBLeee/IDA_ChatGpt/assets/50468890/52bfd320-01a2-4d96-8dcb-193b65769284)

![image](https://github.com/FBLeee/IDA_ChatGpt/assets/50468890/6496e8b3-5a2b-42c8-be1e-98cec2e82f93)



## 致谢
[讯飞星火认知大模型官网](https://xinghuo.xfyun.cn/sparkapi)   
[Gepetto](https://github.com/JusticeRage/Gepetto)，站在大神Gepetto肩膀进行修改以下脚本  
[Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support  



## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=FBLeee/IDA_ChatGpt&type=Date)](https://star-history.com/#FBLeee/IDA_ChatGpt&Date)
