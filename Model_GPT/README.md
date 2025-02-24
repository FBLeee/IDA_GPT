# IDA_AIGpt
集成GPT-Free API到IDA插件中，利用GPT来解释IDA反汇编代码，**增加gpt-4o-mini模型（每天200次调用）**   

## 1. 使用步骤
### (1) 获取免费的API-KEY

[在开源github项目中免费获取API-KEY](https://github.com/chatanywhere/GPT_API_free) 

### (2)下载开源项目

[使用开源github项目Gepetto](https://github.com/JusticeRage/Gepetto)


### (3) 填入API-KEY
将获取的APIK-KEY填入IDA Python插件脚本中
![image](https://github.com/user-attachments/assets/b8b851a4-cb28-4404-b021-193f91cf8c0c)

   
### (4) 将脚本放入插件中
将开源github项目Gepetto的文件放到 IDA 插件文件夹 ( $IDAUSR/plugins)
   
   
            
## 2. 效果图
![image](https://github.com/user-attachments/assets/889f3964-eae0-4f14-a5e7-5077d5f43b4a)


## 3. GPT-4
![image](https://github.com/user-attachments/assets/32c30804-0913-41f9-840c-df168a062e5e)


## 4. Update
1.免费版支持gpt-4，一天3次；支持gpt-4o-mini，和gpt-3.5-turbo共享一天200次。   
2.更新free GPT的url

## 致谢
[GPT-API-free](https://github.com/chatanywhere/GPT_API_free)   
[Gepetto](https://github.com/JusticeRage/Gepetto)，站在大神Gepetto肩膀进行修改以下脚本  
[Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support  



## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=FBLeee/IDA_AIGpt&type=Date)
