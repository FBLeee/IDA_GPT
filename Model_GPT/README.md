# IDA_AIGpt
集成GPT-Free API到IDA插件中，利用GPT来解释IDA反汇编代码

## 1. 使用步骤
### (1) 获取免费的API-KEY

[在开源github项目中免费获取API-KEY](https://github.com/chatanywhere/GPT_API_free) 

### (2)打开开源项目

[使用开源github项目Gepetto](https://github.com/JusticeRage/Gepetto)


### (3) 填入API-KEY
将获取的APIK-KEY填入IDA Python插件脚本中
![image](https://github.com/user-attachments/assets/b8b851a4-cb28-4404-b021-193f91cf8c0c)

   
### (4) 将脚本放入插件中
将开源github项目Gepetto的文件放到 IDA 插件文件夹 ( $IDAUSR/plugins)
   
   
            
## 2. 效果图
![image](https://github.com/user-attachments/assets/889f3964-eae0-4f14-a5e7-5077d5f43b4a)


## 3. GPT-4
修改Model_GPT/FBleee_GPT.py中的代码，将model改成 "gpt-4",每天拥有3次免费使用的机会，GPT-4查询能力还是挺给力的（好像还没有字数限制）   

![image](https://github.com/user-attachments/assets/32c30804-0913-41f9-840c-df168a062e5e)


## 4. Update
免费版支持gpt-4，一天3次；支持gpt-4o-mini，和gpt-3.5-turbo共享一天200次。
更新free GPT的url

## 致谢
[GPT-API-free](https://github.com/chatanywhere/GPT_API_free)   
[Gepetto](https://github.com/JusticeRage/Gepetto)，站在大神Gepetto肩膀进行修改以下脚本  
[Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support  



## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=FBLeee/IDA_AIGpt&type=Date)
