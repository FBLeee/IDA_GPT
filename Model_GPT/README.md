# IDA_AIGpt
集成GPT-Free API到IDA插件中，利用GPT来解释IDA反汇编代码

## 1. 使用步骤
### (1) 获取免费的API-KEY

[在开源github项目中免费获取API-KEY](https://github.com/chatanywhere/GPT_API_free) 

### (2) 填入API-KEY
将获取的APIK-KEY填入IDA Python脚本Model_GPT\Fbleee_GPT.py中
![image](https://github.com/FBLeee/IDA_AIGpt/assets/50468890/e363604c-21bc-4cd2-adea-3237615e190a)
   


   
### (3) 将脚本放入插件中
将Model_GPT中的gepetto-locales 和 Fbleee_GPT.py脚本放到 IDA 插件文件夹 ( $IDAUSR/plugins)
   
   
            
## 2. 效果图
![展示](https://github.com/FBLeee/IDA_AIGpt/assets/50468890/100f25ca-d8c1-4f11-8c9a-d74c6a91ddd5)

## 3. GPT-4
修改Model_GPT/FBleee_GPT.py中的代码，将model改成 "gpt-4",每天拥有3次免费使用的机会，GPT-4查询能力还是挺给力的（好像还没有字数限制）   

      
![image](https://github.com/FBLeee/IDA_AIGpt/assets/50468890/8666420d-2282-45fa-867e-596ec26447b7)


## 4. Update
2024根据最新版本[Gepetto](https://github.com/JusticeRage/Gepetto)更改的使用免费GPT,放在gepetto.zip中，密钥SK-XXXXXXXX获得方法同上

## 致谢
[GPT-API-free](https://github.com/chatanywhere/GPT_API_free)   
[Gepetto](https://github.com/JusticeRage/Gepetto)，站在大神Gepetto肩膀进行修改以下脚本  
[Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support  



## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=FBLeee/IDA_AIGpt&type=Date)
