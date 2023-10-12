# IDA_AIGpt
集成GPT-Free API到IDA插件中，利用AI来解释IDA反汇编代码

## 使用步骤
### 1.获取免费的API-KEY

[在开源github项目中免费获取API-KEY](https://github.com/chatanywhere/GPT_API_free) 

### 2.填入API-KEY
将获取的APIK-KEY填入IDA Python脚本Model_GPT\Fbleee_GPT.py中
![image](https://github.com/FBLeee/IDA_AIGpt/assets/50468890/e363604c-21bc-4cd2-adea-3237615e190a)
   


   
### 3.将脚本放入插件中
将Model_GPT中的gepetto-locales 和 Fbleee_GPT.py脚本放到 IDA 插件文件夹 ( $IDAUSR/plugins)
   
   
            
## 效果图
![展示](https://github.com/FBLeee/IDA_AIGpt/assets/50468890/100f25ca-d8c1-4f11-8c9a-d74c6a91ddd5)
   

## 致谢
[GPT-API-free](https://github.com/chatanywhere/GPT_API_free)   
[Gepetto](https://github.com/JusticeRage/Gepetto)，站在大神Gepetto肩膀进行修改以下脚本  
[Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support  



## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=FBLeee/IDA_ChatGpt&type=Date)](
