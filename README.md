# IDA_AIGpt
集成gpt-3.5-turbo-16k模型到IDA插件中，利用GPT来解释IDA反汇编代码，更适合逆向需求。
# 注意
这个模型不能用就用库里的其他模型，(如果此不可用，IDA_GPT/Model_GPT,可用)。

## 使用步骤
### 1. 科学上网      
clash

### 2. 将脚本放入插件中
将Model_GPT_16k中的gepetto-locales 和 Fbleee_16k.py 脚本放到 IDA 插件文件夹 ( $IDAUSR/plugins)


### 3. 效果图

![1](https://github.com/FBLeee/IDA_GPT/assets/50468890/15271d25-0e8d-4109-8ade-7162ccc3adfb)


## 说明
1. 发现gpt-3.5-turbo-16k更适合对IDA伪C代码的解释说明。    

2. 如果想利用GPT-4等模型需要使用自己的key，有一定的免费额度，但很少。https://gptgod.online/
 ![image-20240228104937807](https://github.com/FBLeee/IDA_GPT/assets/50468890/ff79dc59-2807-49ff-97b7-abcebc9f5f6e)
3. 免费OpenAI key只能使用下列模型（本项目使用此key）
![image-20240228104654637](https://github.com/FBLeee/IDA_GPT/assets/50468890/39a4cd83-4f10-4e17-889a-9557a7472dfd)





## 致谢

**[gpt4free-ts](https://github.com/xiangsx/gpt4free-ts)**，开源GPT项目  
[Gepetto](https://github.com/JusticeRage/Gepetto)，基于Gepetto项目进行修改  
[Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support  

## Star History

![Star History Chart](https://api.star-history.com/svg?repos=FBLeee/IDA_GPT&type=Date)
