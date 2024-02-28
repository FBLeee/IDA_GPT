# IDA_AIGpt
集成gpt-3.5-turbo-16k模型到IDA插件中，利用GPT来解释IDA反汇编代码，更适合逆向需求。

## 使用步骤

### 1.将脚本放入插件中
将Model_GPT_16k中的gepetto-locales 和 Fbleee_16k.py 脚本放到 IDA 插件文件夹 ( $IDAUSR/plugins)


​            

### 2. 效果图

![1](C:\Users\FH\Desktop\1.png)

## 对比
1. 发现gpt-3.5-turbo-16k更适合对IDA反编译的伪C代码的解释说明。    

2. 免费OpenAI key（如果想利用GPT-4等模型，有一定的免费额度，很少）

   ![image-20240228104654637](C:\Users\FH\AppData\Roaming\Typora\typora-user-images\image-20240228104654637.png)

![image-20240228104937807](C:\Users\FH\AppData\Roaming\Typora\typora-user-images\image-20240228104937807.png)

## 致谢

**[gpt4free-ts](https://github.com/xiangsx/gpt4free-ts)**，开源GPT项目  
[Gepetto](https://github.com/JusticeRage/Gepetto)，基于Gepetto项目进行修改  
[Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support  

## Star History

![Star History Chart](https://api.star-history.com/svg?repos=FBLeee/IDA_GPT&type=Date)
