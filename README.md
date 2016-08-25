# httphijack
使用Javascript实现前端防御`http劫持`及防御`XSS攻击`，并且对可疑攻击进行上报

## 相关文章
[【前端安全】JavaScript防http劫持与XSS](http://www.cnblogs.com/coco1s/p/5777260.html)

## 使用方法
引入 `httphijack1.0.0.js` 
```javascript
httphijack.init()
```

## 防范范围：
+ 所有内联 on* 事件执行的代码
+ <a> 标签 href 属性 `javascript:` 内嵌的代码
+ 静态脚本、iframe 等恶意内容
+ 动态添加的脚本文件、iframe 等恶意内容
+ document-write添加的内容
+ iframe 嵌套
   
## 使用须知 
建立自己的域名白名单、关键字黑名单、上报系统及接收后端。

组件处于测试修改阶段，未在生产环境使用，使用了很多 HTML5 才支持的 API，仅供学习交流。

## License
MIT
