# httphijack
使用Javascript实现前端防御http劫持及防御XSS攻击，并且对可疑攻击进行上报
## 使用方法
引入 `httphijack1.0.0.js` 
```javascript
httphijack.init()
```

## 防范范围：
+ 所有内联事件执行的代码
+ <a> 标签 href 属性 `javascript:` 内嵌的代码
+ 静态脚本文件内容
+ 动态添加的脚本文件内容
+ document-write添加的内容
+ iframe嵌套
   
## 使用须知 
建立自己的黑白名单、上报系统及接收后端

## License
MIT
