/**
 * @author Coco
 * @QQ:308695699
 * @name httphijack 1.0.0
 * @update : 2016-08-10
 * @description 使用Javascript实现前端防御http劫持及防御XSS攻击，并且对可疑攻击进行上报
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
1、使用方法：调用 httphijack.init()

2、建立自己的黑白名单、上报系统及接收后端

3、防范范围：
   1）所有内联事件执行的代码
   2）href 属性 javascript: 内嵌的代码
   3）静态脚本文件内容
   4）动态添加的脚本文件内容
   5）document-write添加的内容
   6）iframe嵌套
 *
 */
(function(window, undifined) {

  var httphijack = function() {},
    // 记录内联事件是否被扫描过的 hash map
    mCheckMap = {},
    // 记录内联事件是否被扫描过的id
    mCheckID = 0;

  // 建立白名单
  var whiteList = [
    'www.aaa.com',
    'www.bbb.com',
    's4.cnzz.com'
  ];

  // 建立黑名单
  var blackList = [
    '192.168.1.0'
  ];

  // 建立关键词黑名单
  var keywordBlackList = [
    'xss',
    'BAIDU_SSP__wrapper',
    'BAIDU_DSPUI_FLOWBAR'
  ];

  // 触发内联事件拦截
  function triggerIIE() {
    var i = 0,
      obj = null;

    for (obj in document) {
      if (/^on./.test(obj)) {
        interceptionInlineEvent(obj, i++);
      }
    }
  }

  /**
   * 内联事件拦截
   * @param  {[String]} eventName [内联事件名]
   * @param  {[Number]} eventID   [内联事件id]
   * @return {[type]}             [description]
   */
  function interceptionInlineEvent(eventName, eventID) {
    var isClick = (eventName == 'onclick');

    document.addEventListener(eventName.substr(2), function(e) {
      scanElement(e.target, isClick, eventName, eventID);
    }, true);
  }

  /**
   * 扫描元素是否存在内联事件
   * @param  {[DOM]} elem [DOM元素]
   * @param  {[Boolean]} isClick [是否是内联点击事件]
   * @param  {[String]} eventName [内联 on* 事件名]
   * @param  {[Number]} eventID [给每个内联 on* 事件一个id]
   */
  function scanElement(elem, isClick, eventName, eventID) {
    var
      flag = elem['isScan'],
      // 扫描内联代码
      code = "",
      hash = 0;

    // 跳过已扫描的事件
    if (!flag) {
      flag = elem['isScan'] = ++mCheckID;
    }

    hash = (flag << 8) | eventID;

    if (hash in mCheckMap) {
      return;
    }

    mCheckMap[hash] = true;

    // 非元素节点
    if (elem.nodeType != Node.ELEMENT_NODE) {
      return;
    }

    if (elem[eventName]) {
      code = elem.getAttribute(eventName);
      if (code && blackListMatch(keywordBlackList, code)) {
        // 注销事件
        elem[eventName] = null;
        console.log('拦截可疑内联事件:' + code);
        hijackReport('拦截可疑内联事件', code);
      }
    }

    // 扫描 <a href="javascript:"> 的脚本
    if (isClick && elem.tagName == 'A' && elem.protocol == 'javascript:') {
      var code = elem.href.substr(11);
      if (blackListMatch(keywordBlackList, string)) {
        // 注销代码
        elem.href = 'javascript:void(0)';
        console.log('拦截可疑事件:' + code);
        hijackReport('拦截可疑javascript:代码', code);
      }
    }

    // 递归扫描上级元素
    scanElement(elem.parentNode);
  }

  // 主动防御 MutationEvent
  /**
   * 使用 MutationObserver 进行静态脚本拦截
   * @return {[type]} [description]
   */
  function interceptionStaticScript() {
    // MutationObserver 的不同兼容性写法
    var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;

    // 该构造函数用来实例化一个新的 Mutation 观察者对象
    // Mutation 观察者对象能监听在某个范围内的 DOM 树变化
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        // 返回被添加的节点,或者为null.
        var nodes = mutation.addedNodes;

        // 逐个遍历
        for (var i = 0; i < nodes.length; i++) {
          var node = nodes[i];

          // 扫描 script 与 iframe
          if (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME') {
            // 拦截到可疑iframe
            if (node.tagName === 'IFRAME' && node.srcdoc) {
              node.parentNode.removeChild(node);
              console.log('拦截到可疑iframe', node.srcdoc);
              hijackReport('拦截可疑静态脚本', node.srcdoc);

            } else if (node.src) {
              // 只放行白名单
              if (!whileListMatch(blackList, node.src)) {
                node.parentNode.removeChild(node);
                // 上报
                console.log('拦截可疑静态脚本:', node.src);
                hijackReport('拦截可疑静态脚本', node.src);
              }
            }
          }
        }
      });
    });

    // 传入目标节点和观察选项
    // 如果 target 为 document 或者 document.documentElement
    // 则当前文档中所有的节点添加与删除操作都会被观察到d
    observer.observe(document, {
      subtree: true,
      childList: true
    });
  }

  /**
   * 使用 DOMNodeInserted  进行动态脚本拦截监
   * 此处无法拦截，只能监测
   * @return {[type]} [description]
   */
  function interceptionDynamicScript() {
    // DOMNodeInserted 的执行时机早于 MutationObserver
    document.addEventListener('DOMNodeInserted', function(e) {
      var node = e.target;
      if (/xss/i.test(node.src) || /xss/i.test(node.innerHTML)) {
        node.parentNode.removeChild(node);
        console.log('拦截可疑动态脚本:', node);
        hijackReport('拦截可疑动态脚本', node.src);
      }
    }, true);
  }

  // 重写 createElement
  function resetCreateElement() {}

  /**
   * 重写单个 window 窗口的 document.write 属性
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]}       [description]
   */
  function resetDocumentWrite(window) {
    var old_write = window.document.write;

    window.document.write = function(string) {
      if (blackListMatch(keywordBlackList, string)) {
        console.log('拦截可疑模块:', string);
        hijackReport('拦截可疑document-write', string);
        return;
      }

      // 调用原始接口
      old_write.apply(document, arguments);
    }
  }

  /**
   * 重写单个 window 窗口的 setAttribute 属性
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]} [description]
   */
  function resetSetAttribute(window) {
    // 保存原有接口
    var old_setAttribute = window.Element.prototype.setAttribute;

    // 重写 setAttribute 接口
    window.Element.prototype.setAttribute = function(name, value) {

      // 额外细节实现
      if (this.tagName == 'SCRIPT' && /^src$/i.test(name)) {

        if (!whileListMatch(whiteList, value)) {
          console.log('拦截可疑模块:', value);
          hijackReport('拦截可疑setAttribute', value);
          return;
        }
      }

      // 调用原始接口
      old_setAttribute.apply(this, arguments);
    };
  }

  /**
   * 使用 MutationObserver 对生成的 iframe 页面进行监控，
   * 防止调用内部原生 setAttribute 及 document.write
   * @return {[type]} [description]
   */
  function defenseIframe() {
    // 先保护当前页面
    installHook(window);
  }

  /**
   * 实现单个 window 窗口的 setAttribute保护
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]}       [description]
   */
  function installHook(window) {
    // 重写单个 window 窗口的 setAttribute 属性
    resetSetAttribute(window);
    // 重写单个 window 窗口的 document.Write 属性
    resetDocumentWrite(window);

    // MutationObserver 的不同兼容性写法
    var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;

    // 该构造函数用来实例化一个新的 Mutation 观察者对象
    // Mutation 观察者对象能监听在某个范围内的 DOM 树变化
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        // 返回被添加的节点,或者为null.
        var nodes = mutation.addedNodes;

        // 逐个遍历
        for (var i = 0; i < nodes.length; i++) {
          var node = nodes[i];

          // 给生成的 iframe 里环境也装上重写的钩子
          if (node.tagName == 'IFRAME') {
            installHook(node.contentWindow);
          }
        }
      });
    });

    observer.observe(document, {
      subtree: true,
      childList: true
    });
  }

  /**
   * 使用 Object.defineProperty，锁住call和apply，使之无法被重写
   * @return {[type]} [description]
   */
  function lockCallAndApply() {
    // 锁住 call
    Object.defineProperty(Function.prototype, 'call', {
      value: Function.prototype.call,
      // 当且仅当仅当该属性的 writable 为 true 时，该属性才能被赋值运算符改变
      writable: false,
      // 当且仅当该属性的 configurable 为 true 时，该属性才能够被改变，也能够被删除
      configurable: false,
      enumerable: true
    });
    // 锁住 apply
    Object.defineProperty(Function.prototype, 'apply', {
      value: Function.prototype.apply,
      writable: false,
      configurable: false,
      enumerable: true
    });
  }

  /**
   * 重定向iframe hijack（页面被iframe包裹）
   */
  function redirectionIframeHijack() {
    var flag = 'iframe_hijack_redirected';
    // 当前页面存在于一个 iframe 中
    // 此处需要建立一个白名单匹配规则，白名单默认放行
    if (self != top) {
      var
      // 使用 document.referrer 可以拿到跨域 iframe 父页面的 URL
        parentUrl = document.referrer,
        length = whiteList.length,
        i = 0;

      for (; i < length; i++) {
        // 建立白名单正则
        var reg = new RegExp(whiteList[i], 'i');

        // 存在白名单中，放行
        if (reg.test(parentUrl)) {
          return;
        }
      }

      var url = location.href;
      var parts = url.split('#');
      if (location.search) {
        parts[0] += '&' + flag + '=1';
      } else {
        parts[0] += '?' + flag + '=1';
      }
      try {
        console.log('页面被嵌入iframe中:', parentUrl);
        hijackReport('页面被嵌入iframe中', parentUrl);
        top.location.href = parts.join('#');
      } catch (e) {}
    }
  }

  /**
   * 自定义上报 -- 替换页面中的 console.log()
   * @param  {[String]} name  [拦截类型]
   * @param  {[String]} value [拦截值]
   * @return {[type]}   [description]
   */
  function hijackReport(name, value) {
    var img = document.createElement('img'),
      hijackName = name,
      hijackValue = value.toString(),
      curDate = new Date().getTime();

    // 上报
    img.src = 'http://www.reportServer.com/report/?msg=' + hijackName + '&value=' + hijackValue + '&time=' + curDate;
  }

  /**
   * [白名单匹配]
   * @param  {[Array]} whileList [白名单]
   * @param  {[String]} value    [需要验证的字符串]
   * @return {[Boolean]}         [false -- 验证不通过，true -- 验证通过]
   */
  function whileListMatch(whileList, value) {
    var length = whileList.length,
      i = 0;

    for (; i < length; i++) {
      // 建立白名单正则
      var reg = new RegExp(whiteList[i], 'i');

      // 存在白名单中，放行
      if (reg.test(value)) {
        return true;
      }
    }
    return false;
  }

  /**
   * [黑名单匹配]
   * @param  {[Array]} blackList [黑名单]
   * @param  {[String]} value    [需要验证的字符串]
   * @return {[Boolean]}         [false -- 验证不通过，true -- 验证通过]
   */
  function blackListMatch(blackList, value) {
    var length = blackList.length,
      i = 0;

    for (; i < length; i++) {
      // 建立黑名单正则
      var reg = new RegExp(blackList[i], 'i');

      // 存在黑名单中，拦截
      if (reg.test(value)) {
        return true;
      }
    }
    return false;
  }

  // 待完成：
  // 建立黑白名单列表
  // 对正则匹配精细化

  // 初始化方法
  httphijack.init = function() {
    // 触发内联事件拦截
    triggerIIE();
    // 进行静态脚本拦截
    interceptionStaticScript();
    // 进行动态脚本拦截
    // interceptionDynamicScript();
    // 锁住 apply 和 call
    lockCallAndApply();
    // 对当前窗口及多重内嵌 iframe 进行 setAttribute | document.write 重写
    defenseIframe();
    // 对iframe劫持进行重定向
    redirectionIframeHijack();
  }

  window.httphijack = httphijack;
})(window);
