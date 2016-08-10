/**
 * @author Coco
 * @QQ:308695699
 * @name httphijack 1.0.0
 * @update : 2016-08-10
 * @description 使用Javascript静态防御与动态防御实现前端防御http劫持及防御XSS攻击，并且对可疑攻击进行上报
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * 1、使用方法：调用 httphijack.init()
 *
 */
(function(window, undifined) {
  var httphijack = {},
    // 记录内联事件是否被扫描过的 hash map
    mCheckMap = {},
    // 记录内联事件是否被扫描过的id
    mCheckID = 0;

  /**
   * 内联事件拦截
   * @param  {[String]} eventName [内联事件名]
   * @param  {[Number]} eventID   [内联事件id]
   * @return {[type]}             [description]
   */
  function interceptionInlineEvent(eventName, eventID) {
    var isClick = (eventName == 'onclick');

    /**
     * 扫描元素是否存在内联事件
     * @param  {[DOM]} el [DOM元素]
     */
    function scanElement(el) {
      var
        flag = el['isScan'],
        // 扫描内联代码
        code = "",
        hash = 0;

      // 跳过已扫描的事件
      if (!flag) {
        flag = el['isScan'] = ++mCheckID;
      }

      hash = (flag << 8) | eventID;

      if (hash in mCheckMap) {
        return;
      }

      mCheckMap[hash] = true;

      // 非元素节点
      if (el.nodeType != Node.ELEMENT_NODE) {
        return;
      }

      if (el[eventName]) {
        code = el.getAttribute(eventName);
        if (code && /xss/.test(code)) {
          el[eventName] = null;
          console.log('拦截可疑事件:' + code);
        }
      }

      // 扫描 <a href="javascript:"> 的脚本
      if (isClick && el.tagName == 'A' && el.protocol == 'javascript:') {
        var code = el.href.substr(11);
        if (/xss/.test(code)) {
          el.href = 'javascript:void(0)';
          console.log('拦截可疑事件:' + code);
        }
      }

      // 递归扫描上级元素
      scanElement(el.parentNode);
    }

    document.addEventListener(eventName.substr(2), function(e) {
      scanElement(e.target);
    }, true);
  }

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

  // 主动防御 MutationEvent
  /**
   * 使用 MutationObserver 进行静态脚本拦截
   * @return {[type]} [description]
   */
  function interceptionStaticScript() {
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {

        var nodes = mutation.addedNodes;
        for (var i = 0; i < nodes.length; i++) {
          var node = nodes[i];

          if (/xss/.test(node.src) || /xss/.test(node.innerHTML)) {
            node.parentNode.removeChild(node);
            console.log('拦截可疑模块:', node);
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
   * 使用 DOMNodeInserted  进行动态脚本拦截监测
   * 此处无法拦截，只能监测
   * @return {[type]} [description]
   */
  function interceptionDynamicScript() {
    document.addEventListener('DOMNodeInserted', function(e) {
      var node = e.target;

      if (/xss/.test(node.src) || /xss/.test(node.innerHTML)) {
        node.parentNode.removeChild(node);
        console.log('拦截可疑模块:', node);
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

    window.document.write = function(string){
      if (/xss/.test(string)) {
        console.log('拦截可疑模块:', string);
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
        if (/xss/.test(value)) {
          console.log('拦截可疑模块:', value);
          return;
        }
      }
      // 调用原始接口
      old_setAttribute.apply(this, arguments);
    };
  }

  /**
   * 使用 Object.defineProperty，锁住call和apply，使之无法被重写
   * @return {[type]} [description]
   */
  function lockCallAndApply() {
    // 锁住 call
    Object.defineProperty(Function.prototype, 'call', {
      value: Function.prototype.call,
      writable: false,
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
   * 使用 DOMNodeInserted 对生成的 iframe 页面进行监控，防止调用内部原生 setAttribute
   * @return {[type]} [description]
   */
  function defenseIframe() {
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

      // 监控当前环境的元素
      window.document.addEventListener('DOMNodeInserted', function(e) {
        var element = e.target;

        // 给框架里环境也装个钩子
        if (element.tagName == 'IFRAME') {
          installHook(element.contentWindow);
        }
      }, true);
    }

    // 先保护当前页面
    installHook(window);
  }

  /**
   * 重定向iframe hijack（页面被iframe包裹）
   */
  function redirectionIframeHijack() {
    // 当前页面存在于一个 iframe 中
    if (self != top) {
      var url = location.href;
      var parts = url.split('#');
      if (location.search) {
        parts[0] += '&' + flag + '=1';
      } else {
        parts[0] += '?' + flag + '=1';
      }
      try {
        console.log('页面被嵌入iframe中:', url);
        top.location = parts.join('#');
      } catch (e) {}
    }
  }

  // 待完成：
  // 自定义上报事件
  // 添加黑白名单列表

  // 初始化方法
  httphijack.prototype.init = function() {
    // 触发内联事件拦截
    triggerIIE();
    // 进行静态脚本拦截
    interceptionStaticScript();
    // 进行动态脚本拦截
    interceptionDynamicScript();
    // 锁住 apply 和 call
    lockCallAndApply();
    // 对当前窗口及多重内嵌 iframe 进行 setAttribute 重写
    defenseIframe();
    // 对iframe劫持进行重定向
    redirectionIframeHijack();
  }

  window.httphijack = httphijack;
})(window);
