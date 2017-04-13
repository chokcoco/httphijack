/**
 * @author Coco
 * @QQ:308695699
 * @name httphijack 1.1.0
 * @update : 2017-04-10
 * @description 使用Javascript实现前端防御http劫持及防御XSS攻击，并且对可疑攻击进行上报
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
1、使用方法：调用 httphijack.init()


3、防范范围：
   1）所有内联事件执行的代码
   2）href 属性 javascript: 内嵌的代码
   3）静态脚本文件内容
   4）动态添加的脚本文件内容
   5）document-write添加的内容
   6）iframe嵌套
 *
 */
'use strict';
(function(window) {

    var httphijack = function() {},
        inlineEventMap = {}, //内联事件扫描记录
        inlineEventId = 0, //内联事件扫描ID
        scanInlineElement = false; //是否需要扫描内联事件

    // 安全域，白名单
    var safeList = [
        /([a-zA-Z|a-zA-Z\d])+(\.)+(yy|duowan|yystatic|baidu|hiido|qq|baidu|gclick|minisplat|baidustatic|huanjuyun|sina|1931)+(\.)+[A-Za-z]{2,14}/i, //*.yy.com
        /((https|http):\/\/)+([a-zA-Z|a-zA-Z\d])+(\.)+(yy|duowan|yystatic|baidu|hiido|qq|baidu|gclick|minisplat|baidustatic|huanjuyun|sina|1931)+(\.)+[A-Za-z]{2,14}/i, //http开头
        /([a-zA-Z|a-zA-Z\d])+(\.)+(yy|duowan|yystatic|baidu|hiido|qq|baidu|gclick|minisplat|baidustatic|huanjuyun|sina|1931)+(:[0-9]{1,4})+(\.)+[A-Za-z]{2,14}/i, //帶端口的請求
        /[a-zA-Z0-9]\:\/\/[a-zA-Z0-9_/]*/i //手机相关
    ];


    // 危险域
    // var dangerList = [];

    // 过滤class关键词
    var filterClassName = [
        'BAIDU_DUP_wrapper', //百度推广
        'BAIDU_DSPUI_FLOWBAR'
    ];

    // 过滤name关键词
    var filterProName = [
        'text',
        '#text',
        'IFRAME',
        'SCRIPT',
        'IMG'
    ];

    // 过滤id关键词
    var filterNodeId = [
        '1qa2ws'
    ];

    var inlineEventList = [
        'alert',
        'location'
    ];
    // reset console
    if (!console) {
        window.console = {
            log: function() {
                return true;
            }
        };
    }

    /**
     * 统计上报函数
     * @param  {[type]} url 拦截脚本地址
     * @param  {[type]} className 拦截插入元素className
     * @param  {[type]} eName 内联事件名称
     * @param  {[type]} fUrl ifrmae乔套url
     */
    function hiidoStat(url, className, eName, fUrl) {
        var hiidoParam = {
            'eventid': 10010793,
            'bak1': url,
            'bak2': className,
            'bak3': eName,
            'parm1': fUrl
        };
        h5Report(url, className, eName, fUrl);
        window.on_security_interdiction && window.on_security_interdiction.call(window, hiidoParam);
    }

    /**
     * h5性能检测统计
     * @param  {[type]} url 拦截脚本地址
     * @param  {[type]} className 拦截插入元素className
     * @param  {[type]} eName 内联事件名称
     * @param  {[type]} iframeUrl ifrmae乔套url
     */
    function h5Report(url, className, eName, iframeUrl) {
        var databody = {},
            queryStr = '';

        databody.url = url ? url : '';
        databody.classname = className ? className : '';
        databody.name = eName ? eName : '';
        databody.iframeurl = iframeUrl ? iframeUrl : '';
        databody.pathname = window.location.pathname;
        databody.hostname = window.location.hostname;
        databody.ua = navigator.userAgent;

        for (var n in databody) {
            if (databody[n] !== '') {
                queryStr += n + '=' + databody[n] + '&';
            }
        }

        (new Image).src = 'http://h5.yy.com/hostage/report?' + queryStr;
    }
    /**
     * 过滤指定关键字
     * @param  {[Array]} 过滤词库 
     * @param  {[String]} value    [需要验证的字符串]
     * @return {[Boolean]}         [false -- 验证不通过，true -- 验证通过]
     */
    function filter(list, value) {
        if (list === safeList) {
            if (typeof(value) === 'undefined' || value === '') {
                return true;
            }
        } else {
            if (typeof(value) === 'undefined' || value === '') {
                return false;
            }
        }
        var length = list.length,
            i = 0;
        for (; i < length; i++) {
            // 建立黑名单正则
            var reg = new RegExp(list[i]);

            // 存在黑名单中，拦截
            if (reg.test(value.replace('https://', '').replace('http://', ''))) {
                return true;
            }
        }
        return false;
    }

    // 内联事件劫持
    function inlineEventFilter() {
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
        var isClick = (eventName === 'onclick');

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
        var flag = elem.isScan,
            code = '', // 扫描内联代码
            hash = 0;

        // 跳过已扫描的事件
        if (!flag) {
            flag = elem.isScan = ++inlineEventId;
        }

        hash = (flag << 8) | eventID;

        if (hash in inlineEventMap) {
            return;
        }

        inlineEventMap[hash] = true;

        // 非元素节点
        if (elem.nodeType !== Node.ELEMENT_NODE) {
            return;
        }
        //扫描包括 a iframe img video div 等所有可以写内联事件的元素
        if (elem[eventName]) {
            code = elem.getAttribute(eventName);
            if (code && filter(inlineEventList, code)) {
                // 注销事件
                elem[eventName] = null;
                hiidoStat('', '', code, '');
                // console.log('拦截可疑内联事件:' + code);
            }
        }

        // 扫描 <a href="javascript:"> 的脚本
        if (isClick && elem.tagName === 'A' && elem.protocol === 'javascript:') {
            code = elem.href.substr(11);
            if (filter(inlineEventList, code)) {
                // 注销代码
                elem.href = 'javascript:void(0)';
                hiidoStat('', '', code, '');
                // console.log('拦截可疑事件:' + code);
            }
        }

        // 递归扫描上级元素
        scanElement(elem.parentNode);
    }

    /**
     * 主动防御 MutationEvent
     * 使用 MutationObserver 进行静态插入脚本的拦截
     * @return {[type]} [description]
     */
    function interceptionStaticScript() {
        var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;
        // 该构造函数用来实例化一个新的 Mutation 观察者对象 Mutation 观察者对象能监听在某个范围内的 DOM 树变化
        if (!MutationObserver) return;
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                var nodes = mutation.addedNodes;

                // 逐个遍历
                for (var i = 0; i < nodes.length; i++) {
                    var node = nodes[i];
                    // 扫描 script 与 iframe
                    if (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME') {
                        // 拦截到可疑iframe
                        if (node.tagName === 'IFRAME' && node.src && !filter(safeList, node.src)) {
                            node.parentNode && node.parentNode.removeChild(node);
                            hiidoStat('', 'insertIFRMAETag', '', node.src);
                            // console.log('拦截到可疑iframe', node.src);

                        } else if (node.src) {
                            // 只放行白名单
                            if (!filter(safeList, node.src)) {
                                node.parentNode && node.parentNode.removeChild(node);
                                hiidoStat(node.src, 'insertScriptTag', '', '');
                                // console.log('拦截可疑静态脚本:', node.src);
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
        document.addEventListener('DOMNodeInserted', function(e) {
            var node = e.target;

            if (!filter(safeList, node.src) || filter(filterClassName, node.className) || filter(filterProName, node.name) || filter(filterNodeId, node.id)) {
                node.parentNode.removeChild(node);
                hiidoStat(node.src ? node.src : '', node.className ? node.className : '', node.name ? node.name : '', '');
                // console.log('拦截可以创建节点：'+ node.nodeName + ',id为：'+(node.id?node.id:''));
            }
        }, true);
    }

    /**
     * 重写单个 window 窗口的 document.write 属性
     * @param  {[BOM]} window [浏览器window对象]
     * @return {[type]}       [description]
     */
    function resetDocumentWrite(window) {
        var overWrite = window.document.write;

        window.document.write = function(string) {
            if (filter(filterClassName, string) || filter(filterProName, string) || filter(filterNodeId, string)) {
                hiidoStat('', string, '', '');
                // console.log('拦截可疑模块:', string);
                return;
            }
            overWrite.apply(document, arguments);
        };
    }

    /**
     * 重写单个 window 窗口的 setAttribute 属性
     * @param  {[BOM]} window [浏览器window对象]
     * @return {[type]} [description]
     */
    function resetSetAttribute(window) {
        var overWrite = window.Element.prototype.setAttribute;

        window.Element.prototype.setAttribute = function(name, value) {
            if (this.tagName === 'SCRIPT' && /^src$/i.test(name)) {
                if (!filter(safeList, value)) {
                    hiidoStat(value, '', '', '');
                    // console.log('拦截可疑模块:', value);
                    return;
                }
            }
            overWrite.apply(this, arguments);
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

        resetSetAttribute(window);
        resetDocumentWrite(window);

        // MutationObserver 的不同兼容性写法
        var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;
        if (!MutationObserver) return;
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                var nodes = mutation.addedNodes;

                for (var i = 0; i < nodes.length; i++) {
                    var node = nodes[i];

                    // 给生成的 iframe 里环境也装上重写的钩子
                    if (node.tagName === 'IFRAME') {
                        node.contentWindow && installHook(node.contentWindow);
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
        try {
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
        } catch (e) {
            // console && console.log(e);
        }

    }
    /**
     * 操作cookie的方法
     */
    var s__cookie = {
        set: function(key, val) {
            var date = new Date();
            date.setTime(date.getTime() + 60 * 1000); //格式化为cookie识别的时间
            document.cookie = key + '=' + val + ';expires=' + date.toGMTString(); //设置cookie
        },
        get: function(key) {
            var getCookie = document.cookie.replace(/[ ]/g, '');
            var arrCookie = getCookie.split(';');
            var tips;
            for (var i = 0; i < arrCookie.length; i++) {
                var arr = arrCookie[i].split('=');
                if (key == arr[0]) {
                    tips = arr[1];
                    break;
                }
            }
            return tips;
        }
    };
    /**
     * 重定向iframe url（页面被iframe包裹）
     */
    function redirectionIframeSrc() {
        var flag = 'type';

        if (self !== top) {
            var parentUrl = document.referrer,
                length = safeList.length,
                i = 0;

            for (; i < length; i++) {
                // 建立白名单正则
                var reg = new RegExp(safeList[i], 'i');

                // 存在白名单中，放行
                if (reg.test(parentUrl)) {
                    return;
                }
            }

            var url = location.href;
            var parts = url.split('#');
            if (location.search) {
                parts[0] += '&' + flag + '=3';
            } else {
                parts[0] += '?' + flag + '=3';
            }
            try {
                if (!s__cookie.get('HtpLocTmp')) {
                    top.location.href = parts.join('#');
                    //cookie记录这次跳转的时间点
                    s__cookie.set('HtpLocTmp', '1');
                }
                hiidoStat('', '', '', parentUrl);
                // console.log('页面被嵌入iframe中:', parentUrl);
            } catch (e) {
                hiidoStat('', '', '', parentUrl);
                // console.log('页面被嵌入iframe中, 重定向失败');
            }
        }
    }

    // 初始化方法
    httphijack.init = function() {
        interceptionDynamicScript();
        scanInlineElement && inlineEventFilter();
        interceptionStaticScript();
        lockCallAndApply();
        defenseIframe();
        redirectionIframeSrc();
    };


    if (typeof define === 'function' && define.amd) {
        define('httphijack', [], function() {
            return httphijack;
        });
    } else {
        window.httphijack = httphijack;
    }

    // 不支持 IE8-
    if (navigator.appName == 'Microsoft Internet Explorer' && (navigator.appVersion.split(';')[1].replace(/[ ]/g, '') == 'MSIE6.0' || navigator.appVersion.split(';')[1].replace(/[ ]/g, '') == 'MSIE7.0' || navigator.appVersion.split(';')[1].replace(/[ ]/g, '') == 'MSIE8.0')) {
        return;
    } else {
        if (!(/localhost/i).test(location.host) || (navigator.appName === 'Microsoft Internet Explorer' && (navigator.appVersion.match(/7./i) !== '7.' || navigator.appVersion.match(/8./i) !== '8.'))) {
            httphijack.init();
        }
    }
})(window);