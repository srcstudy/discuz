(window.webpackJsonp=window.webpackJsonp||[]).push([["pages-topic-topic"],{"03ba":function(t,e,i){"use strict";i.r(e);var s=i("d2ab"),n=i.n(s);for(var o in s)["default"].indexOf(o)<0&&function(t){i.d(e,t,(function(){return s[t]}))}(o);e.default=n.a},"17cd":function(t,e,i){"use strict";(function(t){var s;i.d(e,"b",(function(){return n})),i.d(e,"c",(function(){return o})),i.d(e,"a",(function(){return s}));try{s={quiPage:i("29c4").default,quiIcon:i("895d").default}}catch(e){if(-1===e.message.indexOf("Cannot find module")||-1===e.message.indexOf(".vue"))throw e;t.error(e.message),t.error("1. 排查组件名称拼写是否正确"),t.error("2. 排查组件是否符合 easycom 规范，文档：https://uniapp.dcloud.net.cn/collocation/pages?id=easycom"),t.error("3. 若组件不符合 easycom 规范，需手动引入，并在 components 中注册该组件")}var n=function(){var t=this,e=t.$createElement,i=t._self._c||e;return i("qui-page",{staticClass:"pages-topic",attrs:{"data-qui-theme":t.theme}},[i("v-uni-view",{staticClass:"qui-topic-page-box"},[i("v-uni-view",{staticClass:"qui-topic-page-box__hd"},[i("v-uni-view",{staticClass:"qui-topic-page-box__hd__sc"},[i("qui-icon",{staticClass:"icon-search",attrs:{name:"icon-search",size:"30"}}),i("v-uni-input",{attrs:{type:"text","placeholder-class":"input-placeholder","confirm-type":"search",placeholder:t.i18n.t("topic.searchTopic")},on:{input:function(e){arguments[0]=e=t.$handleEvent(e),t.searchInput.apply(void 0,arguments)}},model:{value:t.searchValue,callback:function(e){t.searchValue=e},expression:"searchValue"}})],1)],1)],1),t.shouldShow?i("v-uni-view",{staticClass:"topic-content-item",on:{click:function(e){arguments[0]=e=t.$handleEvent(e),t.returnToPost(-1)}}},[i("v-uni-view",{staticClass:"topic-content-item_title"},[t._v("#"+t._s(t.searchValue)+"#")]),i("v-uni-view",{staticClass:"topic-content-item_heat"},[t._v(t._s(t.i18n.t("topic.newTopic")))])],1):t._e(),t._l(t.topics,(function(e,s){return i("v-uni-view",{key:s,staticClass:"topic-content-item",on:{click:function(e){arguments[0]=e=t.$handleEvent(e),t.returnToPost(s)}}},[i("v-uni-view",{staticClass:"topic-content-item-box"},[i("v-uni-view",{staticClass:"topic-content-item_title"},[t._v("#"+t._s(e.content)+"#")]),1===e.recommended?i("v-uni-view",{staticClass:"topic-content-item_recoment"},[i("qui-icon",{attrs:{name:"icon-tuijian",color:"#1878f3",size:"34"}})],1):t._e()],1),i("v-uni-view",{staticClass:"topic-content-item_heat"},[t._v(t._s(e.view_count)+t._s(t.i18n.t("topic.hot")))])],1)}))],2)},o=[]}).call(this,i("5a52").default)},"245f":function(t,e,i){"use strict";(function(e){var s=i("4ea4").default,n=s(i("6f74")),o=i("b95e"),a=s(i("4c82"));t.exports={mixins:[n.default,a.default],methods:{getForum:function(){var t=this;this.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]).then((function(e){e&&(t.forum=e)}))},jump2PhoneLoginPage:function(){uni.redirectTo({url:"/pages/user/phone-login"})},jump2PhoneLoginRegisterPage:function(){uni.redirectTo({url:"/pages/user/phone-login-register"})},jump2LoginPage:function(){uni.redirectTo({url:"/pages/user/login"})},jump2RegisterPage:function(){uni.redirectTo({url:"/pages/user/register"})},jump2RegisterExtendPage:function(){uni.redirectTo({url:"/pages/user/supple-mentary"})},jump2LoginBindPage:function(){uni.redirectTo({url:"/pages/user/login-bind"})},jump2RegisterBindPage:function(){uni.redirectTo({url:"/pages/user/register-bind"})},jump2LoginBindPhonePage:function(){uni.redirectTo({url:"/pages/user/login-bind-phone"})},jump2RegisterBindPhonePage:function(){uni.redirectTo({url:"/pages/user/register-bind-phone"})},jump2findpwdPage:function(){uni.navigateTo({url:"/pages/modify/findpwd?pas=reset_pwd"})},mpLoginMode:function(){this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&this.jump2LoginPage(),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&(uni.setStorageSync("register",1),uni.setStorageSync("isSend",!0),this.$store.getters["session/get"]("auth").open())},h5LoginMode:function(){a.default.isWeixin().isWeixin?(this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&(uni.setStorageSync("register",1),this.$store.dispatch("session/wxh5Login"))):(this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}))},refreshmpParams:function(){var t=this;uni.login({success:function(i){if("login:ok"===i.errMsg){var s=i.code;uni.getUserInfo({success:function(e){var i={data:{attributes:{js_code:s,iv:e.iv,encryptedData:e.encryptedData}}};t.$store.dispatch("session/setParams",i)},fail:function(t){e.log(t)}})}},fail:function(t){e.log(t)}})},mpLogin:function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0;uni.setStorageSync("register",t),uni.setStorageSync("isSend",!0),this.$store.getters["session/get"]("auth").open()},wxh5Login:function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0,e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:0;uni.setStorageSync("register",t),uni.setStorageSync("rebind",e),uni.setStorageSync("h5_wechat_login",1),this.$store.dispatch("session/wxh5Login")},getLoginParams:function(t,e){var i=t;if(""===t.data.attributes.username)uni.showToast({icon:"none",title:this.i18n.t("user.usernameEmpty"),duration:2e3});else if(""===t.data.attributes.password)uni.showToast({icon:"none",title:this.i18n.t("user.passwordEmpty"),duration:2e3});else{var s=uni.getStorageSync("token");""!==s&&(i.data.attributes.token=s),this.login(i,e)}},getLoginBindParams:function(t,e){var i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:0;this.refreshmpParams();var s=t;if(""===t.data.attributes.username)uni.showToast({icon:"none",title:this.i18n.t("user.usernameEmpty"),duration:2e3});else if(""===t.data.attributes.password)uni.showToast({icon:"none",title:this.i18n.t("user.passwordEmpty"),duration:2e3});else{1===i&&(s.data.attributes.rebind=1);var n=uni.getStorageSync("token");""!==n&&(s.data.attributes.token=n),this.login(s,e)}},login:function(t,i){var s=this;this.$store.dispatch("session/h5Login",t).then((function(t){if(t&&t.data&&t.data.data&&t.data.data.id&&(s.logind(),s.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]).then((function(t){t&&t.set_site&&t.set_site.site_mode!==o.SITE_PAY&&uni.getStorage({key:"page",success:function(t){uni.redirectTo({url:t.data})}}),t&&t.set_site&&t.set_site.site_mode===o.SITE_PAY&&s.user&&!s.user.paid&&uni.redirectTo({url:"/pages/site/info"})})),uni.showToast({title:i,duration:2e3})),t&&t.data&&t.data.errors){if("401"===t.data.errors[0].status||"402"===t.data.errors[0].status||"500"===t.data.errors[0].status){var e=s.i18n.t("core.".concat(t.data.errors[0].code));uni.showToast({icon:"none",title:e,duration:2e3})}if("403"===t.data.errors[0].status||"422"===t.data.errors[0].status){var n=s.i18n.t("core.".concat(t.data.errors[0].code))||s.i18n.t(t.data.errors[0].detail[0]);uni.showToast({icon:"none",title:n,duration:2e3})}}})).catch((function(t){return e.log(t)}))}}}}).call(this,i("5a52").default)},2794:function(t,e,i){var s=i("ea76");"string"==typeof s&&(s=[[t.i,s,""]]),s.locals&&(t.exports=s.locals);(0,i("4f06").default)("dd1ace84",s,!0,{sourceMap:!1,shadowMode:!1})},"368d":function(t,e,i){t.exports=i.p+"static/img/msg-warning.f35ce51f.svg"},"4f7d":function(t,e,i){"use strict";var s=i("17cd");i.d(e,"a",(function(){return s.a})),i.d(e,"b",(function(){return s.b})),i.d(e,"c",(function(){return s.c}))},"6a92":function(t,e,i){"use strict";var s=i("2794");i.n(s).a},"6f74":function(t,e,i){"use strict";var s=i("b95e");t.exports={computed:{user:function(){var t=this.$store.getters["session/get"]("userId");return t?this.$store.getters["jv/get"]("users/".concat(t)):{}}},methods:{getUserInfo:function(){var t=arguments.length>0&&void 0!==arguments[0]&&arguments[0],e=(new Date).getTime(),i=uni.getStorageSync(s.STORGE_GET_USER_TIME);if(t||(e-i)/1e3>60){var n={include:"groups,wechat"},o=this.$store.getters["session/get"]("userId");this.$store.commit("jv/deleteRecord",{_jv:{type:"users",id:o}}),this.$store.dispatch("jv/get",["users/".concat(o),{params:n}]).then((function(){return uni.$emit("updateNotiNum")})),uni.setStorageSync(s.STORGE_GET_USER_TIME,(new Date).getTime())}},logind:function(){var t=this,e=this.$store.getters["session/get"]("userId");if(e){this.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]);this.$store.dispatch("jv/get",["users/".concat(e),{params:{include:"groups,wechat"}}]).then((function(e){t.$u.event.$emit("logind",e)})),this.$store.dispatch("forum/setError",{loading:!1})}}}}},"8b11":function(t,e,i){"use strict";i.r(e);var s=i("4f7d"),n=i("03ba");for(var o in n)["default"].indexOf(o)<0&&function(t){i.d(e,t,(function(){return n[t]}))}(o);i("6a92");var a=i("f0c5"),r=Object(a.a)(n.default,s.b,s.c,!1,null,"5d529def",null,!1,s.a,void 0);e.default=r.exports},b469:function(t,e){t.exports={computed:{forums:function(){return this.$store.getters["jv/get"]("forums/1")}}}},d2ab:function(t,e,i){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.default=void 0,i("99af"),i("4160"),i("159b");var s=null,n={data:function(){return{shouldShow:!1,topics:[],searchValue:"",pageNum:1,pageSize:20,meta:{},types:1}},methods:{searchInput:function(){var t=this;this.searchValue?(this.types="",this.shouldShow=!0):(this.types=1,this.shouldShow=!1),clearTimeout(s),s=setTimeout((function(){t.pageNum=1,t.loadTopics()}),300)},returnToPost:function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0,e={};e.keywords=-1===t?this.searchValue:this.topics[t].content,uni.$emit("clickTopic",e),uni.navigateBack()},loadTopics:function(){var t=this,e={"filter[recommended]":this.types,"page[number]":this.pageNum,"page[limit]":this.pageSize,sort:"recommended"};this.searchValue&&(e["filter[content]"]=this.searchValue),this.$store.dispatch("jv/get",["topics",{params:e}]).then((function(e){t.meta=e._jv.json.links,delete e._jv,t.pageNum>1?t.topics=t.topics.concat(e):t.topics=e,t.topics.forEach((function(e){e.content===t.searchValue&&(t.shouldShow=!1)}))}))}},onLoad:function(){this.loadTopics()},onReachBottom:function(){this.meta.next&&(this.pageNum+=1,this.loadTopics())}};e.default=n},e972:function(t,e,i){t.exports=i.p+"static/img/msg-404.3ba2611f.svg"},ea76:function(t,e,i){(e=i("24fb")(!1)).push([t.i,'@charset "UTF-8";\n/**\n * 这里是uni-app内置的常用样式变量\n *\n * uni-app 官方扩展插件及插件市场（https://ext.dcloud.net.cn）上很多三方插件均使用了这些样式变量\n * 如果你是插件开发者，建议你使用scss预处理，并在插件代码中直接使用这些变量（无需 import 这个文件），方便用户通过搭积木的方式开发整体风格一致的App\n *\n */\n/**\n * 如果你是App开发者（插件使用者），你可以通过修改这些变量来定制自己的插件主题，实现自定义主题功能\n *\n * 如果你的项目同样使用了scss预处理，你也可以直接在你的 scss 代码中使用如下变量，同时无需 import 这个文件\n */\n/* 颜色变量 */\n/* 行为相关颜色 */\n/* 文字基本颜色 */\n/* 背景颜色 */\n/* 边框颜色 */\n/* 尺寸变量 */\n/* 文字尺寸 */\n/* 图片尺寸 */\n/* Border Radius */\n/* 水平间距 */\n/* 垂直间距 */\n/* 透明度 */\n/* 文章场景相关 */\n/* eg:\n  .container {\n    color: --color(BG-1);\n  }\n*/.topic-content-item[data-v-5d529def]{display:-webkit-box;display:-webkit-flex;display:flex;padding:%?35?% 0;margin:0 %?40?%;-webkit-box-pack:justify;-webkit-justify-content:space-between;justify-content:space-between;border-bottom:%?0.5?% solid var(--qui-BOR-ED)}.topic-content-item-box[data-v-5d529def]{display:-webkit-box;display:-webkit-flex;display:flex;max-width:%?500?%}.topic-content-item_title[data-v-5d529def]{max-width:%?420?%;font-size:%?30?%;font-weight:600;color:var(--qui-FC-333);word-break:break-all}.topic-content-item_recoment[data-v-5d529def]{top:%?35?%;left:%?253?%;width:%?34?%;height:%?34?%;margin-left:%?20?%;font-size:%?22?%;line-height:%?34?%;color:#fff;text-align:center;-webkit-align-self:center;align-self:center}.topic-content-item_heat[data-v-5d529def]{top:%?35?%;left:%?15?%;font-size:%?24?%;color:var(--qui-BOR-AAA);white-space:nowrap}.qui-topic-page-box[data-v-5d529def]{width:100%;height:100%;background-color:var(--qui-BG-2)}.qui-topic-page-box__hd[data-v-5d529def]{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-align:center;-webkit-align-items:center;align-items:center;height:%?80?%;padding:%?20?% %?40?%}.qui-topic-page-box__hd__sc[data-v-5d529def]{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-align:center;-webkit-align-items:center;align-items:center;width:100%;height:100%;padding:0 %?10?%;background-color:var(--qui-BG-IT);border-radius:%?7?%}.qui-topic-page-box__hd__sc .icon-search[data-v-5d529def]{margin:0 %?10?%;color:#bbb}.qui-topic-page-box__hd__sc uni-input[data-v-5d529def]{width:100%;height:100%}.qui-topic-page-box__hd__sc[data-v-5d529def] uni-input .input-placeholder{font-size:%?30?%;color:var(--qui-FC-C6)}.qui-topic-page-box__lst .scroll-Y[data-v-5d529def]{height:calc(100vh - %?292?%)}.qui-topic-page-box__lst .scroll-Y .loading-text[data-v-5d529def]{height:%?100?%;font-size:%?28?%;line-height:%?100?%;color:var(--qui-FC-AAA);text-align:center}.qui-topic-page-box__lst .scroll-Y .loading-text__cont[data-v-5d529def]{margin-left:%?20?%}.qui-topic-page-box__ft[data-v-5d529def]{position:absolute;bottom:0;width:100%;padding:%?40?%;background-color:var(--qui-BG-2);box-sizing:border-box}.qui-topic-page-box__ft[data-v-5d529def] .qui-button--button[size="large"]{border-radius:%?5?%}.qui-topic-page-box__ft[data-v-5d529def] .qui-button--button[disabled]{color:#7d7979;background-color:#fff}',""]),t.exports=e}}]);