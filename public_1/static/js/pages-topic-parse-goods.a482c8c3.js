(window.webpackJsonp=window.webpackJsonp||[]).push([["pages-topic-parse-goods"],{"1bdf":function(t,e,i){"use strict";var s=i("a5b5");i.d(e,"a",(function(){return s.a})),i.d(e,"b",(function(){return s.b})),i.d(e,"c",(function(){return s.c}))},"245f":function(t,e,i){"use strict";(function(e){var s=i("4ea4").default,n=s(i("6f74")),o=i("b95e"),r=s(i("4c82"));t.exports={mixins:[n.default,r.default],methods:{getForum:function(){var t=this;this.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]).then((function(e){e&&(t.forum=e)}))},jump2PhoneLoginPage:function(){uni.redirectTo({url:"/pages/user/phone-login"})},jump2PhoneLoginRegisterPage:function(){uni.redirectTo({url:"/pages/user/phone-login-register"})},jump2LoginPage:function(){uni.redirectTo({url:"/pages/user/login"})},jump2RegisterPage:function(){uni.redirectTo({url:"/pages/user/register"})},jump2RegisterExtendPage:function(){uni.redirectTo({url:"/pages/user/supple-mentary"})},jump2LoginBindPage:function(){uni.redirectTo({url:"/pages/user/login-bind"})},jump2RegisterBindPage:function(){uni.redirectTo({url:"/pages/user/register-bind"})},jump2LoginBindPhonePage:function(){uni.redirectTo({url:"/pages/user/login-bind-phone"})},jump2RegisterBindPhonePage:function(){uni.redirectTo({url:"/pages/user/register-bind-phone"})},jump2findpwdPage:function(){uni.navigateTo({url:"/pages/modify/findpwd?pas=reset_pwd"})},mpLoginMode:function(){this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&this.jump2LoginPage(),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&(uni.setStorageSync("register",1),uni.setStorageSync("isSend",!0),this.$store.getters["session/get"]("auth").open())},h5LoginMode:function(){r.default.isWeixin().isWeixin?(this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&(uni.setStorageSync("register",1),this.$store.dispatch("session/wxh5Login"))):(this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}))},refreshmpParams:function(){var t=this;uni.login({success:function(i){if("login:ok"===i.errMsg){var s=i.code;uni.getUserInfo({success:function(e){var i={data:{attributes:{js_code:s,iv:e.iv,encryptedData:e.encryptedData}}};t.$store.dispatch("session/setParams",i)},fail:function(t){e.log(t)}})}},fail:function(t){e.log(t)}})},mpLogin:function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0;uni.setStorageSync("register",t),uni.setStorageSync("isSend",!0),this.$store.getters["session/get"]("auth").open()},wxh5Login:function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0,e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:0;uni.setStorageSync("register",t),uni.setStorageSync("rebind",e),uni.setStorageSync("h5_wechat_login",1),this.$store.dispatch("session/wxh5Login")},getLoginParams:function(t,e){var i=t;if(""===t.data.attributes.username)uni.showToast({icon:"none",title:this.i18n.t("user.usernameEmpty"),duration:2e3});else if(""===t.data.attributes.password)uni.showToast({icon:"none",title:this.i18n.t("user.passwordEmpty"),duration:2e3});else{var s=uni.getStorageSync("token");""!==s&&(i.data.attributes.token=s),this.login(i,e)}},getLoginBindParams:function(t,e){var i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:0;this.refreshmpParams();var s=t;if(""===t.data.attributes.username)uni.showToast({icon:"none",title:this.i18n.t("user.usernameEmpty"),duration:2e3});else if(""===t.data.attributes.password)uni.showToast({icon:"none",title:this.i18n.t("user.passwordEmpty"),duration:2e3});else{1===i&&(s.data.attributes.rebind=1);var n=uni.getStorageSync("token");""!==n&&(s.data.attributes.token=n),this.login(s,e)}},login:function(t,i){var s=this;this.$store.dispatch("session/h5Login",t).then((function(t){if(t&&t.data&&t.data.data&&t.data.data.id&&(s.logind(),s.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]).then((function(t){t&&t.set_site&&t.set_site.site_mode!==o.SITE_PAY&&uni.getStorage({key:"page",success:function(t){uni.redirectTo({url:t.data})}}),t&&t.set_site&&t.set_site.site_mode===o.SITE_PAY&&s.user&&!s.user.paid&&uni.redirectTo({url:"/pages/site/info"})})),uni.showToast({title:i,duration:2e3})),t&&t.data&&t.data.errors){if("401"===t.data.errors[0].status||"402"===t.data.errors[0].status||"500"===t.data.errors[0].status){var e=s.i18n.t("core.".concat(t.data.errors[0].code));uni.showToast({icon:"none",title:e,duration:2e3})}if("403"===t.data.errors[0].status||"422"===t.data.errors[0].status){var n=s.i18n.t("core.".concat(t.data.errors[0].code))||s.i18n.t(t.data.errors[0].detail[0]);uni.showToast({icon:"none",title:n,duration:2e3})}}})).catch((function(t){return e.log(t)}))}}}}).call(this,i("5a52").default)},"368d":function(t,e,i){t.exports=i.p+"static/img/msg-warning.f35ce51f.svg"},"3b0f":function(t,e,i){t.exports=i.p+"static/img/youzan.6fd99004.svg"},"40f9":function(t,e,i){var s=i("df86");"string"==typeof s&&(s=[[t.i,s,""]]),s.locals&&(t.exports=s.locals);(0,i("4f06").default)("8c86c1b8",s,!0,{sourceMap:!1,shadowMode:!1})},6708:function(t,e,i){"use strict";var s=i("40f9");i.n(s).a},"6f74":function(t,e,i){"use strict";var s=i("b95e");t.exports={computed:{user:function(){var t=this.$store.getters["session/get"]("userId");return t?this.$store.getters["jv/get"]("users/".concat(t)):{}}},methods:{getUserInfo:function(){var t=arguments.length>0&&void 0!==arguments[0]&&arguments[0],e=(new Date).getTime(),i=uni.getStorageSync(s.STORGE_GET_USER_TIME);if(t||(e-i)/1e3>60){var n={include:"groups,wechat"},o=this.$store.getters["session/get"]("userId");this.$store.commit("jv/deleteRecord",{_jv:{type:"users",id:o}}),this.$store.dispatch("jv/get",["users/".concat(o),{params:n}]).then((function(){return uni.$emit("updateNotiNum")})),uni.setStorageSync(s.STORGE_GET_USER_TIME,(new Date).getTime())}},logind:function(){var t=this,e=this.$store.getters["session/get"]("userId");if(e){this.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]);this.$store.dispatch("jv/get",["users/".concat(e),{params:{include:"groups,wechat"}}]).then((function(e){t.$u.event.$emit("logind",e)})),this.$store.dispatch("forum/setError",{loading:!1})}}}}},"7a2f":function(t,e,i){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.default=void 0,i("99af"),i("c975");var s={data:function(){return{link:"",type:"",operating:"",threadId:"",isSaveText:"0"}},onLoad:function(t){this.type=t.type,this.operating=t.operating,this.threadId=t.threadId,this.isSaveText=t.isSaveText||"0"},methods:{handleNext:function(){var t=this;if(""===this.link)uni.showToast({icon:"none",title:this.i18n.t("topic.goodsLinkEmpty"),duration:2e3});else{var e={_jv:{type:"goods/analysis"},type:"analysis",address:this.link};this.$store.dispatch("jv/post",e).then((function(e){e&&e._jv&&(t.$store.dispatch("session/setGood",e),"edit"===t.operating&&""!==t.threadId?uni.redirectTo({url:"/topic/post?type=".concat(t.type,"&goodsId=").concat(e._jv.id,"&threadId=").concat(t.threadId,"&operating=edit")}):uni.redirectTo({url:"/topic/post?type=".concat(t.type,"&goodsId=").concat(e._jv.id,"&isSaveText=").concat(t.isSaveText)}),t.link="")})).catch((function(e){e&&e.data&&e.data.code&&-1!==e.data.code.indexOf("cURL error")&&uni.showToast({icon:"none",title:t.i18n.t("topic.goodsErrorTip"),duration:1e3}),e&&e.data&&e.data.errors&&(uni.showToast({icon:"none",title:e.data.errors[0].detail[0],duration:2e3}),t.link="")}))}}}};e.default=s},"8b9c":function(t,e,i){t.exports=i.p+"static/img/tmall.082dd4ed.svg"},"9d11":function(t,e,i){"use strict";i.r(e);var s=i("1bdf"),n=i("e75b");for(var o in n)["default"].indexOf(o)<0&&function(t){i.d(e,t,(function(){return n[t]}))}(o);i("6708");var r=i("f0c5"),a=Object(r.a)(n.default,s.b,s.c,!1,null,"28c80de4",null,!1,s.a,void 0);e.default=a.exports},a5b5:function(t,e,i){"use strict";(function(t){var s;i.d(e,"b",(function(){return n})),i.d(e,"c",(function(){return o})),i.d(e,"a",(function(){return s}));try{s={quiPage:i("29c4").default,quiButton:i("8397").default}}catch(e){if(-1===e.message.indexOf("Cannot find module")||-1===e.message.indexOf(".vue"))throw e;t.error(e.message),t.error("1. 排查组件名称拼写是否正确"),t.error("2. 排查组件是否符合 easycom 规范，文档：https://uniapp.dcloud.net.cn/collocation/pages?id=easycom"),t.error("3. 若组件不符合 easycom 规范，需手动引入，并在 components 中注册该组件")}var n=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("qui-page",{staticClass:"parse-goods",attrs:{"data-qui-theme":t.theme}},[s("v-uni-view",{staticClass:"parse-goods-box"},[s("v-uni-view",{staticClass:"parse-goods-box-title"},[t._v(t._s(t.i18n.t("topic.supportedLink")))]),s("v-uni-view",{staticClass:"parse-goods-box-image"},[s("v-uni-view",{staticClass:"box"},[s("v-uni-image",{staticClass:"image",attrs:{"lazy-load":!0,src:i("e230")}}),s("v-uni-text",[t._v(t._s(t.i18n.t("topic.jingdong")))])],1),s("v-uni-view",{staticClass:"box"},[s("v-uni-image",{staticClass:"image",attrs:{"lazy-load":!0,src:i("df10")}}),s("v-uni-text",[t._v(t._s(t.i18n.t("topic.taobao")))])],1),s("v-uni-view",{staticClass:"box"},[s("v-uni-image",{staticClass:"image",attrs:{"lazy-load":!0,src:i("8b9c")}}),s("v-uni-text",[t._v(t._s(t.i18n.t("topic.tmall")))])],1),s("v-uni-view",{staticClass:"box"},[s("v-uni-image",{staticClass:"image",attrs:{"lazy-load":!0,src:i("aa20")}}),s("v-uni-text",[t._v(t._s(t.i18n.t("topic.pinduoduo")))])],1),s("v-uni-view",{staticClass:"box"},[s("v-uni-image",{staticClass:"image",attrs:{"lazy-load":!0,src:i("3b0f")}}),s("v-uni-text",[t._v(t._s(t.i18n.t("topic.youzan")))])],1)],1),s("v-uni-textarea",{staticClass:"parse-goods-box-con",attrs:{maxlength:"49999",placeholder:t.i18n.t("topic.goodsLink")},model:{value:t.link,callback:function(e){t.link=e},expression:"link"}}),s("qui-button",{staticClass:"parse-goods-box-btn",attrs:{type:"primary",size:"large"},on:{click:function(e){arguments[0]=e=t.$handleEvent(e),t.handleNext.apply(void 0,arguments)}}},[t._v("下一步")])],1)],1)},o=[]}).call(this,i("5a52").default)},aa20:function(t,e,i){t.exports=i.p+"static/img/pinduoduo.441426cf.svg"},b469:function(t,e){t.exports={computed:{forums:function(){return this.$store.getters["jv/get"]("forums/1")}}}},df10:function(t,e,i){t.exports=i.p+"static/img/taobao.39fb5986.svg"},df86:function(t,e,i){(e=i("24fb")(!1)).push([t.i,'@charset "UTF-8";\n/**\n * 这里是uni-app内置的常用样式变量\n *\n * uni-app 官方扩展插件及插件市场（https://ext.dcloud.net.cn）上很多三方插件均使用了这些样式变量\n * 如果你是插件开发者，建议你使用scss预处理，并在插件代码中直接使用这些变量（无需 import 这个文件），方便用户通过搭积木的方式开发整体风格一致的App\n *\n */\n/**\n * 如果你是App开发者（插件使用者），你可以通过修改这些变量来定制自己的插件主题，实现自定义主题功能\n *\n * 如果你的项目同样使用了scss预处理，你也可以直接在你的 scss 代码中使用如下变量，同时无需 import 这个文件\n */\n/* 颜色变量 */\n/* 行为相关颜色 */\n/* 文字基本颜色 */\n/* 背景颜色 */\n/* 边框颜色 */\n/* 尺寸变量 */\n/* 文字尺寸 */\n/* 图片尺寸 */\n/* Border Radius */\n/* 水平间距 */\n/* 垂直间距 */\n/* 透明度 */\n/* 文章场景相关 */\n/* eg:\n  .container {\n    color: --color(BG-1);\n  }\n*/.parse-goods[data-v-28c80de4]{font-size:%?28?%;color:var(--qui-FC-000);background-color:var(--qui-BG-2)}.parse-goods-box[data-v-28c80de4]{margin:%?40?%}.parse-goods-box-title[data-v-28c80de4]{color:var(--qui-FC-000)}.parse-goods-box-image[data-v-28c80de4]{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-orient:horizontal;-webkit-box-direction:normal;-webkit-flex-direction:row;flex-direction:row;-webkit-box-pack:justify;-webkit-justify-content:space-between;justify-content:space-between;-webkit-align-content:flex-start;align-content:flex-start;-webkit-flex-wrap:wrap;flex-wrap:wrap;margin:%?30?% 0 %?14?%;font-size:%?26?%}.parse-goods-box-image .box[data-v-28c80de4]{width:25%;margin-bottom:%?16?%}.parse-goods-box-image .image[data-v-28c80de4]{width:%?40?%;height:%?40?%;margin-right:%?20?%;vertical-align:middle}.parse-goods-box-con[data-v-28c80de4]{width:100%;height:%?400?%;padding:%?20?%;font-size:%?28?%;color:var(--qui-FC-B5);background-color:var(--qui-BG-1);border:%?1?% solid var(--qui-FC-DDD);border-radius:%?10?%;box-sizing:border-box}.parse-goods-box-btn[data-v-28c80de4]{position:absolute;bottom:%?40?%}',""]),t.exports=e},e230:function(t,e,i){t.exports=i.p+"static/img/jingdong.f0c11dce.svg"},e75b:function(t,e,i){"use strict";i.r(e);var s=i("7a2f"),n=i.n(s);for(var o in s)["default"].indexOf(o)<0&&function(t){i.d(e,t,(function(){return s[t]}))}(o);e.default=n.a},e972:function(t,e,i){t.exports=i.p+"static/img/msg-404.3ba2611f.svg"}}]);