(window.webpackJsonp=window.webpackJsonp||[]).push([["pages-modify-rightdetails"],{"245f":function(e,t,i){"use strict";(function(t){var o=i("4ea4"),a=o(i("6f74")),s=i("b95e"),n=o(i("4c82"));e.exports={mixins:[a.default,n.default],methods:{getForum:function(){var e=this;this.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]).then((function(t){t&&(e.forum=t)}))},jump2PhoneLoginPage:function(){uni.redirectTo({url:"/pages/user/phone-login"})},jump2PhoneLoginRegisterPage:function(){uni.redirectTo({url:"/pages/user/phone-login-register"})},jump2LoginPage:function(){uni.redirectTo({url:"/pages/user/login"})},jump2RegisterPage:function(){uni.redirectTo({url:"/pages/user/register"})},jump2LoginBindPage:function(){uni.redirectTo({url:"/pages/user/login-bind"})},jump2RegisterBindPage:function(){uni.redirectTo({url:"/pages/user/register-bind"})},jump2LoginBindPhonePage:function(){uni.redirectTo({url:"/pages/user/login-bind-phone"})},jump2RegisterBindPhonePage:function(){uni.redirectTo({url:"/pages/user/register-bind-phone"})},jump2findpwdPage:function(){uni.navigateTo({url:"/pages/modify/findpwd?pas=reset_pwd"})},mpLoginMode:function(){this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&this.jump2LoginPage(),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&(uni.setStorageSync("register",1),uni.setStorageSync("isSend",!0),this.$store.getters["session/get"]("auth").open())},h5LoginMode:function(){n.default.isWeixin().isWeixin?(this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&(uni.setStorageSync("register",1),this.$store.dispatch("session/wxh5Login"))):(this.forums&&this.forums.set_reg&&0===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}),this.forums&&this.forums.set_reg&&1===this.forums.set_reg.register_type&&this.jump2PhoneLoginRegisterPage(),this.forums&&this.forums.set_reg&&2===this.forums.set_reg.register_type&&uni.navigateTo({url:"/pages/user/login"}))},refreshmpParams:function(){var e=this;uni.login({success:function(i){if("login:ok"===i.errMsg){var o=i.code;uni.getUserInfo({success:function(t){var i={data:{attributes:{js_code:o,iv:t.iv,encryptedData:t.encryptedData}}};e.$store.dispatch("session/setParams",i)},fail:function(e){t.log(e)}})}},fail:function(e){t.log(e)}})},mpLogin:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0;uni.setStorageSync("register",e),uni.setStorageSync("isSend",!0),uni.setStorageSync("isBind",!1),this.$store.getters["session/get"]("auth").open()},wxh5Login:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:0,t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:0;uni.setStorageSync("register",e),uni.setStorageSync("rebind",t),this.$store.dispatch("session/wxh5Login")},getLoginParams:function(e,t){var i=e;if(""===e.data.attributes.username)uni.showToast({icon:"none",title:this.i18n.t("user.usernameEmpty"),duration:2e3});else if(""===e.data.attributes.password)uni.showToast({icon:"none",title:this.i18n.t("user.passwordEmpty"),duration:2e3});else{var o=uni.getStorageSync("token");""!==o&&(i.data.attributes.token=o),this.login(i,t)}},getLoginBindParams:function(e,t){var i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:0;this.refreshmpParams();var o=e;if(""===e.data.attributes.username)uni.showToast({icon:"none",title:this.i18n.t("user.usernameEmpty"),duration:2e3});else if(""===e.data.attributes.password)uni.showToast({icon:"none",title:this.i18n.t("user.passwordEmpty"),duration:2e3});else{1===i&&(o.data.attributes.rebind=1);var a=uni.getStorageSync("token");""!==a&&(o.data.attributes.token=a),this.login(o,t)}},login:function(e,i){var o=this;this.$store.dispatch("session/h5Login",e).then((function(e){if(e&&e.data&&e.data.data&&e.data.data.id&&(o.logind(),o.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]).then((function(e){e&&e.set_site&&e.set_site.site_mode!==s.SITE_PAY&&uni.getStorage({key:"page",success:function(e){t.log("resData",e),uni.redirectTo({url:e.data})}}),e&&e.set_site&&e.set_site.site_mode===s.SITE_PAY&&o.user&&!o.user.paid&&uni.redirectTo({url:"/pages/site/info"})})),uni.showToast({title:i,duration:2e3})),e&&e.data&&e.data.errors){if("401"===e.data.errors[0].status||"402"===e.data.errors[0].status||"500"===e.data.errors[0].status){var a=o.i18n.t("core.".concat(e.data.errors[0].code));uni.showToast({icon:"none",title:a,duration:2e3})}if("403"===e.data.errors[0].status||"422"===e.data.errors[0].status){var n=o.i18n.t(e.data.errors[0].detail[0]);uni.showToast({icon:"none",title:n,duration:2e3})}}})).catch((function(e){return t.log(e)}))}}}}).call(this,i("5a52").default)},"368d":function(e,t,i){e.exports=i.p+"static/img/msg-warning.0c78a551.svg"},"3a75":function(e,t,i){"use strict";(function(e){var o;i.d(t,"b",(function(){return a})),i.d(t,"c",(function(){return s})),i.d(t,"a",(function(){return o}));try{o={quiPage:i("29c4").default,quiCellItem:i("e0ca").default,quiToast:i("2039").default,quiPay:i("35fd").default,quiLoadingCover:i("605f").default,uniPopup:i("1c89").default,quiIcon:i("895d").default}}catch(t){if(-1===t.message.indexOf("Cannot find module")||-1===t.message.indexOf(".vue"))throw t;e.error(t.message),e.error("1. 排查组件名称拼写是否正确"),e.error("2. 排查组件是否符合 easycom 规范，文档：https://uniapp.dcloud.net.cn/collocation/pages?id=easycom"),e.error("3. 若组件不符合 easycom 规范，需手动引入，并在 components 中注册该组件")}var a=function(){var e=this,t=e.$createElement,i=e._self._c||t;return i("qui-page",{staticClass:"details",attrs:{"data-qui-theme":e.theme}},[i("v-uni-view",{staticClass:"details-box"},[i("v-uni-view",{staticClass:"details-box__head"},[e._v(e._s(e.paidusergrouplist.name))]),i("v-uni-view",{staticClass:"details-box__foot"},[i("v-uni-view",{staticClass:"details-box__foot__top"},[e._v(e._s(e.i18n.t("modify.haveauthority")))]),i("v-uni-view",{staticClass:"details-box__foot__center"},e._l(e.paidusergroup,(function(t,o){return i("v-uni-view",{key:o,staticClass:"details-box__foot__center__box"},[e._v(e._s(e.i18n.t("permission."+t.permission.replace(/\./g,"_"))))])})),1)],1),i("v-uni-view",{staticClass:"details-box__bottom"},[i("v-uni-view",{staticClass:"details-box__bottom__top"},[e._v(e._s(e.i18n.t("modify.termofvalidity"))+"：")]),e.oder?i("v-uni-view",{staticClass:"details-box__bottom__bot"},[e._v(e._s(e.i18n.t("modify.purchase"))+e._s(e.paidusergrouplist.days)+"\n        "+e._s(e.i18n.t("modify.daysafter")))]):e._e(),e.oder?e._e():i("v-uni-view",{staticClass:"details-box__bottom__bot"},[e._v(e._s(e.fun(e.expirationTime)))]),e.oder?e._e():i("v-uni-view",{staticClass:"details-box__bottom__bot"},[e._v(e._s(e.sun(e.expirationTime)))])],1),e.oder&&e.forums.paycenter.wxpay_close&&e.paydiisplay?i("v-uni-view",{staticClass:"details-box__purchase purchase-model"},[i("v-uni-view",{staticClass:"details-box__purchase-list money"},[i("qui-cell-item",{attrs:{title:e.pricefun(e.paidusergrouplist.fee),"slot-right":!0,arrow:!1,brief:e.i18n.t("modify.termofvalidity")+e.paidusergrouplist.days+e.i18n.t("modify.days"),border:!1}},[i("v-uni-view",{staticClass:"details-box__purchase-list-btn",on:{click:function(t){arguments[0]=t=e.$handleEvent(t),e.purchase.apply(void 0,arguments)}}},[e._v(e._s(e.i18n.t("modify.immediately")))])],1)],1)],1):e._e(),i("qui-toast",{ref:"toast"}),e.payShowStatus?i("v-uni-view",[i("qui-pay",{ref:"payShow",attrs:{"pay-type-val":e.payTypeVal,"wallet-status":e.user.canWalletPay,"description-show":!0,money:e.paidusergrouplist.fee,balance:Number(e.user.walletBalance),"pay-type":e.i18n.t("modify.purchaseuser"),"pay-type-data":e.payTypeData,"pay-password":e.pwdVal},on:{radioChange:function(t){arguments[0]=t=e.$handleEvent(t),e.radioChange.apply(void 0,arguments)},paysureShow:function(t){arguments[0]=t=e.$handleEvent(t),e.paysureShow.apply(void 0,arguments)},onInput:function(t){arguments[0]=t=e.$handleEvent(t),e.onInput.apply(void 0,arguments)}}}),e._e()],1):e._e(),i("uni-popup",{ref:"codePopup",staticClass:"code-popup-box",attrs:{type:"center"},on:{change:function(t){arguments[0]=t=e.$handleEvent(t),e.codeImgChange.apply(void 0,arguments)}}},[e.qrcodeShow?i("v-uni-view",{staticClass:"code-content"},[i("v-uni-view",{staticClass:"code-title"},[e._v(e._s(e.p.payNow))]),i("v-uni-view",{staticClass:"code-pay-money"},[i("v-uni-view",{staticClass:"code-yuan"},[e._v("￥")]),e._v(e._s(e.price))],1),i("v-uni-view",{staticClass:"code-type-box"},[i("v-uni-view",{staticClass:"code-type-tit"},[e._v(e._s(e.p.payType))]),i("v-uni-view",{staticClass:"code-type"},[i("qui-icon",{staticClass:"code-type-icon",attrs:{name:"icon-wxPay",size:"36",color:"#09bb07"}}),i("v-uni-view",{staticClass:"code-type-text"},[e._v(e._s(e.p.wxPay))])],1)],1),i("v-uni-image",{staticClass:"code-img",attrs:{src:e.codeUrl}}),i("v-uni-view",{staticClass:"code-tip"},[e._v(e._s(e.p.wechatIdentificationQRcode))])],1):e._e()],1),i("uni-popup",{ref:"wechatPopup",attrs:{type:"center"}},[i("uni-popup-dialog",{attrs:{type:"warn",content:e.wechatTip,"before-close":!0},on:{close:function(t){arguments[0]=t=e.$handleEvent(t),e.handleWechatClickCancel.apply(void 0,arguments)},confirm:function(t){arguments[0]=t=e.$handleEvent(t),e.handleWechatClickOk.apply(void 0,arguments)}}})],1)],1)],1)},s=[]}).call(this,i("5a52").default)},"551e":function(e,t,i){"use strict";i.r(t);var o=i("b84b"),a=i.n(o);for(var s in o)["default"].indexOf(s)<0&&function(e){i.d(t,e,(function(){return o[e]}))}(s);t.default=a.a},"6f74":function(e,t,i){"use strict";var o=i("b95e");e.exports={computed:{user:function(){var e=this.$store.getters["session/get"]("userId");return e?this.$store.getters["jv/get"]("users/".concat(e)):{}}},methods:{getUserInfo:function(){var e=arguments.length>0&&void 0!==arguments[0]&&arguments[0],t=(new Date).getTime(),i=uni.getStorageSync(o.STORGE_GET_USER_TIME);if(e||(t-i)/1e3>60){var a={include:"groups,wechat"},s=this.$store.getters["session/get"]("userId");this.$store.commit("jv/deleteRecord",{_jv:{type:"users",id:s}}),this.$store.dispatch("jv/get",["users/".concat(s),{params:a}]).then((function(){return uni.$emit("updateNotiNum")})),uni.setStorageSync(o.STORGE_GET_USER_TIME,(new Date).getTime())}},logind:function(){var e=this,t=this.$store.getters["session/get"]("userId");if(t){this.$store.dispatch("jv/get",["forum",{params:{include:"users"}}]);this.$store.dispatch("jv/get",["users/".concat(t),{params:{include:"groups,wechat"}}]).then((function(t){e.$u.event.$emit("logind",t)})),this.$store.dispatch("forum/setError",{loading:!1})}}}}},"8c24":function(e,t,i){"use strict";i.r(t);var o=i("ee4d"),a=i("551e");for(var s in a)["default"].indexOf(s)<0&&function(e){i.d(t,e,(function(){return a[e]}))}(s);i("ee50");var n=i("f0c5"),r=Object(n.a)(a.default,o.b,o.c,!1,null,"db4da8bc",null,!1,o.a,void 0);t.default=r.exports},"8f17":function(e,t,i){var o=i("a7a6");"string"==typeof o&&(o=[[e.i,o,""]]),o.locals&&(e.exports=o.locals);(0,i("4f06").default)("030e192f",o,!0,{sourceMap:!1,shadowMode:!1})},"913c":function(e,t){e.exports="data:image/png;base64,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"},a7a6:function(e,t,i){(t=i("24fb")(!1)).push([e.i,'@charset "UTF-8";\n/**\n * 这里是uni-app内置的常用样式变量\n *\n * uni-app 官方扩展插件及插件市场（https://ext.dcloud.net.cn）上很多三方插件均使用了这些样式变量\n * 如果你是插件开发者，建议你使用scss预处理，并在插件代码中直接使用这些变量（无需 import 这个文件），方便用户通过搭积木的方式开发整体风格一致的App\n *\n */\n/**\n * 如果你是App开发者（插件使用者），你可以通过修改这些变量来定制自己的插件主题，实现自定义主题功能\n *\n * 如果你的项目同样使用了scss预处理，你也可以直接在你的 scss 代码中使用如下变量，同时无需 import 这个文件\n */\n/* 颜色变量 */\n/* 行为相关颜色 */\n/* 文字基本颜色 */\n/* 背景颜色 */\n/* 边框颜色 */\n/* 尺寸变量 */\n/* 文字尺寸 */\n/* 图片尺寸 */\n/* Border Radius */\n/* 水平间距 */\n/* 垂直间距 */\n/* 透明度 */\n/* 文章场景相关 */\n/* eg:\n  .container {\n    color: --color(BG-1);\n  }\n*/.details[data-v-db4da8bc] {padding-top:0;background:var(--qui-BG-2);box-sizing:border-box}.details[data-v-db4da8bc] .details-box{width:100vw;padding:%?88?% 0 %?150?%;box-sizing:border-box}.details-box[data-v-db4da8bc]{width:100%;height:100%;overflow:hidden;background-color:var(--qui-BG-2);box-sizing:border-box}.details-box__head[data-v-db4da8bc]{width:100%;height:%?97?%;padding-left:%?40?%;font-size:%?36?%;font-weight:700;line-height:%?97?%;color:var(--qui-FC-333);box-sizing:border-box}.details-box__center[data-v-db4da8bc]{width:100%;padding:0 %?40?%;font-size:%?28?%;line-height:%?45?%;box-sizing:border-box}.details-box__foot[data-v-db4da8bc]{width:100%}.details-box__foot__top[data-v-db4da8bc]{width:100%;height:%?31?%;padding-left:%?40?%;font-size:%?28?%;font-weight:700;line-height:%?31?%;color:var(--qui-FC-333);box-sizing:border-box}.details-box__foot__center[data-v-db4da8bc]{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-flex-wrap:wrap;flex-wrap:wrap;width:100%;padding-left:%?40?%;margin-top:%?21?%;box-sizing:border-box}.details-box__bottom[data-v-db4da8bc]{width:100%}.details-box__bottom__top[data-v-db4da8bc]{width:100%;height:%?31?%;padding-left:%?40?%;margin-top:%?50?%;font-size:%?28?%;font-weight:700;line-height:%?31?%;color:var(--qui-FC-333);box-sizing:border-box}.details-box__bottom__bot[data-v-db4da8bc]{width:100%;height:%?40?%;padding:0 %?40?%;margin-top:%?20?%;font-size:%?28?%;font-weight:400;line-height:%?40?%;color:var(--qui-FC-333);box-sizing:border-box}.details-box__purchase[data-v-db4da8bc]{position:fixed;bottom:0;z-index:1;width:100%;height:%?130?%;padding:%?15?% %?40?% 0;background:var(--qui-BG-2);border-top:%?2?% solid var(--qui-BG-ED);box-sizing:border-box}[data-v-db4da8bc] .pay-tip{display:none}[data-v-db4da8bc] .money .cell-item__body__content-title{color:#fa5151}.ele[data-v-db4da8bc]{height:100%}.details-box__foot__center__box[data-v-db4da8bc]{height:%?50?%;min-width:%?136?%;padding:0 %?20?%;margin:%?40?% %?40?% 0 0;font-size:%?24?%;font-weight:400;line-height:%?50?%;color:var(--qui-FC-777);text-align:center;background:var(--qui-BG-F7);border-radius:%?6?%;box-sizing:border-box}.details-box__purchase-list-btn[data-v-db4da8bc]{width:%?230?%;height:%?90?%;font-size:%?28?%;font-weight:400;line-height:%?90?%;color:var(--qui-BG-2);text-align:center;background:var(--qui-RED);border-radius:%?5?%}.code-content[data-v-db4da8bc]{position:fixed;top:10%;left:11%;z-index:22;display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-orient:vertical;-webkit-box-direction:normal;-webkit-flex-direction:column;flex-direction:column;width:78%;padding:%?40?%;background:var(--qui-BG-FFF);border-radius:%?16?%;box-sizing:border-box}.code-content .code-title[data-v-db4da8bc]{text-align:center}.code-content .code-pay-money[data-v-db4da8bc]{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-orient:horizontal;-webkit-box-direction:normal;-webkit-flex-direction:row;flex-direction:row;-webkit-box-pack:center;-webkit-justify-content:center;justify-content:center;padding-top:%?36?%;padding-bottom:%?36?%;font-size:%?70?%}.code-content .code-pay-money .code-yuan[data-v-db4da8bc]{font-size:%?48?%;line-height:%?66?%}.code-type-box[data-v-db4da8bc]{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-orient:horizontal;-webkit-box-direction:normal;-webkit-flex-direction:row;flex-direction:row;-webkit-box-pack:justify;-webkit-justify-content:space-between;justify-content:space-between;padding:%?24?% 0 %?34?%;line-height:%?36?%;border-top:1px solid var(--qui-BG-ED)}.code-type-box .code-type-tit[data-v-db4da8bc]{color:var(--qui-FC-AAA)}.code-type-box .code-type[data-v-db4da8bc]{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-orient:horizontal;-webkit-box-direction:normal;-webkit-flex-direction:row;flex-direction:row}.code-type-box .code-type .code-type-icon[data-v-db4da8bc]{font-size:%?36?%}.code-type-box .code-type .code-type-text[data-v-db4da8bc]{padding-left:%?12?%}.code-img[data-v-db4da8bc]{-webkit-align-self:center;align-self:center;width:%?380?%;height:%?380?%}.code-tip[data-v-db4da8bc]{padding:%?14?% 0 %?20?%}',""]),e.exports=t},b469:function(e,t){e.exports={computed:{forums:function(){return this.$store.getters["jv/get"]("forums/1")}}}},b84b:function(e,t,i){"use strict";(function(e){var o=i("4ea4");i("99af"),i("4160"),i("a9e3"),i("b680"),i("e25e"),i("ac1f"),i("5319"),i("159b"),Object.defineProperty(t,"__esModule",{value:!0}),t.default=void 0;var a=o(i("6f74")),s=o(i("b469")),n=o(i("840a")),r=o(i("245f")),d=o(i("4c82")),u=null,c=null,p={components:{uniPopupDialog:n.default},mixins:[a.default,s.default,r.default],data:function(){return{typenum1:!0,typenum2:!1,payShowStatus:!1,coverLoading:!1,payTypeData:[{name:"微信支付",icon:"icon-wxPay",color:"#09bb07",value:"0"},{name:"钱包支付",icon:"icon-walletPay",color:"#1878f3",value:"1"}],payTypeVal:1,value:"",price:"",orderSn:"",browser:0,isWeixin:!1,isPhone:!1,codeUrl:"",qrcodeShow:!1,groupId:"",paidusergroup:[],oder:"",paidusergrouplist:"",pwdVal:"",expirationTime:"",payingusers:"",rightsice:"",wechatTip:this.i18n.t("discuzq.wechatBind"),paydiisplay:!1}},onLoad:function(e){uni.getSystemInfoSync();this.paydiisplay=!0,this.isWeixin=d.default.isWeixin().isWeixin,this.isPhone=d.default.isWeixin().isPhone,this.browser=1,this.rightsice=e.sice,this.groupId=e.groups,this.payingusers=e.index,"1"===e.sice?this.oder=!0:(this.oder=!1,this.grouplist()),this.allusergroups()},computed:{p:function(){return this.i18n.t("pay")},currentLoginId:function(){var e=this.$store.getters["session/get"]("userId");return parseInt(e,10)},usersid:function(){return this.$store.getters["session/get"]("userId")}},methods:{fun:function(e){var t=e.replace(/T/," ").replace(/Z/,"");if(e)return"".concat(t.substring(0,10).replace(/-/,"年").replace(/-/,"月"),"日")},sun:function(e){var t=new Date,i=new Date(e)-t;if(i>864e5){var o=Math.ceil(i/1e3/60/60/24);return"距离过期还有".concat(o,"天")}if(i<864e5&&i>36e5){var a=parseInt(i/1e3/60/60,0);return"距离过期还有".concat(a,"小时")}if(i<36e5){var s=parseInt(i/1e3/60,0);return"距离过期还有".concat(s,"分钟")}},pricefun:function(e){if(e){var t=e.toFixed(2);return"¥".concat(t,"元")}},allusergroups:function(){var e=this;this.$store.dispatch("jv/get",["groups/".concat(this.groupId),{params:{include:"permission"}}]).then((function(t){e.paidusergroup=t.permission,e.paidusergrouplist=t,e.price=t.fee}))},grouplist:function(){var e=this,t={sort:"created_at","filter[user]":this.usersid,"filter[delete_type]":0,include:"group"};this.$store.dispatch("jv/get",["groups/paid",{params:t}]).then((function(t){t.forEach((function(t){Number(e.groupId)===t.group_id&&(e.expirationTime=t.expiration_time)}))}))},purchase:function(){var e=this;this.payShowStatus=!0,this.payTypeVal=4,this.$nextTick((function(){e.$refs.payShow.payClickShow(e.payTypeVal)}))},radioMyHead:function(e){this.isAnonymous=!e},handleWechatClickOk:function(){this.isWeixin?this.wxh5Login(0,0):uni.showToast({icon:"none",title:this.i18n.t("user.unLogin"),duration:2e3})},handleWechatClickCancel:function(){this.$refs.wechatPopup.close()},onInput:function(e){this.forums.paycenter.wxpay_close?this.value=e:this.value=1,this.creatOrder(this.price,4,this.value,1)},paysureShow:function(e){if(uni.setStorage({key:"page",data:"/pages/modify/rightdetails?sice=".concat(this.rightsice,"&groups=").concat(this.groupId,"&index=").concat(this.payingusers)}),0===e){if(!0===this.isWeixin&&void 0===this.user.wechat)return void this.$refs.wechatPopup.open();if(!0===this.isWeixin&&this.user.wechat&&""===this.user.wechat.mp_openid)return void this.$refs.wechatPopup.open();this.creatOrder(this.price,4,this.value,e)}},allusergroupsusers:function(){var e=this,t={sort:"created_at","filter[user]":this.usersid,"filter[delete_type]":0,include:"group"};this.$store.dispatch("jv/get",["groups/paid",{params:t}]).then((function(){e.oder=!1,e.grouplist()}))},creatOrder:function(t,i,o,a){var s=this,n={_jv:{type:"orders"},type:i,group_id:this.groupId,amount:t,is_anonymous:this.isAnonymous};this.$store.dispatch("jv/post",n).then((function(e){s.orderSn=e.order_sn,0===a?0===s.browser?s.orderPay(13,o,s.orderSn,a,"0"):s.isWeixin&&s.isPhone?s.orderPay(12,o,s.orderSn,a,"1"):s.isPhone?s.orderPay(11,o,s.orderSn,a,"2"):s.orderPay(10,o,s.orderSn,a,"3"):1===a&&s.orderPay(20,o,s.orderSn,a)})).catch((function(t){e.log(t)}))},orderPay:function(e,t,i,o,a){var s=this,n={};0===o?n={_jv:{type:"trade/pay/order/".concat(i)},payment_type:e}:1===o&&(n={_jv:{type:"trade/pay/order/".concat(i)},payment_type:e,pay_password:t}),this.$store.dispatch("jv/post",n).then((function(e){if(s.wxRes=e,0===o)"0"===a?s.wechatPay(e.wechat_js.timeStamp,e.wechat_js.nonceStr,e.wechat_js.package,e.wechat_js.signType,e.wechat_js.paySign):"1"===a?"undefined"==typeof WeixinJSBridge?document.addEventListener?document.addEventListener("WeixinJSBridgeReady",s.onBridgeReady(e),!1):document.attachEvent&&(document.attachEvent("WeixinJSBridgeReady",s.onBridgeReady(e)),document.attachEvent("onWeixinJSBridgeReady",s.onBridgeReady(e))):s.onBridgeReady(e):"2"===a?(c=setInterval((function(){1!==s.payStatus?s.getOrderStatus(i,a):clearInterval(c)}),3e3),window.location.href=e.wechat_h5_link):"3"===a&&e&&(s.codeUrl=e.wechat_qrcode,s.payShowStatus=!1,s.$refs.codePopup.open(),s.qrcodeShow=!0,u=setInterval((function(){1!==s.payStatus?(s.getOrderStatus(s.orderSn,a),uni.hideLoading()):clearInterval(u)}),3e3));else if(1===o){var t=s;"success"===e.wallet_pay.result&&(s.$store.dispatch("jv/get",["users/".concat(s.currentLoginId),{}]),uni.showToast({icon:"none",title:s.i18n.t("modify.purchasedSuccessfully"),duration:2e3}),setTimeout((function(){t.allusergroupsusers()}),1500),s.payShowStatus=!1,s.coverLoading=!1),s.coverLoading=!1}})).catch((function(e){s.$refs.payShow.clearPassword()}))},wechatPay:function(e,t,i,o,a){var s=this;uni.requestPayment({provider:"wxpay",timeStamp:e,nonceStr:t,package:i,signType:o,paySign:a,success:function(e){s.coverLoading=!0,u=setInterval((function(){1!==s.payStatus?s.getOrderStatus(s.orderSn):clearInterval(u)}),3e3)},fail:function(e){s.payShowStatus=!1,s.coverLoading=!1,s.$refs.toast.show({message:s.p.payFail})}})},onBridgeReady:function(e){var t=this;WeixinJSBridge.invoke("getBrandWCPayRequest",{appId:e.wechat_js.appId,timeStamp:e.wechat_js.timeStamp,nonceStr:e.wechat_js.nonceStr,package:e.wechat_js.package,signType:"MD5",paySign:e.wechat_js.paySign},(function(e){"get_brand_wcpay_request:ok"==e.err_msg||("get_brand_wcpay_request:cancel"==e.err_msg||"get_brand_wcpay_request:fail"==e.err_msg)&&(clearInterval(u),resolve)})),u=setInterval((function(){1!==t.payStatus?t.getOrderStatus(t.orderSn):clearInterval(u)}),3e3)},getOrderStatus:function(e,t){var i=this;this.$store.dispatch("jv/get",["orders/".concat(e),{custom:{loading:!1}}]).then((function(e){if(i.payStatus=e.status,1===i.payStatus){if(i.payShowStatus=!1,i.coverLoading=!1,"4"===t||"3"===t&&(i.$refs.codePopup.close(),i.qrcodeShow=!1,uni.showToast({icon:"none",title:"用户组购买成功",duration:2e3}),setTimeout((function(){_this.allusergroupsusers()}),1500)),4===i.payTypeVal)i.allusergroupsusers();i.$refs.toast.show({message:i.p.paySuccess})}})).catch((function(e){i.coverLoading=!1,i.$refs.toast.show({message:i.p.payFail})}))}}};t.default=p}).call(this,i("5a52").default)},e972:function(e,t,i){e.exports=i.p+"static/img/msg-404.e11dc2d7.svg"},ee4d:function(e,t,i){"use strict";var o=i("3a75");i.d(t,"a",(function(){return o.a})),i.d(t,"b",(function(){return o.b})),i.d(t,"c",(function(){return o.c}))},ee50:function(e,t,i){"use strict";var o=i("8f17");i.n(o).a}}]);