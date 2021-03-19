(window.webpackJsonp=window.webpackJsonp||[]).push([[54],{1017:function(e,t,o){},1149:function(e,t,o){"use strict";o(1017)},1241:function(e,t,o){"use strict";o.r(t);var r=o(9),n=(o(31),o(52),o(5)),head=o(714),c=o.n(head),d=o(713),l=o.n(d),h=o(751),f=o.n(h),m=o(888),v=o.n(m),_=o(157),C=o.n(_),y={name:"PhoneLogin",mixins:[c.a,l.a,f.a,v.a,C.a],data:function(){return{title:"手机号登录",phoneNumber:"",content:this.$t("modify.sendVerifyCode"),activeName:"0",verifyCode:"",code:"",site_mode:"",isPaid:!1,canClick:!0,ischeck:!0,loading:!1,preurl:"/"}},computed:{forums:function(){return this.$store.state.site.info.attributes||{}}},mounted:function(){var e=this.$route.query,code=e.code,t=e.preurl;t&&(this.preurl=t),"undefined"!==code&&(this.code=code),this.forums&&this.forums.set_site&&this.forums.set_site.site_mode&&(this.site_mode=this.forums.set_site.site_mode)},methods:{check:function(e){this.ischeck=e},changeinput:function(){var e=this;setTimeout((function(){e.phoneNumber=e.phoneNumber.replace(/[^\d]/g,"")}),30),11===this.phoneNumber.length?this.canClick=!0:this.canClick=!1},sendVerifyCode:function(){var e=this;return Object(r.a)(regeneratorRuntime.mark((function t(){var o;return regeneratorRuntime.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return o={_jv:{type:"sms/send"},mobile:e.phoneNumber,type:"login"},t.next=3,e.checkCaptcha(o);case 3:o=t.sent,n.status.run((function(){return e.$store.dispatch("jv/post",o)})).then((function(t){t.interval&&e.countDown(t.interval)}),(function(t){return e.handleError(t)}));case 5:case"end":return t.stop()}}),t)})))()},PhoneLogin:function(){var e=this;if(this.loading=!0,""===this.phoneNumber)this.$message.error("手机号不能为空"),this.loading=!1;else if(""===this.verifyCode)this.$message.error("验证码不能为空"),this.loading=!1;else if(this.ischeck){var t={data:{attributes:{mobile:this.phoneNumber,code:this.verifyCode,type:"login"}}};this.code&&"undefined"!==this.code&&(t.data.attributes.inviteCode=this.code),this.$store.dispatch("session/verificationCodeh5Login",t).then((function(t){if(e.loading=!1,t&&t.data&&t.data.data&&t.data.data.id&&e.logind(t),t&&t.data&&t.data.errors&&"no_bind_user"===t.data.errors[0].code){var o=t.data.errors[0].token;return localStorage.setItem("mobileToken",o),void e.$router.push("/user/register-bind-phone?phoneNumber=".concat(e.phoneNumber))}if(t&&t.data&&t.data.errors&&"register_validate"===t.data.errors[0].code)return e.$store.commit("session/SET_AUDIT_INFO",{errorCode:"register_validate",username:e.phoneNumber}),void e.$router.push("/user/warning");if(t&&t.data&&t.data.errors&&t.data.errors[0]){var r=t.data.errors[0].detail?t.data.errors[0].detail[0]:t.data.errors[0].code,n=t.data.errors[0].detail?t.data.errors[0].detail[0]:e.$t("core.".concat(r));e.$message.error(n)}})).catch((function(t){e.loading=!1,e.handleError(t)}))}else this.$message.error("请同意协议"),this.loading=!1},toWechat:function(){this.$router.push("/user/wechat?code=".concat(this.code,"&preurl=").concat(this.preurl))},toUserlogin:function(){this.$router.push("/user/login?code=".concat(this.code,"&preurl=").concat(this.preurl))}}},k=(o(1149),o(11)),component=Object(k.a)(y,(function(){var e=this,t=e.$createElement,o=e._self._c||t;return e.forums?o("div",{directives:[{name:"loading",rawName:"v-loading",value:e.loading,expression:"loading"}],staticClass:"register"},[o("div",{staticClass:"register-header"},[e._v(e._s(e.$t("user.phonelogin")))]),e._v(" "),e.forums&&e.forums.qcloud&&e.forums.qcloud.qcloud_sms?o("div",{staticClass:"register-content"},[o("div",{staticClass:"input-box"},[o("span",{staticClass:"title"},[e._v(e._s(e.$t("profile.mobile"))+"：")]),e._v(" "),o("el-input",{staticClass:"phone-input",attrs:{placeholder:e.$t("user.phoneNumber"),maxlength:"11"},model:{value:e.phoneNumber,callback:function(t){e.phoneNumber=t},expression:"phoneNumber"}}),e._v(" "),o("el-button",{staticClass:"count-b",class:{disabled:!e.canClick},attrs:{size:"middle"},on:{click:e.sendVerifyCode}},[e._v(e._s(e.content))])],1),e._v(" "),o("div",{staticClass:"input-box"},[o("span",{staticClass:"title"},[e._v(e._s(e.$t("user.verification"))+"：")]),e._v(" "),o("el-input",{staticClass:"reg-input",attrs:{placeholder:e.$t("user.verificationCode")},nativeOn:{keyup:function(t){return!t.type.indexOf("key")&&e._k(t.keyCode,"enter",13,t.key,"Enter")?null:e.PhoneLogin(t)}},model:{value:e.verifyCode,callback:function(t){e.verifyCode=t},expression:"verifyCode"}})],1),e._v(" "),o("el-button",{staticClass:"r-button",attrs:{type:"primary"},on:{click:e.PhoneLogin}},[e._v("\n      "+e._s(e.$t("user.login"))+"\n    ")]),e._v(" "),o("div",{staticClass:"agreement"},[o("reg-agreement",{on:{check:e.check}})],1),e._v(" "),o("div",{staticClass:"otherlogin"},[o("div",{staticClass:"otherlogin-title"}),e._v(" "),e.forums&&e.forums.passport&&e.forums.passport.oplatform_close&&e.forums.passport.offiaccount_close?o("svg-icon",{staticClass:"wechat-icon",attrs:{type:"wechatlogin"},on:{click:e.toWechat}}):e._e(),e._v(" "),o("svg-icon",{staticClass:"wechat-icon",attrs:{type:"userlogin"},on:{click:e.toUserlogin}})],1)],1):e._e()]):e._e()}),[],!1,null,"3b283914",null);t.default=component.exports;installComponents(component,{RegAgreement:o(898).default,SvgIcon:o(62).default})},728:function(e,t){function o(t){return"function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?(e.exports=o=function(e){return typeof e},e.exports.default=e.exports,e.exports.__esModule=!0):(e.exports=o=function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e},e.exports.default=e.exports,e.exports.__esModule=!0),o(t)}e.exports=o,e.exports.default=e.exports,e.exports.__esModule=!0},751:function(e,t,o){o(13);var r=o(785);e.exports={mixins:[r],computed:{forums:function(){return this.$store.state.site.info.attributes||{}}},methods:{checkCaptcha:function(){var e=this,t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};return new Promise((function(o,r){if(e.forums&&e.forums.qcloud&&e.forums.qcloud.qcloud_captcha)return new TencentCaptcha(e.forums.qcloud.qcloud_captcha_app_id,(function(e){0===e.ret?(t.captcha_rand_str=e.randstr,t.captcha_ticket=e.ticket,o(t)):r(e)})).show();o(t)}))}}}},888:function(e,t){e.exports={methods:{countDown:function(e){var t=this;if(this.canClick){var o=e;this.canClick=!1,this.content=o+this.$t("modify.retransmission");var r=setInterval((function(){o-=1,t.content=o+t.$t("modify.retransmission"),o<0&&(clearInterval(r),t.content=t.$t("modify.sendVerifyCode"),t.canClick=!0)}),1e3)}}}}}}]);