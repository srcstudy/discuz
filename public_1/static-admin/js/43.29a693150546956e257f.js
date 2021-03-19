(window.webpackJsonp=window.webpackJsonp||[]).push([[43],{"8iYX":function(t,s,e){"use strict";e.d(s,"a",(function(){return i})),e.d(s,"b",(function(){return a}));var i=function(){var t=this,s=t.$createElement,e=t._self._c||s;return e("div",[e("Card",{attrs:{header:t.query.typeName}}),t._v(" "),e("Card",{staticClass:"card-radio-con",attrs:{header:"通知方式："}},[e("CardRow",{attrs:{description:"若没勾选，则下面不显示对应的方式。若不能支持，则置灰不能勾选 。 "}},[e("el-checkbox-group",{on:{change:t.noticeListChange},model:{value:t.noticeList,callback:function(s){t.noticeList=s},expression:"noticeList"}},[e("el-checkbox",{attrs:{label:"0"}},[t._v("系统通知")]),t._v(" "),e("el-checkbox",{attrs:{label:"1"}},[t._v("微信模板通知")])],1)],1)],1),t._v(" "),e("div",{directives:[{name:"show",rawName:"v-show",value:t.showSystem,expression:"showSystem"}],staticClass:"system-notice"},[e("p",{staticClass:"system-title"},[t._v("系统通知")]),t._v(" "),e("Card",{attrs:{header:t.query.typeName}},[e("CardRow",{attrs:{description:t.systemList.disabled?"当前通知的内容和格式为系统内置，无法自定义配置":"系统发送的欢迎信息的标题，不支持HTML，不超过75字节"}},[e("el-input",{attrs:{type:"text",maxlength:"75",disabled:t.systemList.disabled},model:{value:t.systemList.title,callback:function(s){t.$set(t.systemList,"title",s)},expression:"systemList.title"}})],1)],1),t._v(" "),e("Card",{attrs:{header:"通知内容："}},[e("CardRow",{attrs:{row:"",description:t.systemList.disabled?"":t.systemDes}},[e("el-input",{attrs:{type:"textarea",autosize:{minRows:5,maxRows:5},disabled:t.systemList.disabled,clearable:""},model:{value:t.systemList.content,callback:function(s){t.$set(t.systemList,"content",s)},expression:"systemList.content"}})],1)],1)],1),t._v(" "),e("div",{directives:[{name:"show",rawName:"v-show",value:t.showWx,expression:"showWx"}],staticClass:"system-notice"},[e("p",{staticClass:"system-title"},[t._v("微信模板信息")]),t._v(" "),e("Card",{attrs:{header:"模板ID："}},[e("CardRow",{attrs:{description:"请填写模板消息的ID"}},[e("el-input",{attrs:{type:"text",maxlength:"75"},model:{value:t.wxList.template_id,callback:function(s){t.$set(t.wxList,"template_id",s)},expression:"wxList.template_id"}})],1)],1),t._v(" "),e("Card",{attrs:{header:""}},[e("div",{staticClass:"applets-box"},[e("div",{staticClass:"applets-box-content"},[e("CardRow",{attrs:{row:"",description:t.wxDes}},[e("div",{staticClass:"applets"},[e("span",{staticClass:"applets-titles"},[t._v("first：")]),t._v(" "),e("el-input",{staticClass:"applets-input",attrs:{type:"input"},model:{value:t.wxList.first_data,callback:function(s){t.$set(t.wxList,"first_data",s)},expression:"wxList.first_data"}})],1),t._v(" "),t._l(t.appletsList,(function(s,i){return e("div",{key:i,staticClass:"applets"},[e("span",{staticClass:"applets-title"},[t._v("keyword"+t._s(i+1)+":")]),t._v(" "),e("el-input",{staticClass:"applets-input",attrs:{type:"input"},model:{value:t.appletsList[i],callback:function(s){t.$set(t.appletsList,i,s)},expression:"appletsList[index]"}}),t._v(" "),e("span",{directives:[{name:"show",rawName:"v-show",value:i>1,expression:"index>1"}],staticClass:"iconfont iconicon_delect iconhuishouzhan",on:{click:function(s){return t.delectClick(i)}}})],1)})),t._v(" "),e("div",{staticClass:"applets"},[e("span",{staticClass:"applets-titles"}),t._v(" "),e("TableContAdd",{attrs:{cont:"添加关键字"},on:{tableContAddClick:t.tableContAdd}})],1),t._v(" "),e("div",{staticClass:"applets"},[e("span",{staticClass:"applets-titles"},[t._v("remark：")]),t._v(" "),e("el-input",{staticClass:"applets-input",attrs:{type:"input"},model:{value:t.wxList.remark_data,callback:function(s){t.$set(t.wxList,"remark_data",s)},expression:"wxList.remark_data"}})],1),t._v(" "),e("div",{staticClass:"applets"},[e("span",{staticClass:"applets-title"},[t._v("跳转类型：")]),t._v(" "),e("div",{staticClass:"applets-radio"},[e("el-radio",{attrs:{label:0},model:{value:t.wxList.redirect_type,callback:function(s){t.$set(t.wxList,"redirect_type",s)},expression:"wxList.redirect_type"}},[t._v("无跳转")]),t._v(" "),e("el-radio",{attrs:{label:2},model:{value:t.wxList.redirect_type,callback:function(s){t.$set(t.wxList,"redirect_type",s)},expression:"wxList.redirect_type"}},[t._v("跳转至小程序")]),t._v(" "),e("el-radio",{attrs:{label:1},model:{value:t.wxList.redirect_type,callback:function(s){t.$set(t.wxList,"redirect_type",s)},expression:"wxList.redirect_type"}},[t._v("跳转至H5")])],1)])],2),t._v(" "),e("CardRow",{attrs:{row:"",description:2===t.wxList.redirect_type?"请填写正确的小程序路径，填写错误将导致用户无法接收到消息通知。":""}},[e("div",{directives:[{name:"show",rawName:"v-show",value:1===t.wxList.redirect_type,expression:"wxList.redirect_type === 1"}],staticClass:"applets"},[e("span",{staticClass:"applets-titles"},[t._v("H5网址：")]),t._v(" "),e("el-input",{staticClass:"applets-input",attrs:{type:"input"},model:{value:t.wxList.redirect_url,callback:function(s){t.$set(t.wxList,"redirect_url",s)},expression:"wxList.redirect_url"}})],1),t._v(" "),e("div",{directives:[{name:"show",rawName:"v-show",value:2===t.wxList.redirect_type,expression:"wxList.redirect_type === 2"}],staticClass:"applets"},[e("span",{staticClass:"applets-titles"},[t._v("小程序路径：")]),t._v(" "),e("el-input",{staticClass:"applets-input",attrs:{type:"input"},model:{value:t.wxList.page_path,callback:function(s){t.$set(t.wxList,"page_path",s)},expression:"wxList.page_path"}})],1)])],1)])])],1),t._v(" "),e("Card",{staticClass:"footer-btn"},[e("el-button",{attrs:{type:"primary",size:"medium"},on:{click:t.Submission}},[t._v("提交")])],1)],1)},a=[]},gMwa:function(t,s,e){"use strict";Object.defineProperty(s,"__esModule",{value:!0});var i=r(e("QbLZ"));e("lpfh");var a=r(e("wu2b"));function r(t){return t&&t.__esModule?t:{default:t}}s.default=(0,i.default)({name:"notice-configure-view"},a.default)},k2Pg:function(t,s,e){"use strict";e.r(s);var i=e("8iYX"),a=e("lqGl");for(var r in a)["default"].indexOf(r)<0&&function(t){e.d(s,t,(function(){return a[t]}))}(r);var l=e("KHd+"),n=Object(l.a)(a.default,i.a,i.b,!1,null,null,null);s.default=n.exports},lqGl:function(t,s,e){"use strict";e.r(s);var i=e("gMwa"),a=e.n(i);for(var r in i)["default"].indexOf(r)<0&&function(t){e.d(s,t,(function(){return i[t]}))}(r);s.default=a.a},wu2b:function(t,s,e){"use strict";Object.defineProperty(s,"__esModule",{value:!0});var i=l(e("4gYi")),a=l(e("pNQN")),r=l(e("kAKY"));function l(t){return t&&t.__esModule?t:{default:t}}s.default={data:function(){return{query:"",typeName:"",showSystem:!1,showWx:!1,noticeList:[],wxDes:"",systemDes:"",systemList:"",wxList:"",appletsList:[]}},components:{Card:i.default,CardRow:a.default,TableContAdd:r.default},created:function(){this.query=this.$route.query,this.typeName=this.$route.query.typeName,this.noticeConfigure()},methods:{tableContAdd:function(){this.appletsList.push("")},delectClick:function(t){this.appletsList.splice(t,1)},noticeListChange:function(t){-1===t.indexOf("0")?this.showSystem=!1:this.showSystem=!0,-1===t.indexOf("1")?this.showWx=!1:this.showWx=!0},noticeConfigure:function(){var t=this;this.appFetch({url:"noticeDetail",method:"get",splice:"?type_name="+this.typeName,data:{}}).then((function(s){if(s.readdata[0]){t.systemList=s.readdata[0]._data;var e=t.systemList.template_variables;if(e)for(var i in t.systemDes="请输入模板消息详细内容对应的变量。关键字个数需与已添加的模板一致。\n\n可以使用如下变量：\n",e)t.systemDes+=i+" "+e[i]+"\n";t.systemList.status?(t.noticeList.push("0"),t.showSystem=!0):t.showSystem=!1}if(s.readdata[1]){t.wxList=s.readdata[1]._data;var a=t.wxList.template_variables;if(a)for(var r in t.wxDes="请输入模板消息详细内容对应的变量。关键字个数需与已添加的模板一致。\n\n可以使用如下变量：\n",a)t.wxDes+=r+" "+a[r]+"\n";t.appletsList=t.wxList.keywords_data.length>0?t.wxList.keywords_data:["",""]}t.wxList.status?(t.noticeList.push("1"),t.showWx=!0):t.showWx=!1}))},Submission:function(){var t=this,s=[];if(!0===this.showSystem?s.push({attributes:{id:this.systemList.tpl_id,status:1,template_id:this.systemList.template_id,title:this.systemList.title,content:this.systemList.content}}):s.push({attributes:{id:this.systemList.tpl_id,status:0}}),!0===this.showWx){if(""===this.wxList.first_data)return void this.$message.error("请填写first");for(var e in this.appletsList){if(e>=2)break;if(!this.appletsList[e])return void this.$message.error("请填写keywords")}if(""===this.wxList.remark_data)return void this.$message.error("请填写remark");s.push({attributes:{id:this.wxList.tpl_id,status:1,template_id:this.wxList.template_id,first_data:this.wxList.first_data,keywords_data:this.appletsList,remark_data:this.wxList.remark_data,redirect_type:this.wxList.redirect_type,redirect_url:this.wxList.redirect_url,page_path:this.wxList.page_path}})}else s.push({attributes:{id:this.wxList.tpl_id,status:0}});this.appFetch({url:"noticeList",method:"patch",data:{data:s}}).then((function(s){s.errors?s.errors[0].detail?t.$message.error(s.errors[0].code+"\n"+s.errors[0].detail[0]):t.$message.error(s.errors[0].code):(t.$message({message:"提交成功",type:"success"}),t.noticeConfigure())}))}}}}}]);