(window.webpackJsonp=window.webpackJsonp||[]).push([[48],{1001:function(e,t,r){},1133:function(e,t,r){"use strict";r(1001)},1227:function(e,t,r){"use strict";r.r(t);r(34),r(25),r(39),r(53),r(54);var n=r(85),o=r(8),c=r(9),d=(r(13),r(24),r(31),r(712)),h=r.n(d),l=r(159),head=r(713),_=r.n(head);function f(object,e){var t=Object.keys(object);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(object);e&&(r=r.filter((function(e){return Object.getOwnPropertyDescriptor(object,e).enumerable}))),t.push.apply(t,r)}return t}function v(e){for(var i=1;i<arguments.length;i++){var source=null!=arguments[i]?arguments[i]:{};i%2?f(Object(source),!0).forEach((function(t){Object(o.a)(e,t,source[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(source)):f(Object(source)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(source,t))}))}return e}var m={layout:"custom_layout",name:"SearchUser",mixins:[h.a,_.a],asyncData:function(e,t){return Object(c.a)(regeneratorRuntime.mark((function r(){var n,o,c,d;return regeneratorRuntime.wrap((function(r){for(;;)switch(r.prev=r.next){case 0:return n=e.store,l.a.isSpider||t(null,{}),r.prev=2,o={},r.next=6,n.dispatch("jv/get",["categories",{}]);case 6:c=r.sent,Array.isArray(c)?o.categoryData=c:c&&c._jv&&c._jv.json&&((d=c._jv.json.data||[]).forEach((function(e,t){d[t]=v(v(v({},e),e.attributes),{},{_jv:{id:e.id}})})),o.categoryData=d),t(null,o),r.next=14;break;case 11:r.prev=11,r.t0=r.catch(2),t(null,{});case 14:case"end":return r.stop()}}),r,null,[[2,11]])})))()},data:function(){return{loading:!1,categoryData:[],pageNum:1,pageSize:10,categoryId:0,value:"",hasMore:!1,userCount:0,userList:[],title:this.$t("search.search")}},computed:{forums:function(){return this.$store.state.site.info.attributes||{}}},watch:{$route:"init"},mounted:function(){this.init()},methods:{init:function(){this.$route.query.categoryId&&(this.categoryId=this.$route.query.categoryId),this.$route.query.value&&(this.value=this.$route.query.value,this.reloadList())},getUserList:function(){var e=this;this.loading=!0;var t={include:"groups",sort:"createdAt","filter[status]":"normal","page[limit]":this.pageSize,"page[number]":this.pageNum,"filter[username]":"*".concat(this.value,"*")};this.$store.dispatch("jv/get",["users",{params:t}]).then((function(t){var data=t;t&&data.forEach((function(e,i){data[i].groupName=e.groups[0]?e.groups[0].name:""})),e.userCount=data._jv.json.meta.total,e.hasMore=data.length===e.pageSize,1===e.pageNum?e.userList=data:e.userList=[].concat(Object(n.a)(e.userList),Object(n.a)(data)),e.pageNum+=1,data._jv&&(e.hasMore=e.userList.length<data._jv.json.meta.total)}),(function(t){e.handleError(t)})).finally((function(){e.loading=!1}))},loadMore:function(){this.getUserList()},reloadList:function(){this.pageNum=1,this.userList=[],this.getUserList()}}},y=(r(1133),r(11)),component=Object(y.a)(m,(function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("div",{staticClass:"container"},[r("main",{staticClass:"cont-left"},[r("div",{staticClass:"search-header"},[r("div",{staticClass:"result-count"},[e._v("\n        "+e._s(e.$t("search.find"))+" "),e.value?r("span",{staticClass:"keyword"},[e._v('"'+e._s(e.value)+'"')]):e._e(),e._v("\n        "+e._s(e.$t("search.searchuserresult"))+" "+e._s(e.userCount)+" "+e._s(e.$t("topic.item"))+"\n      ")]),e._v(" "),r("create-post-popover")],1),e._v(" "),r("div",{staticClass:"user-list"},[r("div",{staticClass:"user-flex"},e._l(e.userList,(function(e,t){return r("user-item",{key:t,attrs:{item:e}})})),1),e._v(" "),r("list-load-more",{attrs:{loading:e.loading,"has-more":e.hasMore,"page-num":e.pageNum,length:e.userList.length,"load-more-text":e.$t("topic.showMore")+e.$t("search.users")},on:{loadMore:e.loadMore}})],1)]),e._v(" "),r("aside",{staticClass:"cont-right"},[r("div",{staticClass:"category background-color"},[r("category-pay",{attrs:{list:e.categoryData}})],1),e._v(" "),r("advertising"),e._v(" "),r("copyright",{attrs:{forums:e.forums}})],1)])}),[],!1,null,"5b6aa24e",null);t.default=component.exports;installComponents(component,{CreatePostPopover:r(892).default,UserItem:r(792).default,ListLoadMore:r(718).default,CategoryPay:r(893).default,Advertising:r(742).default,Copyright:r(743).default})},712:function(e,t,r){var n=r(719);r(31),r(52),e.exports={data:function(){var e=this;return{errorCodeHandler:{default:{model_not_found:function(){return e.$router.replace("/error")},not_authenticated:function(){return e.$router.push("/user/login")}},thread:{permission_denied:function(){return e.$router.replace("/error?code=permissionDenied")}}}}},methods:{handleError:function(e){var t=arguments,r=this;return n(regeneratorRuntime.mark((function n(){var o,c,d,h,l,_;return regeneratorRuntime.wrap((function(n){for(;;)switch(n.prev=n.next){case 0:if(o=t.length>1&&void 0!==t[1]?t[1]:"",c=e.response.data.errors,!(Array.isArray(c)&&c.length>0)){n.next=17;break}if(d=c[0].code,h=c[0].detail&&c[0].detail.length>0?c[0].detail[0]:c[0].code,l=c[0].detail&&c[0].detail.length>0?c[0].detail[0]:r.$t("core.".concat(h)),"site_closed"!==c[0].code){n.next=10;break}return n.next=9,r.siteClose(c);case 9:return n.abrupt("return",n.sent);case 10:if("need_ext_fields"!==c[0].code){n.next=14;break}return _=r.$store.getters["session/get"]("userId"),r.$router.push("/user/supple-mentary?id=".concat(_)),n.abrupt("return");case 14:"Permission Denied"===d?r.$message.error(r.$t("core.permission_denied2")):"content_banned_show_words"===d?r.$message.error(r.$t("core.content_banned_show_words")+c[0].detail):r.$message.error(l),r.errorCodeHandler.default[d]&&r.errorCodeHandler.default[d](),o&&r.errorCodeHandler[o][d]&&r.errorCodeHandler[o][d]();case 17:case"end":return n.stop()}}),n)})))()},siteClose:function(e){var t=this;return n(regeneratorRuntime.mark((function r(){return regeneratorRuntime.wrap((function(r){for(;;)switch(r.prev=r.next){case 0:return r.prev=0,r.next=3,t.$store.dispatch("forum/setError",{code:e[0].code,detail:e[0].detail&&e[0].detail.length>0&&e[0].detail[0]});case 3:return r.next=5,t.$router.push("/site/close");case 5:r.next=9;break;case 7:r.prev=7,r.t0=r.catch(0);case 9:case"end":return r.stop()}}),r,null,[[0,7]])})))()}}}},713:function(e,t){e.exports={data:function(){return{title:"‎"}},computed:{forums:function(){return this.$store.state.site.info.attributes||{}}},head:function(){return{title:"‎"!==this.title&&this.forums&&this.forums.set_site&&this.forums.set_site.site_name?"".concat(this.title," - ").concat(this.forums.set_site.site_name):this.title}}}},719:function(e,t){function r(e,t,r,n,o,c,d){try{var h=e[c](d),l=h.value}catch(e){return void r(e)}h.done?t(l):Promise.resolve(l).then(n,o)}e.exports=function(e){return function(){var t=this,n=arguments;return new Promise((function(o,c){var d=e.apply(t,n);function h(e){r(d,o,c,h,l,"next",e)}function l(e){r(d,o,c,h,l,"throw",e)}h(void 0)}))}},e.exports.default=e.exports,e.exports.__esModule=!0},847:function(e,t,r){},848:function(e,t,r){},886:function(e,t,r){"use strict";r(847)},887:function(e,t,r){"use strict";r(848)},892:function(e,t,r){"use strict";r.r(t);var n=r(157),o={name:"CreatePostPopover",mixins:[r.n(n).a],data:function(){return{userId:this.$store.getters["session/get"]("userId"),visible:!1,noCreateThread:!1,can_create_thread:!0,can_create_thread_long:!0,can_create_thread_video:!0,can_create_thread_image:!0,can_create_thread_question:!0,can_create_thread_goods:!0}},computed:{userInfo:function(){return this.$store.getters["jv/get"]("/users/".concat(this.userId))},forums:function(){return this.$store.state.site.info.attributes||{}},categoryId:function(){return this.$route.query.categoryId}},methods:{showAndHidePopover:function(){var e=this;if(this.$store.getters["session/get"]("isLogin")){if(!this.visible){var t=this.forums.other,r=this.userInfo;if(!t)return;if(!(t.can_create_thread||t.can_create_thread_long||t.can_create_thread_video||t.can_create_thread_image||t.can_create_thread_question||t.can_create_thread_goods))return void this.$message.error(this.$t("home.noPostingPermission"));if(t.publish_need_real_name&&!r.realname)return void this.$message.error(this.$t("home.needRealname"));if(t.publish_need_bind_phone&&!r.mobile)return void this.$message.error(this.$t("home.needPhone"));if(!t.can_create_thread_in_category)return void this.$message.error(this.$t("home.noPostingCategory"));if(this.categoryId)this.$store.getters["jv/get"]("categories/".concat(this.categoryId)).canCreateThread||this.$message.error(this.$t("home.noPostingCategory"));t.can_create_thread||(this.can_create_thread=!1),t.can_create_thread_long||(this.can_create_thread_long=!1),t.can_create_thread_video||(this.can_create_thread_video=!1),t.can_create_thread_image||(this.can_create_thread_image=!1),t.can_create_thread_question||(this.can_create_thread_question=!1),t.can_create_thread_goods||(this.can_create_thread_goods=!1)}this.visible=!this.visible}else this.$message.warning("请登录"),window.setTimeout((function(){e.headerTologin()}),1e3)},toRouter:function(e){this.$router.push("/thread/postpay?type=".concat(e).concat(this.categoryId?"&categoryId=".concat(this.categoryId):""))}}},c=(r(886),r(11)),component=Object(c.a)(o,(function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("el-popover",{attrs:{placement:"bottom",width:"120","min-width":"120",trigger:"manual","popper-class":"custom-popover-width"},model:{value:e.visible,callback:function(t){e.visible=t},expression:"visible"}},[r("ul",{staticClass:"type-container"},[e.can_create_thread?r("li",{on:{click:function(t){return t.stopPropagation(),e.toRouter(0)}}},[e._v("\n      "+e._s(e.$t("home.word"))+"\n    ")]):e._e(),e._v(" "),e.can_create_thread_long?r("li",{on:{click:function(t){return t.stopPropagation(),e.toRouter(1)}}},[e._v("\n      "+e._s(e.$t("home.invitation"))+"\n    ")]):e._e(),e._v(" "),e.can_create_thread_image?r("li",{on:{click:function(t){return t.stopPropagation(),e.toRouter(3)}}},[e._v("\n      "+e._s(e.$t("home.picture"))+"\n    ")]):e._e(),e._v(" "),e.can_create_thread_video?r("li",{on:{click:function(t){return t.stopPropagation(),e.toRouter(2)}}},[e._v("\n      "+e._s(e.$t("home.video"))+"\n    ")]):e._e(),e._v(" "),e.can_create_thread_question?r("li",{on:{click:function(t){return t.stopPropagation(),e.toRouter(5)}}},[e._v("\n      "+e._s(e.$t("home.question"))+"\n    ")]):e._e(),e._v(" "),e.can_create_thread_goods?r("li",{on:{click:function(t){return t.stopPropagation(),e.toRouter(6)}}},[e._v("\n      "+e._s(e.$t("home.product"))+"\n    ")]):e._e()]),e._v(" "),r("template",{slot:"reference"},[e._t("button",[r("el-button",{staticClass:"new-post",attrs:{type:"primary"},on:{click:e.showAndHidePopover}},[r("span",{staticClass:"add-icon"},[e._v("+")]),e._v(e._s(e.$t("profile.post"))+"\n        \n        \n      ")])])],2)],2)}),[],!1,null,"5f4b8fa4",null);t.default=component.exports},893:function(e,t,r){"use strict";r.r(t);var n=r(85),o=(r(24),r(712)),c={name:"Category",mixins:[r.n(o).a],props:{postLoading:{type:Boolean,default:!1},list:{type:Array,default:function(){return[]}}},data:function(){return{categoryList:[],selectId:0,selectId_parent:0}},watch:{list:{handler:function(e){0===this.categoryList.length&&this.handleData(e)},deep:!0}},mounted:function(){0===this.categoryList.length&&this.getCategoryList(),this.$route.params.id&&(this.selectId=+this.$route.params.id)},methods:{getCategoryList:function(){var e=this;this.$store.dispatch("jv/get",["categories",{}]).then((function(t){var r=Object(n.a)(t)||[];e.handleData(r)}),(function(t){e.handleError(t)}))},handleData:function(data){var e=this,t=0;this.categoryList=[],data.forEach((function(r){var n=!1,o=[];t+=r.thread_count,r.children&&r.children.length>0&&(n=!0,r.children.forEach((function(e){o.push({id:parseInt(e.id),search_ids:e.search_ids,name:e.name,thread_count:e.thread_count})}))),e.categoryList.push({id:parseInt(r._jv.id),search_ids:r.search_ids,name:r.name,thread_count:r.thread_count,hasChild:n,children:o})})),this.categoryList.unshift({id:0,search_ids:"0",name:this.$t("topic.whole"),thread_count:t}),this.categoryList.forEach((function(t){t.id===e.selectId?e.selectId_parent=t.id:t.children&&t.children.forEach((function(r){r.id===e.selectId&&(e.selectId_parent=t.id)}))}))},onChange:function(e,t,r){this.postLoading||(this.selectId=e,this.selectId_parent=t,this.$emit("onChange",{id:e,search_ids:r}))}}},d=(r(887),r(11)),component=Object(d.a)(c,(function(){var e=this,t=e.$createElement,r=e._self._c||t;return e.categoryList.length>0?r("div",{staticClass:"category-container"},e._l(e.categoryList,(function(t){return r("div",{key:t.id},[r("div",{staticClass:"category-item",class:{active:e.selectId===t.id||e.selectId_parent===t.id,loading:e.postLoading},on:{click:function(r){return e.onChange(t.id,t.id,t.search_ids)}}},[e.selectId_parent===t.id?r("i",{staticClass:"el-icon-arrow-left arrow-icon"}):e._e(),e._v(" "),r("div",{staticClass:"title"},[e._v(e._s(t.name))]),e._v(" "),r("div",{staticClass:"count"},[e._v(e._s(t.thread_count))])]),e._v(" "),t.hasChild?r("div",e._l(t.children,(function(n){return r("div",{directives:[{name:"show",rawName:"v-show",value:e.selectId_parent===t.id,expression:"selectId_parent === item.id"}],key:n.id,staticClass:"category-item category-item-sub",class:{active:e.selectId===n.id,loading:e.postLoading},on:{click:function(r){return e.onChange(n.id,t.id,n.search_ids)}}},[r("div",{staticClass:"title"},[e._v(e._s(n.name))]),e._v(" "),r("div",{staticClass:"count"},[e._v(e._s(n.thread_count))])])})),0):e._e()])})),0):e._e()}),[],!1,null,"513115d2",null);t.default=component.exports}}]);