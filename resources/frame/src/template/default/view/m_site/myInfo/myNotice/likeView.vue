<template>
  <div>
    <LikeHeader title="点赞我的"></LikeHeader>
    <van-list
    v-model="loading"
    :finished="finished"
    :offset="offset"
    finished-text="没有更多了"
    @load="onLoad"
    :immediate-check="false"
    >
    <van-pull-refresh v-model="isLoading" @refresh="onRefresh">
    <main class="like-main content" >
      <div class="like-cont cell-crossing" v-for='(item,index) in likeList' :key='index'>
        <ContHeader
          :imgUrl="item._data.user_avatar"
          :userId="item._data.user_id"
          :stateTitle="stateTitle"
          :time="$dayjs(item._data.created_at).format('YYYY-MM-DD HH:mm')"
          :userName="item._data.user_name">
           <div slot="operating" @click.prevent="deleteReply(item._data.id)">删除</div>
        </ContHeader>
        <div class="likePostContent" v-if="item._data.post_content" @click="jumpDetails(item._data.thread_id)">
        <a href="javascript:;" v-html="item._data.post_content" ></a>
        </div>
        <!-- <div class="quote-reply" v-if="item._data.post_content">
        <span>{{item._data.post_content}}</span>
        </div> -->
      </div>
    </main>
    </van-pull-refresh>
  </van-list>
    <footer class="my-info-money-footer"></footer>
  </div>
</template>

<script>

import '../../../../defaultLess/m_site/modules/myInfo.less';
import '../../../../defaultLess/m_site/common/common.less';
import likeCon from '../../../../controllers/m_site/myInfo/myNotice/likeCon';
export default {
  name: "like-view",
  ...likeCon
}
</script>

