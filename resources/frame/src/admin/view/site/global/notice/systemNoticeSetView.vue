<template>
    <div class="system-notice-box">
      <div class="system-notice-table marT15">
        <el-table
          :data="tableData"
          style="width: 100%">

          <el-table-column
            prop=""
            label="序号"
            width="100">
            <template slot-scope="scope">
              <span v-text="getIndex(scope.$index)"> </span>
            </template>
          </el-table-column>

          <el-table-column
            prop="_data.name"
            label="通知类型"
          >
          </el-table-column>

          <el-table-column
            prop="_data.type_status"
            label="通知方式"
            align="center"
          >
            <!-- <template slot-scope="scope">
              <span v-if="scope.row._data.status === 1" class="iconfont iconicon_select" ></span>
              <span v-else class="iconfont iconicon_"  ></span>
            </template> -->
          </el-table-column>

          <el-table-column
            prop="address"
            label="操作"
            width="200">
            <template slot-scope="scope">
              <!-- <div v-if="scope.row._data.status == 1"> -->
                <el-button
                  size="mini"
                  @click="configClick(scope.row._data.id,scope.row._data.name)">
                  配置
                </el-button>

                <!-- <el-button
                  @click.native.prevent="noticeSetting(scope.row._data.id,'close')"
                  size="mini">
                  关闭
                </el-button> -->
              <!-- </div> -->
              <!-- <div v-if="scope.row._data.status == 0"> -->
                <!-- <el-button
                  size="mini"
                  @click.native.prevent="noticeSetting(scope.row._data.id,'open')"
                >开启
                </el-button> -->
              <!-- </div> -->
            </template>
          </el-table-column>

        </el-table>
        <Page v-if="total > 1" :total="total" :pageSize="pageLimit" :currentPage="pageNum" @current-change="handleCurrentChange" />
      </div>
    </div>
</template>

<script>
  import '../../../../scss/site/module/globalStyle.scss';
  import systemNoticeSetCon from "../../../../controllers/site/global/notice/systemNoticeSetCon";
  export default {
    name: "systemNoticeSetView",
    ...systemNoticeSetCon
  }
</script>
