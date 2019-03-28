# -*- coding: utf-8 -*-
#!/usr/bin/env python3

__author__ = 'geyeg'

import logging
import logging.handlers
import requests
from config import *
import threading
from queue import Queue
import traceback

# L1最大长度
MAX_PACKET_SIZE = 16383
# L1最小长度
MIN_PACKET_SIZE = 16
#头部长长度，两个分隔符2,L1和L2
HEADER_SIZE = 6

GDW_HEADER_TAG = 0x68  #头部分隔符
GDW_END_TAG = 0x16  #帧结束符

'''
GDW_AFN_SW_CLOSE = 0x81  # 81H    关阀                   关停水表
GDW_AFN_SW_OPEN = 0x82  # 82H    开阀                   开阀水表
GDW_AFN_ME_READ_ALL = 0x83  # 83H    抄读所有表             抄读集中器对应水表
GDW_AFN_ME_READ_ONE = 0x84  #  84H    抄读单表               抄读单表
GDW_AFN_DOWNLOAD_SETTING = 0x85  # 85H    下载档案               建立集中器、采集器、水表关联档案
GDW_AFN_ME_READ_DISABLE = 0x86  # 86H    关闭档案               停止抄读此水表
GDW_AFN_READ_SETTING = 0x87  # 87H    读取档案               读取集中器档案信息
GDW_AFN_SET_GPRS = 0x88  # 88H    设置GPRS参数           设置IP及端口等参数信息
GDW_AFN_MSG_DISABLE = 0x89  # 89H    设置上报停止           设置集中器定时自动上报停止
GDW_AFN_MSG_ENABLE = 0x8A  # 8AH    设置上报允许           设置集中器定时自动上报开启
GDW_AFN_MSG_SEND_STATUS = 0x8B  # 8BH    读取上报是否允许       读取集中定时自动上报状态
GDW_AFN_SET_UPLOAD_TIME = 0x8C  # 8CH    设置上报时间           设置集中器定时上报时间
GDW_AFN_READ_UPLOAD_TIME = 0x8D  # 8DH    读上报时间             读取集中器定时上报时间
GDW_AFN_TIME_VERIFY = 0x8E  # 8EH    设置时钟               校时
GDW_AFN_READ_CLOCK = 0x8F  # 8FH    读时钟                 读取集中器当前时间
GDW_AFN_READ_VER = 0x91  # 91H    读集中器版本           读取集中器软硬件版本号
GDW_AFN_SET_ADDRESS = 0x92  #92H    设置集中器地址         设置集中器地址
GDW_AFN_CLEAR = 0x93  # 93H    数据初始化             清空集中器档案信息
GDW_AFN_HEARTBEAT = 0x94  # 94H    集中器(心跳)           心跳包
GDW_AFN_LOGON = 0x95  # 95H    集中器(登录)           集中器登录
GDW_AFN_UPLOAD_TIME = 0x96  # 96H    定时自动上传           定时上传数据包
GDW_AFN_LOGOUT = 0x97  # 97H    集中器(退出登录)       集中器退出登录
阀门控制器号  valve_controller_number
液位传感器号  liquid_level_sensor_number
液位值（比例值） liquid_level_value
阀门开度值 valve_opening_value

'''
'''
--------------------------------------------
关键字说明：
upload_single    有线点抄
upload_single_lora   无线点抄
upload_single_timing_lora  无线定时上传
upload_single_timing_lora
upload_multiple
upload_multiple_timing   有线定时上传
upload_multiple_timing_lora
runonce_upload_multiple_timing  集抄
upload_single_timing_lora_big  大口径水表定时上传
--------------------------------------------
'''

# AFN
feature_to_afn = dict(
    upload_single=0x84,  # 点抄901F
    upload_single_lora=0x53,  # 点抄90EF
    upload_single_timing_lora_big=0x61,  # 大口径水表定时上传，每次一个表
    upload_single_timing_lora=0x65,  # 90EF定时上传(无线小表定时上传，每次一个表)
    runonce_upload_multiple_timing=0x9D,  # 集抄901F（每次多个表）
    upload_multiple_timing=0x96,  # 901F定时上传（每次多个表）
    upload_multiple = 0x83,  # 抄读多表
    upload_sensor_pressure_temperature = 0x60,  # 传感器值上传，单值，压力、温度
    upload_sensor_pressure_multiple = 0x61,  # 传感器值上传，多值，压力
    close_valve=0x81,
    open_valve=0x82,
    close_all_valve=0x51,  # 关阀一个集中器下所有水表的阀门
    open_all_valve=0x52,  # 打开一个集中器下所有水表的阀门
    set_doc=0x85,  # 下载档案（有线集中器）
    read_doc=0x87,  # 读取档案
    set_gprs=0x88,  # 设置ip,端口,APN
    set_upload_disable=0x89,  # 设置上报停止
    set_upload_enable=0x8A,  # 设置上报允许
    read_upload_status=0x8B,  # 读上报状态
    set_upload_time_stamp_and_cycle_unit=0x8C,  # 设置上传基准时间和上传频率
    read_upload_time_stamp_and_cycle_unit=0x8D,  # 读上传基准时间和上传频率
    set_concentrator_number=0x92,  # 设置集中器地址
    data_initialization=0x93,  # 数据初始化
    heartbeat=0x94,
    login=0x95,
    logout=0x97,
    upload_liquid_level=0x54,  # 液位高度数据上传
    upload_valve_position=0x56,  # 阀门开度上传
    set_valve_position=0x55  # 阀门开度控制设置
)
afn_to_feature = dict((v, k) for k, v in feature_to_afn.items())


# feature_to_feature = dict(
#     set_doc='set_doc_lora'
# )
# feature_to_feature.update({(v, k) for k, v in feature_to_feature.items()})


#方向
direction = dict(
    S2C=0,
    C2S=1
)
direction.update({(v, k) for k, v in direction.items()})

headers = {
    "Content-Type": "application/json",
}

'''
在线设备
online_dev={
              'dev_id':{
                  'fd': 10,
                  'ser'：1    发送报文序列号
                  'living_count':0    生命值，超过设定值会被删除，每秒加1
                  'is_sending': False 正在发送
                  'current_server_cmd_id':'320jk3kk-iie8-lkjfdsj86k3-kdklj8'  服务器指令id
                  'reply_cmd_timing_count': 等待回复计数器,到达指定数据，is_waitting_reply = False 并且为true时才开始计数
              }
             ｝
'''

# 在线设备列表线程锁
online_dev_lock = threading.RLock()
lock = threading.RLock()
# post_q_lock = threading.RLock()

# 用于转二进制包时直接填充控制域
control_code = dict(
    login=b'\x10',
    logout=b'\x10',
    heartbeat=b'\x10',
    upload_multiple_timing=b'\x88',
    close_valve=b'\x70',
    open_valve=b'\x70',
    close_all_valve=b'\x70',
    open_all_valve=b'\x70',
    set_doc=b'\x70',
    runonce_upload_multiple_timing=b'\x70',
    upload_single_timing_lora=b'\x80',
    upload_single_lora=b'\xC0',
    upload_single_timing_lora_big=b'\x60',
    upload_single=b'\x70',
    upload_multiple=b'\x70',
    set_upload_time_stamp_and_cycle_unit=b'\x70',
    read_upload_time_stamp_and_cycle_unit=b'\x70',
    read_doc=b'\x70',
    set_upload_disable=b'\x70',
    set_upload_enable=b'\x70',
    read_upload_status=b'\x70',
    set_concentrator_number=b'\x70',
    data_initialization=b'\x70',
    upload_sensor_pressure_temperature=b'\x10',
    upload_sensor_pressure_multiple=b'\x10',
    set_gprs=b'\x70',
    upload_liquid_level=b'\x70',
    upload_valve_position=b'\x70',
    set_valve_position=b'\x70'
)

# 用于随机生成16进制的样本
hex_letters = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']

# 计量单位(适用90EF)
unit = dict(
    Wh=0x02,
    KWh=0x05,
    MWh=0x08,
    MWh100=0x0A,
    J=0x01,
    KJ=0x0B,
    MJ=0x0E,
    GJ=0x11,
    GJ100=0x13,
    W=0x14,
    KW=0x17,
    MW=0x1A,
    L=0x29,
    m3=0x2C,
    L_h=0x32,
    m3_h=0x35
)
unit.update({(v, k) for k, v in unit.items()})

'''
# 阀门状态
meter_status_valve = dict(
    open=0x00,
    close=0x01,
    abnormity=0x02
)
meter_status_valve.update({(v, k) for k, v in meter_status_valve.items()})
# 阀门响应标志
meter_status_valve_response = dict(
    no_response=0x00,
    ok=0x01
)
meter_status_valve_response.update({(v, k) for k, v in meter_status_valve_response.items()})
# 电池电压
meter_status_voltage_level = dict(
    normal=0x00,
    low=0x01
)
meter_status_voltage_level.update({(v, k) for k, v in meter_status_voltage_level.items()})
# 温度传感器
meter_status_temperature_sensor = dict(
    ok=0x00,
    error=0x01
)
meter_status_temperature_sensor.update({(v, k) for k, v in meter_status_temperature_sensor.items()})
# 电子铅封
meter_status_elock = dict(
    close=0x00,
    open=0x01
)
meter_status_elock.update({(v, k) for k, v in meter_status_elock.items()})
'''

# 发送到上海公司的uri
uri_meter_value_shanghai = r'https://wuyexin.superwallet.com.cn/wyx/water_day'

# 允许服务器下发指令处理列表，不在列表的不处理
server_handle_feature_list = ['close_valve', 'open_valve', 'set_doc', 'read_doc', 'close_all_valve', 'open_all_valve',
                              'runonce_upload_multiple_timing', 'upload_single', 'set_upload_disable',
                              'set_upload_enable', 'read_upload_status', 'read_upload_time_stamp_and_cycle_unit',
                              'set_upload_time_stamp_and_cycle_unit', 'set_concentrator_number', 'data_initialization',
                              'upload_sensor_pressure_multiple', 'upload_sensor_pressure_temperature', 'set_gprs',
                              'set_valve_position']

# 需要把结果上报给服务器的feature
need_post_feature_list = ['upload_multiple_timing', 'upload_single_timing_lora', 'heartbeat',
                          'upload_single_timing_lora_big', 'upload_single',
                          'upload_sensor_pressure_multiple', 'upload_sensor_pressure_temperature',
                          'upload_liquid_level', 'upload_valve_position']

# 接收到需要回复的feature
need_reply_feature_list = ['heartbeat', 'upload_single_timing_lora', 'logout', 'login',
                           'upload_single_timing_lora_big', 'upload_sensor_pressure_multiple',
                           'upload_sensor_pressure_temperature',
                           'upload_liquid_level', 'upload_valve_position']

# 接收到无需回复，也无需上报
no_need_handle_feature_list = ['set_upload_time_stamp_and_cycle_unit', 'set_upload_disable', 'set_upload_enable',
                               'set_concentrator_number', 'data_initialization', 'runonce_upload_multiple_timing',
                               'close_valve', 'open_valve', 'close_all_valve', 'open_all_valve', 'set_gprs']

meter_value_features = ['upload_multiple_timing', 'upload_single_timing_lora', 'upload_single_timing_lora_big',
                        'upload_single', 'upload_single_lora']

# 在线设备
online_dev = dict()
# socket句柄转socket
fd_to_socket = dict()
fd_to_connector = dict()
# fd在线时长
fd_living_count = dict()
# 消息认证字段
token = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


'''  指令格式样本
---------------------
heartbeat:
68 49 00 49 00 68 C9 02 00 00 21 00 94 7E 00 00 01 00 11 33 14 18 64 18 EB 16
68 39 00 39 00 68 10 02 00 00 21 00 94 6E 00 00 01 00 94 00 CA 16

send :68 49 00 49 00 68 C9 {04 12 67 02 00} 94 7B {00 00 01 00} [43 57 06 13 A4 18] C7 16    中括号内是客户端带上来的时间
reply:68 39 00 39 00 68 10 {04 12 67 02 00} 94 6B {00 00 01 00} [94 00]             23 16    返回AFN码作为确认

login:

logout:

---------------------
runonce_upload_multiple_timing 集抄

-----------------
upload_single
{
    "_f": "upload_single",
    "time_stamp_server": "20190319150802",
    "AFN": 132,
    "body": {
        "meter_number": "02017062000373",
        "meter_value": 148.0
    },
    "is_confirm": false,
    "data_Pn": 0,
    "FIN": 1,
    "concentrator_number": "02072100",
    "PRM_Fn": 8,
    "CON": 0,
    "msg_len": 25,
    "FIR": 1,
    "ser": 2,
    "data_Fn": 1,
    "_t": "C2S",
    "TpV": 0,
    "PRM": 0
}
-----------------
upload_single_lora
同upload_single_timing_lora

------------------
upload_multiple_timing
{
    "AFN": 150,
    "time_stamp_server": "20190318022913",
    "body": [
        {
            "meter_number": "FA000353921264",
            "meter_value": 24.0
        },
        {
            "meter_number": "FA0003646175EA",
            "meter_value": 106.0
        },
        {
            "meter_number": "FA00035393739B",
            "meter_value": 27.0
        },
        {
            "meter_number": "FA0003646417CC",
            "meter_value": 23.0
        },
        {
            "meter_number": "FA000364569540",
            "meter_value": 8.0
        },
        {
            "meter_number": "FA00036456722A",
            "meter_value": 18.0
        }
    ],
    "TpV": 0,
    "PRM_Fn": 8,
    "_t": "C2S",
    "CON": 0,
    "is_confirm": false,
    "ser": 13,
    "_f": "upload_multiple_timing",
    "PRM": 0,
    "data_Pn": 0,
    "FIR": 1,
    "data_Fn": 1,
    "msg_len": 80,
    "concentrator_number": "02072115",
    "FIN": 1
}


----------------
upload_single_timing_lora
{
    "msg_len": 133,
    "PRM": 0,
    "_t": "C2S",
    "_f": "upload_single_timing_lora",
    "time_stamp_server": "20190225014128",
    "CON": 1,
    "is_confirm": true,
    "body": {
        "fmv22": 0.0,
        "fmv20": 0.0,
        "water_temperature": 9,
        "fmv9": 0.0,
        "state_valve": 0,
        "cell_voltage_2": 3.6,
        "state_temperature_sensor": 0,
        "signal": 59,
        "meter_time": "2019-02-25 01:32:20",
        "temp_up_time": "00-00-00 00:00",
        "fmv17": 0.0,
        "temp_up": 0,
        "fmv0": 0.0,
        "fmv15": 0.0,
        "fmv21": 0.0,
        "fmv2": 0.0,
        "flow_up_time": "00-00-00 00:00",
        "meter_number": "11110087491387",
        "fmv10": 0.0,
        "fmv18": 0.0,
        "fmv8": 0.0,
        "meter_value": 90.98,
        "cover_is_opened": "00-00-00 00:00",
        "fmv4": 0.0,
        "state_voltage_level": 0,
        "fmv19": 0.0,
        "collect_time": "2019-02-25 01:41:28",
        "fmv14": 0.0,
        "fmv6": 0.0,
        "fmv16": 0.0,
        "meter_revalue": 0.24,
        "flow_up": 0,
        "cell_voltage_lora": 3.5,
        "fmv23": 0.0,
        "state_elock": 0,
        "_mid": 3188137984,
        "cell_voltage_1": 3.6,
        "unit_revalue": "m3",
        "unit": "m3",
        "fmv5": 0.0,
        "fmv1": 0.0,
        "low_voltage": "00-00-00 00:00",
        "state_valve_response": 0,
        "fmv11": 0.0,
        "point0_freeze_value": 90.987,
        "read_meter_times": 1,
        "empty_pipe_alarm": "19-02-25 01:00",
        "fmv3": 0.0,
        "fmv12": 0.0,
        "fmv7": 0.0,
        "fmv13": 0.0,
        "reflow_up_time": "00-00-00 00:00",
        "reflow_up": 0
    },
    "TpV": 0,
    "FIR": 1,
    "concentrator_number": "C002A086",
    "FIN": 1,
    "data_Fn": 1,
    "data_Pn": 0,
    "ser": 5,
    "PRM_Fn": 0,
    "AFN": 101
}

----------------
upload_single_timing_lora_big
{
    "_f": "upload_single_timing_lora_big",
    "time_stamp_server": "20190224001613",
    "ser": 5,
    "FIN": 1,
    "body": {
        "meter_data_value_15": 0.0,
        "meter_data_value_16": 0.0,
        "meter_data_value_12": 0.0,
        "state_valve": 0,
        "meter_data_value_21": 0.0,
        "meter_number": "010016077361",
        "collect_time": "2019-02-24 00:16:13",
        "meter_data_value_9": 0.0,
        "meter_data_value_20": 0.0,
        "meter_data_value_2": 0.0,
        "meter_data_value_6": 0.0,
        "state_valve_response": 0,
        "meter_data_value_19": 0.0,
        "unit": "m3",
        "meter_data_value_23": 0.0,
        "meter_time": "2019-02-24 00:16:01",
        "state_voltage_level": 0,
        "meter_data_value_18": 0.0,
        "meter_data_value_17": 0.0,
        "state_elock": 0,
        "meter_data_value_0": 0.0,
        "meter_data_value_8": 0.0,
        "meter_data_value_13": 0.0,
        "state_temperature_sensor": 0,
        "meter_index": 1,
        "meter_data_value_1": 0.0,
        "meter_data_value_10": 0.0,
        "meter_data_value_11": 0.0,
        "meter_data_value_3": 0.0,
        "meter_data_value_14": 0.0,
        "meter_data_value_22": 0.0,
        "meter_data_value_5": 0.0,
        "meter_data_value_7": 0.0,
        "meter_data_value_4": 0.0
    },
    "concentrator_number": "C003A120",
    "_c": "apply_cmd_reply",
    "is_confirm": true,
    "data_Fn": 1,
    "concentrator_address": "{0xC0,0x03,0xA1,0x20,0x00}",
    "_t": "C2S",
    "PRM": 0,
    "PRM_Fn": 0,
    "data_Pn": 0,
    "AFN": 97,
    "msg_len": 130,
    "FIR": 1,
    "feature": "upload_single_timing_lora_big",
    "TpV": 0,
    "CON": 1
}
'''

''' 关于meter_address meter_number concentrator_number concentrator_address 的说明(衡阳协议格式)
meter_address={0x01,0x00,0x87,0x20,0x10,0x56}  ==>> meter_number=87201056
                         -------------------

concentrator_address={0x02,0x00,0x00,0x21,0x00}  ==>> concentrator_number=02000021
                      -------------------
'''


''' API 说明  *********************

API_BASE_URL = http://182.61.56.51

http

1.取服务器下发指令
URI: /command_data
方式：get

-------------------------------------------
  开、关阀
[
    {
        concentrator_number='92000001',
        meter_number='88051393',
        meter_index=1,
        feature='open_valve',
        category=''
    }
]
--------------------------------------------
  下载档案
[
    {
        "id": "",
        "concentrator_number": "",
        "meter_number": "",
        "feature": "",
        "category": "",
        "body": [
            {
                "meter_index": 1,
                "meter_number": "",
                "measuring_point_properties": "00",
                "wiring": "00",
                "meter_rate_number": "00",
                "table_type_code": "00",
                "line_number": "0000",
                "table_box_number": "0000",
                 "acquisition_module_number": "000000"
            },
            {
            ....
            }
        ]

    }
]

修改为：
body:
[
    {"meter_index":1,"meter_number":"010088041123", "channel":1},
    {"meter_index":2,"meter_number":"010088041028", "channel": 1}
]


runonce_upload_multiple_timing 集抄 --------------------------------------------
不需要下发表号
集抄
[
    {
        "id": "6e834698-7e94-11e8-88f6-024288ed0b8a",
        "concentrator_number": "04126702",
        "meter_number": "",
        "feature": "runonce_upload_multiple_timing",
        "category": "",
        "body": {
            "protocol": "901f"
            "meter_numbers": [
                "11111111111111",
                "11111111111111"
            ]
        }
    }
]

upload_single,upload_single_lora 点抄------------------------------------------------------------
[
    {
        "id": "6e834698-7e94-11e8-88f6-024288ed0b8a",
        "concentrator_number": "04126702",
        "meter_number": "",
        "feature": "runonce_upload_multiple_timing",
        "category": "",
        "body": {
            "protocol": "901f"
            "meter_index": 1,
            "meter_number": "11111111111111"
            ]
        }
    }
]


post到上海公司
https://wuyexin.superwallet.com.cn/wyx/water_day
{
  "list": [
    {
      "concentrator_number": 1,
      "meter_number": 1,
      "value": 1,
      "upload_time": "2018-12-12 13:00:12",
      "collect_time": "2018-12-12 13:00:12"
    }
  ]
}

-------------------------------------------------------
心跳或其它指令上传：
post /command_date http/1.1
Host: 182.61.56.51
Content-Type: application/json
Cache-Control:no-cache

[
    {
        "concentrator_number": "",
        "feature": "heartbeat",
        "upload_time": "",
        "collect_time": ""
    }

]

----------------------------------------------------------
upload_liquid_level:
68 55 00 55 00 68 C9 92 00 00 01 00 54 70 00 00 01 00 78 56 34 12 00 11 11 00 03 5A 16
68 55 00 55 00 68 C9 92 00 00 01 00 54 70 00 00 01 00 78 56 34 12 00 11 11 00 08 5F 16

upload_valve_position：
68 55 00 55 00 68 C9 92 00 00 01 00 56 70 00 00 01 00 01 09 03 49 00 11 11 57 09 FB 16


'''