# -*- coding: utf-8 -*-
#!/usr/bin/env python3

__author__ = 'geyeg'

HOST = '120.76.72.84'
PORT = 8015
ip = '120.76.72.84'
port = 8015
TIME_OUT = 240

API_BASE_URL = r'http://182.61.56.51'
POST_RETRY_INTERVAL = 3
log_file = '/var/log/amwares/8015/water'
timezone = 8

instruction_translation_dict = {
    'upload_single': 'upload_single_lora'
}

# 如果协议中FIR、FIN位没正确使用，设为True(目前只针对宁波水表)
NO_USE_FIR_FIN_FLAG = False

# 标准长度为True时按协议中的算法 L = length(控制域+地址域+链路用户数据) * 4 + 1），False直接填入真实长度
standard_length = True