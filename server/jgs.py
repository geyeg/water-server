__author__ = 'geyeg'

import time
from queue import Queue
import requests
import logging

jgs_q = Queue(maxsize=10000)
jgs_concentrators = ('C002A162', 'C002A163', 'C002A161', 'C002A157', 'C002A160', 'C002A159', 'C002A175', 'C002A158',
                     'C002A170', 'C003A243', 'C003A244', 'C0070001', 'C0070002', 'C0070003', 'C002A054', 'C002A010',
                     '02000088', '02000026', '02000079', '02000082', '02000034', '02000051', '02000077', '02000081',
                     '02000004', 'C002A016', 'C002A065')
# jgs_api_url = r'http://rocky1102.gnway.cc:8055/webservice.asmx/UploadRead'
jgs_api_url = r'http://61.180.38.85:8055/webservice.asmx/UploadRead'
http_headers_jgs = {
    "Content-Type": "application/x-www-form-urlencoded",
    "charset": "gbk"
}

'''
post_data_jgs = {
    'remoteMeterCode': 'zh',
    'userCode': '079601',
    'meterData': 'FF123456~000~2018-08-13 12:12:12~200~正常~88888881#FF123456~000~2018-08-13 12:12:12~201~正常~88888882'
}
多项用#号分隔
'''
def http_post_worker_jgs():
    post_data_jgs = {
        'remoteMeterCode': 'zh',
        'userCode': '079601',
        'meterData': ''
    }
    while True:
        if jgs_q.empty():
            time.sleep(1)
            continue

        cmd = jgs_q.get()
        me_data_string = ''
        if cmd.get('concentrator_number') in jgs_concentrators:
            _f = cmd.get('_f')
            if _f in ['upload_single_lora', 'upload_single_timing_lora', 'upload_single']:
                # 只有一个读数
                me_data_string += cmd.get('concentrator_number')  # 集中器地址
                me_data_string += '~' + '000'   # 表序号
                me_data_string += '~' + cmd['body'].get('meter_time')  # 本期抄表时间
                me_data_string += '~' + str(int(float(cmd['body'].get('meter_value'))))  # 本期度数
                me_data_string += '~' + '正常'  # 抄表状态
                me_data_string += '~' + cmd['body'].get('meter_number')[-8:]   # 水表编码(8位)
            elif _f in ['upload_multiple_timing']:
                pass
            elif _f in ['upload_single_timing_lora_big']:
                # 只有一个读数
                me_data_string += cmd.get('concentrator_number')  # 集中器地址
                me_data_string += '~' + '000'   # 表序号
                me_data_string += '~' + cmd['body'].get('meter_time')  # 本期抄表时间
                me_data_string += '~' + str(int(float(cmd['body'].get('meter_data_value'))))  # 本期度数
                me_data_string += '~' + '正常'  # 抄表状态
                me_data_string += '~' + cmd['body'].get('meter_number')[-8:]   # 水表编码(8位)
            else:
                pass

        # 开始post发送
        if me_data_string:
            post_data_jgs['meterData'] = me_data_string
            # noinspection PyBroadException
            try:
                req_jgs = requests.post(jgs_api_url, post_data_jgs, headers=http_headers_jgs)
            except Exception as e:
                logging.error('post to JGS failure.')
            else:
                if req_jgs.status_code == requests.codes.ok:
                    logging.info('[{}] - {}'.format(req_jgs.status_code, req_jgs.text))
                else:
                    logging.error('[{}] - {}'.format(req_jgs.status_code, req_jgs.text))

    logging.critical('http_get_worker(JGS) is broken.')
