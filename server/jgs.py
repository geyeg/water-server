__author__ = 'geyeg'

from ws_vars import *
import time

jgs_q = Queue(maxsize=10000)


'''
post_data_jgs = {
    'remoteMeterCode': 'zh',
    'userCode': '079601',
    'meterData': 'FF123456~000~2018-08-13 12:12:12~200~正常~88888881#FF123456~000~2018-08-13 12:12:12~201~正常~88888882'
}
多项用#号分隔
'''
def http_post_worker_jgs():
    # jgs_api_url = r'http://rocky1102.gnway.cc:8055/webservice.asmx/UploadRead'
    # jgs_api_url = r'http://61.180.38.85:8055/webservice.asmx/UploadRead'
    jgs_api_url = r'http://61.180.38.85:8055/webservice.asmx/UploadRead'
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
