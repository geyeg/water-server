__author__ = 'geyeg'

from ws_common import *
import time
from decode import *

fragment_packet_q = Queue(maxsize=20000)
# 碎片包丢弃时间
timeout = 60

'''
{
    'concentrator_number': '',
    {
        'living_count': 0,
        'frag_packet': {}
    }

}
--------------------------
FIR：置“1”，报文的第一帧。
FIN：置“1”，报文的最后一帧。
FIR	FIN	应用说明
0	0	多帧：中间帧
0	1	多帧：结束帧
1	0	多帧：第1帧，有后续帧
1	1	单帧

'''
fragment_packet_dict = dict()

def assemble_worker():
    while True:
        # 处理周期
        time.sleep(1)

        # 处理一次队列内所有任务
        while not fragment_packet_q.empty():
            in_frag_pack = fragment_packet_q.get()
            _concentrator = in_frag_pack.get('concentrator_number')
            if not _concentrator:
                continue
            # 把碎片包放入字典，序号为key(自动排序)
            if _concentrator not in fragment_packet_dict:  # 不在字典内（新包）就创建新项
                fragment_packet_dict[_concentrator] = dict()
                fragment_packet_dict[_concentrator]['living_count'] = 0
                fragment_packet_dict[_concentrator]['frag_packet'] = dict()
            # 新进包一律放入字典
            fragment_packet_dict[_concentrator]['frag_packet'][in_frag_pack['data_Pn']] = in_frag_pack.copy()

            # 收到结束帧，开始处理组包
            if in_frag_pack['FIR'] == 0 and in_frag_pack['FIN'] == 1:
                body_data = b''
                for pk_idx in range(0, in_frag_pack['data_Pn'] + 1):
                    data = fragment_packet_dict[_concentrator]['frag_packet'][pk_idx]['body_hex']
                    if data:
                        body_data += data
                    else:
                        body_data = ''
                        break
                if body_data:
                    full_packet = decode_body(body_data, in_frag_pack)
                    logging.info('assembled packet:{}'.format(json.dumps(full_packet, indent=4)))
                    if full_packet:
                        if full_packet['_f'] in need_post_feature_list:
                            post_q.put(full_packet)
                del(fragment_packet_dict[in_frag_pack['concentrator_number']])

        # 累加超时(时间不准确，有大量组包任务超时偏差很大)
        concentrator_list = list(fragment_packet_dict.keys()).copy()
        for _c in concentrator_list:
            fragment_packet_dict[_c]['living_count'] += 1
            if fragment_packet_dict[_c]['living_count'] > timeout:
                del(fragment_packet_dict[_c])

    logging.critical('assemble_worker is broken.')
