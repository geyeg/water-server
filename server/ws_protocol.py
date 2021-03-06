# -*- coding: utf-8 -*-
#!/usr/bin/env python3

__author__ = 'geyeg'

from ws_common import *
from ws_vars import *


'''
字典格式打包成二进制字节流
传入字典必要key
{ is_confirm, _f,   }
包格式：控制域(1B)+地址(5B)+AFN(1B)+SEQ(1B)+数据单元标识(4B)+数据体+checksum(1B)
协议修改说明：
   开、关阀加入表号，在控制字后加8位BCD码（表号），原序号保留可用可不用
'''
def pack(hy_cmd=dict()):
    byte_pack = b''

    if not hy_cmd:
        logging.error('package is empty, can not run pack().')
        return ''

    # 控制域
    '''
    control_code = 0b00000000
    # 方向置位 服务器包默认为0 不用设置
    control_code |= direction['S2C'] << 8
    # PRM 启动标志位
    control_code |= hy_cmd['PRM'] << 7
    # 功能码
    control_code |= hy_cmd['PRM_Fn']
    # byte_pack += struct.pack('<B', control_code)
    '''
    # 控制域临时解决方案,查字典填充
    byte_pack += control_code[hy_cmd['_f']]
    # 集中器地址
    byte_pack += str_bcd_to_bytes(hy_cmd['concentrator_number'] + '00')
    # AFN
    byte_pack += struct.pack('<B', feature_to_afn[hy_cmd['_f']])
    # SEQ
    _seq = 0b00000000
    _seq |= (hy_cmd['TpV'] << 7)
    _seq |= (hy_cmd['FIR'] << 6)
    _seq |= (hy_cmd['FIN'] << 5)
    _seq |= (int(hy_cmd['is_confirm']) << 4)
    _seq |= hy_cmd['ser']
    byte_pack += struct.pack('<B', _seq)
    # 数据单元标识
    byte_pack += struct.pack('<HH', hy_cmd['data_Pn'], hy_cmd['data_Fn'])

    # 以下为私有部分(长度可变)----------

    # 数据体部分，分情况,只对服务器发给客户端的包作处理
    if hy_cmd['_t'] == 'C2S':
        logging.error('Only S2C packages can be pack:{}'.format(hy_cmd))
        return ''

    if hy_cmd['_f'] in ['login', 'logout']:  # 集中器登录、退出登录、心跳 回复
        byte_pack += struct.pack('<B', feature_to_afn[hy_cmd['_f']])  # 回复 AFN 码
        byte_pack += struct.pack('<B', hy_cmd['err'])  # 是否出错
    elif hy_cmd['_f'] == 'heartbeat':
        byte_pack += struct.pack('<B', feature_to_afn[hy_cmd['_f']])  # 回复 AFN 码
        byte_pack += struct.pack('<B', hy_cmd['err'])  # 是否出错
        byte_pack += str_bcd_to_bytes(convert_datetime_hy_to_gdw(now(fmt='time_stamp')))
    elif hy_cmd['_f'] in ['close_valve', 'open_valve']:
        byte_pack += b'\x00\x00\x00'  # 管理员密码，填充
        byte_pack += str_bcd_to_bytes(hy_cmd['body']['meter_number'], 'reverse')  # 表号
        byte_pack += b'\x00\x00\x00\x00'  # 密钥，填充
        byte_pack += b'\x00'  # 中继方式,填充
        # 控制字  0xAA-关阀，0x55-开阀
        if hy_cmd['_f'] == 'close_valve':
            byte_pack += b'\xAA'
        else:  # open_valve
            byte_pack += b'\x55'
        byte_pack += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # 消息认证字段PWD：未用（可任意）
    elif hy_cmd['_f'] in ['close_all_valve', 'open_all_valve']:
        pass  # payload为空
    elif hy_cmd['_f'] == 'upload_single_timing_lora':  # 无线小表定时上传回复
        hy_cmd['time_stamp_server'] = now(fmt='time_stamp')   # +_**********************************
        byte_pack += str_bcd_to_bytes(convert_datetime_hy_to_gdw(hy_cmd['time_stamp_server']))
        byte_pack += struct.pack('<B', hy_cmd['body']['error'])
        byte_pack += struct.pack('>I', hy_cmd['body']['_mid'])  # ****************************
    elif hy_cmd['_f'] == 'upload_single_timing_lora_big':  # 大口径无线水表定时上传回复
        byte_pack += str_bcd_to_bytes(convert_datetime_hy_to_gdw(now(fmt='time_stamp')))
        byte_pack += struct.pack('<B', hy_cmd['body']['error'])
        byte_pack += struct.pack('>I', 4)  # mid****************************
    elif hy_cmd['_f'] == 'upload_single_timing_lora_big_15min':  # 大口径无线水表15min数据上传回复
        byte_pack += str_bcd_to_bytes(convert_datetime_hy_to_gdw(now(fmt='time_stamp')))
        byte_pack += struct.pack('<B', hy_cmd['body']['error'])
        byte_pack += struct.pack('>I', 4)  # mid****************************
    elif hy_cmd['_f'] == 'upload_single_timing_lora_big_15min':  # 大口径无线水表定时上传回复(15分钟)
        byte_pack += str_bcd_to_bytes(convert_datetime_hy_to_gdw(now(fmt='time_stamp')))
        byte_pack += struct.pack('<B', hy_cmd['body']['error'])
        byte_pack += struct.pack('>I', 4)  # mid****************************
    elif hy_cmd['_f'] == 'upload_single_lora':  # 无线小表点抄
        byte_pack += b'\x01'  # 表序号 暂时没用上，填充
        byte_pack += str_bcd_to_bytes(hy_cmd['body']['meter_number'], 'reverse')
        # byte_pack += b'\x00'  # 抄读方式
        # byte_pack += b'\x01\x00'  # 点抄数量
        # byte_pack += str_bcd_to_bytes(hy_cmd['body']['meter_number'], 'reverse')
    elif hy_cmd['_f'] == 'upload_single':  # 有线点抄
        byte_pack += b'\x00'  # 抄读方式
        byte_pack += b'\x01\x00'  # 点抄数量
        byte_pack += str_bcd_to_bytes(hy_cmd['body']['meter_number'], 'reverse')
    elif hy_cmd['_f'] == 'runonce_upload_multiple_timing':  # 启动定时上传（集抄）
        pass  # 无数据体
    elif hy_cmd['_f'] == 'upload_multiple':  # 抄读多表
        byte_pack += b'\x00'  #抄读方式
        byte_pack += struct.pack('<H', len(hy_cmd['body']['meter_numbers']))
        for meter_number in hy_cmd['body']['meter_numbers']:
            byte_pack += bytes_to_bcd_str(meter_number)
    elif hy_cmd['_f'] == 'set_doc':  # 下载档案
        byte_pack += struct.pack('<H', len(hy_cmd['body']))
        for body_item in hy_cmd['body']:
            byte_pack += struct.pack('<H', body_item['meter_index'])
            # 如位数不够表号前补0
            # byte_pack += str_bcd_to_bytes(reverse_bcd(body_item['meter_number'].rjust(length_of_meter_number, '0')))
            byte_pack += str_bcd_to_bytes(reverse_bcd(body_item['meter_number']))
            byte_pack += struct.pack('<B', body_item['channel'])
        byte_pack += token  # 认证，填充
    elif hy_cmd['_f'] == 'read_doc':  # 读取档案
        byte_pack += struct.pack('<H', len(hy_cmd['body']['meter_numbers']))
        for meter_number in hy_cmd['body']['meter_numbers']:
            byte_pack += str_bcd_to_bytes(meter_number)
    elif hy_cmd['_f'] == 'set_upload_time_stamp_and_cycle_unit':  # 设置上传基准时间和上传频率
        byte_pack += struct.pack('<B', int(hy_cmd['body']['upload_cycle_unit'], 16))
        byte_pack += str_bcd_to_bytes(convert_datetime_hy_to_gdw(hy_cmd['body']['upload_time_stamp']))
        byte_pack += token  # 认证，填充
    elif hy_cmd['_f'] == 'read_upload_time_stamp_and_cycle_unit':  # 读上传基准时间和上传频率
        pass  # 无数据体
    elif hy_cmd['_f'] == 'set_upload_disable':
        byte_pack += b'\xAA'
        byte_pack += token   # 消息认证码字段
    elif hy_cmd['_f'] == 'set_upload_enable':
        byte_pack += b'\x55'
        byte_pack += token   # 消息认证码字段
    elif hy_cmd['_f'] == 'read_upload_status':
        pass  # 无数据体
    elif hy_cmd['_f'] == 'set_concentrator_number':
        byte_pack += str_bcd_to_bytes(hy_cmd['body']['new_concentrator_number'])
        byte_pack += token   # 消息认证码字段
    elif hy_cmd['_f'] == 'data_initialization':
        byte_pack += token   # 消息认证码字段
    elif hy_cmd['_f'] == 'set_gprs':
        byte_pack += b'\x00'  # 通道类型
        new_ip = list(map(int, hy_cmd['body']['ip'].split('.')))
        byte_pack += struct.pack('>BBBB', *new_ip)  # 主用ip
        byte_pack += struct.pack('<H', hy_cmd['body']['port'])  # 主用端口
        byte_pack += b'\x00\x00\x00\x00'  # 备用ip
        byte_pack += b'\x00\x00'  # 备用port
        byte_pack += b'\x00\x00\x00\x00'  # 网关
        byte_pack += b'\x00\x00'  # 端口
        byte_pack += b'\x00\x00\x00\x00'  # 代理服务器
        byte_pack += b'\x00\x00'  # 端口
        byte_pack += bytes(hy_cmd['body']['apn'], encoding='ascii').ljust(16, b'\x00')  # APN(接入点名称)补足16位
        byte_pack += b'\x00\x00\x00\x00'  # 本地ip
        byte_pack += b'\x00\x00'  # 端口
        byte_pack += b'\x00\x00\x00\x00'  # 子网掩码
        byte_pack += b'\x00\x00\x00\x00\x00\x00'  # MAC
        byte_pack += token
    elif hy_cmd['_f'] in ['upload_liquid_level', 'upload_valve_position']:  # 液位高度数据上传,阀门开度上传
        byte_pack += struct.pack('<B', feature_to_afn[hy_cmd['_f']])  # 回复 AFN 码
        byte_pack += struct.pack('<B', hy_cmd['body']['error'])
        byte_pack += str_bcd_to_bytes(convert_datetime_hy_to_gdw(now(fmt='time_stamp')))
    elif hy_cmd['_f'] == 'set_valve_position':  # 阀门开度控制设置
        byte_pack += str_bcd_to_bytes(hy_cmd['body']['meter_number'], 'reverse')
        byte_pack += struct.pack('<H', hy_cmd['body']['meter_value'])
    elif hy_cmd['_f'] == 'upload_sensor_pressure_multiple':
        byte_pack += struct.pack('<B', feature_to_afn[hy_cmd['_f']])  # 回复 AFN 码
        byte_pack += struct.pack('<B', hy_cmd['body']['error'])
    else:
        logging.error('pack body error.')
        return ''

    # 长度，包头，包尾，checksum
    length = len(byte_pack) * 4 + 1
    byte_pack = byte_pack + struct.pack('<B', checksum(byte_pack))
    byte_pack = b'\x68' + struct.pack('<HH', length, length) + b'\x68' + byte_pack
    byte_pack = byte_pack + struct.pack('<B', GDW_END_TAG)

    return byte_pack


'''
heartbeat:
{
    concentrator_number:'',
    feature:'',
    category:'',
    upload_time:'',
    collect_time:'',
}
转换为服务器格式的包，转换后可以根据不同功能发送到对应api
'''
def convert_hy_to_server(hy_dict=dict()):
    server_list = list()
    server_dict = dict()

    if not hy_dict:
        logging.error('cmd_in package is empty.')
        return ''

    _f = hy_dict.get('_f')
    server_dict['ip'] = ip
    server_dict['port'] = port
    if _f == 'heartbeat':
        server_dict['body'] = dict()
        server_dict['concentrator_number'] = get_dict_val('concentrator_number', hy_dict)
        server_dict['feature'] = get_dict_val('_f', hy_dict)
        server_dict['category'] = ''
        # server_dict['upload_time'] = verify_time(hy_dict['time_stamp_server'])
        server_dict['upload_time'] = verify_time(hy_dict['time_stamp_server'])
        # 由于集中器上传时间会严重出错（复位），这里改用服务器时间
        # server_dict['collect_time'] = verify_time(get_dict_val('upload_time_stamp', hy_dict['body']))
        server_dict['collect_time'] = verify_time(hy_dict['time_stamp_server'])
        if hy_dict['body'].get('signal'):
            server_dict['body']['signal'] = hy_dict['body']['signal']
        server_list.append(server_dict)
    elif _f in ['login', 'logout']:
        server_dict['concentrator_number'] = hy_dict.get('concentrator_number')
        server_dict['feature'] = _f
        server_dict['category'] = ''
        server_dict['upload_time'] = verify_time(hy_dict['time_stamp_server'])
        server_dict['collect_time'] = ''
        server_list.append(server_dict)
    elif _f == 'upload_single_timing_lora':
        server_dict['feature'] = _f
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['meter_number'] = hy_dict['body']['meter_number']
        server_dict['value'] = hy_dict['body']['meter_value']
        server_dict['upload_time'] = hy_dict['time_stamp_server']
        # server_dict['collect_time'] = hy_dict['body']['collect_time']
        server_dict['collect_time'] = hy_dict['time_stamp_server']
        server_dict['body'] = hy_dict['body'].copy()
        server_list.append(server_dict)
    elif _f == 'upload_single_timing_lora_big':
        server_dict['feature'] = _f
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['meter_number'] = hy_dict['body']['meter_number']
        server_dict['value'] = hy_dict['body']['meter_data_value_0']
        server_dict['upload_time'] = now()
        # server_dict['collect_time'] = hy_dict['body']['collect_time']
        server_dict['collect_time'] = now()
        server_dict['body'] = hy_dict['body'].copy()
        server_list.append(server_dict)
    elif _f == 'upload_single_timing_lora_big_15min':
        server_dict['feature'] = _f
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['meter_number'] = hy_dict['body']['meter_number']
        server_dict['value'] = hy_dict['body']['meter_data_values'][0]
        server_dict['upload_time'] = now()
        # server_dict['collect_time'] = hy_dict['body']['collect_time']
        server_dict['collect_time'] = now()
        server_dict['body'] = hy_dict['body'].copy()
        server_list.append(server_dict)
    elif _f in ['upload_multiple_timing']:
        for body_item in hy_dict['body']:
            server_dict['feature'] = _f
            server_dict['concentrator_number'] = hy_dict['concentrator_number']
            server_dict['meter_number'] = body_item['meter_number']
            server_dict['value'] = body_item['meter_value']
            server_dict['upload_time'] = verify_time(hy_dict.get('time_stamp_server'))
            server_dict['collect_time'] = ''
            server_list.append(server_dict.copy())
    elif _f == 'upload_single_lora':
        server_dict['id'] = hy_dict['id']
        server_dict['result'] = 'ok'
        server_list.append(server_dict)
    elif _f == 'upload_single':
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['meter_number'] = hy_dict['body']['meter_number']
        server_dict['value'] = hy_dict['body']['meter_value']
        server_dict['upload_time'] = now()
        server_dict['collect_time'] = now()
        server_list.append(server_dict)
    elif _f == 'read_doc':
        server_dict['feature'] = _f
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['meter_number'] = ''
        server_dict['body'] = hy_dict['body'].copy()
        server_list.append(server_dict)
    elif _f in ['close_valve', 'open_valve']:
        server_dict['id'] = hy_dict['id']
        server_dict['result'] = 'ok'
        server_list.append(server_dict)
    elif _f in ['close_all_valve', 'open_all_valve']:
        server_dict['id'] = hy_dict['id']
        server_dict['result'] = 'ok'
        server_list.append(server_dict)
    elif _f == 'read_upload_status':
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['feature'] = _f
        server_dict['body'] = hy_dict['body'].copy()
        server_list.append(server_dict)
    elif _f == 'set_upload_time_stamp_and_cycle_unit':
        server_dict['id'] = hy_dict['id']
        server_list.append(server_dict)
    elif _f == 'read_upload_time_stamp_and_cycle_unit':
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['feature'] = _f
        server_dict['body'] = hy_dict['body'].copy()
        server_list.append(server_dict)
    elif _f == 'set_concentrator_number':
        server_dict['id'] = hy_dict['id']
        server_dict['result'] = 'ok'
        server_list.append(server_dict)
    elif _f == 'data_initialization':
        server_dict['id'] = hy_dict['id']
        server_dict['result'] = 'ok'
        server_list.append(server_dict)
    elif _f == 'set_gprs':
        server_dict['id'] = hy_dict['id']
        server_dict['result'] = 'ok'
        server_list.append(server_dict)
    elif _f in ['upload_liquid_level', 'upload_valve_position']:
        server_dict['body'] = dict()
        server_dict['feature'] = _f
        server_dict['concentrator_number'] = hy_dict.get('concentrator_number')
        server_dict['meter_number'] = hy_dict['body']['meter_number']
        server_dict['value'] = hy_dict['body']['meter_value']
        server_dict['body'] = hy_dict['body'].copy()
        server_dict['upload_time'] = verify_time(hy_dict.get('time_stamp_server'))
        server_dict['collect_time'] = verify_time(hy_dict.get('time_stamp_server'))
        server_list.append(server_dict)
    elif _f == 'set_valve_position':
        server_dict['body'] = dict()
        server_dict['feature'] = _f
        server_dict['concentrator_number'] = hy_dict['concentrator_number']
        server_dict['body']['afn'] = hy_dict['body']['afn']
        server_dict['body']['error'] = hy_dict['body']['error']
        server_list.append(server_dict)
    elif _f == 'upload_sensor_pressure_multiple':
        server_dict['body'] = dict()
        server_dict['body'] = hy_dict['body'].copy()
        server_dict['feature'] = _f
        server_dict['concentrator_number'] = hy_dict.get('concentrator_number')
        server_dict['body']['pressure_sensor']['pressure_value'] = \
            hy_dict['body']['pressure_sensor']['pressure_values'][-1]
        server_dict['collect_time'] = now()
        server_dict['upload_time'] = now()
        server_list.append(server_dict)
    elif _f is None:
        server_list.append(hy_dict)
    else:
        logging.error('[HY to server]AFN out of services.')
        return []

    return server_list


'''
把服务器指令转为协议字典格式
{
    'meter_number': '87201088',
    'feature': 'close_valve',
    'category': '',
    'concentrator_number': '02000029'
}

转成 (此例不完全)

sample = {
    "length": 4,
    "meter_type": 32,
    "direction": "S2C",
    "action": "read",
    "sn": 1,
    "status": "ok",
    "data_id": 6048,
    "meter_number": "00000000001111",
    "feature": "close_valve"
}

'''
def convert_server_to_hy(server_dict=dict()):
    hy_pack_dict = dict()
    hy_pack_dict['body'] = dict()
    # 公共部分
    if server_dict.get('_c') in ['assign_cmd', 'assign_cmd_reply']:
        hy_pack_dict['id'] = server_dict['id']
    hy_pack_dict['_t'] = 'S2C'
    hy_pack_dict['PRM'] = 1
    hy_pack_dict['concentrator_number'] = server_dict['concentrator_number']
    # hy_pack_dict['concentrator_address'] =
    # convert_number_to_address(server_dict['concentrator_number'], 'concentrator')
    hy_pack_dict['TpV'] = 0
    hy_pack_dict['FIR'] = 1
    hy_pack_dict['FIN'] = 1
    hy_pack_dict['data_Pn'] = 0x00
    hy_pack_dict['_c'] = server_dict['_c']
    hy_pack_dict['err'] = 0  # 暂时认为都是正确，以后要去掉，放在其它地方
    hy_pack_dict['_f'] = server_dict['feature']
    if server_dict['body']:
        hy_pack_dict['body'] = server_dict['body'].copy()
    hy_pack_dict['data_Fn'] = 0x01

    _feature = server_dict['feature']
    if _feature == 'heartbeat':  # 心跳 回复
        hy_pack_dict['is_confirm'] = False
        hy_pack_dict['_c'] = 'apply_cmd_reply'
    elif _feature in ['login', 'logout']:  # 登录、退出登录 回复
        hy_pack_dict['is_confirm'] = False
        hy_pack_dict['_c'] = 'apply_cmd_reply'
    elif _feature == 'upload_multiple_timing':  # 有线定时上传 回复
        pass  # 无需回复
    elif _feature == 'upload_single_timing_lora':  # 定时上传，无线水表，每次上传一个
        hy_pack_dict['is_confirm'] = False
        hy_pack_dict['_c'] = 'apply_cmd_reply'
        hy_pack_dict['body']['time_stamp_server'] = now(fmt='time_stamp')
        hy_pack_dict['body']['error'] = 0
        hy_pack_dict['body']['_mid'] = server_dict['body']['_mid']
    elif _feature in ['upload_single_timing_lora_big', 'upload_single_timing_lora_big_15min']:
        hy_pack_dict['is_confirm'] = False
        hy_pack_dict['_c'] = 'apply_cmd_reply'
        hy_pack_dict['body']['time_stamp_server'] = now(fmt='time_stamp')
        hy_pack_dict['body']['error'] = 0
        # hy_pack_dict['body']['_mid'] = server_dict['body']['_mid']
        # hy_pack_dict['body']['_mid'] = convert_address_to_number(server_dict['body']['meter_address'], 'meter')
        hy_pack_dict['body']['_mid'] = 0
    elif _feature in ['close_valve', 'open_valve']:  # 开、关阀
        hy_pack_dict['is_confirm'] = True
    elif _feature in ['close_all_valve', 'open_all_valve']:  # 一个集中器下所有水表开、关阀
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'set_doc':  # 下载档案
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'read_doc':
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'runonce_upload_multiple_timing' and server_dict['_c'] == 'assign_cmd':  # 901F集抄
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'runonce_upload_multiple_timing_lora' and server_dict['_c'] == 'assign_cmd':  # 90EF集抄
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'upload_single_lora' and server_dict['_c'] == 'assign_cmd' and \
            server_dict['body']['protocol'] == '90ef':  # 无线点抄
        hy_pack_dict['is_confirm'] = True
        hy_pack_dict['body']['meter_number'] = server_dict['body']['meter_number']
        hy_pack_dict['body']['meter_index'] = 1
    # elif _feature == 'upload_single_lora' and server_dict['assign_cmd_reply']:  # 无线点抄回复
    #     hy_pack_dict['is_confirm'] = False
    #     hy_pack_dict['_f'] = _feature
    elif _feature == 'upload_single' and server_dict['_c'] == 'assign_cmd':  # 有线点抄
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'set_upload_time_stamp_and_cycle_unit' and server_dict['_c'] == 'assign_cmd':
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'read_upload_time_stamp_and_cycle_unit' and server_dict['_c'] == 'assign_cmd':
        hy_pack_dict['is_confirm'] = True
    elif _feature in ['set_upload_disable', 'set_upload_enable'] and server_dict['_c'] == 'assign_cmd':
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'set_concentrator_number' and server_dict['_c'] == 'assign_cmd':
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'data_initialization' and server_dict['_c'] == 'assign_cmd':
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'set_gprs' and server_dict['_c'] == 'assign_cmd':
        hy_pack_dict['is_confirm'] = True
    elif _feature in ['upload_liquid_level', 'upload_valve_position']:
        hy_pack_dict['is_confirm'] = False
        hy_pack_dict['_c'] = 'apply_cmd_reply'
        hy_pack_dict['body']['time_stamp_server'] = now(fmt='time_stamp')
        hy_pack_dict['body']['error'] = 0
    elif _feature == 'set_valve_position' and server_dict['_c'] == 'assign_cmd':
        hy_pack_dict['is_confirm'] = True
    elif _feature == 'upload_sensor_pressure_multiple':
        hy_pack_dict['is_confirm'] = False
        hy_pack_dict['_c'] = 'apply_cmd_reply'
        hy_pack_dict['body']['time_stamp_server'] = now(fmt='time_stamp')
        hy_pack_dict['body']['error'] = 0
    else:
        logging.error('feature out of services:{}'.format(server_dict))
        hy_pack_dict = ''

    # 如果是下发指令，需要取ser(报文序列)
    if hy_pack_dict['is_confirm']:
        if hy_pack_dict['concentrator_number'] in online_dev:
            hy_pack_dict['ser'] = (online_dev[server_dict['concentrator_number']]['ser'] % 16) + 1
        else:
            logging.error('[convert_server_to_hy] concentrator offline, can not convert this pack.')
            logging.error(hy_pack_dict)
            return ''
    else:  # apply_cmd_reply
        hy_pack_dict['ser'] = server_dict['ser']

    return hy_pack_dict
