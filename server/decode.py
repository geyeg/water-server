__author__ = 'geyeg'

from ws_vars import *
from ws_common import *

'''
解出头部，body以二进制返回
返回：（{}, b''）,返回元组格式，head字典形式返回，body二进制格式返回
'''
def decode_head(msg_bin=b''):
    msg = msg_bin
    raw_body_data = b''
    gdw_pack = dict(body=dict())
    # 检查长度是否太短，太短会造成下面利用下标定位的操作出错，这里先防止
    if len(msg) < 20:
        logging.error('Packet is too short:{}'.format(bytes_to_show(msg)))
        return {}, ''
    # 检测分隔符是否存在
    if (msg[0] != GDW_HEADER_TAG) or (msg[5] != GDW_HEADER_TAG) or (msg[-1] != GDW_END_TAG):
        logging.error('Packet tag error:{}'.format(bytes_to_show(msg)))
        return {}, ''
    # checksum
    if not is_checksum_pass(msg):
        logging.error('packet checksum error:{}'.format(bytes_to_show(msg)))
        return {}, ''
    # 检查长度是否出现错误，从包中读出长度,这里的长度不是真正的长度
    length, length_verify = struct.unpack('<HH', msg[1:5])
    if length != length_verify:
        logging.error('Length scope mismatch:{}'.format(bytes_to_show(msg)))
        return {}, ''
    # 取原始长度字段后两位D1D0位作为协议类型
    # gdw_pack['protocol_type'] = length & 0x0003
    '''
    其计算方式为: L = length(控制域+地址域+链路用户数据) * 4 + 1
    在使用专用无线数传信道时，长度L1不能大于255字节；采用网络传输时，长度L1可以支持到16383字节。
    '''
    # 转为真正的长度，其计算方式为: L = length(控制域+地址域+链路用户数据) * 4 + 1
    length = int((length - 1) / 4)
    if length != len(msg[HEADER_SIZE:-2]):
        logging.error('Length error:{}'.format(bytes_to_show(msg)))
        return {}, ''
    gdw_pack['msg_len'] = length
    # 去掉无关数据
    msg = msg[HEADER_SIZE:-2]
    # 控制域解包
    _control_code = int.from_bytes(msg[0:1], 'little')
    # DIR=1：表示此帧报文是由终端发出的上行报文
    # DIR=0：表示此帧报文是由主站发出的下行报文
    gdw_pack['DIR'] = direction[(_control_code & 0b10000000) >> 7]
    # PRM 未清楚
    gdw_pack['PRM'] = (_control_code & 0b01000000) >> 6
    gdw_pack['PRM_Fn'] = _control_code & 0b00001111
    # 地址
    gdw_pack['concentrator_number'] = bytes_to_bcd_str(msg[1:6])[:-2]
    # AFN
    gdw_pack['AFN'] = int.from_bytes(msg[6:7], 'little')
    # 判断 AFN 是否超出处理范围
    if gdw_pack['AFN'] not in afn_to_feature:
        logging.error('AFN {} out of services.'.format(hex(gdw_pack['AFN'])))
        return {}, ''
    gdw_pack['_f'] = afn_to_feature.get(gdw_pack['AFN'])
    if not gdw_pack['_f']:
        logging.error('AFN name not found:{}'.format(bytes_to_show(msg)))
        return {}, ''
    # SEQ
    seq = int.from_bytes(msg[7:8], 'little')
    gdw_pack['TpV'] = (seq & 0b10000000) >> 7
    gdw_pack['FIR'] = (seq & 0b01000000) >> 6
    gdw_pack['FIN'] = (seq & 0b00100000) >> 5
    gdw_pack['CON'] = (seq & 0b00010000) >> 4
    gdw_pack['is_confirm'] = bool(gdw_pack['CON'])
    gdw_pack['ser'] = seq & 0b00001111
    # 数据标识
    gdw_pack['data_Pn'], gdw_pack['data_Fn'] = struct.unpack('<HH', msg[8:12])
    # 保存数据体原始包
    raw_body_data = msg[12:]
    # gdw_pack['body_hex'] = raw_body_data

    # 加上服务器接收时间
    gdw_pack['time_stamp_server'] = now(fmt='time_stamp')
    gdw_pack['feature'] = gdw_pack['_f']

    return gdw_pack, raw_body_data

'''
解出body，
'''
def decode_body(raw_body_data=b'', head=dict()):
    payload = dict()
    if not head:
        logging.error('head dict null.')
        return {}
    feature = head.get('_f')
    if not feature:
        logging.error('feature not found:{}'.format(head))
        return {}

    if feature == 'heartbeat':
        # 判断是否存在信号这一段
        if len(raw_body_data) > 6:
            concentrator_clock = raw_body_data[0:6]
            payload['signal'] = raw_body_data[6]
        else:
            concentrator_clock = raw_body_data
        heartbeat_time = bytes_to_bcd_str(concentrator_clock[::-1])
        month_and_week = concentrator_clock[-2]
        # 月份中D0~D3为月份个位D5为月份10位，其它可以去掉（星期）
        month_low = month_and_week & 0b00001111
        month_high = month_and_week & 0b00010000 >> 5
        month_and_week_str = str(month_high) + str(month_low)
        heartbeat_time = heartbeat_time[0:2] + month_and_week_str + heartbeat_time[5:]
        payload['upload_time_stamp'] = '20' + heartbeat_time
        # gdw_pack['body']['upload_time_stamp'] = convert_datetime_gdw_to_hy(raw_body_data)
    elif feature in ['login', 'logout']:
        pass
    elif feature == 'upload_single_timing_lora':
        payload = decode_upload_single_timing_lora(raw_body_data).copy()
    elif feature == 'upload_single_timing_lora_big':
        payload = decode_upload_single_timing_lora_big(raw_body_data).copy()
    elif feature == 'upload_single_timing_lora_big_15min':
        payload = decode_upload_single_timing_lora_big_15min(raw_body_data).copy()
    elif feature == 'upload_single':
        payload['meter_number'] = bytes_to_bcd_str(raw_body_data[2:9], 'reverse')
        payload['meter_value'] = convert_to_int_90ef(bytes_to_bcd_str(raw_body_data[9:], 'reverse'))
    elif feature == 'set_doc':  # 下载档案
        payload['error'] = head['data_Fn']
    elif feature == 'read_doc':  # 读取档案
        payload = list()
        meter_count = struct.unpack('<H', raw_body_data[0:2])[0]
        for _i in range(0, meter_count):
            body_item = dict(
                meter_index=struct.unpack('<H', raw_body_data[2 + _i * 8: 4 + _i * 8])[0],
                meter_number=bytes_to_bcd_str(raw_body_data[4 + _i * 8: 10 + _i * 8])
            )
            payload.append(body_item.copy())
    elif feature in ['upload_multiple_timing', 'upload_single']:
        payload = list()
        meter_count = struct.unpack('<H', raw_body_data[0:2])[0]
        for _i in range(0, meter_count):
            body_item = dict(
                meter_number=bytes_to_bcd_str(raw_body_data[2 + _i * 11: 9 + _i * 11], 'reverse'),
                meter_value = convert_to_int_90ef(bytes_to_bcd_str(raw_body_data[9 + _i * 11:13 + _i * 11], 'reverse'))
            )
            payload.append(body_item.copy())
    elif feature == 'runonce_upload_multiple_timing':
        pass  # 无数据体
    elif feature in ['set_upload_disable', 'set_upload_enable']:
        pass  # 无数据体
    elif feature == 'read_upload_status':
        if raw_body_data[0] == b'\xAA':
            payload['upload_status'] = 'disable'
        else:  # ==b'\x55'
            payload['upload_status'] = 'enable'
    elif feature == 'set_upload_time_stamp_and_cycle_unit':
        pass  # 无数据体
    elif feature == 'read_upload_time_stamp_and_cycle_unit':
        payload['upload_cycle_unit'] = raw_body_data[0]
        payload['upload_time_stamp'] = convert_datetime_gdw_to_hy(bytes_to_bcd_str(raw_body_data[1:]))
    elif feature == 'set_concentrator_number':
        pass  # 无数据体
    elif feature == 'data_initialization':
        pass  # 无数据体
    elif feature == 'set_gprs':
        pass  # 无数据体
    elif feature == 'upload_sensor_pressure_temperature':
        payload['pressure_sensor'] = dict()
        payload['temperature_sensor'] = dict()
        payload['pressure_sensor']['number'] = bytes_to_bcd_str(raw_body_data[0:4], 'reverse')
        payload['temperature_sensor']['number'] = payload['pressure_sensor']['number']
        payload['pressure_sensor']['pressure_value'] = struct.unpack('<H', raw_body_data[5:8])
        payload['temperature_sensor']['temperature_value'] = struct.unpack('<H', raw_body_data[9:])
    elif feature == 'upload_sensor_pressure_multiple':
        payload = decode_upload_sensor_pressure_multiple(raw_body_data).copy()
    elif feature in ['upload_liquid_level', 'upload_valve_position']:  # 液位高度数据上传、阀门开度上传
        payload['meter_number'] = bytes_to_bcd_str(raw_body_data[0:7], 'reverse')
        payload['meter_value'] = struct.unpack('<H', raw_body_data[7:])[0]
    elif feature == 'set_valve_position':  # 阀门开度控制设置
        payload['reply_afn'] = raw_body_data[0]
        payload['error'] = raw_body_data[1]
    else:
        logging.error('decode body but feature not found:[{}] - {}'.format(bytes_to_show(raw_body_data), head))

    full_packet = head.copy()
    full_packet['body'] = payload.copy()

    return full_packet


'''
解释小表90EF
'''
def decode_upload_single_timing_lora(body_bytes=b''):
    body_dict = dict()
    # body_dict['collect_time'] = convert_datetime_gdw_to_hy(body_bytes[0:6])
    body_dict['collect_time'] = now()
    # body_dict['meter_index'] = body_bytes[6]
    # body_dict['meter_address'] = format_address(bytes_to_bcd_str(body_bytes[7:13]))
    body_dict['meter_number'] = bytes_to_bcd_str(body_bytes[6:13], 'reverse')
    # 当前正累计流量
    # body_dict['meter_value'] = ''.join(re.findall(r'.{2}', bytes_to_bcd_str(body_bytes[13:17]))[::-1])
    body_dict['meter_value'] = convert_to_int_90ef(bytes_to_bcd_str(body_bytes[13:17], 'reverse'))
    body_dict['unit'] = unit.get(body_bytes[17])
    # 当前负累积流量
    body_dict['meter_revalue'] = convert_to_int_90ef(bytes_to_bcd_str(body_bytes[18:22], 'reverse'))
    body_dict['unit_revalue'] = unit.get(body_bytes[22])
    # 水表时间
    body_dict['meter_time'] = verify_time(bytes_to_bcd_str(body_bytes[23:30], 'reverse'))

    # 表计状态
    st0 = body_bytes[30]
    # 阀门状态
    # body_dict['state_valve'] = meter_status_valve[body_bytes[30] & 0b00000011]
    body_dict['state_valve'] = st0 & 0b00000011
    # 电池电压
    # body_dict['state_voltage_level'] = meter_status_voltage_level[body_bytes[30] & 0b00000100 >> 2]
    body_dict['state_voltage_level'] = (st0 & 0b00000100) >> 2
    # 电子铅封
    body_dict['state_elock'] = (st0 & 0b00100000) >> 5
    # 温度传感器
    # body_dict['state_temperature_sensor'] = meter_status_temperature_sensor[body_bytes[30] & 0b01000000 >> 6]
    body_dict['state_temperature_sensor'] = (st0 & 0b01000000) >> 6
    # 阀门响应标志
    # body_dict['state_valve_response'] = meter_status_valve_response[body_bytes[30] & 0b10000000 >> 7]
    body_dict['state_valve_response'] = (st0 & 0b10000000) >> 7

    # 流量超量程
    body_dict['flow_up'] = body_bytes[31]
    # 流量超量程出现时间
    body_dict['flow_up_time'] = format_90ef_datetime(bytes_to_bcd_str(body_bytes[32:36], 'reverse'))
    # 温度超范围
    body_dict['temp_up'] = body_bytes[36]
    # 温度超范围出现时间
    body_dict['temp_up_time'] = format_90ef_datetime(bytes_to_bcd_str(body_bytes[37:41], 'reverse'))
    # 上盖被打开报警出现时间
    body_dict['cover_is_opened'] = format_90ef_datetime(bytes_to_bcd_str(body_bytes[41:45], 'reverse'))
    # 空管报警出现时间
    body_dict['empty_pipe_alarm'] = format_90ef_datetime(bytes_to_bcd_str(body_bytes[45:49], 'reverse'))
    # 电池低电压报警时间
    body_dict['low_voltage'] = format_90ef_datetime(bytes_to_bcd_str(body_bytes[49:53], 'reverse'))
    # 反向流量曾达到值
    body_dict['reflow_up'] = convert_to_int(bytes_to_bcd_str(body_bytes[53:55], 'reverse')) / 1000
    # 反向流量报警时间
    body_dict['reflow_up_time'] = format_90ef_datetime(bytes_to_bcd_str(body_bytes[55:59], 'reverse'))
    # 0点总流量数据
    body_dict['point0_freeze_value'] = convert_to_int(bytes_to_bcd_str(body_bytes[59:63], 'reverse')) / 1000
    # 每小时流量数据BCD码,后3位是小数
    for mv in range(0, 24):
        body_dict['fmv' + str(mv)] = \
            convert_to_int(bytes_to_bcd_str(body_bytes[63 + mv * 2:65 + mv * 2], 'reverse')) / 1000
    # 1号电池电压  2号电池电压  无线模块电池电压
    body_dict['cell_voltage_1'] = convert_to_int(body_bytes[111]) / 10
    body_dict['cell_voltage_2'] = convert_to_int(body_bytes[112]) / 10
    body_dict['cell_voltage_lora'] = convert_to_int(body_bytes[113]) / 10
    # 水温
    body_dict['water_temperature'] = body_bytes[114]
    # 采表次数
    body_dict['read_meter_times'] = body_bytes[115]
    # 信号强度
    body_dict['signal'] = body_bytes[116]
    # MID
    body_dict['_mid'] = struct.unpack('>I', body_bytes[117:])[0]
    return body_dict


'''
解释大表90EF
'''
def decode_upload_single_timing_lora_big(body_bytes=b''):
    body_dict = dict()
    body_dict['collect_time'] = now()
    # body_dict['meter_index'] = body_bytes[6]
    body_dict['meter_number'] = bytes_to_bcd_str(body_bytes[6:12], 'reverse')

    # 24小时读数BCD码，无小数位
    for mv in range(0, 24):
        body_dict['meter_data_value_' + str(mv)] = \
            convert_to_int(bytes_to_bcd_str(body_bytes[12 + mv * 4: 16 + mv * 4], 'reverse'))
    body_dict['unit'] = unit.get(body_bytes[108])
    body_dict['meter_time'] = verify_time(bytes_to_bcd_str(body_bytes[109:116], 'reverse'))
    # 表计状态
    st0 = body_bytes[116]
    # 阀门状态
    # body_dict['state_valve'] = meter_status_valve[body_bytes[30] & 0b00000011]
    body_dict['state_valve'] = st0 & 0b00000011
    # 电池电压
    # body_dict['state_voltage_level'] = meter_status_voltage_level[body_bytes[30] & 0b00000100 >> 2]
    body_dict['state_voltage_level'] = (st0 & 0b00000100) >> 2
    # 电子铅封
    body_dict['state_elock'] = (st0 & 0b00100000) >> 5
    # 温度传感器
    # body_dict['state_temperature_sensor'] = meter_status_temperature_sensor[body_bytes[30] & 0b01000000 >> 6]
    body_dict['state_temperature_sensor'] = (st0 & 0b01000000) >> 6
    # 阀门响应标志
    # body_dict['state_valve_response'] = meter_status_valve_response[body_bytes[30] & 0b10000000 >> 7]
    body_dict['state_valve_response'] = (st0 & 0b10000000) >> 7
    return body_dict


'''
解包：大口径水表15分钟读数上传
'''
def decode_upload_single_timing_lora_big_15min(body_bytes=b''):
    body_dict = dict()
    body_dict['collect_time'] = verify_time('20' + bytes_to_bcd_str(body_bytes[0:6], 'reverse'))
    # body_dict['collect_time'] = now()
    body_dict['meter_number'] = bytes_to_bcd_str(body_bytes[6:13], 'reverse')
    meter_data_values = [bytes_to_bcd_str(body_bytes[13 + i * 4:13 + i * 4 + 4], 'reverse') for i in range(0, 96)]
    body_dict['meter_data_values'] = list(map(convert_to_int_90ef, meter_data_values))
    _unit = unit.get(body_bytes[397])
    if _unit:
        body_dict['unit'] = _unit
    else:
        body_dict['unit'] = ''
    body_dict['meter_time'] = verify_time(bytes_to_bcd_str(body_bytes[398:405], 'reverse'))
    # body_dict['meter_time'] = now()
    st0 = body_bytes[404]
    # 阀门状态
    # body_dict['state_valve'] = meter_status_valve[body_bytes[30] & 0b00000011]
    body_dict['state_valve'] = st0 & 0b00000011
    # 电池电压
    # body_dict['state_voltage_level'] = meter_status_voltage_level[body_bytes[30] & 0b00000100 >> 2]
    body_dict['state_voltage_level'] = (st0 & 0b00000100) >> 2
    # 电子铅封
    body_dict['state_elock'] = (st0 & 0b00100000) >> 5
    # 温度传感器
    # body_dict['state_temperature_sensor'] = meter_status_temperature_sensor[body_bytes[30] & 0b01000000 >> 6]
    body_dict['state_temperature_sensor'] = (st0 & 0b01000000) >> 6
    # 阀门响应标志
    # body_dict['state_valve_response'] = meter_status_valve_response[body_bytes[30] & 0b10000000 >> 7]
    body_dict['state_valve_response'] = (st0 & 0b10000000) >> 7
    return body_dict


'''
压力传感器15分钟上传
出错值\0xEE\0xEE(61166) 上报给服务器14141414
'''
def decode_upload_sensor_pressure_multiple(body_bytes=b''):
    body_dict = dict()
    body_dict['pressure_sensor'] = dict()
    body_dict['pressure_sensor']['number'] = bytes_to_bcd_str(body_bytes[0:7], 'reverse')
    body_dict['pressure_sensor']['pressure_values'] = list()
    for i in range(0, 96):  # 8*12
        pressure_value = struct.unpack('<H', body_bytes[7 + i * 2:7 + i * 2 + 2])[0]
        if pressure_value == 61166:
            body_dict['pressure_sensor']['pressure_values'].append(14141414)
        else:
            body_dict['pressure_sensor']['pressure_values'].append(pressure_value)
    return body_dict
