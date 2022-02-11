import pprint

import click
import yaml
import time
import socket
import sys

from ipaddress import IPv4Interface

from scrapli import Scrapli
from scrapli.helper import textfsm_parse
from scrapli.exceptions import ScrapliAuthenticationFailed, ScrapliConnectionNotOpened

from dns.resolver import resolve, NXDOMAIN

from configurations import *


def validate_ip(string):
    prefix = '32'
    if '/' in string:
        string, prefix = string.split('/')

    octets = string.split('.')

    if len(octets) == 4 and any(l.isdigit() and 0<int(l)<256 for l in octets) and 0<int(prefix)<33:
        return '{}/{}'.format('.'.join(octets), prefix)

    return False


def load_data_form_file(path_to_file: Path) -> tuple[int, list]:
    def dns_lookup(hostname: str) -> tuple[int, list]:
        response = resolve(hostname)

        return response.rrset.ttl, [row.address for row in response]

    result = []

    with open(path_to_file) as f:
        min_ttl = 604800
        for row in f:
            row = row.strip()
            ip_address = validate_ip(row)

            if ip_address:
                # Разобраться, какой устанавливать ttl для адресов. [min_ttl]
                ttl, addresses = 10000, [IPv4Interface(ip_address)]
            else:
                try:
                    ttl, addresses = dns_lookup(row)
                    addresses = [IPv4Interface(f'{ip}/32') for ip in addresses]
                except NXDOMAIN:
                    logger.log(logging.CRITICAL, f'Не распознаное имя {row}')
                    continue

            min_ttl = ttl if ttl < min_ttl else min_ttl

            result.extend(addresses)

        logger.log(logging.INFO, f'Данные {path_to_file} загрежены')
        logger.log(logging.INFO, f'Минимальный ttl = {min_ttl}')

        return min_ttl, result


def get_devices(groups: list, path_to_file: Path) -> list[dict]:
    def filter_by_ip(all_, ip):
        nonlocal result

        if ip in all_:
            result.append(dict(host=ip, **all_[ip]))
        else:
            logger.log(logging.CRITICAL, f'Устройство {ip} отсутствует в inventory_file')

    result = []

    with open(path_to_file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    all_ = data.get('all', [])

    if 'all' in groups:
        result.extend([dict(host=k, **all_[k]) for k in all_])
    else:
        for gname in groups:
            if validate_ip(gname):
                filter_by_ip(all_, gname)
            elif gname in data:
                ip_addresses = data.get(gname)
                for ip in ip_addresses:
                    filter_by_ip(all_, ip)
            else:
                print(f'{gname}: отсутствует в файле инвенторизации')
                print('Проверьте правильность веденных даных !')

    return result


def get_srs_or_dest(row: dict, dst=False) -> IPv4Interface:
    prefix = 'src_' if not dst else 'dst_'

    host = prefix + 'host'
    network = prefix + 'network'
    wildcard = prefix + 'wildcard'

    if not row[host]:
        result_str = f'{row.get(network)}/{row.get(wildcard)}'
    else:
        result_str = row.get(host) + '/32'

    return IPv4Interface(result_str)


def iface_to_str(ip_interface: IPv4Interface, with_='with_hostmask') -> str:
    ip, prefix = getattr(ip_interface, with_).split('/')

    if prefix == '0.0.0.0':
        result_str = f'host {ip}'
    else:
        result_str = f'{ip} {prefix}'

    return result_str


def create_acl_cfg(conn: Scrapli, dst_interfaces: list[IPv4Interface], acl_name: str) -> list:
    rows = [f'ip access-list ex {acl_name}']
    row_tpl = 'permit ip {source} {destination}'
    textfsm_tpl = BASEDIR.joinpath('cisco_ios_show_ip_access-lists.textfsm')

    cur_acl_cfg = conn.send_command(f'show ip access-list {acl_name}').result

    if not cur_acl_cfg:
        logger.log(logging.CRITICAL, f' Список доступа {acl_name} отсутствует')

    parsed_data = textfsm_parse(textfsm_tpl, cur_acl_cfg)[1:]
    srs_interfaces = set([get_srs_or_dest(row) for row in parsed_data])

    for cur_acl_row in parsed_data:
        src = get_srs_or_dest(cur_acl_row)
        dst = get_srs_or_dest(cur_acl_row, dst=True)

        if dst in dst_interfaces:
            dst_interfaces.remove(dst)
        else:
            rows.append('no ' + row_tpl.format(source=iface_to_str(src), destination=iface_to_str(dst)))

    for dst in dst_interfaces:
        for src in srs_interfaces:
            rows.append(row_tpl.format(source=iface_to_str(src), destination=iface_to_str(dst)))

    return rows


def check_port_alive(host: str, port=22) -> bool:
    result = False

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        code = s.connect_ex((host, port))

        if code == 0:
            s.close()
            result = True
    except Exception:
        pass

    return result


def create_loiface(csr, ip_interfaces, username, password):
    global LAST_CREATED_INTERFACE

    delete_cfg_tpl = 'no interface loopback{}'
    create_cfg_tpl = 'interface loopback{}\n ip address {}'

    tmp = list()
    for i, ip_interface in enumerate(ip_interfaces, 10):
        ip_address = ' '.join(ip_interface.with_netmask.split('/'))
        tmp.append(create_cfg_tpl.format(i, ip_address))

    delete_cfg = '\n!\n'.join([delete_cfg_tpl.format(_) for _ in range(10, LAST_CREATED_INTERFACE)])
    create_cfg = '\n!\n'.join(tmp)

    conn = connect_open(csr, username, password)
    if conn:
        if delete_cfg:
            logger.log(logging.INFO, f'Удалено {LAST_CREATED_INTERFACE} loopback интерфейсов ')
            conn.send_config(delete_cfg)

        logger.log(logging.INFO, f'Создано {len(tmp)} loopback интерфейсов ')
        conn.send_config(create_cfg)

    LAST_CREATED_INTERFACE = len(tmp)


def connect_open(
        host: str,
        username: str,
        password: str,
        platform='cisco_iosxe',
        transport='ssh',
        **kwargs) -> [Scrapli, bool]:

    loglevel = logging.CRITICAL
    msg = f'Подключение к утройству {host} выполнено'

    result = False

    if not check_port_alive(host):
        msg = f'Устройство {host} не доступно'
    else:
        conn = Scrapli(
            host=host,
            auth_username=username,
            auth_password=password,
            transport='paramiko' if transport == 'ssh' else 'telnet',
            platform=platform,
            auth_strict_key=False,
            **kwargs
        )

        try:
            conn.open()
            result = conn
            loglevel = logging.INFO
        except ScrapliAuthenticationFailed:
            msg = 'Не верный логин или пароль.\n'
        except ScrapliConnectionNotOpened:
            msg = f'не удалось подключиться к устройству {host}\n'

    logger.log(loglevel, msg)
    return result


def connect_close(conn):
    # conn.send_command('copy running-config startup-config')
    conn.close()


@click.command()
@click.argument('groups', nargs=-1)
@click.option('-u', '--username', prompt='Username', required=True)
@click.password_option('-p', '--password', confirmation_prompt=False)
@click.option('--acl-name', type=str, default='130')
@click.option(
    '--inventory-file',
    type=click.Path(exists=True),
    default=str(INVENTORY_FILE), show_default=str(INVENTORY_FILE))
def cli(username, password, inventory_file, groups, acl_name):
    devices = get_devices(groups, inventory_file)

    while devices:
        min_ttl, destination_hosts = load_data_form_file(INPUT_DATA_FILE)

        if min_ttl == 0:
            time.sleep(2)
            continue

        start_time = time.time()

        # create_loiface('1.1.1.1', destination_hosts, username, password)

        for device in devices:
            host = device.get('host')
            platform = device.get('platform')

            conn = connect_open(host, username, password, platform=platform)

            if conn:
                acl_cfg = create_acl_cfg(conn, destination_hosts.copy(), acl_name)
                if len(acl_cfg) == 1:
                    logger.log(logging.INFO, 'Изменения не требуются.')
                    break
                # else:
                pprint.pprint(acl_cfg)
                conn.send_configs(acl_cfg)
                logger.log(logging.INFO, 'Изменения применены успешно.')
                connect_close(conn)
            else:
                pass

        min_ttl -= int(time.time() - start_time - 1)

        if min_ttl > 0:
            logger.log(logging.INFO, f'Ожидание {min_ttl} сек ...')
            with click.progressbar(range(min_ttl)) as bar:
                for _ in bar:
                    time.sleep(1)

        click.clear()


if __name__ == '__main__':
    cli()

