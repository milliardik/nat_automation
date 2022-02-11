import click
import yaml
import time
import socket
import sys

from ipaddress import IPv4Interface

from scrapli import Scrapli
from scrapli.helper import textfsm_parse
from scrapli.exceptions import ScrapliAuthenticationFailed, ScrapliConnectionNotOpened

from dns.resolver import resolve

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
                ttl, addresses = dns_lookup(row)
                addresses = [IPv4Interface(f'{ip}/32') for ip in addresses]

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
        result.extend([dict(ip=k, **all_[k]) for k in all_])
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


def create_acl_cfg(conn: Scrapli, dst_interfaces: list[IPv4Interface], acl_name: str) -> str:
    def create_str(ip_interface: IPv4Interface) -> str:
        ip, prefix = ip_interface.with_hostmask.split('/')

        if prefix == '0.0.0.0':
            result_str = f'host {ip}'
        else:
            result_str = f'{ip} {prefix}'

        return result_str

    rows = list()
    row_tpl = 'access-list {acl_name} permit ip {source} {destination}'

    cur_acl_cfg = conn.send_command(f'show ip access-list {acl_name}').result

    if not cur_acl_cfg:
        logger.log(logging.ERROR, f'Список доступа {acl_name} отсутствует')
        sys.exit(1)

    srs_interfaces = set(get_srs_from_acl(cur_acl_cfg))

    for srs_interface in srs_interfaces:
        srs_str = create_str(srs_interface)
        for dst_interface in dst_interfaces:
            dst_str = create_str(dst_interface)
            rows.append(row_tpl.format(acl_name=acl_name, source=srs_str, destination=dst_str))

    rows.insert(0, f'access-list {acl_name} permit ip 10.0.0.0 0.0.0.255 host 3.3.3.3')
    logger.log(logging.INFO, f'Создан новая конфигурация для списка {acl_name}')

    return '\n'.join(rows)


def get_srs_from_acl(acl_cfg: str) -> list[IPv4Interface]:
    textfsm_tpl = BASEDIR.joinpath('cisco_ios_show_ip_access-lists.textfsm')
    result = []

    if textfsm_tpl.exists():
        with textfsm_tpl.open() as f:
            rows = textfsm_parse(f, acl_cfg)
    else:
        # raise
        print(f'{str(textfsm_tpl)} not exists')

    for row in rows:
        result_str = ''
        if row.get('src_host'):
            result_str = row.get("src_host")+'/32'
        elif row.get('src_network'):
            result_str = f'{row.get("src_network")}/{row.get("src_wildcard")}'

        if result_str:
            result.append(IPv4Interface(result_str))

    return result


def delete_acl(conn: Scrapli, acl_name: str) -> bool:
    result = conn.send_config(f'no ip access-list extended {acl_name}')
    logger.log(logging.INFO, f'Старый спсиок доступа {acl_name} удален успешно.')
    return not result.failed


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

    loglevel = logging.ERROR
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
    conn.send_command('copy running-config startup-config')
    conn.close()


@click.command()
@click.argument('groups', nargs=-1)
@click.option('-u', '--username', prompt='Username', required=True)
@click.password_option('-p', '--password', confirmation_prompt=False)
@click.option('--acl-name', type=str, default='130')
@click.option(
    '--inventory-file',
    type=click.Path(exists=True),
    default=str(BASEDIR.joinpath('inventory_file.yaml')), show_default='inventory_file.yaml')
def cli(username, password, inventory_file, groups, acl_name):
    devices = get_devices(groups, inventory_file)

    while devices:
        min_ttl, destination_hosts = load_data_form_file(INPUT_DATA_FILE)

        if min_ttl == 0:
            continue

        start_time = time.time()

        create_loiface('1.1.1.1', destination_hosts, username, password)

        for device in devices:
            host = device.get('host')
            platform = device.get('platform')

            conn = connect_open(host, username, password, platform=platform)

            if not conn:
                continue

            acl_cfg = create_acl_cfg(conn, destination_hosts, acl_name)
            delete_acl(conn, acl_name)
            conn.send_config(acl_cfg)
            logger.log(logging.INFO, 'Новый спсиок доступа применен успешно.')

            connect_close(conn)

        min_ttl -= int(time.time() - start_time)

        if min_ttl <= 0:
            continue

        logger.log(logging.INFO, f'Ожидание {min_ttl} сек ...')

        with click.progressbar(range(min_ttl)) as bar:
            for _ in bar:
                time.sleep(1)

        click.clear()


if __name__ == '__main__':
    cli()

