import click

from scrapli import Scrapli

from configurations import BASEDIR, INVENTORY_FILE
from nat_automation import get_devices, connect_open

PATH_TO_RESULT_DIR = BASEDIR.joinpath('instruction_and_cfg')


@click.command()
@click.argument('groups', nargs=-1)
@click.option('-u', '--username', prompt='Username', required=True)
@click.password_option('-p', '--password', confirmation_prompt=False)
@click.option(
    '--inventory-file',
    type=click.Path(exists=True),
    default=str(BASEDIR.joinpath('inventory_file.yaml')), show_default='inventory_file.yaml')
def cli(groups, username, password, inventory_file):
    devices = get_devices(groups, INVENTORY_FILE)

    for device in devices:
        host = device.get('host')
        platform = device.get('platform')
        conn = connect_open(host, username, password, platform)

        if conn:
            hostname = conn.get_prompt()[:-1]
            response = conn.send_command('show running-config')
            if not response.failed:
                with open(PATH_TO_RESULT_DIR.joinpath(hostname+'.confg'), 'w') as handle:
                    handle.write(response.result)

            conn.close()


if __name__ == '__main__':
    cli()