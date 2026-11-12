"""SubHunter terminal interface. All scanning and file handling live in the engine."""

import argparse
import sys
from time import monotonic

from rich.cells import cell_len
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.spinner import Spinner
from rich.text import Text
from rich.theme import Theme

import SubHunterEngine as engine


THEME = Theme({'brand': 'dark_red', 'muted': 'grey70', 'SUCCESS': 'green',
               'EMPTY': 'grey70', 'FAILED': 'red', 'TIMEOUT': 'yellow', 'SKIPPED': 'dim'})
BANNER = '''  ▄▄▄▄         █      ▄    ▄                 ▄
 █▀   ▀ ▄   ▄  █▄▄▄   █    █ ▄   ▄  ▄ ▄▄   ▄▄█▄▄   ▄▄▄    ▄ ▄▄
 ▀█▄▄▄  █   █  █▀ ▀█  █▄▄▄▄█ █   █  █▀  █    █    █▀  █   █▀  ▀
     ▀█ █   █  █   █  █    █ █   █  █   █    █    █▀▀▀▀   █
 ▀▄▄▄█▀ ▀▄▄▀█  ██▄█▀  █    █ ▀▄▄▀█  █   █    ▀▄▄  ▀█▄▄▀   █'''


def parse_arguments(argv, console):
    parser = argparse.ArgumentParser(
        prog='SubHunter', description='Small terminal subdomain finder. No module flags means all modules.')
    parser.add_argument('-u', '--url', help='Target domain (example.com), without scheme or path')
    parser.add_argument('-w', '--wordlist', help='UTF-8 wordlist; required for DNS and VHost')
    parser.add_argument('-c', '--crt', action='store_true', help='Run CRT enumeration')
    parser.add_argument('-d', '--dns', action='store_true', help='Run DNS enumeration')
    parser.add_argument('-v', '--vhost', action='store_true', help='Run VHost enumeration')
    parser.add_argument('-o', '--output', help='Save sorted results to this file (overwrites it)')
    parser.add_argument('--user-agent', help='Custom HTTP User-Agent for CRT and VHost')
    args = parser.parse_args(argv)
    if args.user_agent is not None:
        value = args.user_agent
        if not value.strip() or value[0].isspace() or any(
                (ord(char) < 32 and char != '\t') or char == '\x7f' for char in value):
            parser.error('--user-agent must be non-empty and contain valid HTTP header characters.')
        try:
            value.encode('latin-1')
        except UnicodeEncodeError:
            parser.error('--user-agent must be encodable as Latin-1 for HTTP headers.')
    if not argv and sys.stdin.isatty() and console.is_terminal:
        args.url = Prompt.ask('Target domain', console=console)
        while True:
            choice = Prompt.ask('Modules: all, or space-separated crt dns vhost',
                                default='all', console=console).lower().split()
            if choice == ['all']:
                break
            if choice and all(name in ('crt', 'dns', 'vhost') for name in choice):
                args.crt = 'crt' in choice
                args.dns = 'dns' in choice
                args.vhost = 'vhost' in choice
                break
            console.print('Choose all or names from crt dns vhost.', style='FAILED')
        selected = engine.select_modules(args.crt, args.dns, args.vhost)
        if 'DNS' in selected or 'VHOST' in selected:
            args.wordlist = Prompt.ask('Wordlist path', console=console)
        args.output = Prompt.ask('Output path (optional)', default='', console=console) or None
    if not args.url:
        parser.error('A target is required. Use -u example.com (see --help).')
    return args


def main(argv=None):
    console = Console(theme=THEME, highlight=False)
    try:
        args = parse_arguments(sys.argv[1:] if argv is None else argv, console)
        banner = 'SubHunter'
        if not console.options.ascii_only and console.width >= max(map(cell_len, BANNER.splitlines())):
            banner = BANNER
        console.print(Text(banner, style='brand'))
        console.print('\nBy Saleh / GitHub: redHDDD', style='#d29959')
        console.print()
        console.print(Panel.fit(Text(args.url), title='TARGET', title_align='left',
                                border_style='muted'))
        selected = engine.select_modules(args.crt, args.dns, args.vhost)
        console.print('  '.join(
            f'{name}: ' + ('[green]enabled[/]' if name in selected else '[red]disabled[/]')
            for name in ('CRT', 'DNS', 'VHOST')
        ), style='muted')
        console.print()
        current = {'name': '', 'detail': '', 'started': 0, 'hint_shown': False}

        def render_status():
            if not current['name']:
                return Text('')
            elapsed = monotonic() - current['started']
            message = f'{current["name"]}  {elapsed:.1f}s  {current["detail"]}'
            if current['name'] == 'CRT' and elapsed >= 5 and not current['hint_shown']:
                current['hint_shown'] = True
                target = engine.normalize_domain(args.url)
                console.print(Text(
                    '[!] crt.sh is taking longer than usual.\n'
                    f'[i] Try checking manually: https://crt.sh/?q=%25.{target}',
                    style='muted'))
            return Spinner('line', text=Text(message, style='muted'), style='brand')

        with Live(console=console, get_renderable=render_status, refresh_per_second=4,
                  auto_refresh=console.is_terminal, transient=True) as live:
            def show_status(name, state, detail, seconds, count):
                if state == 'RUNNING':
                    is_new = current['name'] != name
                    if is_new:
                        current['name'] = name
                        current['started'] = monotonic()
                        current['hint_shown'] = False
                    current['detail'] = detail
                    if not console.is_terminal and (is_new or 'retry' in detail.lower()
                                                   or detail.startswith('Partial')):
                        console.print(Text(f'{name}  RUNNING  {detail}', style='muted'))
                    return
                current['name'] = ''
                line = Text(f'{name:<6} {state:<7}  {seconds:6.1f}s  {count} results', style=state)
                if detail:
                    line.append(f'  {detail}')
                live.console.print(line)

            report = engine.run_scan(args.url, args.wordlist, args.crt, args.dns,
                                     args.vhost, args.output, show_status, user_agent=args.user_agent)
        console.print()
        for domain in report['results']:
            console.print(domain, markup=False)
        console.print(f'\nUnique subdomains: {len(report["results"])}')
        if report['output']:
            console.print(Text(f'Saved: {report["output"]}', style='muted'))
        failed = any(item['state'] in ('FAILED', 'TIMEOUT') or item['detail'].startswith('Partial results:')
                     for item in report['modules'].values())
        if failed:
            console.print('Scan incomplete: one or more modules reported errors.', style='TIMEOUT')
        return 1 if failed else 0
    except KeyboardInterrupt:
        console.print('\nCancelled.', style='TIMEOUT')
        return 130
    except EOFError:
        console.print('\nInput ended; cancelled.', style='TIMEOUT')
        return 2
    except (ValueError, OSError) as error:
        console.print(Text(f'Error: {error}', style='FAILED'))
        return 2


if __name__ == '__main__':
    sys.exit(main())
