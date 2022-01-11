#!/usr/bin/env python3

__author__ = "Gary Choi"
__project__= "Graduate Research Project"
__name__="WAAT"

import os
import sys
import subprocess
import asyncio
import pyrcrack

from rich.console import Console
from rich.prompt import Prompt

res = subprocess.run('dpkg-query -l aircrack-ng', shell=True)
print(res.returncode)

if(res.returncode != 0):
    print("Please install aircrack-ng")
    exit(1)

def banner():
    print ("\n+----------------------------------------------------------------+")
    print ("|WAAT (Wireless Analysis and Assessment Tool)                    |")
    print ("|Coded by Gary Choi                                              |")
    print ("|Repo: https://github.com/garychd214/WAAT                        |")
    print ("+----------------------------------------------------------------+\n")


async def scan_for_targets():
    """Scan for targets, return json."""
    console = Console()
    console.clear()
    console.show_cursor(False)
    airmon = pyrcrack.AirmonNg()

    interface = Prompt.ask(
        'Select an interface',
        choices=[a['interface'] for a in await airmon.interfaces])

    async with airmon(interface) as mon:
        async with pyrcrack.AirodumpNg() as pdump:
            async for result in pdump(mon.monitor_interface):
                console.clear()
                console.print(result.table)
                await asyncio.sleep(2)


asyncio.run(scan_for_targets())