#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from ryu.cmd import manager


def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6653')
    sys.argv.append('simple_switch_13.py')
    sys.argv.append('--config-file')
    sys.argv.append('params.conf')
    sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == '__main__':
    from gevent import monkey
    monkey.patch_all()
    main()
