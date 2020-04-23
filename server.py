# -*- coding: utf-8 -*-
# @Author: amitshah
# @Date:   2020-03-27 14:22:11
# @Last Modified by:   amitshah
# @Last Modified time: 2020-03-27 14:38:40



#!/usr/bin/env python

"""
How to use it:
1. Just `kill -2 PROCESS_ID` or `kill -15 PROCESS_ID`,
   The Tornado Web Server Will shutdown after process all the request.
2. When you run it behind Nginx, it can graceful reboot your production server.
"""

import time
import signal
import logging
from functools import partial
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)

MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 0


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello, world")


def sig_handler(server, sig, frame):
    io_loop = tornado.ioloop.IOLoop.instance()

    def stop_loop(deadline):
        now = time.time()
        if now < deadline and (io_loop._callbacks or io_loop._timeouts):
            logging.info('Waiting for next tick')
            io_loop.add_timeout(now + 1, stop_loop, deadline)
        else:
            io_loop.stop()
            logging.info('Shutdown finally')

    def shutdown():
        logging.info('Stopping http server')
        server.stop()
        logging.info('Will shutdown in %s seconds ...',
                     MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
        stop_loop(time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)

    logging.warning('Caught signal: %s', sig)
    io_loop.add_callback_from_signal(shutdown)


def main():
    tornado.options.parse_command_line()
    application = tornado.web.Application([
        (r"/", MainHandler),
    ])

    server = tornado.httpserver.HTTPServer(application)
    server.listen(options.port)

    signal.signal(signal.SIGTERM, partial(sig_handler, server))
    signal.signal(signal.SIGINT, partial(sig_handler, server))

    tornado.ioloop.IOLoop.instance().start()

    logging.info("Exit...")


if __name__ == "__main__":
    main()