import zmq
from core import echo, dot
from tornado import ioloop
import os

if __name__ == '__main__':
    print('Initialazing..')
    ctx = zmq.Context.instance()
    s = ctx.socket(zmq.PULL)
    if os.getenv('PRODUCTION') == '1':
        ZMQ_DP_ADDR = 'tcp://0.0.0.0:43001'
    else:
        ZMQ_DP_ADDR = 'tcp://127.0.0.1:43001'
    s.bind(ZMQ_DP_ADDR)
    print('port 43001 binded...')
    loop = ioloop.IOLoop.current()
    loop.add_handler(s, echo, loop.READ)
    loop.add_callback(dot)
    loop.start()