import zmq
from core import echo, dot
from tornado import ioloop
import os


def server(ZMQ_DP_ADDR):
    print('Initialazing..')
    ctx = zmq.Context.instance()
    socket = ctx.socket(zmq.PULL)
    socket.bind(ZMQ_DP_ADDR)
    print(ZMQ_DP_ADDR + ' binded...')
    loop = ioloop.IOLoop.current()
    loop.add_handler(socket, echo, loop.READ)
    loop.add_callback(dot)
    loop.start()


if __name__ == '__main__':
    print('Initialazing..')
    if os.getenv('PRODUCTION') == '1':
        server('tcp://0.0.0.0:43001')
    else:
        server('tcp://127.0.0.1:43001')
