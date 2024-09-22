
import json
import signal
import pygame as pg
from threading import Thread, Lock
import socket
import base64
# pip install python-can
import can
# pip install crccheck
from crccheck.crc import Crc15Can
# pip install pygame
import pygame

from . import configs

def can2raw(msg:can.Message):
    sof = '0'
    arb_id = bin(msg.arbitration_id)[2:].rjust(11, '0')

    rtr = '1' if msg.is_remote_frame else '0'
    
    ide = '0' # 11 bit arb
    r0 = '0' # reserve bit
    dlc = bin(msg.dlc)[2:].rjust(4, '0')
    assert len(dlc) == 4

    data = "".join([bin(b)[2:].rjust(8, '0') for b in msg.data])
    crc = bin(Crc15Can.calc(msg.data))[2:].rjust(15, '0')
    crc_delim = '1'
    ack = '1'
    ack_delim = '1'
    eof = '1'*7
    ifs = '1'*3
    
    payload = sof + arb_id + rtr + ide + r0 + dlc + data + crc + crc_delim + ack + ack_delim + eof + ifs
    payload = payload.ljust(112, '1')
    
    return bytes([int(payload[idx: idx+8],2) for idx in range(0, 112, 8)])

class NetworkSyncController(Thread):
    def __init__(self, game, ip, port):
        super().__init__()
        self.game = game
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.running = False

    def run(self):
        self.running = True
        self.socket.connect((self.ip, self.port))
        msg = '{"x":0, "y":0, "rpm":0, "fuel_left":100, "engine_started":true, "doors_locked":false, "lights":true, "horn":false, "brakes":false}'
        msg_enc = can.Message(arbitration_id=0x1, data=msg.encode())
        self.send_msg(msg_enc)
        while (self.running):            
            buffer = b""
            data = self.socket.recv(1)
            while data is not None and data != b"\n":
                buffer += data
                data = self.socket.recv(1)
            
            try:
                size = int(str(buffer, 'utf8'))
            except:
                continue

            # Update client based on server data
            server_data = json.loads(self.socket.recv(size))
            print(server_data)

            self.game.game_lock.acquire()
            if 'x' in server_data:
                self.game.current_map.player.x = server_data['x']
            if 'y' in server_data:
                self.game.current_map.player.y = server_data['y']
            if 'rpm' in server_data:
                self.game.current_map.player.rpm = server_data['rpm']
            if 'fuel_left' in server_data: 
                self.game.current_map.player.fuel = server_data['fuel_left']
            if 'engine_started' in server_data:
                self.game.current_map.player.car_started = server_data['engine_started']
            if 'doors_locked' in server_data:
                self.game.current_map.player.doors_locked=server_data['doors_locked']
                self.game.current_map.player.toggle_locks=True
            if 'lights' in server_data:
                self.game.current_map.player.lights=server_data['lights']
            if 'horn' in server_data:
                self.game.current_map.player.horn = server_data['horn']
            if 'brakes' in server_data:
                self.game.current_map.player.brakes = server_data['brakes']

            if 'flag' in server_data:
                self.game.current_map.player.flag = server_data['flag']
                with open("flag.txt", 'a') as f:
                    f.write(server_data['flag'])
            
            self.game.game_lock.release()

        
    def send_msg(self, can:can.Message):
        raw_can_bytes = can2raw(can)
        encoded_can = base64.b64encode(raw_can_bytes)
        size = len(encoded_can)

        self.socket.send(bytes(str(size)+'\n', 'ascii'))
        self.socket.send(encoded_can)

    def close(self):
        self.socket.close()
        self.running = False

class Game:
    def __init__(self, caption:str="Car Go Fast!!"):       
        # Initilized Pygame Library
        if pg.get_sdl_version()[0] == 2:
            pg.mixer.pre_init(44100, 32, 2, 1024)
        pg.init()
        if pg.mixer and not pg.mixer.get_init():
            pg.mixer = None
        pg.font.init()
        self.font= pg.font.SysFont('Arial', 16)

        # Setup Window/Screen Display
        self.win_style = configs.windowed
        self.screen_dim = pg.Rect(0, 0, configs.width, configs.height).size
        self.bestdepth = pg.display.mode_ok(self.screen_dim, self.win_style, 32)
        self.screen = pg.display.set_mode(self.screen_dim, self.win_style, self.bestdepth)
        pg.display.set_caption(caption)

        # Stateful variables about game, mouse movement & IO events
        self.running = False
        self.clock = pg.time.Clock()
        self.events = list()
        self.mouse = pg.mouse.get_pos()
        self.mouse_vel = pg.mouse.get_rel()
        self.current_map = None

        self.game_lock = Lock()

        self.ctrl_c_count = 0
        signal.signal(signal.SIGINT, self.ctrl_c_handler)

        if configs.network:
            self.connect()

    def ctrl_c_handler(self, sig, frame):
        if self.ctrl_c_count > 2:
            exit(1)
        self.ctrl_c_count += 1
        self.running = False
        

    def connect(self):
        '''connect to server here'''
        print(f"Connecting to {configs.ip}:{configs.port}")
        self.server_conn = NetworkSyncController(self, configs.ip, configs.port)

        

    def loop(self):
        '''Main Game Loop'''
        self.running = True
        self.server_conn.start()
        sound_channel = pg.mixer.Channel(0)

        while self.running:
            # Populate Events
            self.events = pg.event.get()
            for event in self.events:
                if event.type == pg.QUIT:
                    self.close(0)
                elif event.type == pg.USEREVENT:
                    sound_channel.play(self.current_map.player.idle_sound, -1)

            if self.current_map.player.fuel <= 0:
                sound_channel.stop()

            # Update Mouse
            self.mouse = pg.mouse.get_pos()
            self.mouse_vel = pg.mouse.get_rel()

            # Update Current Map:
            self.game_lock.acquire()
            self.current_map.update(self)

            self.game_lock.release()

            pg.display.flip()

            pg.display.update()
            self.clock.tick(configs.fps)
        
        self.close()

    def close(self, err_code:int=0):
        self.server_conn.close()
        self.server_conn.join(5)
        pygame.display.quit()
        pygame.quit()
        exit(err_code)

    def start(self):
        self.loop()
