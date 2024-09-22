import os
import json

from rich import print

class Config:
    '''
    Class to manage loading and saving persistent settings.
    '''

    FULL_SCREEN = 0
    WINDOWED = 1

    def __init__(self):
        self.filepath = "cfg.json"
        # Used by both server & client
        self.debug = False
        self.fps = 60
        
        # Used differently by server and client
        self.ip = "127.0.0.1"
        self.port = 3555
    
        # client only
        self.resource_path = os.path.join(".", "res")
        self.width = 640
        self.height = 480
        self.windowed = Config.WINDOWED
        self.network = True

        # server only
        self.concurrent_clients = 10

        # Auto Create default one if it doesn't exist
        if not os.path.exists(self.filepath):
            self.save()
            print(f"Config File: {self.filepath} Does not Exist. Creating Default...")

    def load(self):
        with open(self.filepath, 'r') as f:
            raw = json.load(f)

        count = 0
        for key, value in raw.items():
            setattr(self, key, value)
            count += 1

        if not os.path.exists(self.resource_path):
            print(f"root resource folder cannot be found. Creating Default Empty One: {self.resource_path}")
            os.makedirs(self.resource_path)
            os.makedirs(os.path.join(self.resource_path, "images"))
            os.makedirs(os.path.join(self.resource_path, "audio"))
            os.makedirs(os.path.join(self.resource_path, "maps"))

        print(f"Successfully Loaded {count} Config Keys")

    def save(self):
        with open(self.filepath, 'w') as f:
            d = dict()
            d['windowed'] = self.windowed
            d['width'] = self.width
            d['height'] = self.height
            d['fps'] = self.fps
            d['resource_path'] = self.resource_path
            d['network'] = self.network
            d['ip'] = self.ip
            d['port'] = self.port
            d['concurrent_clients'] = self.concurrent_clients

            json.dump(d, f, indent=4)
        return True

