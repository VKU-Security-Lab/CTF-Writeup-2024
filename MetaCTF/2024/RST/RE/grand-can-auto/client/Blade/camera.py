from __future__ import annotations

from . import configs

class Camera:
    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.width = configs.width
        self.height = configs.height
        self.x_vel = 0
        self.y_vel = 0
        self.x_accel = 0
        self.y_accel = 0

    def follow(self, ent:Entity):
        pass

    def unfollow(self):
        pass

    def move(self, x:int, y:int, x_vel:float=0, y_vel:float=0, x_accel:float=0, y_accel:float=0):
        pass

    def center_on(self, x:int, y:int):
        self.x = x - (self.width // 2)
        self.y = y - (self.height // 2)

    def zoom_in(self):
        pass

    def zoom_out(self):
        pass

    def shake(self):
        pass

    def effect(self):
        pass

    