from typing import List, Tuple

import pygame as pg

class Animation:
    '''
    Represents a series of Surfaces
    '''
    def __init__(self, frames:List[pg.Surface], repeat:bool=True):
        self.frames = frames

        # Index of the current frame
        self.index = -1

        # ticks per frame
        self.speed = 1
        self.counter = 0

        self.running = True
        self.repeat = repeat

        self._max_width = None
        self._max_height = None

    def frame(self):
        return self.frames[self.index]

    def update(self):
        if self.running:
            if self.counter == self.speed:
                self.index += 1

            if self.repeat:
                self.index = self.index % len(self.frames)
            elif self.index == len(self.frames) - 1:
                self.index = len(self.frames) - 1

            self.counter += 1

    def start(self):
        self.running = True

    def stop(self):
        self.running = False
        self.index = 0
        self.counter = 0

    def pause(self):
        self.running = False

    def is_finished(self) -> bool:
        return self.index == len(self.frames) - 1 and not self.repeat
    
    def max_width(self) -> int:
        if self._max_width:
            return self._max_width
        
        self._max_width = max(s.get_width() for s in self.frames)
        return self._max_width

    def max_height(self) -> int:
        if self._max_height:
            return self._max_height
        
        self._max_height = max(s.get_height() for s in self.frames)
        return self._max_height