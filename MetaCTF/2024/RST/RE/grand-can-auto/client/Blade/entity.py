from __future__ import annotations
from typing import Callable
import random

import pygame as pg

from .game import Game
from .camera import Camera
from .consts import Direction

class Entity:
    '''
    Any "Thing" that can be displayed and interacted with (Player, Enemies, Trees, UI Components, etc...)
    '''

    def __init__(self, x,y,w,h,z=0, name:str="", type:str=None, parent:Entity=None):
        '''
        Creates a new Entity
        :param x: x coordinate
        :param y: y coordinate
        :param w: width
        :param h: height
        :param z: z coordinate
        :param parent: If specified, then the x and y coordinates will be relative to the parent Enity
        '''
        self.id = random.randint(0, 2**32)
        self.parent = parent
        if parent:
            self.rect = pg.Rect(x + self.parent.x, y+self.parent.y, w, h)
            parent.add_child(self)
        else:
            self.rect = pg.Rect(x,y,w,h)
        self.name = name
        self.type = type
        self.z = z
        self.x_old = self.x
        self.y_old = self.y
        self.x_speed = 0
        self.y_speed = 0
        self.collisions = set()

        self.animation = None
        self.render_behind = None
        self.render_infront = None
        self.custom_update = None

        # Whether or not to even update the entity
        self.enabled = True
        # Whether or not to draw the entity
        self.visible = True
        # Collides with other things that are solid
        self.solid = False

        self.children = set()
        self.registered_events = dict()

    def __hash__(self):
        return self.id

    def __repr__(self):
        return f"<Ent id={self.id} name={self.name} x={self.x} y={self.y} w={self.width} h={self.height}>"

    def __copy__(self):
        e = Entity(self.x, self.y, self.width, self.height, self.z, self.parent)
        e.id = self.id
        e.name = self.name
        e.type = e.type
        e.enabled = self.enabled
        e.visible = self.visible
        e.solid = self.solid
        e.children = self.children
        e.registered_events = self.registered_events
        return e

    @property
    def x(self):
        return self.rect.x

    @x.setter
    def x(self, value):
        '''
        Set the X coordiate. If self has a parent, then value is relative to the parent.x
        '''
        self.x_old = self.rect.x
        if self.parent:
            self.rect.x = self.parent.x + value
        else:
            self.rect.x = value

        for child in self.children:
            child.x += value

    @property
    def y(self):
        return self.rect.y
    
    @y.setter
    def y(self, value):
        '''
        Set the Y coordiate. If self has a parent, then value is relative to the parent.y
        '''
        self.y_old = self.rect.y
        if self.parent:
            self.rect.y = self.parent.y + value
        else:
            self.rect.y = value

        for child in self.children:
            child.y += value

    @property
    def width(self):
        return self.rect.width
    
    @width.setter
    def width(self, value):
        self.rect.width = value

    @property
    def height(self):
        return self.rect.height
    
    @height.setter
    def height(self, value):
        self.rect.height = value

    @property
    def next_x(self):
        return self.x + self.x_speed
    
    @property
    def next_y(self):
        return self.y + self.y_speed

    def new_id(self):
        self.id = random.randint(0, 2**32)

    def update(self, game:Game):
        if not self.enabled:
            return

        # Fire off any event listeners 
        for reg_event in self.registered_events:
            if reg_event(self, game):
                self.registered_events[reg_event](self, game)

        if self.solid:
            for _, side in self.collisions:
                if side == Direction.RIGHT and self.next_x - self.x > 0:
                    self.x_speed = 0
                if side == Direction.LEFT and self.next_x - self.x < 0:
                    self.x_speed = 0
                if side == Direction.UP and self.next_y - self.y < 0:
                    self.y_speed = 0
                if side == Direction.DOWN and self.next_y - self.y > 0:
                    self.y_speed = 0


        if self.custom_update is not None:
            self.custom_update(self, game)
        
        # Update Children
        for child in self.children:
            child.update(game)

        self.collisions.clear()

    def render(self, game:Game, camera:Camera):
        if not self.visible:
            return
        
        if self.render_behind is not None:
            self.render_behind(self, game, camera)
        
        if self.animation:
            game.screen.blit(self.animation.frame(), (self.x - camera.x, self.y - camera.y))
            self.animation.update()

        if self.render_infront is not None:
            self.render_infront(self, game, camera)

    def add_child(self, child:Entity):
        self.children.add(child)

    def apply_to_children(self, recursive:bool, func:Callable, *args, **kwarg):
        '''
        BDS-style apply a function to each child.
        :param recursive: if True, apply function to children recursively
        :param func: function to apply on children
        :param args: positional arguments to func
        :param kwargs: keyword arguments to funct
        '''
        for child in self.children:
            func(child, *args, **kwarg)

        if recursive:
            for child in self.children:
                child.apply_to_children(func, recursive, *args, **kwarg)

    
    def register_event(self, event:Callable[[Entity, Game], bool], callback:Callable[[Entity, Game]]):
        '''
        Registers callbacks based on an event
        :param event: Function that if it evaluates to true, then callback will be called like so: event(self, game_ctxt). see Actions class
        :param callback: The callback function to associate with the given event. Is called like so: callback(self, game_ctxt)
        :returns: True if successful
        '''
        if not callable(event):
            print('[-] Event is not a function. Must be a function that evalutes to a boolean value')
            return False

        if not callable(callback):
            print('[-] Callback registered for {} is not callable'.format(event))
            return False

        self.registered_events[event] = callback
        return True
    
    def unregister_event(self, event:Callable[[Entity, Game], bool]):
        if event in self.register_events:
            del self.register_events[event]
    
    def is_clicked(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the mouse is clicked inside the component
        :returns: True if the left or right mouse button has been clicked inside the component
        '''
        return self.is_left_clicked(game_ctxt) or self.is_right_clicked(game_ctxt)

    
    def is_mouse_released(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the mouse button has been released inside the component
        :returns: True if the left or right mouse button has been released inside the component
        '''
        return self.is_left_released(game_ctxt) or self.is_right_released(game_ctxt)

   
    def is_mouse_pressed(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the mouse is held down inside the component
        :returns: True if the left or right mouse button is being held down inside the component
        '''
        return self.is_left_pressed(game_ctxt) or self.is_right_pressed(game_ctxt)

    
    def is_right_clicked(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the right mouse button is clicked inside the component
        :returns: True if the right mouse button has been clicked inside the component
        '''
        if self.rect.collidepoint(pg.mouse.get_pos()):
            for event in game_ctxt.events:
                if event.type == pg.MOUSEBUTTONDOWN and event.button == 3:
                    return True
        return False

    
    def is_right_released(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the right mouse button has been released inside the component
        :returns: True if the right mouse button has been released inside the component
        '''
        if self.rect.collidepoint(pg.mouse.get_pos()):
            for event in game_ctxt.events:
                if event.type == pg.MOUSEBUTTONUP and event.button == 3:
                    return True
        return False

    
    def is_right_pressed(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the right mouse button has been released inside the component
        :returns: True if the right mouse button has been released inside the component
        '''
        if self.rect.collidepoint(pg.mouse.get_pos()):
            click = pg.mouse.get_pressed()[2] == 1
            inside = self.rect.collidepoint(pg.mouse.get_pos())
            return click and inside
        return False

    
    def is_left_clicked(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the left mouse button is clicked inside the component
        :returns: True if the left mouse button has been clicked inside the component
        '''
        if self.rect.collidepoint(pg.mouse.get_pos()):
            for event in game_ctxt.events:
                if event.type == pg.MOUSEBUTTONDOWN and event.button == 1:
                    return True
        return False

    def is_left_released(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the left mouse button has been released inside the component
        :returns: True if the left mouse button has been released inside the component
        '''
        if self.rect.collidepoint(pg.mouse.get_pos()):
            for event in game_ctxt.events:
                if event.type == pg.MOUSEBUTTONUP and event.button == 1:
                    return True
        return False

    def is_left_pressed(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the left mouse button has been released inside the component
        :returns: True if the left mouse button has been released inside the component
        '''
        if self.rect.collidepoint(pg.mouse.get_pos()):
            click =  pg.mouse.get_pressed()[0] == 1
            inside = self.rect.collidepoint(pg.mouse.get_pos())
            return click and inside
        return False

    
    def mouse_is_moving(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the mouse is moving inside the component
        :returns: True if the mouse is moving inside the component
        '''
        inside = self.rect.collidepoint(pg.mouse.get_pos())
        x_vel, y_vel = game_ctxt.mouse_rel
        moved = x_vel != 0 and y_vel != 0
        return inside and moved

    
    def mouse_exited(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the mouse has just left the component
        :returns: True if the mouse has just left the component
        '''
        x, y = pg.mouse.get_pos()
        x_vel, y_vel = game_ctxt.mouse_rel
        inside_before = self.rect.collidepoint(x-x_vel,y-y_vel) == 1
        outside_after = not self.rect.collidepoint(x,y)
        return inside_before and outside_after

    
    def mouse_entered(self, game_ctxt:Game) -> bool:
        '''
        Evalutes whether or not the mouse has just entered the component
        :returns: True if the mouse has just entered the component
        '''
        x, y = pg.mouse.get_pos()
        x_vel, y_vel = game_ctxt.mouse_rel

        outside_before = not self.rect.collidepoint(x-x_vel, y-y_vel)
        inside_after = self.rect.collidepoint(x,y) == 1
        return outside_before and inside_after
    
    def has_moved(self) -> bool:
        return self.x != self.old_x or self.y != self.old_y
    
    def is_stationary(self) -> bool:
        return self.x == self.x_old and self.y == self.y_old