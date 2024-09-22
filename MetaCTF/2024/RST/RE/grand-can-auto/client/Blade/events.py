import pygame as pg
import pygame.locals

from .game import Game
from .entity import Entity

def key_pressed(key, game_ctxt:Game) -> bool:
    '''
    Evalutes whether or not keyboard button key is pressed
    :param key: a string representing the keyboard button
    :returns: True if key is pressed
    '''
    keystate = pg.key.get_pressed()
    return keystate[pg.key.key_code(key)] == 1
    

def key_down(key, game_ctxt:Game) -> bool:
    '''
    Evalutes whether or not keyboard button key has been pushed down
    :param key: a string representing the keyboard button
    :returns: True if key was pressed
    '''
    for event in game_ctxt.events:
        if event.type == pg.KEYDOWN and event.key == ord(key):
            return True


def key_up(key, game_ctxt:Game) -> bool:
    '''
    Evalutes whether or not keyboard button key is released
    :param key: a string representing the keyboard button
    :returns: True if key was released
    '''
    for event in game_ctxt.events:
        print("event", event.type, event.key, ord(key))
        if event.type == pg.KEYUP and event.key == ord(key):
            return True
        
class Events:
    @staticmethod
    def on_click(ent:Entity, game:Game):
        return ent.is_clicked(game)

    @staticmethod
    def on_right_click(ent:Entity, game:Game):
        return ent.is_right_clicked(game)

    @staticmethod
    def on_left_click(ent:Entity, game:Game):
        return ent.is_left_clicked(game)

    @staticmethod
    def on_mouse_move(ent:Entity, game:Game):
        return ent.mouse_is_moving(game)

    @staticmethod
    def on_mouse_exit(ent:Entity, game:Game):
        return ent.mouse_exited(game)

    @staticmethod
    def on_mouse_enter(ent:Entity, game:Game):
        return ent.mouse_entered(game)
    
    @staticmethod
    def has_moved(ent:Entity, game:Game):
        return ent.has_moved()
    
    @staticmethod
    def idling(ent:Entity, game:Game):
        return ent.is_stationary()
    
'''
event functions for every keyboard key that pygame supports is dynamically loaded
pygame.locals.__dict__ return all the constants pygame has, so I filter out only those with the prefix "K_" which represent each key. 
I create a function for each key and make that function a member of Event

BUT, this creates an issue with symbols that cannot be used in python variables such as all the operators (+=-!|&/%)
These Events currently can only be reached with the getattr python build in function. e.g. getattr(Event, "on_key_+_pressed")
'''
keys = [getattr(pygame.locals,k) for k in pygame.locals.__dict__ if k.startswith('K_')]
for key in keys:
    key_name = pygame.key.name(key)
    setattr(Events, 
            "on_key_{}_pressed".format(key_name),  
            lambda ent, game, key=key_name: key_pressed(key, game))
            
    setattr(Events,
            "on_key_{}_down".format(key_name),
            lambda ent, game, key=key_name: key_down(key, game))

    setattr(Events,
            "on_key_{}_up".format(key_name),
            lambda ent, game, key=key_name: key_up(key, game))
