from __future__ import annotations

import os
import functools

import pygame as pg
from rich import print

from . import configs

class Resources:
    root_path = configs.resource_path

    @classmethod
    @functools.lru_cache()
    def image(cls, filename:str):
        full_path = os.path.join(
            cls.root_path, 
            "images",
            filename
        )

        if os.path.exists(full_path) and os.path.isfile(full_path):
            surface = pg.image.load(full_path).convert_alpha()
            return surface
        
        print(f"Not a valid File: {full_path}")
        # TODO create default surface
        return None
        
    @classmethod
    @functools.lru_cache()
    def audio(cls, filename:str):
        if not pg.mixer:
            print(f"Unable to load {filename}. Mixer not Initialized")
            return None
        
        full_path = os.path.join(
            cls.root_path, 
            "audio",
            filename
        )

        if os.path.exists(full_path) and os.path.isfile(full_path):
            sound = pg.mixer.Sound(full_path)
            return sound
        
        print(f"Not a valid File: {full_path}")
        return None
    
    @classmethod
    @functools.lru_cache(maxsize=4)
    def map(cls, filename:str):
        full_path = os.path.join(
            cls.root_path, 
            "maps",
            filename
        )

        if os.path.exists(full_path) and os.path.isfile(full_path):
            return Map(full_path)
            
        print(f"Not a valid File: {full_path}")
        return None