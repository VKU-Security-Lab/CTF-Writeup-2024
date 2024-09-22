from __future__ import annotations

import os
from copy import copy
from typing import Any, Callable, Generator, Iterable, Tuple, Set, List, Optional

import pytmx
import pygame as pg

from .game import Game
from .entity import Entity
from .consts import Direction
from .camera import Camera
from . import configs

class InvalidMapException:
    pass

class Map:
    def __init__(self, game):
        self.game = game
        self.camera = Camera(0,0)
        
        self.player = Entity(0, 0, 64, 64)
        self.entities = set()
        self.statics:Quadtree = None
        self.dynamics:Grid = None
        self.hints = list()
        
    @classmethod
    def TiledMap(cls, game, filepath:str):
        m = cls(game)

        m.filepath = filepath
        if not os.path.exists(m.filepath) or not os.path.isfile(m.filepath):
            raise InvalidMapException(f"Not a File: {m.filepath}")
        m.tiled = pytmx.util_pygame.load_pygame(filepath)

        # Support only squares for now
        assert m.tiled.tileheight == m.tiled.tilewidth
        m.tile_dim = m.tiled.tileheight

        m.width = m.tiled.width
        m.height = m.tiled.height
        m.width_px = m.tiled.tilewidth * m.width
        m.height_px = m.tiled.tileheight * m.height

        static_ents = list()
        m.dynamics = Grid(m.height, m.width, cell_size=m.tile_dim * 4)

        for layer_idx in m.tiled.visible_object_groups:
            layer = m.tiled.layers[layer_idx]
            for obj in layer:
                e = Entity(obj.x, obj.y, obj.width, obj.height, layer_idx)
                e.name = obj.name
                e.type = obj.type
                e.visible = obj.visible
                e.solid = obj.properties['solid']
                
                if e.type is not None and e.type.startswith('hint'):
                    m.hints.append(e)

                if obj.properties['static']:
                    static_ents.append(e)
                else:
                    m.dynamics.add(e)

        # TODO set default "home" position for camera
                    
        m.statics = Quadtree(0, m.width_px, 0, m.height_px, m.tile_dim, static_ents, 16)

        m.player.x, m.player.y = m.get_player_start()
        m.dynamics.add(m.player)

        return m
    
    def add(self, e:Entity):
        self.dynamics.add(e)
    
    def touching(self, rect1, rect2):
        return rect1.left <= rect2.right and rect1.right >= rect2.left and rect1.top <= rect2.bottom and rect1.bottom >= rect2.top

    def update(self, game:Game):
        for e in self.statics:
            e.update(game)

        for e in self.dynamics:
            # Collisions
            for solid in filter(lambda e: e.solid, self.statics.get_region(e.x, e.y, e.width, e.height)):
                # TODO make note of who we are colliding and who we are just touching
                # if e.rect.colliderect(solid.rect):
                if self.touching(e.rect, solid.rect):
                    dr = abs(e.rect.right - solid.rect.left)
                    dl = abs(e.rect.left - solid.rect.right)
                    dt = abs(e.rect.top - solid.rect.bottom)
                    db = abs(e.rect.bottom - solid.rect.top)
                    if min(dl, dr) < min(dt, db):
                        if dl < dr:
                            e.collisions.add((solid, Direction.LEFT))
                        else:
                            e.collisions.add((solid, Direction.RIGHT))
                    else:
                        if db < dt:
                            e.collisions.add((solid, Direction.DOWN))
                        else:
                            e.collisions.add((solid, Direction.UP))

            
            # Update entities
            e.update(game)

            # Update map after entities update
            self.dynamics.update_entity(e, e.x_old, e.y_old, e.x, e.y)

        self.render(game)
    
    def render(self, game:Game):
        self.camera.center_on(self.player.rect.centerx, self.player.y)
        for layer_idx in self.tiled.visible_tile_layers:
            layer = self.tiled.layers[layer_idx]
            for c,r, tile_surface in layer.tiles():
                game.screen.blit(tile_surface, (c*self.tiled.tilewidth - self.camera.x, r*self.tiled.tileheight - self.camera.y))
    
        for e in self.statics:
            e.render(game, self.camera)

        for e in self.dynamics:
            e.render(game, self.camera)

        # DEBUG
        if configs.debug:
            # import pygame
            # self.statics.iter_nodes(lambda n: pygame.draw.rect(game.screen, (0,0,255), pygame.Rect(n.origin[0]- self.camera.x, n.origin[1]- self.camera.y, n.grid_width*n.grid_dim, n.grid_height*n.grid_dim), 1))
            # def static_debug(n):
            #     qinfo = game.font.render(f"L={n.origin[0]} R={n.origin[0]+n.grid_width*n.grid_dim} T={n.origin[1]} B={n.origin[1]+n.grid_height*n.grid_dim}", False, (0,0,0), (255,255,255))
            #     game.screen.blit(qinfo, (4+n.origin[0]- self.camera.x, 4+n.origin[1]- self.camera.y))

            # self.statics.iter_nodes(static_debug)
            # for node in self.statics.get_node_region(self.player.x, self.player.y, self.player.width, self.player.height):
            #     pygame.draw.rect(game.screen, (0,255,0), pygame.Rect(node.origin[0]- self.camera.x, node.origin[1]- self.camera.y, node.grid_width*node.grid_dim, node.grid_height*node.grid_dim), 4)


            # for e in self.statics:
            #     import random
            #     r = pg.Rect(e.rect.x - self.camera.x, e.rect.y - self.camera.y, e.rect.width, e.rect.height)
            #     pygame.draw.rect(game.screen, (random.randint(96, 255),0,0), r, 1)

            # for r in range(self.dynamics.num_rows):
            #     for c in range(self.dynamics.num_cols):
            #         rect = pygame.Rect(c*self.dynamics.cell_size, r*self.dynamics.cell_size, self.dynamics.cell_size, self.dynamics.cell_size)
            #         pygame.draw.rect(game.screen, (0,0,255), rect, 2)
            #         chunk_info = game.font.render(f"{r=} {c=} count={len(self.dynamics._data[r][c])}", False, (0,0,0), (255,255,255))
            #         game.screen.blit(chunk_info, (4+c*self.dynamics.cell_size, 4+r*self.dynamics.cell_size))

            # player_info = game.font.render(f"L={self.player.x} R={self.player.x+self.player.width} T={self.player.y} B={self.player.y+self.player.height}", False, (0,0,0), (255,255,255))
            # game.screen.blit(player_info, (4+self.player.x, 4+self.player.y))
            
            car_state = {
                "Fuel": self.player.fuel,
                "RPM": self.player.rpm,
                "Speed": self.player.y - self.player.y_old,
            }
            count = 0
            for label, val in car_state.items():
                state = game.font.render(f"{label}: {val}", False, (0,0,0), (255,255,255))
                game.screen.blit(state, (4, 4 + 32*count))
                count += 1


    def get_player_start(self):
        for e in self.hints:
            if e.type == "hint_player_start":
                return (e.x, e.y)
        return (0, 0)

class Quadtree:
    '''For Static Entities (Non-moving)'''

    class QNode:
        def __init__(self, tree: Quadtree, parent: Quadtree.QNode, origin:Tuple[int, int], data:List[List[Optional[Entity]]], grid_dim:int, max_bin:int):
            self._data = data
            self.bucket = set()
            self.grid_width = len(self._data[0])
            self.grid_height = len(self._data)
            self.half_width = self.grid_width // 2
            self.half_height = self.grid_height // 2
            self.max_bin = max_bin
            self.grid_dim = grid_dim
            self.origin = origin

            self.tree = tree
            self.parent = parent
            self.siblings = None

        def _needs_subdivide(self) -> bool:
            none_count = sum(map(lambda x: 1 if x is None else 0, [col for row in self._data for col in row]))
            stuff_count = (self.grid_width * self.grid_height) - none_count
            return stuff_count > self.max_bin

        def _point2cell(self, x:int, y:int):
            x0, y0 = self.origin
            c = (x - x0) // self.grid_dim
            r = (y - y0) // self.grid_dim
            return r, c

        def _get_node_idx(self, x:int, y:int):
            r, c = self._point2cell(x,y)
            if c < self.half_width:
                if r < self.half_height:
                    return 0
                else:
                    return 3
            else:
                if r < self.half_height:
                    return 1
                else:
                    return 2

        def has_data(self) -> bool:
            return len(self._data) > 0
        
        def get_node(self, x:int, y:int, max_depth=None):
            if self.has_data():
                return self
            
            node_idx = self._get_node_idx(x, y)
            node = self.nodes[node_idx]
            return node.get_node(x, y)
        
        def get_node_region(self, x:int, y:int, w:int, h:int):
            nodes = set()
            nodes.add(self.get_node(x, y))
            nodes.add(self.get_node(x+w, y))
            nodes.add(self.get_node(x+w, y+h))
            nodes.add(self.get_node(x, y+h))
            return nodes
            

        def get(self, x:int, y:int) -> List[Entity]:
            return self.get_node(x, y).bucket
        
        def get_region(self, x:int, y:int, w:int, h:int) -> Set[Entity]:
            items = set()
            for n in self.get_node_region(x, y, w, h,):
                items |= set(n.bucket)
           
            return items

        def _empty_grid(self):
            return all([col == None for row in self._data for col in row])
        
        def _all_same(self):
            first = self._data[0][0]
            return not any([col != first for row in self._data for col in row])

        def coalesce(self):
            for r in range(self.grid_height):
                for c in range(self.grid_width):
                    curr = self._data[r][c]

                    if curr is None:
                        continue

                    self._data[r][c] = None

                    grow_vertical = True
                    grow_horizontal = True
                    height = 1
                    width = 1
                    while grow_vertical:
                        if r+height < self.grid_height and self._data[r+height][c] is not None and self._data[r+height][c].id == curr.id:
                            self._data[r+height][c] = None
                            height += 1
                        else:
                            grow_vertical = False

                    while grow_horizontal:
                        in_bounds = c + width < self.grid_width
                        if not in_bounds:
                            break

                        all_same_ent = all(e is not None and e.id == curr.id for e in [cols[c+width] for cols in self._data[r:r+height]])
                        if all_same_ent:
                            for row in range(r, r+height):
                                self._data[row][c+width] = None
                            width += 1
                        else:
                            grow_horizontal = False

                    curr.width = width * self.grid_dim
                    curr.height = height * self.grid_dim
                    curr.new_id()
                    self.bucket.add(curr)
                    self.tree.entities.append(curr)

        def subdivide(self, depth=0):
            if self._empty_grid():
                return
            
            if self._all_same():
                self.coalesce()
                return
            
            if self._needs_subdivide():                
                x, y = self.origin
                self.i = Quadtree.QNode(self.tree, self, (x, y), [cols[0:self.half_width] for cols in self._data[0:self.half_height]], self.grid_dim, self.max_bin)
                self.ii = Quadtree.QNode(self.tree, self, (x+(self.half_width*self.grid_dim), y), [cols[self.half_width:self.grid_width] for cols in self._data[0:self.half_height]], self.grid_dim, self.max_bin)
                self.iii = Quadtree.QNode(self.tree, self, (x+(self.half_width*self.grid_dim), y+(self.half_height*self.grid_dim)), [cols[self.half_width:self.grid_width] for cols in self._data[self.half_height:self.grid_height]], self.grid_dim, self.max_bin)
                self.iv = Quadtree.QNode(self.tree, self, (x, y+(self.half_height*self.grid_dim)), [cols[0:self.half_width] for cols in self._data[self.half_height:self.grid_height]], self.grid_dim, self.max_bin)

                self.i.siblings = (self.ii, self.iii, self.iv)
                self.ii.siblings = (self.i, self.iii, self.iv)
                self.iii.siblings = (self.ii, self.i, self.iv)
                self.iv.siblings = (self.ii, self.iii, self.i)

                self.nodes = (self.i, self.ii, self.iii, self.iv)
                self._data.clear()
                for node in self.nodes:
                    node.subdivide(depth=depth+1)
            else:
                self.coalesce()
                
    class QuadTreeIterator:
        def __init__(self, qtree:Quadtree):
            self.entities = qtree.entities
            self.idx = 0

        def __next__(self):
            if self.idx < len(self.entities):
                e = self.entities[self.idx]
                self.idx += 1
                return e
            raise StopIteration

        def __iter__(self):
            return self

    def __init__(self, min_x:int, max_x:int, min_y:int, max_y:int, grid_dim:int, entities=Iterable[Entity], max_bin:int=16):
        self.min_x = min_x
        self.max_x = max_x
        self.min_y = min_y
        self.max_y = max_y
        self.grid_dim = grid_dim
        self.max_bin = max_bin
        self.grid_width = abs(self.max_x - self.min_x) // self.grid_dim
        self.grid_height = abs(self.max_y - self.min_y) // self.grid_dim
        self.entities = list()

        ents = self.decompose_ents(entities)
        self.decomp = ents
        entity_data = list()
        for _ in range(self.grid_height):
            row = list()
            for _ in range(self.grid_width):
                row.append(None)
            entity_data.append(row)
        
        for e in ents:
            entity_data[e.y//self.grid_dim][e.x//self.grid_dim] = e

        self.root = Quadtree.QNode(self, None, (0, 0), entity_data, self.grid_dim, max_bin)
        self.root.subdivide()

    def __len__(self):
        return len(self.entities)
    
    def __contains__(self, e:Entity):
        return e in self.entities
    
    def __iter__(self):
        return Quadtree.QuadTreeIterator(self)
    
    def iter_nodes(self, callback):
        return self._iter_nodes(self.root, callback)
        
    def _iter_nodes(self, node, callback):
        callback(node)
        if hasattr(node, 'nodes'):
            for n in node.nodes:
                self._iter_nodes(n, callback)
    
    def decompose_ents(self, entities:Iterable[Entity]):
        decomposed = list()

        for e in entities:
            assert e.width % self.grid_dim == 0
            assert e.height % self.grid_dim == 0

            for r in range(0, e.height, self.grid_dim):
                for c in range(0, e.width, self.grid_dim):
                    decomp = copy(e)
                    decomp.x = e.x + c
                    decomp.y = e.y + r
                    decomp.width = self.grid_dim
                    decomp.height = self.grid_dim
                    decomposed.append(decomp)

        return decomposed
    
    def get_node(self, x:int, y:int):
        return self.root.get_node(x, y)
    
    def get_node_region(self, x:int, y:int, w:int, h:int):
        return self.root.get_node_region(x,y,w,h)

    def get(self, x:int, y:int) -> Set[Tuple[Entity, int, int]]:
        return self.root.get(x, y)

    def get_region(self, x:int, y:int, w:int, h:int):
        return self.root.get_region(x, y, w, h)
    
class Grid:
    '''For Dynamic Entities (Moves)'''

    class GridIterator:
        def __init__(self, grid:Grid):
            self.grid = grid
            self.r = 0
            self.c = 0
            self.i = 0
            self.curr_bucket = list(self.grid._data[self.r][self.c])

        def __next__(self):
            if self.i < len(self.curr_bucket):
                e = self.curr_bucket[self.i]
                self.i += 1
                return e
            
            while self.i >= len(self.curr_bucket):
                self.i = 0
                self.c += 1
                if self.c >= self.grid.num_cols:
                    self.c = 0
                    self.r += 1

                if self.r == self.grid.num_rows:
                    raise StopIteration

                self.curr_bucket = list(self.grid._data[self.r][self.c])

            if self.i < len(self.curr_bucket):
                e = self.curr_bucket[self.i]
                self.i += 1
                return e

        def __iter__(self):
            return self

    def __init__(self, n_rows, n_cols, cell_size):
        self.num_rows = n_rows
        self.num_cols = n_cols
        self.cell_size = cell_size

        self._data = list()
        for _ in range(self.num_rows):
            row = list()
            for _ in range(self.num_cols):
                row.append(set())
            self._data.append(row)

        self._data.append(row)
        self._count = 0
        self._lookup = set()

    def __len__(self):
        return self._count
    
    def __iter__(self):
        return Grid.GridIterator(self)

    def __contains__(self, e:Entity):
        r = self._point2cell(e.y)
        c = self._point2cell(e.x)

        return e in self._data[r][c]

    def _point2cell(self, value):
        return value // self.cell_size
    
    def add(self, e:Entity, r=None, c=None):
        if (c is None and r is not None) or (c is not None and r is None):
            raise ValueError("r and c must be either both None or integers")
        
        if r is None and c is None:
            r = self._point2cell(e.y)
            c = self._point2cell(e.x)
    
        if e in self._data[r][c]:
            return
        
        self._data[r][c].add(e)
        self._count += 1

    def remove(self, e:Entity, r=None, c=None):
        if (c is None and r is not None) or (c is not None and r is None):
            raise ValueError("r and c must be either both None or integers")
        
        if r is None and c is None:
            r = self._point2cell(e.y)
            c = self._point2cell(e.x)

        if e in self._data[r][c]:
            self._data[r][c].remove(e)
            self._count -= 1

    def update_entity(self, e:Entity, old_x:int, old_y:int, x:int, y:int):
        # if old_x == x and old_y == y:
        #     return

        old_r = self._point2cell(old_y)
        old_c = self._point2cell(old_x)
        r = self._point2cell(y)
        c = self._point2cell(x)

        if old_r == r and old_c == c:
            return

        old_grid = self._data[old_r][old_c]
        new_grid = self._data[r][c]
        
        # Double updating...
        if e in old_grid:
            old_grid.remove(e)

        if e not in new_grid:
            new_grid.add(e)

        # .remove(e)
        # .add(e)

    def radial(self, x:int, y:int, grid_radius:int=1, invert:bool=False) -> Generator[Entity, None, None]:
        '''
        Queries for objects near (x, y) based on a square grid radius
        :param x: x position
        :param y: y position
        :param grid_radius: The Square (not ^2) Radius. 0 is the grid that x,y reside in. 1 would be the 3x3 centered around x,y (Think Minecraft lol)
        :param invert: Invert the selection. i.e. everything outside of the radius. Slight performance worries
        :returns: generator of objects that are within the grid radius
        '''
        r = self._point2chunk(y)
        c = self._point2chunk(x)

        start_r = max(r - grid_radius, 0)
        start_c = max(c - grid_radius, 0)
        end_r = min(r + grid_radius + 1, self.num_rows)
        end_c = min(c + grid_radius + 1, self.num_cols)

        if invert:
            rows = list(range(start_r, end_r))
            cols = list(range(start_c, end_c))
            for r_idx in range(0, self.num_rows):
                for c_idx in range(0, self.num_cols):
                    if not (r_idx in rows and c_idx in cols):
                        for item in self._data[r_idx][c_idx]:
                            yield item
        else:
            for r_idx in range(start_r, end_r):
                for c_idx in range(start_c, end_c):
                    for item in self._data[r_idx][c_idx]:
                        yield item

    def find(self, start_x:int, end_x:int, start_y:int, end_y:int, filter:Callable[[Any,int, int], bool], first_only=False) -> Generator[Entity, None, None]:
        '''
        Search for all items within the rectangle that filter will return true for
        :param start_x:
        :param end_x:
        :param start_y:
        :param end_y:
        :param filter: A function who's positional arguments are the object being checked, the x coordinate of the object, and the y coordinate of the object. If filter returns True then that object will be returned by this function
        :param first_only: only yield the first object
        :returns: generator of objects within the specificed rectangle that filter returns true on
        '''
        start_r = self._point2chunk(start_y)
        end_r = self._point2chunk(end_y)
        start_c = self._point2chunk(start_x)
        end_c = self._point2chunk(end_x)

        for r_idx in range(start_r, end_r+1):
            for c_idx in range(start_c, end_c+1):
                for item in self._data[r_idx][c_idx]:
                   
                    # Check Bounds and Filter
                    if item.x >= start_x and \
                        item.x <= end_x and \
                        item.y >= start_y and \
                        item.y <= end_y and \
                        filter(item, item.x, item.y):
                        yield item

                        if first_only:
                            return
