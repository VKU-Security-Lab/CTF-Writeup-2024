import pygame

from Blade.game import Game
from Blade.animation import Animation
from Blade.map import Map

from Blade import resources

def draw_lights(player, game, camera):
    if player.lights:
        game.screen.blit(
            player.front_lights.frame(), 
            (player.x - camera.x - 16, player.y - camera.y - 110)
        )

    if player.brakes:
        game.screen.blit(
            player.brake_lights.frame(), 
            (player.x - camera.x + 4, player.y - camera.y + 248)
        )

def car_update(car, game):
    if car.horn:
        car.horn = False
        pygame.mixer.Sound.play(car.horn_sound)

    if car.toggle_locks:
        car.toggle_locks = False
        pygame.mixer.Sound.play(car.lock_sound)

    if car.car_started and car.fuel > 0:
        if not car.toggle_engine_start:
            car.toggle_engine_start = True
            pygame.mixer.Sound.play(car.start_sound)
            pygame.time.set_timer(pygame.USEREVENT, 3000)

def main():
    game = Game()
    map = Map.TiledMap(game, "race.tmx")

    player = map.player
    player.name='player'
    player.solid = True
    player.animation = Animation([resources.image("white_car.png")])
    player.width = player.animation.max_width()
    player.height = player.animation.max_height()
    player.horn_sound = resources.audio("horn.mp3")
    player.lock_sound = resources.audio("lock.mp3")
    player.start_sound = resources.audio("car_start.mp3")
    player.idle_sound = resources.audio("car_idle.mp3")

    player.front_lights = Animation([resources.image("front_lights.png")])
    player.brake_lights = Animation([resources.image("brake_lights.png")])

    player.render_infront = draw_lights

    player.fuel = 1000
    player.rpm = 0
    player.speed = 0
    player.doors_locked = True
    player.toggle_locks = False
    player.lights = False
    player.brakes = False
    player.horn = False
    player.car_started = False
    player.toggle_engine_start = False
    player.flag = "nice try"

    player.custom_update = car_update

    map.add(player)

    game.current_map = map

    game.start()

if __name__ == "__main__":
    main()
