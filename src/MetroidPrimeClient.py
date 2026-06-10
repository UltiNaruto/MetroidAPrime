import asyncio
import json
import multiprocessing
import os
import struct
import subprocess
import time
import traceback
import zipfile
from random import Random

from typing import Any, cast, DefaultDict, Dict, List, Optional, Tuple, TYPE_CHECKING

from CommonClient import (
    get_base_parser,
    logger,
    server_loop,
    gui_enabled,
)
from NetUtils import ClientStatus, HintStatus
from settings import get_settings
import Utils

from . import SuitUpgrade
from .Config import make_version_specific_changes
from .ClientReceiveItems import handle_receive_items
from .Container import construct_hook_patch
from .DolphinClient import (
    DolphinException,
    assert_no_running_dolphin,
    get_num_dolphin_instances,
)
from .Enum import ProgressiveUpgrade
from .Items import PROGRESSIVE_ITEM_MAPPING, suit_upgrade_table
from .Locations import METROID_PRIME_LOCATION_BASE, PICKUP_LOCATIONS
from .MetroidPrimeInterface import (
    HUD_MESSAGE_DURATION,
    ConnectionState,
    InventoryItemData,
    MetroidPrimeInterface,
    MetroidPrimeLevel,
    MetroidPrimeSuit,
)
from .NotificationManager import NotificationManager
from .PrimeSettings import get_strg, get_tweaks
from .PrimeUtils import count_ammo, get_apworld_version, get_output_path

tracker_loaded = False
try:
    from worlds.tracker.TrackerClient import (TrackerCommandProcessor as ClientCommandProcessor,
                                              TrackerGameContext as CommonContext, UT_VERSION)
    tracker_loaded = True
except ImportError:
    from CommonClient import ClientCommandProcessor, CommonContext


if TYPE_CHECKING:
    from kivymd.uix.fitimage import FitImage


class MetroidPrimeCommandProcessor(ClientCommandProcessor):
    ctx: "MetroidPrimeContext"

    def __init__(self, ctx: "MetroidPrimeContext"):
        super().__init__(ctx)

    def _cmd_export_iso(self, *_args: List[Any]):
        if not self.ctx.apmp1_file:
            logger.error("That client wasn't started from a apmp1 file!")
            return

        output_path = get_output_path(self.ctx.apmp1_file)

        if self.ctx.game_interface.connection_status != ConnectionState.DISCONNECTED:
            logger.error("Cannot regen the iso if the game is already running!")
            return

        if os.path.isfile(output_path):
            logger.info("Genned iso file detected! Deleting..")
            os.remove(output_path)

        Utils.async_start(patch_and_run_game(self.ctx.apmp1_file, self.ctx.mp1_iso))

    def _cmd_test_hud(self, *args: List[Any]):
        """Send a message to the game interface."""
        self.ctx.notification_manager.queue_notification(" ".join(map(str, args)))

    def _cmd_status(self, *_args: List[Any]):
        """Display the current dolphin connection status."""
        logger.info(f"Connection status: {status_messages[self.ctx.connection_state]}")

    def _cmd_deathlink(self):
        """Toggle deathlink from client. Overrides default setting."""
        self.ctx.death_link_enabled = not self.ctx.death_link_enabled
        Utils.async_start(
            self.ctx.update_death_link(self.ctx.death_link_enabled),
            name="Update Deathlink",
        )
        message = (
            f"Deathlink {'enabled' if self.ctx.death_link_enabled else 'disabled'}"
        )
        logger.info(message)
        self.ctx.notification_manager.queue_notification(message)

    def _cmd_toggle_gravity_suit(self):
        """Toggles the gravity suit functionality on/off if the player has received it. Note that this will not change the player's current suit they are wearing but disables the functionality of the gravity suit."""
        self.ctx.gravity_suit_enabled = not self.ctx.gravity_suit_enabled
        self.ctx.notification_manager.queue_notification(
            f"{'Enabling' if self.ctx.gravity_suit_enabled else 'Disabling'} Gravity Suit..."
        )

    def _cmd_set_cosmetic_suit(self, val: str):
        """Set the cosmetic suit of the player. This will not affect the player's current suit but will change the appearance of the suit in the game. Note that if you start a new seed without closing the client, the option will persist. If you close the client and get a new suit, you may need to re set this."""
        if val == "None":
            logger.info("Removing cosmetic suit")
            self.ctx.cosmetic_suit = None
            suit = self.ctx.game_interface.get_highest_owned_suit()
            self.ctx.game_interface.set_cosmetic_suit_by_id(
                suit_upgrade_table[suit.value].id
            )
            self.ctx.game_interface.set_current_suit(
                self.ctx.game_interface.get_current_cosmetic_suit()
            )
            return
        suit = MetroidPrimeSuit.get_by_key(val)
        if suit is None:
            options = ", ".join(
                [suit.name for suit in MetroidPrimeSuit if "Fusion" not in suit.name]
                + ["None"]
            )
            logger.warning(
                f"Invalid cosmetic suit: {suit}. Valid options are: {options}"
            )
            return
        logger.info(f"Setting cosmetic suit to: {suit.name} Suit")
        self.ctx.cosmetic_suit = suit


status_messages = {
    ConnectionState.IN_GAME: "Connected to Metroid Prime",
    ConnectionState.IN_MENU: "Connected to game, waiting for game to start",
    ConnectionState.DISCONNECTED: "Unable to connect to the Dolphin instance, attempting to reconnect...",
    ConnectionState.MULTIPLE_DOLPHIN_INSTANCES: "Warning: Multiple Dolphin instances detected, client may not function correctly.",
    ConnectionState.VANILLA_ROM_DETECTED: "Warning: Connected to a non-randomized Metroid Prime game"
}


artifact_hint_scans: Dict[str, int] = {
    "Artifact of Truth": 852090318,
    "Artifact of Strength": 3026038624,
    "Artifact of Elder": 2130803909,
    "Artifact of Wild": 1644448893,
    "Artifact of Lifegiver": 2841157592,
    "Artifact of Warrior": 801959286,
    "Artifact of Chozo": 3834658515,
    "Artifact of Nature": 365333510,
    "Artifact of Sun": 3734658979,
    "Artifact of World": 4223573402,
    "Artifact of Spirit": 820137535,
    "Artifact of Newborn": 3061202065,
}


def get_image(source: str, width: int = 0, height: int = 0, is_upgrade: bool=True) -> 'FitImage':
    from importlib import resources
    from kivy.core.image import Image
    from kivy.metrics import dp
    from kivymd.uix.fitimage import FitImage
    from io import BytesIO

    img = resources.files(f'{__package__}.assets.items').joinpath(source)
    data = img.read_bytes()
    raw_image = Image(BytesIO(data), ext=img.suffix[1:])
    image = FitImage(texture=raw_image.texture)
    if width > 0:
        image.size_hint_x = None if is_upgrade else .001
        image.width = dp(width)
    if height > 0:
        image.size_hint_y = None if is_upgrade else .001
        image.height = dp(height)

    image.fit_mode = "scale-down"
    return image


class MetroidPrimeContext(CommonContext):
    current_level_id = 0
    previous_level_id = 0
    is_pending_death_link_reset = False
    command_processor = MetroidPrimeCommandProcessor
    game_interface: MetroidPrimeInterface
    notification_manager: NotificationManager
    game = "Metroid Prime"
    items_handling = 0b111
    dolphin_sync_task: Optional[asyncio.Task[Any]] = None
    connection_state = ConnectionState.DISCONNECTED
    slot_data: Dict[str, Utils.Any] = {}
    death_link_enabled = False
    gravity_suit_enabled: bool = True
    previous_location_str: str = ""
    cosmetic_suit: Optional[MetroidPrimeSuit] = None
    slot_name: Optional[str] = None
    last_error_message: Optional[str] = None
    apmp1_file: Optional[str] = None

    def __init__(
        self,
        server_address: Optional[str],
        password: Optional[str],
        apmp1_file: Optional[str] = None,
        mp1_iso: Optional[str] = None,
    ):
        super().__init__(server_address, password)

        self.game_interface = MetroidPrimeInterface(logger)
        self.notification_manager = NotificationManager(
            HUD_MESSAGE_DURATION, self.game_interface.send_hud_message
        )
        self.apmp1_file = apmp1_file
        self.mp1_iso = mp1_iso

    def on_deathlink(self, data: Utils.Dict[str, Utils.Any]) -> None:
        super().on_deathlink(data)
        self.game_interface.set_alive(False)

    async def server_auth(self, password_requested: bool = False):
        if password_requested and not self.password:
            await super(MetroidPrimeContext, self).server_auth(password_requested)
        await self.get_username()
        self.tags = set()
        await self.send_connect()

    def on_package(self, cmd: str, args: Dict[str, Any]) -> None:
        super().on_package(cmd, args)

        if cmd == "Connected":
            self.slot_data = args["slot_data"]
            if "death_link" in args["slot_data"]:
                self.death_link_enabled = bool(args["slot_data"]["death_link"])
                Utils.async_start(
                    self.update_death_link(bool(args["slot_data"]["death_link"]))
                )

            if self.ui:
                self.ui.update_upgrades(self.slot_data, [])
                self.ui.update_artifacts(0, self.slot_data.get('required_artifacts', 12))
                self.ui.update_energy_tanks(0)
                self.ui.update_missile_expansions(0)
                self.ui.update_power_bomb_expansions(0)
        elif cmd == "ReceivedItems":
            if self.ui:
                items = [self.item_names.lookup_in_game(i.item, self.game) for i in self.items_received]
                missile_ammo = count_ammo(
                    [i for i in items if i.startswith('Missile')],
                    SuitUpgrade.Missile_Launcher.value,
                    SuitUpgrade.Missile_Expansion.value,
                    self.slot_data.get('missile_launcher', 0) == 1,
                )
                pb_ammo = count_ammo(
                    [i for i in items if 'Power Bomb' in i],
                    SuitUpgrade.Main_Power_Bomb.value,
                    SuitUpgrade.Power_Bomb_Expansion.value,
                    self.slot_data.get('main_power_bomb', 0) == 1,
                )
                etank_count = sum([1 for i in items if i == SuitUpgrade.Energy_Tank.value])
                artifact_count = sum([1 for i in items if i.startswith('Artifact ')])

                self.ui.update_upgrades(self.slot_data, items)
                self.ui.update_artifacts(artifact_count)
                self.ui.update_energy_tanks(etank_count)
                self.ui.update_missile_expansions(missile_ammo, any([i for i in items if i == SuitUpgrade.Unlimited_Missiles.value]))
                self.ui.update_power_bomb_expansions(pb_ammo, any([i for i in items if i == SuitUpgrade.Unlimited_Power_Bombs.value]))

    # noinspection PyUnresolvedReferences
    def make_gui(self) -> "type[GameManager]":
        from kvui import GameManager
        base_class: type = GameManager
        ut_title: str = ""

        if tracker_loaded and UT_VERSION >= "v0.2.12":
            base_class = super().make_gui()
            ut_title += f" | Universal Tracker {UT_VERSION}"

        class MetroidPrimeManager(base_class):
            logging_pairs = [("Client", "Archipelago")]
            base_title = f"Metroid Prime Client {get_apworld_version()}{ut_title} | AP"

            def build(self):
                container = super().build()

                from kivy.metrics import dp
                from kvui import MDBoxLayout, MDGridLayout, MDLabel

                def _update_text_size(inst, val):
                    inst.text_size = val
                    inst.texture_update()

                layout = MDBoxLayout(
                    orientation="horizontal",
                    size_hint_y=None,
                    height=dp(64),
                    spacing=dp(5),
                    padding=dp(5),
                )

                artifacts_layout = MDGridLayout(
                    rows=2,
                    spacing=dp(3),
                    size_hint_x=None,
                    width=dp(40),
                    row_default_height=dp(32),
                    row_force_default=True,
                )
                artifacts_layout.add_widget(get_image('artifacts.png', 32, 32, True))
                self.artifacts_text: MDLabel = MDLabel(text='0', halign='center', valign='middle', role='large')  # noqa
                self.artifacts_text.bind(size=_update_text_size)
                artifacts_layout.add_widget(self.artifacts_text)
                layout.add_widget(artifacts_layout)

                missile_expansion_layout = MDGridLayout(
                    rows=2,
                    spacing=dp(3),
                    size_hint_x=None,
                    width=dp(40),
                    row_default_height=dp(32),
                    row_force_default=True,
                )
                missile_expansion_layout.add_widget(get_image('missileexpansion.png', 32, 32, False))
                self.missile_expansion_text: MDLabel = MDLabel(text='0', halign='center', valign='middle', role='large')  # noqa
                self.missile_expansion_text.bind(size=_update_text_size)
                missile_expansion_layout.add_widget(self.missile_expansion_text)
                layout.add_widget(missile_expansion_layout)

                # Power Bomb Expansion
                power_bomb_expansion_layout = MDGridLayout(
                    rows=2,
                    spacing=dp(3),
                    size_hint_x=None,
                    width=dp(40),
                    row_default_height=dp(32),
                    row_force_default=True,
                )
                power_bomb_expansion_layout.add_widget(get_image('powerbombexpansion.png', 32, 32, False))
                self.power_bomb_expansion_text: MDLabel = MDLabel(text='0', halign='center', valign='middle', role='large')  # noqa
                self.power_bomb_expansion_text.bind(size=_update_text_size)
                power_bomb_expansion_layout.add_widget(self.power_bomb_expansion_text)
                layout.add_widget(power_bomb_expansion_layout)

                etank_layout = MDGridLayout(
                    rows=2,
                    spacing=dp(3),
                    size_hint_x=None,
                    width=dp(40),
                    row_default_height=dp(32),
                    row_force_default=True,
                )
                etank_layout.add_widget(get_image('energytank.png', 32, 32, False))
                self.etank_text: MDLabel = MDLabel(text='0', halign='center', valign='middle', role='large')  # noqa
                self.etank_text.bind(size=_update_text_size)
                etank_layout.add_widget(self.etank_text)
                layout.add_widget(etank_layout)

                layout.add_widget(MDLabel(
                    text='',
                    size_hint_x=None,
                    width=dp(1),
                ))

                self.upgrade_icon_w, self.upgrade_icon_h = 24, 24 # noqa
                self.upgrades_grid = MDGridLayout( # noqa
                    rows=2,
                    padding=0,
                    spacing=2,
                    size_hint_x=None,
                    width=dp(self.upgrade_icon_w * 10),
                )
                self.upgrades: dict[str, FitImage] = {  # noqa
                    # beams
                    SuitUpgrade.Power_Beam.value: get_image('powerbeam.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Wave_Beam.value: get_image('wavebeam.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Ice_Beam.value: get_image('icebeam.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Plasma_Beam.value: get_image('plasmabeam.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    # charge beam
                    SuitUpgrade.Charge_Beam.value: get_image('chargebeam.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Power_Charge_Beam.value: get_image('chargebeam_power.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Wave_Charge_Beam.value: get_image('chargebeam_wave.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Ice_Charge_Beam.value: get_image('chargebeam_ice.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Plasma_Charge_Beam.value: get_image('chargebeam_plasma.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    # beam combos
                    SuitUpgrade.Super_Missile.value: get_image('supermissile.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Wavebuster.value: get_image('wavebuster.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Ice_Spreader.value: get_image('icespreader.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Flamethrower.value: get_image('flamethrower.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    # visors
                    SuitUpgrade.Scan_Visor.value: get_image('scanvisor.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Thermal_Visor.value: get_image('thermalvisor.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.X_Ray_Visor.value: get_image('xrayvisor.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    # suits
                    SuitUpgrade.Varia_Suit.value: get_image('variasuit.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Gravity_Suit.value: get_image('gravitysuit.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Phazon_Suit.value: get_image('phazonsuit.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    # morph upgrades
                    SuitUpgrade.Morph_Ball.value: get_image('morphball.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Morph_Ball_Bomb.value: get_image('morphballbomb.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Spring_Ball.value: get_image('springball.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Main_Power_Bomb.value: get_image('powerbomb.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Boost_Ball.value: get_image('boostball.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Spider_Ball.value: get_image('spiderball.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    # misc
                    SuitUpgrade.Missile_Launcher: get_image('missilelauncher.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Space_Jump_Boots: get_image('spacejumpboots.png', self.upgrade_icon_w, self.upgrade_icon_h),
                    SuitUpgrade.Grapple_Beam: get_image('grapplebeam.png', self.upgrade_icon_w, self.upgrade_icon_h),
                }

                self.update_upgrades({}, [])
                layout.add_widget(self.upgrades_grid)

                self.grid.add_widget(layout)
                return container

            def update_upgrades(self, slot_data: dict[str, Any], items: list[str]) -> None:
                from collections import OrderedDict
                from kivy.metrics import dp

                displayed_upgrades: OrderedDict[str, bool] = OrderedDict({})
                if slot_data.get('progressive_beam_upgrades', 0) == 1:
                    for i in [
                        ProgressiveUpgrade.Progressive_Power_Beam,
                        ProgressiveUpgrade.Progressive_Wave_Beam,
                        ProgressiveUpgrade.Progressive_Ice_Beam,
                        ProgressiveUpgrade.Progressive_Plasma_Beam,
                    ]:
                        match items.count(i):
                            case 0:
                                displayed_upgrades[PROGRESSIVE_ITEM_MAPPING[i][0].value] = False
                            case 1:
                                displayed_upgrades[PROGRESSIVE_ITEM_MAPPING[i][0].value] = True
                            case 2:
                                displayed_upgrades[PROGRESSIVE_ITEM_MAPPING[i][1].value] = True
                            case 3:
                                displayed_upgrades[PROGRESSIVE_ITEM_MAPPING[i][2].value] = True
                else:
                    for i in [
                        SuitUpgrade.Power_Beam,
                        SuitUpgrade.Wave_Beam,
                        SuitUpgrade.Ice_Beam,
                        SuitUpgrade.Plasma_Beam,
                        SuitUpgrade.Charge_Beam,
                        SuitUpgrade.Super_Missile,
                        SuitUpgrade.Wavebuster,
                        SuitUpgrade.Ice_Spreader,
                        SuitUpgrade.Flamethrower,
                    ]:
                        displayed_upgrades[i.value] = i.value in items

                displayed_upgrades[SuitUpgrade.Missile_Launcher.value] = (
                    slot_data.get('missile_launcher', 0) == 0 or
                    SuitUpgrade.Missile_Launcher.value in items
                )

                for i in [
                    SuitUpgrade.Space_Jump_Boots,
                    SuitUpgrade.Grapple_Beam,
                    SuitUpgrade.Morph_Ball,
                ]:
                    displayed_upgrades[i.value] = i.value in items

                # if spring ball is set to lower than 2 then ignore spring ball
                match slot_data.get('spring_ball', 0):
                    # its own progressive item
                    case 3:
                        i = ProgressiveUpgrade.Progressive_Bomb
                        match items.count(i.value):
                            case 0:
                                displayed_upgrades[PROGRESSIVE_ITEM_MAPPING[i][0].value] = False
                            case 1:
                                displayed_upgrades[PROGRESSIVE_ITEM_MAPPING[i][0].value] = True
                            case 2:
                                displayed_upgrades[PROGRESSIVE_ITEM_MAPPING[i][1].value] = True
                    case v:
                        displayed_upgrades[SuitUpgrade.Morph_Ball_Bomb.value] = SuitUpgrade.Morph_Ball_Bomb.value in items
                        if v == 2:
                            displayed_upgrades[SuitUpgrade.Spring_Ball.value] = SuitUpgrade.Spring_Ball.value in items

                displayed_upgrades[SuitUpgrade.Main_Power_Bomb.value] = (
                    slot_data.get('main_power_bomb', 0) == 0 or
                    SuitUpgrade.Main_Power_Bomb.value in items
                )
                for i in [
                    SuitUpgrade.Boost_Ball,
                    SuitUpgrade.Spider_Ball,
                    SuitUpgrade.Scan_Visor,
                    SuitUpgrade.Thermal_Visor,
                    SuitUpgrade.X_Ray_Visor,
                    SuitUpgrade.Varia_Suit,
                    SuitUpgrade.Gravity_Suit,
                    SuitUpgrade.Phazon_Suit,
                ]:
                    displayed_upgrades[i.value] = i.value in items

                self.upgrades_grid.clear_widgets()
                self.upgrades_grid.width = dp(len(displayed_upgrades) * self.upgrade_icon_w)
                for upgrade_name, obtained in displayed_upgrades.items():
                    self.upgrades[upgrade_name].opacity = 1 if obtained else .2
                    self.upgrades_grid.add_widget(self.upgrades[upgrade_name])

            def update_artifacts(self, current: int, goal: Optional[int]=None) -> None:
                # only set once per connection since the goal cannot change during the session
                if goal is None:
                    try:
                        idx = self.artifacts_text.text.index('/') + 1
                        goal = int(self.artifacts_text.text[idx:])
                        # Cap current to goal if artifacts are required
                        if goal > 0:
                            current = min(current, goal)
                    except ValueError:
                        goal = 0

                text = f'{current}'
                if goal is not None and goal > 0:
                    text += f'/{goal}'

                if self.artifacts_text.text != text:
                    self.artifacts_text.text = text

            def update_energy_tanks(self, current: int) -> None:
                if self.etank_text.text != f'{current}':
                    self.etank_text.text = f'{current}'

            def update_missile_expansions(self, current: int, is_unlimited: bool=False) -> None:
                if is_unlimited:
                    text = '∞'
                else:
                    text = f'{current}'

                if self.missile_expansion_text.text != text:
                    self.missile_expansion_text.text = text

            def update_power_bomb_expansions(self, current: int, is_unlimited: bool=False) -> None:
                if is_unlimited:
                    text = '∞'
                else:
                    text = f'{current}'

                if self.power_bomb_expansion_text.text != text:
                    self.power_bomb_expansion_text.text = text

        return MetroidPrimeManager


def update_connection_status(ctx: MetroidPrimeContext, status: ConnectionState):
    if ctx.connection_state == status:
        return
    else:
        logger.info(status_messages[status])
        if get_num_dolphin_instances() > 1:
            logger.info(status_messages[ConnectionState.MULTIPLE_DOLPHIN_INSTANCES])
        ctx.connection_state = status


async def dolphin_sync_task(ctx: MetroidPrimeContext):
    try:
        # This will not work if the client is running from source
        version = get_apworld_version()
        logger.info(f"Using metroidprime.apworld version: {version}")
    except (Exception,):
        pass

    if ctx.apmp1_file:
        Utils.async_start(patch_and_run_game(ctx.apmp1_file, ctx.mp1_iso))

    logger.info("Starting Dolphin Connector, attempting to connect to emulator...")

    while not ctx.exit_event.is_set():
        try:
            connection_state = ctx.game_interface.get_connection_state()
            update_connection_status(ctx, connection_state)
            if connection_state == ConnectionState.IN_MENU:
                await handle_check_goal_complete(
                    ctx
                )  # It will say the player is in menu sometimes
            if connection_state == ConnectionState.IN_GAME:
                await _handle_game_ready(ctx)
            else:
                await _handle_game_not_ready(ctx)
                await asyncio.sleep(1)
        except Exception as e:
            if isinstance(e, DolphinException):
                logger.error(str(e))
            else:
                logger.error(traceback.format_exc())
            await asyncio.sleep(3)
            continue


async def handle_checked_location(
    ctx: MetroidPrimeContext, _current_inventory: Dict[str, InventoryItemData]
):
    """Checks for active memory relays in each worlds"""
    checked_locations: List[int] = []
    i = 0
    for mlvl, memory_relay in PICKUP_LOCATIONS:
        if ctx.game_interface.is_memory_relay_active(f"{mlvl.value:X}", memory_relay):
            checked_locations.append(METROID_PRIME_LOCATION_BASE + i)
        i += 1
    await ctx.send_msgs([{"cmd": "LocationChecks", "locations": checked_locations}])


async def handle_check_goal_complete(ctx: MetroidPrimeContext):
    if ctx.game_interface.current_game:
        current_level = ctx.game_interface.get_current_level()
        if current_level == MetroidPrimeLevel.End_of_Game:
            await ctx.send_msgs(
                [{"cmd": "StatusUpdate", "status": ClientStatus.CLIENT_GOAL}]
            )


async def handle_tracker_level(ctx: MetroidPrimeContext):
    current_level = ctx.game_interface.get_current_level()
    if current_level is None:
        level = 0
    else:
        level = current_level.value

    await ctx.send_msgs([{
        'cmd': 'Set',
        'key': f'metroidprime_level_{ctx.team}_{ctx.slot}',
        'default': 0,
        'want_reply': False,
        'operations': [{'operation': 'replace', 'value': level}]
    }])


async def handle_artifact_hints(ctx: MetroidPrimeContext, scans: Dict[int, bool]):
    artifact_locations: Optional[Dict[str, Tuple[int, int]]] = ctx.slot_data.get("artifact_locations")
    if not artifact_locations:
        return

    scanned_hints: DefaultDict[int, List[int]] = DefaultDict(list)
    for artifact_name, asset_id in artifact_hint_scans.items():
        if scans.get(asset_id) and artifact_name in artifact_locations:
            location, player = artifact_locations[artifact_name]
            scanned_hints[player].append(location)
    await ctx.send_msgs([
        {"cmd": "CreateHints", "locations": locations, "player": player, "status": HintStatus.HINT_PRIORITY}
        for player, locations in scanned_hints.items()
    ])


async def handle_check_deathlink(ctx: MetroidPrimeContext):
    health = ctx.game_interface.get_current_health()
    if health <= 0 and ctx.is_pending_death_link_reset == False and ctx.slot:
        await ctx.send_death(ctx.player_names[ctx.slot] + " ran out of energy.")
        ctx.is_pending_death_link_reset = True
    elif health > 0 and ctx.is_pending_death_link_reset == True:
        ctx.is_pending_death_link_reset = False


async def _handle_game_ready(ctx: MetroidPrimeContext):
    if ctx.server:
        ctx.last_error_message = None
        if not ctx.slot:
            await asyncio.sleep(1)
            return
        ctx.game_interface.update_relay_tracker_cache()
        current_inventory = ctx.game_interface.get_current_inventory()
        await handle_receive_items(ctx, current_inventory)
        ctx.notification_manager.handle_notifications()
        await handle_checked_location(ctx, current_inventory)
        await handle_check_goal_complete(ctx)
        await handle_tracker_level(ctx)
        scans = ctx.game_interface.get_scans()
        await handle_artifact_hints(ctx, scans)

        if ctx.death_link_enabled:
            await handle_check_deathlink(ctx)
        await asyncio.sleep(0.5)
    else:
        message = "Waiting for player to connect to server"
        if ctx.last_error_message is not message:
            logger.info("Waiting for player to connect to server")
            ctx.last_error_message = message
        await asyncio.sleep(1)


async def _handle_game_not_ready(ctx: MetroidPrimeContext):
    """If the game is not connected or not in a playable state, this will attempt to retry connecting to the game."""
    ctx.game_interface.reset_relay_tracker_cache()
    if ctx.connection_state == ConnectionState.DISCONNECTED:
        ctx.game_interface.connect_to_game()
    elif ctx.connection_state in [
        ConnectionState.IN_MENU,
        ConnectionState.VANILLA_ROM_DETECTED,
    ]:
        await asyncio.sleep(3)


async def run_game(romfile: str):
    metroidprime_options = get_settings()["metroidprime_options"]
    auto_start: bool = metroidprime_options['emulator_settings']['auto_start']
    emulator_path: str = metroidprime_options['emulator_settings']['executable_path']
    emulator_arguments: list = metroidprime_options['emulator_settings']['arguments']

    if auto_start is True and assert_no_running_dolphin():
        subprocess.Popen(
            [str(emulator_path), romfile, *emulator_arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


_GC_GAME_VERSIONS: dict[tuple[str, int], str] = {
    ("E", 0): "0-00",
    ("E", 1): "0-01",
    ("E", 2): "0-02",
    ("E", 48): "kor",
    ("P", 0): "pal",
    ("J", 0): "jpn",
}

def get_version_from_iso(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Couldn't get version for iso {path}!")

    with open(path, "rb") as f:
        # detecting any non-ISO format
        f.seek(0x200, 0)
        if f.read(4).decode("utf-8") == "NKIT":
            raise Exception("NKit format is not supported! Please dump your ISO from your disc.")

        f.seek(0, 0)
        file_format = f.read(3).decode("utf-8")
        if file_format in ["RVZ", "WIA"]:
            raise Exception(f"{file_format} format is not supported! Please dump your ISO from your disc.")

        f.seek(0, 0)
        gcz_magic = struct.unpack('<H', f.read(2))[0]
        if gcz_magic == 0xB10B:
            raise Exception("GCZ format is not supported! Please dump your ISO from your disc.")

        f.seek(0, 0)
        if f.read(3).decode("utf-8") == "CISO":
            raise Exception("CISO format is not supported! Please dump your ISO from your disc.")

        # detecting game infos
        f.seek(0, 0)
        game_id = f.read(6).decode("utf-8")
        f.read(1)
        game_rev = f.read(1)[0]
        if game_id[:3] != "GM8":
            raise Exception("This is not Metroid Prime GC")

        result = _GC_GAME_VERSIONS.get((game_id[3], game_rev), None)

        if result is None:
            raise Exception(
                f"Unknown version of Metroid Prime GC (game_id : {game_id} | game_rev : {game_rev})"
            )

        return result


def get_options_from_apmp1(apmp1_file: str) -> Dict[str, Any]:
    with zipfile.ZipFile(apmp1_file) as zip_file:
        with zip_file.open("options.json") as file:
            options_json = file.read().decode("utf-8")
            options_json = json.loads(options_json)
    return cast(Dict[str, Any], options_json)


def get_randomprime_config_from_apmp1(apmp1_file: str) -> Dict[str, Any]:
    with zipfile.ZipFile(apmp1_file) as zip_file:
        with zip_file.open("config.json") as file:
            config_json = file.read().decode("utf-8")
            config_json = json.loads(config_json)
    return config_json


async def patch_and_run_game(apmp1_file: str, mp1_iso: Optional[str] = None):
    import py_randomprime # type: ignore

    metroidprime_options = get_settings()['metroidprime_options']
    apmp1_file = os.path.abspath(apmp1_file)
    input_iso_path = metroidprime_options['rom_file'] if mp1_iso is None or mp1_iso == '' else mp1_iso
    base_name = os.path.splitext(apmp1_file)[0]
    output_path = f'{base_name}.iso'

    if not os.path.exists(output_path):
        if not zipfile.is_zipfile(apmp1_file):
            raise Exception(f'Invalid APMP1 file: {apmp1_file}')

        config_json = get_randomprime_config_from_apmp1(apmp1_file)
        options_json = get_options_from_apmp1(apmp1_file)

        build_progressive_beam_patch = False
        if options_json:
            build_progressive_beam_patch = options_json['progressive_beam_upgrades']

        try:
            game_version = get_version_from_iso(input_iso_path)

            config_json['gameConfig']['updateHintStateReplacement'] = (
                construct_hook_patch(game_version, build_progressive_beam_patch)
            )
            # HUD settings
            config_json['tweaks'] = get_tweaks(metroidprime_options)
            # Suit Settings
            config_json['strg'] = get_strg(metroidprime_options, config_json['strg'])
            if metroidprime_options['suit_settings']['randomize_suit_colors']:
                r = Random(time.time())
                config_json['preferences']['suitColors'] = {
                    'gravityDeg': r.randint(1, 35) * 10,
                    'phazonDeg': r.randint(1, 35) * 10,
                    'powerDeg': r.randint(1, 35) * 10,
                    'variaDeg': r.randint(1, 35) * 10,
                }
            else:
                config_json["preferences"]["suitColors"] = {
                    'gravityDeg': metroidprime_options['suit_settings']['gravity_suit_color'],
                    'phazonDeg': metroidprime_options['suit_settings']['phazon_suit_color'],
                    'powerDeg': metroidprime_options['suit_settings']['power_suit_color'],
                    'variaDeg': metroidprime_options['suit_settings']['varia_suit_color'],
                }
            config_json['preferences']['forceFusion'] = metroidprime_options['suit_settings']['fusion_suit']
            config_json['preferences']['defaultGameOptions'] = metroidprime_options['default_game_settings'].to_config()

            disc_version: str = str(py_randomprime.rust.get_iso_mp1_version(os.fspath(input_iso_path)))  # type: ignore
            # Version specific changes to the config
            config_json = make_version_specific_changes(config_json, disc_version)

            notifier = py_randomprime.ProgressNotifier(  # type: ignore
                lambda progress, message: print("Generating ISO: ", progress, message)  # type: ignore
            )
            logger.info("--------------")
            logger.info(f"Input ISO Path: {input_iso_path}")
            logger.info(f"Output ISO Path: {output_path}")
            logger.info(f"Disc Version: {disc_version}")
            logger.info("Patching ISO...")
            py_randomprime.patch_iso(input_iso_path, output_path, config_json, notifier)  # type: ignore
            logger.info("Patching Complete")

        except BaseException as e:
            logger.error(f"Failed to patch ISO: {e}")
            # Delete the output file if it exists since it will be corrupted
            if os.path.exists(output_path):
                os.remove(output_path)

            raise RuntimeError(f"Failed to patch ISO: {e}")
        logger.info("--------------")

    Utils.async_start(run_game(output_path))


def main(*args: str):
    Utils.init_logging("MetroidPrime Client")

    async def _main(connect: Optional[str], password: Optional[str], apmp1_file: Optional[str], mp1_iso: Optional[str]) -> None:
        from .PrimeUtils import setup_libs
        setup_libs()

        multiprocessing.freeze_support()
        logger.info("main")

        ctx = MetroidPrimeContext(connect, password, apmp1_file, mp1_iso)

        if apmp1_file:
            slot = get_options_from_apmp1(apmp1_file)["player_name"]
            if slot:
                ctx.auth = slot

        logger.info("Connecting to server...")
        ctx.server_task = asyncio.create_task(server_loop(ctx), name="Server Loop")

        # Runs Universal Tracker's internal generator
        if tracker_loaded:
            ctx.run_generator()
            ctx.tags.remove("Tracker")

        if gui_enabled:
            ctx.run_gui()
        ctx.run_cli()

        logger.info("Running game...")
        ctx.dolphin_sync_task = asyncio.create_task(
            dolphin_sync_task(ctx), name="Dolphin Sync"
        )

        await ctx.exit_event.wait()
        # Reusing https://github.com/ArchipelagoMW/Archipelago/blob/0.6.7/worlds/tww/TWWClient.py#L718-L719
        # Wake the sync task, if it is currently sleeping, so it can start shutting down when it sees that the
        # exit_event is set.
        ctx.watcher_event.set()
        ctx.server_address = None

        await ctx.shutdown()

        if ctx.dolphin_sync_task:
            await asyncio.sleep(3)
            await ctx.dolphin_sync_task

    parser = get_base_parser()
    parser.add_argument(
        "apmp1_file", default="", type=str, nargs="?", help="Path to an apmp1 file"
    )
    parser.add_argument(
        "mp1_iso", default="", type=str, nargs="?", help="Path to Metroid Prime iso"
    )
    parser_args = parser.parse_args(args)

    import colorama

    colorama.init()
    asyncio.run(_main(parser_args.connect, parser_args.password, parser_args.apmp1_file, parser_args.mp1_iso))
    colorama.deinit()
