from collections.abc import Sequence
import time
from random import Random

from settings import Bool, Group, UserFilePath
from typing import Any, Dict, List, Optional, Self

from .Config import PAUSE_MENU_STRG_KEY
from .Container import get_version_from_iso
from .Enum import HudColor as EHudColor
from .PrimeUtils import is_between_or_throw


def color_settings_to_value(settings: "MetroidPrimeSettings") -> List[float]:
    if settings['hud_settings']['color'].lower() == 'random':
        return [c for c in EHudColor.random(Random(time.time())).value]
    else:
        return [
            settings['hud_settings']['color_red'],
            settings['hud_settings']['color_green'],
            settings['hud_settings']['color_blue'],
        ]


def get_tweaks(settings: "MetroidPrimeSettings") -> Dict[str, List[float]]:
    color = color_settings_to_value(settings)
    if color != EHudColor.DEFAULT.value:
        return {"hudColor": [c / 255 for c in color]}
    else:
        return {}


def get_strg(settings: "MetroidPrimeSettings", strg: Dict[str, List[float]]) -> Dict[str, List[float]]:
    # Show suit colors in pause menu
    pause_menu_overrides = {
        "Power Suit": settings['suit_settings']['power_suit_color'],
        "Varia Suit": settings['suit_settings']['varia_suit_color'],
        "Gravity Suit": settings['suit_settings']['gravity_suit_color'],
        "Phazon Suit": settings['suit_settings']['phazon_suit_color'],
    }

    # Update the name to include the color index if it is set
    for item in strg[PAUSE_MENU_STRG_KEY]:
        if item in pause_menu_overrides and pause_menu_overrides[item] != 0:
            index = strg[PAUSE_MENU_STRG_KEY].index(item)
            strg[PAUSE_MENU_STRG_KEY][
                index
            ] = f"{item} (Color: {pause_menu_overrides[item]})"

    return strg


class RomFile(UserFilePath):
    """File name of the Metroid Prime ISO"""

    description = "Metroid Prime GC ISO file"
    copy_to = "Metroid_Prime.iso"

    def browse(self, filetypes: Sequence[tuple[str, Sequence[str]]] | None = None, **kwargs) -> Self | None:
        if filetypes is None:
            filetypes = [("GameCube disc image", [".iso"])]
        return super().browse(filetypes, **kwargs)

    @classmethod
    def validate(cls, path: str):
        get_version_from_iso(path)


class EmulatorSettings(Group):
    """Settings related to the emulator."""
    class EmulatorExecutable(UserFilePath):
        """Path to Dolphin or PrimeHack."""

        is_exe = True
        description = "Dolphin/PrimeHack Emulator Executable"

    class EmulatorArguments(list):
        """Arguments to use with Dolphin or PrimeHack."""
        pass

    class EmulatorAutoStart(Bool):
        """Should the Emulator be started automatically?"""
        pass

    executable_path: EmulatorExecutable = EmulatorExecutable(EmulatorExecutable.copy_to)
    arguments: EmulatorArguments = []
    auto_start: EmulatorAutoStart = True

    def __init__(self):
        should_save = any([attr not in self for attr in self])
        if should_save:
            self.update({attr: self[attr] for attr in self.__dict__.keys()})


class HUDSettings(Group):
    """Settings related to HUD."""
    class HudColor(str):
        """
        Default: [102, 174, 225]
        Red:     [255, 0, 0]
        Green:   [0, 255, 0]
        Blue:    [0, 0, 255]
        Violet:  [255, 0, 255]
        Yellow:  [255, 255, 0]
        Cyan:    [0, 255, 255]
        White:   [255, 255, 255]
        Orange:  [255, 128, 0]
        Pink:    [255, 128, 255]
        Lime:    [128, 255, 0]
        Teal:    [128, 255, 255]
        Purple:  [128, 0, 255]
        Random:  [random R, random G, random B]
        Custom:  [chosen R, chosen G, chosen B]

        Custom uses color_red, color_green and color_blue.
        """

    class HudColorChannel(int):
        """
        Value must be between 0 and 255
        """

    color: HudColor = 'default'
    color_red: HudColorChannel = HudColorChannel(EHudColor.DEFAULT.value[0])
    color_green: HudColorChannel = HudColorChannel(EHudColor.DEFAULT.value[1])
    color_blue: HudColorChannel = HudColorChannel(EHudColor.DEFAULT.value[2])

    def __init__(self):
        should_save = any([attr not in self for attr in self])
        if should_save:
            self.update({attr: self[attr] for attr in self.__dict__.keys()})

    def __getitem__(self, key: str) -> Any:
        hud_color = super().__getitem__('color')

        match key:
            case 'color_red':
                return HUDSettings.get_hud_color(hud_color, 0, super().__getitem__(key))
            case 'color_green':
                return HUDSettings.get_hud_color(hud_color, 1, super().__getitem__(key))
            case 'color_blue':
                return HUDSettings.get_hud_color(hud_color, 2, super().__getitem__(key))

        return super().__getitem__(key)

    @staticmethod
    def get_hud_color(color_name: str, index: int, v: int) -> Optional[int]:
        match index:
            case 0:
                channel_name = 'red'
            case 1:
                channel_name = 'green'
            case 2:
                channel_name = 'blue'
            case _:
                return None

        match color_name.lower():
            case 'default':
                return EHudColor.DEFAULT.value[index]
            case 'red':
                return EHudColor.RED.value[index]
            case 'green':
                return EHudColor.GREEN.value[index]
            case 'blue':
                return EHudColor.BLUE.value[index]
            case 'violet':
                return EHudColor.VIOLET.value[index]
            case 'yellow':
                return EHudColor.YELLOW.value[index]
            case 'cyan':
                return EHudColor.CYAN.value[index]
            case 'white':
                return EHudColor.WHITE.value[index]
            case 'orange':
                return EHudColor.ORANGE.value[index]
            case 'pink':
                return EHudColor.PINK.value[index]
            case 'lime':
                return EHudColor.LIME.value[index]
            case 'teal':
                return EHudColor.TEAL.value[index]
            case 'purple':
                return EHudColor.PURPLE.value[index]
            case 'random':
                return 0
            case 'custom':
                if v < 0 or v > 255:
                    raise RuntimeError(f'Invalid value {v * 255.0} supplied for color_{channel_name}!')
            case _:
                raise RuntimeError(f'Unknown color {v} supplied for hud_color!')
        return v


class SuitSettings(Group):
    """Settings related to Suit."""

    class FusionSuit(Bool):
        """If enabled, will replace all the suits in game with the Fusion Suit variants (cosmetic only). Suit color randomization will have no effect if this is enabled."""
        pass

    class RandomizeSuitColors(Bool):
        """Randomize the colors of the suits. Is overridden if any of the color overrides are greater than 0. Note: This is not compatible with the Fusion Suit and will have no effect."""
        pass

    class SuitColorRotation(int):
        """Override the color of the suit using an index from the game's color wheel. Allowed values are between 0 and 359."""
        pass

    fusion_suit: FusionSuit = False
    randomize_suit_colors: RandomizeSuitColors = False
    power_suit_color: SuitColorRotation = 0
    varia_suit_color: SuitColorRotation = 0
    gravity_suit_color: SuitColorRotation = 0
    phazon_suit_color: SuitColorRotation = 0

    def __init__(self):
        should_save = any([attr not in self for attr in self])
        if should_save:
            self.update({attr: self[attr] for attr in self.__dict__.keys()})


class DefaultGameOptionsSettings(Group):
    """Settings related to default options."""
    class VisorSettings(Group):
        """Visor Settings section of default game options."""
        class Opacity(int):
            """Allowed values are between 0 and 100."""
            pass
        class HudLag(Bool):
            pass

        visor_opacity: Opacity = 100
        helmet_opacity: Opacity = 100
        hud_lag: HudLag = True

        def __init__(self):
            should_save = any([attr not in self for attr in self])
            if should_save:
                self.update({attr: self[attr] for attr in self.__dict__.keys()})

    class DisplaySettings(Group):
        """Visor Settings section of default game options."""
        class Brightness(int):
            """Allowed values are :
            - 0   %
            - 12  %
            - 25  %
            - 38  %
            - 50  %
            - 62  %
            - 75  %
            - 88  %
            - 100 %"""
            pass
        class Offset(int):
            """Allowed values are between -30 and 30."""
            pass
        class Stretch(int):
            """Allowed values are between -10 and 10."""
            pass

        screen_brightness: Brightness = 50
        screen_offset_x: Offset = 0
        screen_offset_y: Offset = 0
        screen_stretch: Stretch = 0

        def __init__(self):
            should_save = any([attr not in self for attr in self])
            if should_save:
                self.update({attr: self[attr] for attr in self.__dict__.keys()})

    class SoundSettings(Group):
        """Visor Settings section of default game options."""
        class Volume(int):
            """Allowed values are between 0 and 100."""
            pass
        class SoundMode(str):
            """Allowed values are mono, stereo and dolby."""
            pass

        sfx_volume: Volume = 100
        music_volume: Volume = 100
        sound_mode: SoundMode = "stereo"

        def __init__(self):
            should_save = any([attr not in self for attr in self])
            if should_save:
                self.update({attr: self[attr] for attr in self.__dict__.keys()})

    class ControllerSettings(Group):
        """Visor Settings section of default game options."""
        class ReverseYAxis(Bool):
            """True means you look up by aiming up. False means you look up by aiming down."""
            pass
        class Rumble(Bool):
            """Enables rumble mode."""
            pass
        class SwapBeamControls(Bool):
            """When true, beams are on the left. Else they are on the right."""
            pass

        reverse_y_axis: ReverseYAxis = False
        rumble: Rumble = True
        swap_beam_controls: SwapBeamControls = False

    visor_settings: VisorSettings = VisorSettings()
    display_settings: DisplaySettings = DisplaySettings()
    sound_settings: SoundSettings = SoundSettings()
    controller_settings: ControllerSettings = ControllerSettings()

    def __init__(self):
        should_save = any([attr not in self for attr in self])
        if should_save:
            self.update({attr: self[attr] for attr in self.__dict__.keys()})

    def to_config(self) -> dict[str, Any]:
        def to_final_brightness(val: int):
            values = [0, 12, 25, 38, 50, 62, 75, 88, 100]

            val = is_between_or_throw(val, 0, 100)
            if val not in values:
                raise RuntimeError(f'Invalid value {val} for screen_brightness!')
            return values.index(val)

        def to_final_volume(val: int) -> int:
            return int(127 * ((is_between_or_throw(val, 0, 100) - 50) / 50))

        def to_final_opacity(val: int) -> int:
            return (255 * is_between_or_throw(val, 0, 100)) // 100

        sound_mode_index = 1

        match self['sound_settings'].sound_mode.lower():
            case 'mono':
                sound_mode_index = 0
            case 'stereo':
                sound_mode_index = 1
            case 'dolby':
                sound_mode_index = 2
            case v:
                raise RuntimeError(f'Unknown value {v} supplied for sound_mode!')

        return {
            'screenBrightness': to_final_brightness(self['display_settings']['screen_brightness']),
            'screenOffsetX': is_between_or_throw(self['display_settings']['screen_offset_x'], -30, 30),
            'screenOffsetY': is_between_or_throw(self['display_settings']['screen_offset_y'], -30, 30),
            'screenStretch': is_between_or_throw(self['display_settings']['screen_stretch'], -10, 10),
            'soundMode': sound_mode_index,
            'sfxVolume': to_final_volume(self['sound_settings']['sfx_volume']),
            'musicVolume': to_final_volume(self['sound_settings']['music_volume']),
            'visorOpacity': to_final_opacity(self['visor_settings']['visor_opacity']),
            'helmetOpacity': to_final_opacity(self['visor_settings']['helmet_opacity']),
            'hudLag': self['visor_settings']['hud_lag'],
            'reverseYAxis': self['controller_settings']['reverse_y_axis'],
            'rumble': self['controller_settings']['rumble'],
            'swapBeamControls': self['controller_settings']['swap_beam_controls'],
        }


class MetroidPrimeSettings(Group):
    rom_file: RomFile = RomFile(RomFile.copy_to)
    emulator_settings: EmulatorSettings = EmulatorSettings()
    hud_settings: HUDSettings = HUDSettings()
    suit_settings: SuitSettings = SuitSettings()
    default_game_settings: DefaultGameOptionsSettings = DefaultGameOptionsSettings()

    def __init__(self):
        should_save = any([attr not in self for attr in self])
        if should_save:
            self.update({attr: self[attr] for attr in self.__dict__.keys()})
