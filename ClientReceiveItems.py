
from typing import TYPE_CHECKING

from CommonClient import logger
from NetUtils import NetworkItem

from .Items import custom_suit_upgrade_table
from .MetroidPrimeInterface import InventoryItemData

if TYPE_CHECKING:
    from .MetroidPrimeClient import MetroidPrimeContext


async def handle_receive_items(ctx: 'MetroidPrimeContext', current_items: dict[str, InventoryItemData]):
    for network_item in ctx.items_received:
        item_data = inventory_item_by_network_id(
            network_item.item, current_items)
        if item_data is None:
            continue
        if item_data.name == "Missile Launcher":
            continue
        elif item_data.name == "Power Bomb (Main)":
            continue

        # Handle Single Item Upgrades
        if item_data.max_capacity == 1 and item_data.current_amount == 0:
            ctx.game_interface.give_item_to_player(item_data.id, 1, 1)
            if network_item.player != ctx.slot:
                receipt_message = "online" if not item_data.name.startswith("Artifact") else "received"
                ctx.notification_manager.queue_notification(f"{item_data.name} {receipt_message} ({ctx.player_names[network_item.player]})")
        elif item_data.max_capacity > 1:
            continue

    await handle_receive_missiles(ctx, current_items)
    await handle_receive_power_bombs(ctx, current_items)
    await handle_receive_energy_tanks(ctx, current_items)

    # Handle Artifacts
    ctx.game_interface.sync_artifact_layers()


async def handle_receive_missiles(ctx: 'MetroidPrimeContext', current_items: dict[str, InventoryItemData]):
    # Slot data is required for missiles + Power Bombs so we can check if launcher / main pb are enabled
    if ctx.slot_data is not None:
        # Handle Missile Expansions
        amount_per_expansion = 5
        missile_item = current_items["Missile Expansion"]
        current_capacity = missile_item.current_capacity
        current_amount = missile_item.current_amount
        new_capacity = 0

        missile_sender = None
        has_missile_launcher = False

        for network_item in ctx.items_received:
            item_data = inventory_item_by_network_id(
                network_item.item, current_items)
            if item_data is None:
                continue

            if item_data.name == "Missile Launcher":
                has_missile_launcher = True
                new_capacity += amount_per_expansion

                # If they just got the missile launcher, and they have no missiles, then notify
                if current_capacity == 0:
                    if network_item.player != ctx.slot:
                        ctx.notification_manager.queue_notification(f"{item_data.name} online ({ctx.player_names[network_item.player]})")

            elif item_data.name == "Missile Expansion":
                missile_sender = network_item.player
                new_capacity += amount_per_expansion

        # If playing with missile launcher and they haven't collected yet, then don't give any missiles
        if ctx.slot_data["missile_launcher"] and not has_missile_launcher:
            return

        diff = new_capacity - current_capacity
        new_amount = min(current_amount + diff, new_capacity)

        ctx.game_interface.give_item_to_player(
            missile_item.id, new_amount, new_capacity)
        if missile_sender != ctx.slot and diff > 0 and missile_sender != None:
            message = f"Missile capacity increased by {diff}" if diff > 5 else f"Missile capacity increased by {diff} ({ctx.player_names[missile_sender]})"
            ctx.notification_manager.queue_notification(message)


async def handle_receive_power_bombs(ctx: 'MetroidPrimeContext', current_items: dict[str, InventoryItemData]):
    # Handle Power Bomb Expansions
    if ctx.slot_data is not None:
        # Handle Missile Expansions
        amount_per_expansion = 1
        pb_item = current_items["Power Bomb Expansion"]
        current_capacity = pb_item.current_capacity
        current_amount = pb_item.current_amount
        new_capacity = 0
        main_pb_capacity = 4

        pb_sender = None
        has_main_pb = False

        for network_item in ctx.items_received:
            item_data = inventory_item_by_network_id(
                network_item.item, current_items)
            if item_data is None:
                continue

            if item_data.name == "Power Bomb (Main)":
                has_main_pb = True
                new_capacity += main_pb_capacity

                # If they just got the main pb, and they have no power bombs, then notify
                if current_capacity == 0:
                    if network_item.player != ctx.slot:
                        ctx.notification_manager.queue_notification(f"{item_data.name} online ({ctx.player_names[network_item.player]})")

            elif item_data.name == "Power Bomb Expansion":
                pb_sender = network_item.player
                new_capacity += amount_per_expansion

        # If playing with main_power_bomb and they haven't collected yet, then don't give any missiles
        if ctx.slot_data["main_power_bomb"] and not has_main_pb:
            return

        diff = new_capacity - current_capacity
        new_amount = min(current_amount + diff, new_capacity)

        ctx.game_interface.give_item_to_player(
            pb_item.id, new_amount, new_capacity)
        if pb_sender != ctx.slot and diff > 0 and pb_sender != None:
            message = f"Power Bomb capacity increased by {diff}" if diff > 5 else f"Power Bomb capacity increased by {diff} ({ctx.player_names[pb_sender]})"
            ctx.notification_manager.queue_notification(message)


async def handle_receive_energy_tanks(ctx: 'MetroidPrimeContext', current_items: dict[str, InventoryItemData]):
    # Handle Energy Tanks
    energy_tank_item = current_items["Energy Tank"]
    num_energy_tanks_received = 0
    energy_tank_sender = None
    for network_item in ctx.items_received:
        item_data = inventory_item_by_network_id(
            network_item.item, current_items)
        if item_data is None:
            continue

        if item_data.name == "Energy Tank":
            num_energy_tanks_received += 1
            energy_tank_sender = network_item.player

    diff = num_energy_tanks_received - energy_tank_item.current_capacity
    if diff > 0 and energy_tank_item.current_capacity < energy_tank_item.max_capacity:
        new_capacity = min(num_energy_tanks_received,
                           energy_tank_item.max_capacity)
        ctx.game_interface.give_item_to_player(
            energy_tank_item.id, new_capacity, new_capacity)

        if energy_tank_sender != ctx.slot and diff > 0:
            message = f"Energy Tank capacity increased by {diff}" if diff > 5 else f"Energy Tank capacity increased by {diff} ({ctx.player_names[energy_tank_sender]})"
            ctx.notification_manager.queue_notification(message)

        # Heal player when they receive a new energy tank
        # Player starts with 99 health and each energy tank adds 100 additional
        ctx.game_interface.set_current_health(new_capacity * 100.0 + 99)


def inventory_item_by_network_id(network_id: int, current_inventory: dict[str, InventoryItemData]) -> InventoryItemData:

    for item in current_inventory.values():
        if item.code == network_id:
            return item

    # Handle custom items like missile launcher and main power bomb
    for key, value in custom_suit_upgrade_table.items():
        if value.code == network_id:
            return InventoryItemData(value, 0, 0)
    return None
