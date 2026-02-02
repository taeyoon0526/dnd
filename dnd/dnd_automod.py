from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

import discord
from redbot.core import Config, commands
from redbot.core.utils.chat_formatting import humanize_list

try:
    from discord.http import Route
except Exception:  # pragma: no cover - depends on discord.py internals
    Route = None


log = logging.getLogger("red.dnd_automod")

TARGET_USER_ID = 1173942304927645786
RULE_NAME = "DND Block Mention (1173942304927645786)"

# We only block real direct mentions. These two forms are how Discord represents a user mention.
# We intentionally do NOT block @everyone/@here/role mentions per requirements.
KEYWORDS = [f"<@{TARGET_USER_ID}>", f"<@!{TARGET_USER_ID}>"]

CUSTOM_BLOCK_MESSAGE = (
    "현재 DND 모드로 해당 사용자의 멘션 메시지는 차단됩니다. "
    "(잠시 후 다시 시도해주세요.)"
)

COOLDOWN = commands.cooldown(1, 5, commands.BucketType.guild)


class DndAutomod(commands.Cog):
    """DND AutoMod controller for blocking direct mentions of a target user."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.config = Config.get_conf(self, identifier=3214589621)
        self.config.register_guild(
            allowed_controller_ids=[TARGET_USER_ID],
            dnd_enabled=False,
            last_changed_ts=0,
            automod_rule_id=None,
            automod_rule_name=RULE_NAME,
            logging_enabled=False,
            log_channel_id=None,
            enable_exemptions=False,
            exempt_channel_ids=[],
            exempt_role_ids=[],
            enable_startup_heal=False,
        )

    # ----------------------------
    # Permission / controller checks
    # ----------------------------
    async def _is_allowed_controller(self, guild: discord.Guild, user_id: int) -> bool:
        allowed = await self.config.guild(guild).allowed_controller_ids()
        return user_id in allowed

    async def _require_allowed(self, ctx: commands.Context) -> bool:
        if ctx.guild is None:
            await ctx.send("DM에서는 사용할 수 없습니다.")
            return False
        if not await self._is_allowed_controller(ctx.guild, ctx.author.id):
            await ctx.send("이 명령은 허용된 컨트롤러만 사용할 수 있습니다.")
            return False
        return True

    async def _require_super_controller(self, ctx: commands.Context) -> bool:
        if ctx.guild is None:
            await ctx.send("DM에서는 사용할 수 없습니다.")
            return False
        is_owner = await ctx.bot.is_owner(ctx.author)
        if not is_owner or ctx.author.id != TARGET_USER_ID:
            await ctx.send("권한이 부족합니다.")
            return False
        return True

    def _has_manage_guild(self, guild: discord.Guild) -> bool:
        me = guild.me or guild.get_member(self.bot.user.id)
        if not me:
            return False
        return me.guild_permissions.manage_guild

    # ----------------------------
    # AutoMod helpers (native + REST fallback)
    # ----------------------------
    async def _http_request(self, method: str, route: str, *, json: Optional[dict] = None) -> Any:
        if Route is None:
            raise RuntimeError("discord.http.Route is unavailable")
        return await self.bot.http.request(Route(method, route), json=json)

    async def _http_get_rule(self, guild_id: int, rule_id: int) -> Optional[dict]:
        try:
            return await self._http_request(
                "GET", f"/guilds/{guild_id}/auto-moderation/rules/{rule_id}",
                json=None,
            )
        except discord.NotFound:
            return None

    async def _http_list_rules(self, guild_id: int) -> List[dict]:
        return await self._http_request("GET", f"/guilds/{guild_id}/auto-moderation/rules", json=None)

    async def _http_create_rule(self, guild_id: int, payload: dict) -> dict:
        return await self._http_request(
            "POST", f"/guilds/{guild_id}/auto-moderation/rules",
            json=payload,
        )

    async def _http_edit_rule(self, guild_id: int, rule_id: int, payload: dict) -> dict:
        return await self._http_request(
            "PATCH", f"/guilds/{guild_id}/auto-moderation/rules/{rule_id}",
            json=payload,
        )

    async def _http_delete_rule(self, guild_id: int, rule_id: int) -> None:
        await self._http_request(
            "DELETE", f"/guilds/{guild_id}/auto-moderation/rules/{rule_id}",
            json=None,
        )

    def _rule_payload(
        self,
        *,
        enabled: bool,
        exempt_roles: Sequence[int],
        exempt_channels: Sequence[int],
    ) -> dict:
        return {
            "name": RULE_NAME,
            "event_type": 1,  # MESSAGE_SEND
            "trigger_type": 1,  # KEYWORD
            "trigger_metadata": {"keyword_filter": KEYWORDS},
            "actions": [
                {
                    "type": 1,  # BLOCK_MESSAGE
                    "metadata": {"custom_message": CUSTOM_BLOCK_MESSAGE},
                }
            ],
            "enabled": enabled,
            "exempt_roles": [str(rid) for rid in exempt_roles],
            "exempt_channels": [str(cid) for cid in exempt_channels],
        }

    def _native_trigger_metadata(self) -> Optional[discord.AutoModTrigger]:
        try:
            return discord.AutoModTrigger(keyword_filter=KEYWORDS)
        except Exception:
            return None

    def _native_actions(self) -> Optional[List[discord.AutoModAction]]:
        try:
            return [
                discord.AutoModAction(
                    discord.AutoModActionType.block_message,
                    custom_message=CUSTOM_BLOCK_MESSAGE,
                )
            ]
        except Exception:
            return None

    def _rule_mismatch(self, rule_data: dict) -> bool:
        if rule_data.get("name") != RULE_NAME:
            return True
        if rule_data.get("event_type") != 1 or rule_data.get("trigger_type") != 1:
            return True
        trigger_meta = rule_data.get("trigger_metadata") or {}
        if sorted(trigger_meta.get("keyword_filter", [])) != sorted(KEYWORDS):
            return True
        actions = rule_data.get("actions") or []
        if len(actions) != 1:
            return True
        action = actions[0]
        if action.get("type") != 1:
            return True
        action_meta = action.get("metadata") or {}
        if action_meta.get("custom_message") != CUSTOM_BLOCK_MESSAGE:
            return True
        return False

    def _native_rule_to_dict(self, rule: discord.AutoModRule) -> dict:
        trigger_meta = {}
        if rule.trigger_metadata and getattr(rule.trigger_metadata, "keyword_filter", None) is not None:
            trigger_meta["keyword_filter"] = list(rule.trigger_metadata.keyword_filter)
        actions = []
        for action in rule.actions:
            action_meta = {}
            if action.metadata and getattr(action.metadata, "custom_message", None):
                action_meta["custom_message"] = action.metadata.custom_message
            actions.append({"type": action.type.value, "metadata": action_meta})
        return {
            "id": rule.id,
            "name": rule.name,
            "event_type": rule.event_type.value,
            "trigger_type": rule.trigger_type.value,
            "trigger_metadata": trigger_meta,
            "actions": actions,
            "enabled": rule.enabled,
        }

    async def _find_rule_by_name(self, guild: discord.Guild) -> Optional[dict]:
        try:
            if hasattr(guild, "fetch_automod_rules"):
                rules = await guild.fetch_automod_rules()
                for rule in rules:
                    if rule.name == RULE_NAME:
                        return self._native_rule_to_dict(rule)
        except Exception:
            pass
        try:
            rules = await self._http_list_rules(guild.id)
            for rule in rules:
                if rule.get("name") == RULE_NAME:
                    return rule
        except Exception:
            return None
        return None

    async def _fetch_rule_by_id(self, guild: discord.Guild, rule_id: int) -> Optional[dict]:
        try:
            if hasattr(guild, "fetch_automod_rule"):
                rule = await guild.fetch_automod_rule(rule_id)
                return self._native_rule_to_dict(rule)
        except discord.NotFound:
            return None
        except Exception:
            pass
        try:
            return await self._http_get_rule(guild.id, rule_id)
        except Exception:
            return None

    async def _create_rule(self, guild: discord.Guild, enabled: bool) -> dict:
        exempt_roles, exempt_channels = await self._get_exemptions(guild)
        trigger = self._native_trigger_metadata()
        actions = self._native_actions()
        if trigger and actions and hasattr(guild, "create_automod_rule"):
            try:
                rule = await guild.create_automod_rule(
                    name=RULE_NAME,
                    event_type=discord.AutoModEventType.message_send,
                    trigger_type=discord.AutoModTriggerType.keyword,
                    trigger_metadata=trigger,
                    actions=actions,
                    enabled=enabled,
                    exempt_roles=exempt_roles,
                    exempt_channels=exempt_channels,
                )
                return self._native_rule_to_dict(rule)
            except Exception:
                pass
        payload = self._rule_payload(
            enabled=enabled,
            exempt_roles=exempt_roles,
            exempt_channels=exempt_channels,
        )
        return await self._http_create_rule(guild.id, payload)

    async def _edit_rule(self, guild: discord.Guild, rule_id: int, enabled: bool) -> dict:
        exempt_roles, exempt_channels = await self._get_exemptions(guild)
        trigger = self._native_trigger_metadata()
        actions = self._native_actions()
        if trigger and actions and hasattr(guild, "fetch_automod_rule"):
            try:
                rule = await guild.fetch_automod_rule(rule_id)
                rule = await rule.edit(
                    name=RULE_NAME,
                    event_type=discord.AutoModEventType.message_send,
                    trigger_type=discord.AutoModTriggerType.keyword,
                    trigger_metadata=trigger,
                    actions=actions,
                    enabled=enabled,
                    exempt_roles=exempt_roles,
                    exempt_channels=exempt_channels,
                )
                return self._native_rule_to_dict(rule)
            except Exception:
                pass
        payload = self._rule_payload(
            enabled=enabled,
            exempt_roles=exempt_roles,
            exempt_channels=exempt_channels,
        )
        return await self._http_edit_rule(guild.id, rule_id, payload)

    async def _get_exemptions(self, guild: discord.Guild) -> tuple[List[int], List[int]]:
        cfg = self.config.guild(guild)
        if not await cfg.enable_exemptions():
            return ([], [])
        return (await cfg.exempt_role_ids(), await cfg.exempt_channel_ids())

    # ----------------------------
    # Logging helpers
    # ----------------------------
    async def _log_event(
        self,
        guild: discord.Guild,
        actor: discord.abc.User,
        action: str,
        rule_id: Optional[int],
        result: str,
        error: Optional[str] = None,
    ) -> None:
        cfg = self.config.guild(guild)
        if not await cfg.logging_enabled():
            return
        channel_id = await cfg.log_channel_id()
        if not channel_id:
            return
        channel = guild.get_channel(channel_id)
        if not channel:
            return
        embed = discord.Embed(title="DND-AutoMod", color=discord.Color.orange())
        embed.add_field(name="Guild", value=f"{guild.name} ({guild.id})", inline=False)
        embed.add_field(name="Actor", value=f"{actor} ({actor.id})", inline=False)
        embed.add_field(name="Action", value=action, inline=True)
        embed.add_field(name="RuleID", value=str(rule_id) if rule_id else "None", inline=True)
        embed.add_field(name="Result", value=result, inline=False)
        if error:
            embed.add_field(name="Error", value=error, inline=False)
        await channel.send(embed=embed)

    # ----------------------------
    # Core operations
    # ----------------------------
    async def _ensure_rule(self, guild: discord.Guild) -> dict:
        cfg = self.config.guild(guild)
        rule_id = await cfg.automod_rule_id()
        if rule_id:
            rule = await self._fetch_rule_by_id(guild, rule_id)
            if rule:
                return rule
        rule = await self._find_rule_by_name(guild)
        if rule:
            await cfg.automod_rule_id.set(int(rule["id"]))
            return rule
        rule = await self._create_rule(guild, enabled=False)
        await cfg.automod_rule_id.set(int(rule["id"]))
        return rule

    async def _set_dnd(self, ctx: commands.Context, enabled: bool) -> bool:
        guild = ctx.guild
        if guild is None:
            await ctx.send("DM에서는 사용할 수 없습니다.")
            return False
        if not self._has_manage_guild(guild):
            await ctx.send("권한 부족: 서버 관리(Manage Guild) 권한이 필요합니다.")
            await self._log_event(guild, ctx.author, "PERMISSION_CHECK", None, "FAILED")
            return False

        cfg = self.config.guild(guild)
        try:
            rule = await self._ensure_rule(guild)
            rule_id = int(rule["id"])

            # Heal rule if it diverged from the spec.
            if self._rule_mismatch(rule):
                rule = await self._edit_rule(guild, rule_id, enabled)
            else:
                rule = await self._edit_rule(guild, rule_id, enabled)

            await cfg.dnd_enabled.set(enabled)
            await cfg.last_changed_ts.set(int(datetime.now(tz=timezone.utc).timestamp()))
            await self._log_event(
                guild,
                ctx.author,
                "DND_ON" if enabled else "DND_OFF",
                rule_id,
                "SUCCESS",
            )
            return True
        except (discord.Forbidden, discord.NotFound) as exc:
            await ctx.send("AutoMod 룰 접근에 실패했습니다. 권한 또는 룰 상태를 확인해주세요.")
            await self._log_event(guild, ctx.author, "AUTOMOD", None, "FAILED", error=str(exc))
            return False
        except discord.HTTPException as exc:
            await ctx.send("AutoMod 룰 생성/수정에 실패했습니다.")
            await self._log_event(guild, ctx.author, "AUTOMOD", None, "FAILED", error=str(exc))
            return False
        except Exception as exc:
            await ctx.send("예상치 못한 오류가 발생했습니다.")
            await self._log_event(guild, ctx.author, "AUTOMOD", None, "FAILED", error=str(exc))
            log.exception("Unexpected error while toggling DND", exc_info=exc)
            return False

    # ----------------------------
    # Commands
    # ----------------------------
    @commands.group(name="dnd")
    @commands.guild_only()
    @COOLDOWN
    async def dnd_group(self, ctx: commands.Context) -> None:
        """DND AutoMod controller."""
        if ctx.invoked_subcommand is None:
            if not await self._require_allowed(ctx):
                return
            enabled = await self.config.guild(ctx.guild).dnd_enabled()
            ok = await self._set_dnd(ctx, not enabled)
            if ok:
                if not enabled:
                    await ctx.send(
                        "DND 활성화됨: 이제 해당 사용자 직접 멘션하는 메시지는 차단됩니다."
                    )
                else:
                    await ctx.send("DND 해제됨: 멘션 차단 룰이 비활성화되었습니다.")

    @dnd_group.command(name="on")
    @commands.guild_only()
    @COOLDOWN
    async def dnd_on(self, ctx: commands.Context) -> None:
        if not await self._require_allowed(ctx):
            return
        ok = await self._set_dnd(ctx, True)
        if ok:
            await ctx.send(
                "DND 활성화됨: 이제 해당 사용자 직접 멘션하는 메시지는 차단됩니다."
            )

    @dnd_group.command(name="off")
    @commands.guild_only()
    @COOLDOWN
    async def dnd_off(self, ctx: commands.Context) -> None:
        if not await self._require_allowed(ctx):
            return
        cfg = self.config.guild(ctx.guild)
        rule_id = await cfg.automod_rule_id()
        if rule_id:
            try:
                await self._edit_rule(ctx.guild, int(rule_id), False)
            except (discord.Forbidden, discord.NotFound) as exc:
                await ctx.send("AutoMod 룰 비활성화에 실패했습니다.")
                await self._log_event(ctx.guild, ctx.author, "DND_OFF", rule_id, "FAILED", error=str(exc))
                return
            except discord.HTTPException as exc:
                await ctx.send("AutoMod 룰 비활성화에 실패했습니다.")
                await self._log_event(ctx.guild, ctx.author, "DND_OFF", rule_id, "FAILED", error=str(exc))
                return
        else:
            await ctx.send("비활성화할 룰이 없어 상태만 OFF로 둡니다.")
        await cfg.dnd_enabled.set(False)
        await cfg.last_changed_ts.set(int(datetime.now(tz=timezone.utc).timestamp()))
        await self._log_event(ctx.guild, ctx.author, "DND_OFF", rule_id, "SUCCESS")
        await ctx.send("DND 해제됨: 멘션 차단 룰이 비활성화되었습니다.")

    @dnd_group.command(name="status")
    @commands.guild_only()
    async def dnd_status(self, ctx: commands.Context) -> None:
        if not await self._require_allowed(ctx):
            return
        cfg = self.config.guild(ctx.guild)
        enabled = await cfg.dnd_enabled()
        rule_id = await cfg.automod_rule_id()
        last_ts = await cfg.last_changed_ts()
        last_str = "N/A"
        if last_ts:
            dt = datetime.fromtimestamp(last_ts, tz=timezone.utc)
            last_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        rule_status = "Unknown"
        if rule_id:
            rule = await self._fetch_rule_by_id(ctx.guild, int(rule_id))
            if rule:
                rule_status = "Enabled" if rule.get("enabled") else "Disabled"
            else:
                rule_status = "Missing"
        await ctx.send(
            f"DND: {'ON' if enabled else 'OFF'} | RuleID: {rule_id or 'None'} "
            f"| RuleStatus: {rule_status} | LastChanged: {last_str}"
        )

    # ----------------------------
    # Allowlist management (super controller only)
    # ----------------------------
    @dnd_group.group(name="allow")
    @commands.guild_only()
    async def dnd_allow(self, ctx: commands.Context) -> None:
        """Manage allowed controllers."""
        if ctx.invoked_subcommand is None:
            await ctx.send("사용법: [p]dnd allow add/remove/list/reset")

    @dnd_allow.command(name="add")
    @commands.guild_only()
    async def dnd_allow_add(self, ctx: commands.Context, user: discord.User) -> None:
        if not await self._require_super_controller(ctx):
            return
        cfg = self.config.guild(ctx.guild)
        allowed = await cfg.allowed_controller_ids()
        if user.id in allowed:
            await ctx.send("이미 허용된 사용자입니다.")
            return
        if len(allowed) >= 20:
            await ctx.send("허용 목록은 최대 20명까지 가능합니다.")
            return
        allowed.append(user.id)
        await cfg.allowed_controller_ids.set(allowed)
        await ctx.send(f"허용 목록에 추가됨: {user} ({user.id})")

    @dnd_allow.command(name="remove")
    @commands.guild_only()
    async def dnd_allow_remove(self, ctx: commands.Context, user: discord.User) -> None:
        if not await self._require_super_controller(ctx):
            return
        cfg = self.config.guild(ctx.guild)
        allowed = await cfg.allowed_controller_ids()
        if user.id not in allowed:
            await ctx.send("허용 목록에 없는 사용자입니다.")
            return
        allowed = [uid for uid in allowed if uid != user.id]
        warn = ""
        if user.id == TARGET_USER_ID:
            warn = " (주의: 기본 컨트롤러를 제거했습니다.)"
        if not allowed:
            allowed = [TARGET_USER_ID]
            warn += " (안전장치: 목록이 비어 기본 컨트롤러로 복구됨)"
        await cfg.allowed_controller_ids.set(allowed)
        await ctx.send(f"허용 목록에서 제거됨: {user} ({user.id}){warn}")

    @dnd_allow.command(name="list")
    @commands.guild_only()
    async def dnd_allow_list(self, ctx: commands.Context) -> None:
        if not await self._require_super_controller(ctx):
            return
        allowed = await self.config.guild(ctx.guild).allowed_controller_ids()
        mentions = []
        for uid in allowed:
            member = ctx.guild.get_member(uid)
            if member:
                mentions.append(member.mention)
            else:
                mentions.append(str(uid))
        await ctx.send(f"허용 컨트롤러 목록: {humanize_list(mentions)}")

    @dnd_allow.command(name="reset")
    @commands.guild_only()
    async def dnd_allow_reset(self, ctx: commands.Context) -> None:
        if not await self._require_super_controller(ctx):
            return
        await self.config.guild(ctx.guild).allowed_controller_ids.set([TARGET_USER_ID])
        await ctx.send("허용 컨트롤러 목록이 기본값으로 초기화되었습니다.")

    # ----------------------------
    # Exemptions (optional, default OFF)
    # ----------------------------
    @dnd_group.group(name="setexempt")
    @commands.guild_only()
    async def dnd_setexempt(self, ctx: commands.Context) -> None:
        if ctx.invoked_subcommand is None:
            await ctx.send("사용법: [p]dnd setexempt enable/disable/channel/role")

    @dnd_setexempt.command(name="enable")
    @commands.guild_only()
    async def dnd_exempt_enable(self, ctx: commands.Context) -> None:
        if not await self._require_super_controller(ctx):
            return
        await self.config.guild(ctx.guild).enable_exemptions.set(True)
        await ctx.send("예외 기능이 활성화되었습니다.")

    @dnd_setexempt.command(name="disable")
    @commands.guild_only()
    async def dnd_exempt_disable(self, ctx: commands.Context) -> None:
        if not await self._require_super_controller(ctx):
            return
        await self.config.guild(ctx.guild).enable_exemptions.set(False)
        await ctx.send("예외 기능이 비활성화되었습니다.")

    @dnd_setexempt.group(name="channel")
    @commands.guild_only()
    async def dnd_exempt_channel(self, ctx: commands.Context) -> None:
        if ctx.invoked_subcommand is None:
            await ctx.send("사용법: [p]dnd setexempt channel add/remove/list")

    @dnd_exempt_channel.command(name="add")
    @commands.guild_only()
    async def dnd_exempt_channel_add(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        if not await self._require_super_controller(ctx):
            return
        if not await self.config.guild(ctx.guild).enable_exemptions():
            await ctx.send("예외 기능이 비활성화되어 있습니다.")
            return
        cfg = self.config.guild(ctx.guild)
        ids = await cfg.exempt_channel_ids()
        if channel.id in ids:
            await ctx.send("이미 예외 채널입니다.")
            return
        ids.append(channel.id)
        await cfg.exempt_channel_ids.set(ids)
        await ctx.send(f"예외 채널 추가됨: {channel.mention}")

    @dnd_exempt_channel.command(name="remove")
    @commands.guild_only()
    async def dnd_exempt_channel_remove(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        if not await self._require_super_controller(ctx):
            return
        if not await self.config.guild(ctx.guild).enable_exemptions():
            await ctx.send("예외 기능이 비활성화되어 있습니다.")
            return
        cfg = self.config.guild(ctx.guild)
        ids = await cfg.exempt_channel_ids()
        if channel.id not in ids:
            await ctx.send("예외 채널이 아닙니다.")
            return
        ids = [cid for cid in ids if cid != channel.id]
        await cfg.exempt_channel_ids.set(ids)
        await ctx.send(f"예외 채널 제거됨: {channel.mention}")

    @dnd_exempt_channel.command(name="list")
    @commands.guild_only()
    async def dnd_exempt_channel_list(self, ctx: commands.Context) -> None:
        if not await self._require_super_controller(ctx):
            return
        if not await self.config.guild(ctx.guild).enable_exemptions():
            await ctx.send("예외 기능이 비활성화되어 있습니다.")
            return
        ids = await self.config.guild(ctx.guild).exempt_channel_ids()
        channels = []
        for cid in ids:
            channel = ctx.guild.get_channel(cid)
            channels.append(channel.mention if channel else str(cid))
        await ctx.send(f"예외 채널 목록: {humanize_list(channels) if channels else '없음'}")

    @dnd_setexempt.group(name="role")
    @commands.guild_only()
    async def dnd_exempt_role(self, ctx: commands.Context) -> None:
        if ctx.invoked_subcommand is None:
            await ctx.send("사용법: [p]dnd setexempt role add/remove/list")

    @dnd_exempt_role.command(name="add")
    @commands.guild_only()
    async def dnd_exempt_role_add(self, ctx: commands.Context, role: discord.Role) -> None:
        if not await self._require_super_controller(ctx):
            return
        if not await self.config.guild(ctx.guild).enable_exemptions():
            await ctx.send("예외 기능이 비활성화되어 있습니다.")
            return
        cfg = self.config.guild(ctx.guild)
        ids = await cfg.exempt_role_ids()
        if role.id in ids:
            await ctx.send("이미 예외 역할입니다.")
            return
        ids.append(role.id)
        await cfg.exempt_role_ids.set(ids)
        await ctx.send(f"예외 역할 추가됨: {role.mention}")

    @dnd_exempt_role.command(name="remove")
    @commands.guild_only()
    async def dnd_exempt_role_remove(self, ctx: commands.Context, role: discord.Role) -> None:
        if not await self._require_super_controller(ctx):
            return
        if not await self.config.guild(ctx.guild).enable_exemptions():
            await ctx.send("예외 기능이 비활성화되어 있습니다.")
            return
        cfg = self.config.guild(ctx.guild)
        ids = await cfg.exempt_role_ids()
        if role.id not in ids:
            await ctx.send("예외 역할이 아닙니다.")
            return
        ids = [rid for rid in ids if rid != role.id]
        await cfg.exempt_role_ids.set(ids)
        await ctx.send(f"예외 역할 제거됨: {role.mention}")

    @dnd_exempt_role.command(name="list")
    @commands.guild_only()
    async def dnd_exempt_role_list(self, ctx: commands.Context) -> None:
        if not await self._require_super_controller(ctx):
            return
        if not await self.config.guild(ctx.guild).enable_exemptions():
            await ctx.send("예외 기능이 비활성화되어 있습니다.")
            return
        ids = await self.config.guild(ctx.guild).exempt_role_ids()
        roles = []
        for rid in ids:
            role = ctx.guild.get_role(rid)
            roles.append(role.mention if role else str(rid))
        await ctx.send(f"예외 역할 목록: {humanize_list(roles) if roles else '없음'}")
