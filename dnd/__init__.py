from .dnd_automod import DndAutomod

async def setup(bot):
    await bot.add_cog(DndAutomod(bot))
