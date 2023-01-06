from asyncio import Event
from collections import deque

from my_scanner.net.explorer import Explorer
from my_scanner.net.crawler import AsyncCrawler
from my_scanner.net.classes import CrawlerConfiguration
from my_scanner.net import Request
from my_scanner.net.scope import Scope


async def browse_url(url: str):
    request = Request(url)
    crawler_configuration = CrawlerConfiguration(request)
    scope = Scope(request, "folder")
    explorer = Explorer(crawler_configuration, scope, Event())
    results = []
    async for resource, response in explorer.async_explore(deque([request])):
        yield resource, response
