import unittest
from asyncio import Event
from collections import deque

from ..net.explorer import Explorer
from ..net.crawler import AsyncCrawler
from ..net.classes import CrawlerConfiguration
from ..net import Request
from ..net.scope import Scope


class TestExplorer(unittest.IsolatedAsyncioTestCase):
    async def test_explorer_extract_links(self):
        request = Request('http://localhost:8000/')
        crawler_configuration = CrawlerConfiguration(request)
        scope = Scope(request, "folder")
        explorer = Explorer(crawler_configuration, scope, Event())

        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            response = await crawler.async_send(request)
            results = list(explorer.extract_links(response, request))
            print(results)

    async def test_explorer_explore(self):
        request = Request('http://localhost:8000/')
        crawler_configuration = CrawlerConfiguration(request)
        scope = Scope(request, "folder")
        explorer = Explorer(crawler_configuration, scope, Event())
        async for resource, response in explorer.async_explore(deque([request])):
            print(resource)