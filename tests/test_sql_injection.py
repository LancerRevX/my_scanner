import unittest
from collections import deque
import asyncio
from asyncio import Event

from my_scanner import browse_url
from my_scanner.attack.sql_injection import SqlInjection
from my_scanner.net.crawler import AsyncCrawler
from my_scanner.net.web import Request
from my_scanner.net.classes import CrawlerConfiguration
from my_scanner.net.sql_persister import SqlPersister
from my_scanner.net.scope import Scope
from my_scanner.net.explorer import Explorer


async def print_report(persister: SqlPersister):
    async for payload in persister.get_payloads():
        print(payload.type, payload)


class TestSqlInjection(unittest.IsolatedAsyncioTestCase):
    async def test_sql_injection(self):
        request = Request('http://localhost:8000/')
        crawler_configuration = CrawlerConfiguration(request)
        persister = SqlPersister('./persister.db')
        await persister.create()
        scope = Scope(request, "folder")
        explorer = Explorer(crawler_configuration, scope, Event())
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            attack = SqlInjection(crawler, persister, {'timeout': 3}, Event(), crawler_configuration)
            resources = [(request, response) async for request, response in explorer.async_explore(deque([request]))]
            for request, response in resources:
                request.path_id = 0
            persister.save_requests(resources)
            attacked_ids = []
            for request, response in resources:
                await attack.attack(request, response)
                attacked_ids.append(request.path_id)
            await persister.set_attacked(attacked_ids, SqlInjection.name)
            # await persister.close()
            payloads = [payload async for payload in persister.get_payloads()]
            for payload in payloads:
                print(payload)
