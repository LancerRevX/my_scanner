import asyncio
from collections import deque
from urllib.parse import unquote

from my_scanner.net.crawler import AsyncCrawler
from my_scanner.net.web import Request
from my_scanner.net.classes import CrawlerConfiguration
from my_scanner.net.sql_persister import SqlPersister
from my_scanner.net.scope import Scope
from my_scanner.net.explorer import Explorer
from my_scanner.report import ResultEntry

from my_scanner.attack.sql_injection import SqlInjection
from my_scanner.attack.csp import Csp


async def attack_server(url: str, attack_class):
    request = Request(url)
    crawler_configuration = CrawlerConfiguration(request)
    persister = SqlPersister('./persister.db')
    await persister.create()
    await persister.flush_attacks()
    scope = Scope(request, "folder")
    explorer = Explorer(crawler_configuration, scope, asyncio.Event())
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        attack = attack_class(crawler, persister, {'timeout': 3}, asyncio.Event(), crawler_configuration)
        resources = [(request, response) async for request, response in explorer.async_explore(deque([request]))]
        for request, response in resources:
            request.path_id = 0
        await persister.save_requests(resources)
        attacked_ids = []
        for request, response in resources:
            await attack.attack(request, response)
            attacked_ids.append(request.path_id)
        await persister.set_attacked(attacked_ids, attack_class.name)
        payloads = [payload async for payload in persister.get_payloads()]
        return payloads


def scan_server(url: str, *, sql_injection=False, csp=False) -> list[ResultEntry]:
    payloads = []
    if sql_injection:
        payloads += asyncio.run(attack_server(url, SqlInjection))
    if csp:
        payloads += asyncio.run(attack_server(url, Csp))
    results = {}
    for payload in payloads:
        print(payload)
        if payload.type == 'vulnerability' and payload.category == 'SQL Injection':
            if not results.get(payload.category):
                results[payload.category] = ResultEntry(
                    'CWE-89',
                    'Непринятие мер по защите структуры запроса SQL',
                    [
                        'Использование параметризованных SQL-запросов.',
                        'Реализация экранирования специальных символов для динамических запросов.',
                        'Использование оператора LIMIT или других элементов управления (для предотвращения утечек данных).'
                    ],
                    []
                )
            results[payload.category].vulnerabilities.append((
                'SQL инъекция',
                unquote(payload.evil_request.url)
            ))
        elif payload.category == 'Content Security Policy Configuration':
            if not results.get(payload.category):
                results[payload.category] = ResultEntry(
                    'CWE-79',
                    'Непринятие мер по защите структуры веб-страницы',
                    [
                        'Использование параметризованных SQL-запросов.',
                        'Реализация экранирования специальных символов для динамических запросов.',
                        'Использование оператора LIMIT или других элементов управления (для предотвращения утечек данных).'
                    ],
                    []
                )
            if payload.info == 'CSP is not set':
                results[payload.category].vulnerabilities.append((
                    'Заголовок CSP не установлен',
                    unquote(payload.evil_request.url)
                ))


    return list(results.values())