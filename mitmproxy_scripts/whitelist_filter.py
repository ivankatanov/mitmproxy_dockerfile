#!/usr/bin/env python3
"""
Whitelist filter for mitmproxy
Allows only specific domains and endpoints
Logs all requests for analysis

Whitelist фильтр для mitmproxy
Разрешает только определенные домены и эндпоинты
Логирует все запросы для анализа
"""

from mitmproxy import http
import logging
import json
import os
from datetime import datetime
from urllib.parse import urlparse

# Logging configuration
# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/n8n_requests.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Configuration settings
# Конфигурационные настройки
CONFIG_FILE = '/scripts/whitelist_config.json'
DEFAULT_CONFIG = {
    'whitelist_enabled': True,  # Whether whitelist checking is enabled
                                # Включена ли проверка whitelist
    'log_all_requests': True,   # Whether to log all requests
                                # Логировать ли все запросы
    'block_mode': True          # True = block, False = only log
                                # True = блокировать, False = только логировать
}

def load_config():
    """Loads configuration from file or creates a file with default settings
    
    Загружает конфигурацию из файла или создает файл с настройками по умолчанию
    """
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # Add missing keys from default configuration
                # Добавляем недостающие ключи из дефолтной конфигурации
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                return config
        else:
            # Create configuration file with default settings
            # Создаем файл конфигурации с настройками по умолчанию
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
            logger.info(f"Created default config file: {CONFIG_FILE}")
            return DEFAULT_CONFIG.copy()
    except Exception as e:
        logger.error(f"Error loading config: {e}. Using default settings.")
        return DEFAULT_CONFIG.copy()

# Load configuration at startup
# Загружаем конфигурацию при старте
config = load_config()

# Whitelist of allowed domains and paths
# Whitelist разрешенных доменов и путей
ALLOWED_REQUESTS = {
    # Google Sheets API
    'sheets.googleapis.com': {
        'paths': ['*'],  # All paths are allowed
                          # Все пути разрешены
        'methods': ['GET', 'POST', 'PUT', 'PATCH']
    },
    
    # Microsoft Graph API (Outlook)
    'graph.microsoft.com': {
        'paths': [
            '/v1.0/me/messages*',
            '/v1.0/me/mailFolders*',
            '/v1.0/users/*/messages*',
            '/v1.0/users/*/sendMail',  # This pattern will now work with any email addresses
                                # Этот шаблон теперь будет работать с любыми email-адресами
            '/beta/me/messages*'
        ],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    },
    
    # Microsoft Login
    'login.microsoftonline.com': {
        'paths': ['*'],
        'methods': ['GET', 'POST']
    },
    
    # Google OAuth
    'accounts.google.com': {
        'paths': ['*'],
        'methods': ['GET', 'POST']
    },
    
    'oauth2.googleapis.com': {
        'paths': ['*'],
        'methods': ['GET', 'POST']
    },
    
    # n8n (all methods/paths)
    # n8n (все методы/пути)
    'api.n8n.io': {
        'paths': ['*'],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    },
    
    # OpenAI
    'api.openai.com': {
        'paths': ['*'],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    },
    
    # Revolut API
    'b2b.revolut.com': {
        'paths': [
            '/api/1.0/auth/token',
            '/api/1.0/accounts',
            '/api/1.0/counterparties',
            '/api/1.0/counterparty',
            '/api/1.0/counterparty/',
            '/api/1.0/payment-drafts',
            '/api/1.0/payment-drafts/'
        ],
        'methods': ['GET', 'POST', 'DELETE']
    },
    
    # Wise API (sandbox)
    'api.sandbox.transferwise.tech': {
        'paths': [
            '/v1/profiles',
            '/v3/profiles/',
            '/v3/profiles/28758769/quotes',
            '/v1/accounts',
            '/v1/transfers'
        ],
        'methods': ['GET', 'POST']
    },
    
    # Google Drive API
    'www.googleapis.com': {
        'paths': [
            '/drive/v3/files*'
        ],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    },
    
    # Other popular services (can be added as needed)
    # Другие популярные сервисы (можно добавить по необходимости)
    'api.github.com': {
        'paths': ['*'],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    },
    
    # Local services (JWT signing service)
    # Локальные сервисы (JWT signing service)
    '172.17.0.1:3050': {
        'paths': ['/sign*', '/verify*', '*'],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    },
    
    # Localhost and other local addresses
    # Localhost и другие локальные адреса
    'localhost': {
        'paths': ['*'],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    },
    
    '127.0.0.1': {
        'paths': ['*'],
        'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    }
}

def is_path_allowed(domain, path, allowed_paths):
    """Checks if the path is allowed for the domain
    
    Проверяет, разрешен ли путь для домена
    """
    for allowed_path in allowed_paths:
        if allowed_path == '*':
            return True
        
        # If there is a '*' symbol in the template
        # Если в шаблоне есть символ '*'
        if '*' in allowed_path:
            # Split the template and path into parts
            # Разбиваем шаблон и путь на части
            pattern_parts = allowed_path.split('*')
            
            # If the template ends with '*', check only the beginning of the path
            # Если шаблон заканчивается на '*', проверяем только начало пути
            if allowed_path.endswith('*'):
                if path.startswith(pattern_parts[0]):
                    return True
            # If '*' is in the middle of the path, check a more complex pattern
            # Если '*' в середине пути, проверяем более сложный шаблон
            else:
                # Check if the path starts with the first part of the template
                # Проверяем, начинается ли путь с первой части шаблона
                if not path.startswith(pattern_parts[0]):
                    continue
                    
                remaining_path = path[len(pattern_parts[0]):]
                match = True
                
                # Check the remaining parts of the template
                # Проверяем остальные части шаблона
                for i in range(1, len(pattern_parts)):
                    part = pattern_parts[i]
                    if not part:  # Empty part (two '*' in a row)
                                      # Пустая часть (два '*' подряд)
                        continue
                    
                    # Look for the part in the remaining path
                    # Ищем часть в оставшемся пути
                    pos = remaining_path.find(part)
                    if pos == -1:
                        match = False
                        break
                    
                    # Move to the next part of the path
                    # Переходим к следующей части пути
                    remaining_path = remaining_path[pos + len(part):]
                
                if match:
                    return True
        # Exact path match
        # Точное совпадение пути
        elif path == allowed_path:
            return True
    return False

def is_request_allowed(url, method):
    """Checks if the request is allowed according to the whitelist
    
    Проверяет, разрешен ли запрос согласно whitelist
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path
    
    # Check for exact domain match
    # Проверяем точное совпадение домена
    if domain in ALLOWED_REQUESTS:
        config = ALLOWED_REQUESTS[domain]
        if method.upper() in config['methods']:
            return is_path_allowed(domain, path, config['paths'])
    
    # Check subdomains
    # Проверяем поддомены
    for allowed_domain in ALLOWED_REQUESTS:
        if domain.endswith('.' + allowed_domain):
            config = ALLOWED_REQUESTS[allowed_domain]
            if method.upper() in config['methods']:
                return is_path_allowed(domain, path, config['paths'])
    
    return False

def log_request(flow, status, reason=""):
    """Logs information about the request
    
    Логирует информацию о запросе
    """
    request_info = {
        'timestamp': datetime.now().isoformat(),
        'method': flow.request.method,
        'url': flow.request.pretty_url,
        'host': flow.request.pretty_host,
        'path': flow.request.path,
        'status': status,
        'reason': reason,
        'headers': dict(flow.request.headers),
        'user_agent': flow.request.headers.get('User-Agent', 'Unknown')
    }
    
    logger.info(f"{status}: {flow.request.method} {flow.request.pretty_url} - {reason}")
    
    # Save detailed information in JSON format
    # Сохраняем детальную информацию в JSON формате
    with open('/logs/detailed_requests.jsonl', 'a', encoding='utf-8') as f:
        f.write(json.dumps(request_info, ensure_ascii=False) + '\n')

def reload_config():
    """Reloads configuration from file
    
    Перезагружает конфигурацию из файла
    """
    global config
    config = load_config()
    logger.info(f"Config reloaded: {config}")

def request(flow: http.HTTPFlow) -> None:
    """Handler for incoming requests
    
    Обработчик входящих запросов
    """
    # Reload configuration on each request (for quick changes)
    # Перезагружаем конфигурацию при каждом запросе (для быстрых изменений)
    reload_config()
    
    url = flow.request.pretty_url
    method = flow.request.method
    
    # Always log if enabled
    # Всегда логируем если включено
    if config.get('log_all_requests', True):
        log_request(flow, "INTERCEPTED", "Request intercepted by proxy")
    
    # Check whitelist only if filtering is enabled
    # Проверяем whitelist только если включена фильтрация
    if config.get('whitelist_enabled', True):
        if is_request_allowed(url, method):
            if config.get('log_all_requests', True):
                log_request(flow, "ALLOWED", "Request matches whitelist")
            # Request is allowed, let it pass
            # Запрос разрешен, пропускаем дальше
            return
        else:
            log_request(flow, "BLOCKED", "Request not in whitelist")
            # Block the request only if blocking mode is enabled
            # Блокируем запрос только если включен режим блокировки
            if config.get('block_mode', True):
                flow.response = http.Response.make(
                    403,
                    b"Request blocked by whitelist filter",
                    {"Content-Type": "text/plain"}
                )
            else:
                # Only log, but let the request pass
                # Только логируем, но пропускаем запрос
                log_request(flow, "LOGGED_ONLY", "Request logged but not blocked (block_mode=false)")
    else:
        # Whitelist is disabled, let all requests pass
        # Whitelist отключен, пропускаем все запросы
        if config.get('log_all_requests', True):
            log_request(flow, "PASSED", "Whitelist disabled - all requests allowed")

def response(flow: http.HTTPFlow) -> None:
    """Response handler (for logging)
    
    Обработчик ответов (для логирования)
    """
    if flow.response:
        response_info = {
            'timestamp': datetime.now().isoformat(),
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'status_code': flow.response.status_code,
            'response_size': len(flow.response.content) if flow.response.content else 0,
            'content_type': flow.response.headers.get('Content-Type', 'Unknown')
        }
        
        logger.info(f"RESPONSE: {flow.request.method} {flow.request.pretty_url} -> {flow.response.status_code}")
        
        # Save information about responses
        # Сохраняем информацию об ответах
        with open('/logs/responses.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(response_info, ensure_ascii=False) + '\n')

# Initialization at startup
# Инициализация при запуске
logger.info("Whitelist filter initialized")
logger.info(f"Allowed domains: {list(ALLOWED_REQUESTS.keys())}")