"""
Главный модуль сервиса
"""

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from configs import settings
from routers.v1.scanner_routers import scanner_router


# Инициализация веб-сервиса.
app = FastAPI(
    title=settings.app_title,
    version=settings.api_version,
    # openapi_tags=tags,
)


# Подключение маршрутов.
app.include_router(scanner_router)


@app.exception_handler(HTTPException)
def http_exception_handler(
    request: Request,
    exc: HTTPException,
):
    return JSONResponse(
        status_code=exc.status_code,
        content=(
            {"msg": exc.detail}
            if exc.detail
            else {
                "msg": "Произошла ошибка на стороне сервера. Пожалуйста, попробуйте еще раз позже."
            }
        ),
    )


if __name__ == '__main__':
    uvicorn.run(
        app='main:app',
        host='0.0.0.0',
        port=5000,
        reload=True,
        log_level='info',
        workers=1,
    )
