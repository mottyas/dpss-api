#!make

run:	## Запуск веб-сервера
	uvicorn app.main:app --reload

