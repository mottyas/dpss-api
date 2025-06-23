#!make

run:	## Запуск веб-сервера без докера
	python src/main.py

build:
	docker compose --build

up:
	docker compose up --build

down:
	docker compose down

restart:
	docker compose restart
