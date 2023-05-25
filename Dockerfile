FROM python:3.9-slim-buster

WORKDIR /app

COPY ./app /app

RUN pip install --trusted-host pypi.python.org -r "requirements.txt"

EXPOSE 80

ENV FLASK_APP=app.py

CMD ["flask", "run", "--host=0.0.0.0", "--port=80"]