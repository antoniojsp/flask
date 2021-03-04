FROM python:3.8

COPY . /app
WORKDIR /app

RUN python3 -m pip install --upgrade pip
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "-u"]
CMD ["server.py"]

