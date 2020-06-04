FROM python:3.6

WORKDIR /usr/src/app

ENV FLASK_RUN_HOST 0.0.0.0
RUN pip install --upgrade pip
RUN apt-get update && apt-get install -y libxmlsec1 libxmlsec1-dev
COPY ./requirements.txt /usr/src/app/requirements.txt
RUN pip install -r requirements.txt

COPY . /usr/src/app/
CMD ["flask", "run"]
