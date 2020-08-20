#!/bin/sh

if [ "x$FLASK_ENV" = "xdevelopment" ]
then
  flask run --reload
else
  gunicorn -w 4 -b 0.0.0.0:5000 ${WSGI_APP:-app:app}
fi
