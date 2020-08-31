#!/bin/sh

if [ "x$FLASK_ENV" = "xdevelopment" ]
then
  FLASK_APP=turnpike.app flask run --reload
else
  gunicorn -w 4 -b 0.0.0.0:5000 ${WSGI_APP:-turnpike.app:app}
fi
