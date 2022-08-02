# pull the official base image
FROM python:3


# set work directory
WORKDIR /usr/src/app

#RUN apk add -u gcc musl-dev

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip install --upgrade pip 
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# copy project
COPY . /usr/src/app

EXPOSE 9000


#CMD ["python", "manage.py", "runserver" , "0.0.0.0:8000"]