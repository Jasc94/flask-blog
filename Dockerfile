FROM python:3.9-slim

RUN apt-get update && apt-get install -y nodejs npm

WORKDIR /app

RUN npm install bootstrap@5.3.3
RUN mv node_modules /opt/node_modules

COPY . /app

ENV NODE_PATH=/opt/node_modules
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y git

ENV FLASK_APP=app/blog.py

EXPOSE 5001

CMD ["python", "app/blog.py"]