FROM python:3.10-alpine3.17
COPY . /Coffee-Shop
WORKDIR /Coffee-Shop/src
RUN pip install -r ../requirements.txt
RUN pip uninstall Werkzeug -y
RUN pip install Werkzeug==2.3.7
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
