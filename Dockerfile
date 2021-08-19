FROM python:3.9

EXPOSE 8126

RUN mkdir -p /src
WORKDIR /src
RUN pip install riot
CMD ["/bin/bash"]
