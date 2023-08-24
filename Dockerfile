FROM python:3

WORKDIR /usr/src/app

# install angr pandas and numpy
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# important for package installing
RUN apt-get update

# install radare
RUN git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh

# install ghidra
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.3_build/ghidra_10.2.3_PUBLIC_20230208.zip && unzip ghidra_10.2.3_PUBLIC_20230208.zip && rm ghidra_10.2.3_PUBLIC_20230208.zip && mv ghidra_10.2.3_PUBLIC ghidra
RUN apt-get install -y ca-certificates-java openjdk-17-jdk

# install retdec
RUN wget https://github.com/avast/retdec/releases/download/v4.0/retdec-v4.0-debian-64b.tar.xz && tar -xvf retdec-v4.0-debian-64b.tar.xz && rm retdec-v4.0-debian-64b.tar.xz
ENV PATH=${PATH}:/usr/src/app/retdec/bin/

# install damicore
RUN apt-get install -y python3-igraph python3-cairo
RUN wget https://gitlab.uspdigital.usp.br/acbd/damicore-python3/-/archive/7a4a51525db0d698c588eecf24cd84d10473d46f/damicore-python3-7a4a51525db0d698c588eecf24cd84d10473d46f.zip && unzip damicore-python3-7a4a51525db0d698c588eecf24cd84d10473d46f.zip && rm damicore-python3-7a4a51525db0d698c588eecf24cd84d10473d46f.zip && mv damicore-python3-7a4a51525db0d698c588eecf24cd84d10473d46f damicore
RUN pip3 install igraph
ENV PYTHONPATH=${PYTHONPATH}:/usr/src/app/damicore/damicore/

# install binclustre
COPY binclustre.py ./
COPY modules ./modules/

RUN python -m py_compile binclustre.py ./modules/*.py

ENTRYPOINT [ "python", "./binclustre.py" ]
CMD ["--help"]
