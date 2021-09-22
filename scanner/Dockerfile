FROM amazonlinux:2.0.20210721.2

RUN yum update -y \
    && curl -sL https://rpm.nodesource.com/setup_14.x | bash - \
    && yum -y install tar gzip unzip python3 nodejs \
    && npm i -g npm@latest \
    && curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py \
    && python3 get-pip.py \
    && rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm \
    && yum install -y dotnet-sdk-5.0 \
    && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash 

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "app.py"]