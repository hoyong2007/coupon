FROM ubuntu:18.04
MAINTAINER eyeball<hoyong2007@naver.com>

ENV user coupon
ENV problem coupon

RUN useradd -ms /bin/bash coupon
RUN apt-get update
RUN apt-get install socat libssl-dev openssl -y
RUN whoami

ADD coupon /home/coupon/coupon
ADD GiftBag /home/coupon/GiftBag

WORKDIR /home/coupon
RUN chgrp coupon /home/coupon/coupon
RUN chgrp coupon /home/coupon/GiftBag -R
RUN chmod 750 /home/coupon/coupon
RUN chmod 550 /home/coupon/GiftBag/
RUN chmod 640 /home/coupon/GiftBag/*

RUN echo '4' | ./coupon
RUN chgrp coupon /home/coupon/key.txt
RUN chmod 640 /home/coupon/key.txt

RUN chown -R root /home/coupon/
RUN chmod 641 /home

RUN rm -rf /home/coupon/.bashrc /home/coupon/.profile /home/coupon/.bash_logout
RUN ls -al /home/coupon/
RUN ls -al /home/coupon/GiftBag/

USER coupon
CMD socat TCP-LISTEN:5559,reuseaddr,fork EXEC:./coupon

EXPOSE 5559