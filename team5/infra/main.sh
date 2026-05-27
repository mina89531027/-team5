#!/bin/bash

chown -R mysql:mysql /var/lib/mysql /var/run/mysqld

echo '[+] Starting mysql...'
service mysql start

echo '[+] Waiting for MySQL to be ready...'
until mysqladmin ping --silent 2>/dev/null; do
    sleep 1
done

echo '[+] Initializing DVWA database...'
TABLE_EXISTS=$(mysql -u root -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='dvwa' AND table_name='users';" 2>/dev/null | tail -1)

if [ "$TABLE_EXISTS" != "1" ]; then
    mysql -u root << 'EOSQL'
CREATE DATABASE IF NOT EXISTS dvwa;

CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;

USE dvwa;

CREATE TABLE IF NOT EXISTS `users` (
  `user_id`      int(6) unsigned NOT NULL AUTO_INCREMENT,
  `first_name`   varchar(15)     NOT NULL,
  `last_name`    varchar(15)     NOT NULL,
  `user`         varchar(15)     NOT NULL,
  `password`     varchar(32)     NOT NULL,
  `avatar`       varchar(70)     DEFAULT NULL,
  `last_login`   timestamp       NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  `failed_login` int(3)          DEFAULT '0',
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

INSERT INTO `users` VALUES
('1','admin','admin','admin','5f4dcc3b5aa765d61d8327deb882cf99','/hackable/users/admin.jpg',NULL,'0'),
('2','Gordon','Brown','gordonb','e99a18c428cb38d5f260853678922e03','/hackable/users/gordonb.jpg',NULL,'0'),
('3','Hack','Me','1337','8d3533d75ae2c3966d7e0d4fcc69216b','/hackable/users/1337.jpg',NULL,'0'),
('4','Pablo','Picasso','pablo','0d107d09f5bbe40cade3de5c71e9e9b7','/hackable/users/pablo.jpg',NULL,'0'),
('5','Bob','Smith','smithy','5f4dcc3b5aa765d61d8327deb882cf99','/hackable/users/smithy.jpg',NULL,'0');

CREATE TABLE IF NOT EXISTS `guestbook` (
  `comment_id` smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  `comment`    varchar(300)         NOT NULL,
  `name`       varchar(100)         NOT NULL,
  PRIMARY KEY (`comment_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

INSERT INTO `guestbook` VALUES ('1','This is a test comment.','test');
EOSQL
    echo '[+] DVWA database initialized.'
else
    echo '[+] DVWA database already exists, skipping.'
fi

echo '[+] Starting apache'
service apache2 start

while true
do
    tail -f /var/log/apache2/*.log
    exit 0
done
