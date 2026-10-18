#!/bin/sh
export LD_PRELOAD=/usr/local/lib/bindhook.so
export LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib:/usr/local/cim/usr/local/lib
exec /usr/local/bin/webgo /usr/local/www -d
