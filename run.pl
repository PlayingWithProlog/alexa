:- use_module(library(http/http_unix_daemon)).
:- use_module(library(http/thread_httpd)).

:- use_module(alexa_mod).

:- http_handler(/, alexa, [methods([get,head,options]),prefix]).