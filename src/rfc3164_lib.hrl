%%%-------------------------------------------------------------------
%%% @author Mathieu Kerjouan
%%% @copyright (c) 2017, Mathieu Kerjouan <mk [at] steepath.eu>
%%% @doc 
%%%       rfc3164 headers.
%%% @end
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-type raw_packet() :: bitstring().
-type options() :: list().
-type struct() :: map() | list().
-type key() :: term().
-type value() :: term().
-type push() :: {key(), value()}.

-define( FACILITY(INTEGER, ATOM)
       , facility(INTEGER) -> ATOM; 
	 facility(ATOM) -> INTEGER
).

-define( SEVERITY(INTEGER, ATOM)
       , severity(INTEGER) -> ATOM; 
	 severity(ATOM) -> INTEGER
).

-define(MONTH(LITERAL, NUMBER),
	month(<<LITERAL, " ", Rest/bitstring>>, PropList, Options) ->
	       day(Rest, push({month, NUMBER}, PropList), Options)
).

