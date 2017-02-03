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

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-record(rfc3164, { priority = undefined :: undefined | tuple(),
		   facility = undefined :: atom() | integer(),
		   severity = undefined ::  atom() | integer(),
		   year = undefined :: undefined | integer(),
		   month = undefined :: undefined | integer(),
		   day = undefined :: undefined | integer(),
		   hour = undefined :: undefined | integer(),
		   minute = undefined :: undefined | integer(),
		   second = undefined :: undefined | integer(),
		   hostname = undefined :: undefined | bitstring(),
		   tag = undefined :: undefined | bitstring(),
		   processid = undefined :: undefined | integer(),
		   message = undefined :: undefined | bitstring()
		 }
).


%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-define( PUSH_RECORD(ATOM),
	 push({ATOM, Value}, Prop, Options) 
	    when is_record(Prop, rfc3164) ->
	       Prop#rfc3164{ATOM = Value}
).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-define(PULL_RECORD(ATOM),
	pull(ATOM, Prop, Options) 
	   when is_record(Prop, rfc3164)
).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-define( FACILITY(INTEGER, ATOM)
       , facility(INTEGER) -> ATOM; 
	 facility(ATOM) -> INTEGER
).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-define( SEVERITY(INTEGER, ATOM)
       , severity(INTEGER) -> ATOM; 
	 severity(ATOM) -> INTEGER
).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-define(MONTH(LITERAL, NUMBER),
	month(<<LITERAL, " ", Rest/bitstring>>, PropList, Options) ->
	       day(Rest, push({month, NUMBER}, PropList), Options)
).

