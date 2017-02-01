%%%-------------------------------------------------------------------
%%% @author Mathieu Kerjouan
%%% @copyright (c) 2017, Mathieu Kerjouan <mk [at] steepath.eu>
%%% @doc 
%%%      rfc3164 implementation.
%%% @end
%%%-------------------------------------------------------------------

-module(rfc3164).
-export([options/0, packet_check/1, packet_check/2]).
-include_lib("eunit/include/eunit.hrl").

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
-spec options() -> list().
options() ->
    [struct].

%%--------------------------------------------------------------------
%% datastructure wrapper
%%--------------------------------------------------------------------
-spec push(push(), map()) -> map();
	  (push(), list()) -> list().
push({Key, Value}, Prop) ->
    push({Key, Value}, Prop, []).

-spec push(push(), map(), list()) -> map();
	  (push(), list(), list()) -> list().
push({Key, Value}, Prop, Options) 
  when is_map(Prop) ->
    maps:put(Key, Value, Prop);
push({Key, Value}, Prop, Options) 
  when is_list(Prop) ->
    [{Key, Value}] ++ Prop.

%%--------------------------------------------------------------------
%% rfc3164 packet check
%%--------------------------------------------------------------------
-spec packet_check(raw_packet()) 
		  -> struct().
packet_check(RawPacket) ->
    packet_check(RawPacket, []).

-spec packet_check(raw_packet(), list()) 
		  -> struct().
packet_check(RawPacket, Options) ->
    case proplists:get_value(struct, Options, list) of
	map -> priority(RawPacket, #{}, Options);
	_ -> priority(RawPacket, [], Options)
    end.

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-spec priority(bitstring(), map() | list()) 
	      -> struct().
priority(RawPacket, PropList) ->
    priority(RawPacket, PropList, []).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-spec priority(bitstring(), map() | list(), list()) 
	      -> map() | list().
priority( <<"<", Priority:8/bitstring, ">", Rest/bitstring>>
	, PropList
	, Options) ->
    priority_check(Rest, PropList, Priority, Options);
priority( <<"<0", Priority:8/bitstring, ">", Rest/bitstring>>
	, PropList
	, Options) ->
    Ret = {priority, {deformed, <<"<0", Priority/bitstring>>}},
    priority_check(Rest, push(Ret, PropList), Priority, Options);
priority( <<"<00", Priority:8/bitstring, ">", Rest/bitstring>>
	, PropList
	, Options) ->
    Ret = {priority, {deformed, <<"<00", Priority/bitstring>>}},
    priority_check(Rest, push(Ret, PropList), Priority, Options);
priority( <<"<000>", Rest/bitstring>>
	, PropList
	, Options) ->
    Ret = {priority, {deformed, <<"<000>">>}},
    priority_check(Rest, push(Ret, PropList), 0, Options);
priority( <<"<", Priority:16/bitstring, ">", Rest/bitstring>>
	, PropList
	, Options) ->
    priority_check(Rest, PropList, Priority, Options);
priority( <<"<", Priority:24/bitstring, ">", Rest/bitstring>>
	, PropList
	, Options) ->
    priority_check(Rest, PropList, Priority, Options);
priority( RawPacket
	, PropList
	, Options) ->
    year(RawPacket, push({priority, undefined}, PropList), Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
priority_check(RawPacket, PropList, Priority) ->
    priority_check(RawPacket, PropList, Priority, []).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-spec priority_check(raw_packet(), struct(), bitstring(), list())
		    -> struct().
priority_check( RawPacket
	      , PropList
	      , Priority
	      , Options) ->
    case bitstring_to_integer_check(Priority, 0, 191) of
	{ok, Integer} -> 
	    facility_and_severity(RawPacket, PropList, Integer, Options);
	{error, Reason} ->
	    year( RawPacket
		, push({priority, Reason}, PropList)
		, Options)
    end.

%%--------------------------------------------------------------------
%% 
%%--------------------------------------------------------------------
-spec facility_and_severity(raw_packet(), struct(), bitstring(), list())
			   -> struct().
facility_and_severity(RawPacket, PropList, Priority, Options) ->
    Facility = Priority bsr 3,
    Severity = Priority - (Facility*8),
    ReturnF = push({facility, facility(Facility)}, PropList),
    Ret = push({severity, severity(Severity)}, ReturnF),
    year(RawPacket, Ret, Options).

%%--------------------------------------------------------------------
%% facility table, simply hardcoded here.
%%--------------------------------------------------------------------
-define( FACILITY(INTEGER, ATOM)
       , facility(INTEGER) -> ATOM; 
	 facility(ATOM) -> INTEGER
).
-spec facility(integer()) -> atom();
	      (atom()) -> integer().
?FACILITY( 0, kern);
?FACILITY( 1, user);
?FACILITY( 2, mail);
?FACILITY( 3, daemon);
?FACILITY( 4, auth);
?FACILITY( 5, syslog);
?FACILITY( 6, lpr);
?FACILITY( 7, news);
?FACILITY( 8, uucp);
?FACILITY( 9, cron);
?FACILITY(10, authpriv);
?FACILITY(11, ftp);
?FACILITY(12, ntp);
?FACILITY(13, security);
?FACILITY(14, console);
?FACILITY(15, reserved);
?FACILITY(16, local0);
?FACILITY(17, local1);
?FACILITY(18, local2);
?FACILITY(19, local3);
?FACILITY(20, local4);
?FACILITY(21, local5);
?FACILITY(22, local6);
?FACILITY(23, local7).

%%--------------------------------------------------------------------
%% severity table, simply hardcoded here.
%%--------------------------------------------------------------------
-define( SEVERITY(INTEGER, ATOM)
       , severity(INTEGER) -> ATOM; 
	 severity(ATOM) -> INTEGER
).

-spec severity(integer()) -> atom();
	      (atom()) -> integer().
?SEVERITY(0, emerg);
?SEVERITY(1, alert);
?SEVERITY(2, crit);
?SEVERITY(3, err);
?SEVERITY(4, warning);
?SEVERITY(5, notice);
?SEVERITY(6, info);
?SEVERITY(7, debug).
  
%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------   
-spec year(raw_packet(), struct(), list())
	  -> struct().
year(<<>>, PropList, Options) ->
    PropList;
year(<<Year:16/bitstring, " ", Rest/bitstring>>, PropList, Options) ->
    case bitstring_to_integer_check(Year, 0, 99) of
	{ok, Integer} ->
	    month(Rest, push({year, Integer}, PropList), Options);
	{error, Reason} ->
	    month(Rest, push({year, Reason}, PropList), Options)
    end;
year(<<Year:32/bitstring, " ", Rest/bitstring>>, PropList, Options) ->
    case bitstring_to_integer_check(Year, 0, 9999) of
	{ok, Integer} ->
	    month(Rest, push({year, Integer}, PropList), Options);
	{error, Reason} ->
	    month(Rest, push({year, Reason}, PropList), Options)
    end;
year(RawPacket, PropList, Options) ->
    month(RawPacket, PropList, Options).


%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-define(MONTH(LITERAL, NUMBER),
	month(<<LITERAL, " ", Rest/bitstring>>, PropList, Options) ->
	       day(Rest, push({month, NUMBER}, PropList), Options)
).

-spec month(raw_packet(), struct(), list())
	   -> struct().
?MONTH("Jan", 1);
?MONTH("Feb", 2);
?MONTH("Mar", 3);
?MONTH("Apr", 4);
?MONTH("May", 5);
?MONTH("Jun", 6);
?MONTH("Jul", 7);
?MONTH("Aug", 8);
?MONTH("Sep", 9);
?MONTH("Oct", 10);
?MONTH("Nov", 11);
?MONTH("Dec", 12);
month(RawPacket, PropList, Options) ->
    day(RawPacket, PropList, Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
day(<<Day:8, " ", Rest/bitstring>>, PropList, Options) ->
    case bitstring_to_integer_check(<<Day>>, 1, 9) of
	{ok, Integer} ->
	    ttime(Rest, push({day, Integer}, PropList), Options);
	{error, Reason} ->
	    ttime(Rest, push({day, Reason}, PropList), Options)
    end;

day(<<" ", Day:8, " ", Rest/bitstring>>, PropList, Options) ->
    case bitstring_to_integer_check(<<Day>>, 1, 9) of
	{ok, Integer} ->
	    ttime(Rest, push({day, Integer}, PropList), Options);
	{error, Reason} ->
	    ttime(Rest, push({day, Reason}, PropList), Options)
    end;

day(<<DayA:8, DayB:8, " ",Rest/bitstring>>, PropList, Options) 
  when (DayA >= $1 andalso DayB >= $0 andalso DayB =< $9) orelse 
       (DayA >= $2 andalso DayB >= $0 andalso DayB =< $9) orelse
       (DayA >= $3 andalso DayB >= $0 andalso DayB =< $1) ->
    case bitstring_to_integer_check(<<DayA, DayB>>, 10, 31) of
	{ok, Integer} ->
	    ttime(Rest, push({day, Integer}, PropList), Options);
	{error, Reason} ->
	    ttime(Rest, push({day, Reason}, PropList), Options)
    end;
day(RawPacket, PropList, Options) ->
    ttime(RawPacket, PropList, Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
ttime(<<Hour:16/bitstring, ":",
	Minute:16/bitstring, ":",
	Second:16/bitstring, " ", 
	Rest/bitstring>>, PropList, Options) ->
    hour(Rest, PropList, {Hour, Minute, Second}, Options);
ttime(<<Hour:16/bitstring, ":",
	Minute:16/bitstring, ":",
	Second:16/bitstring, ".",
	MSecond:24/bitstring, " ",
	Rest/bitstring>>, PropList, Options) ->
    hour(Rest, PropList, {Hour, Minute, Second, MSecond}, Options);
ttime(<<Hour:16/bitstring, ":",
	Minute:16/bitstring, ":",
	Second:16/bitstring, 
	Rest/bitstring>>, PropList, Options) ->
    hour(Rest, PropList, {Hour, Minute, Second}, Options);
ttime(RawPacket, PropList, Options) ->
    timezone(RawPacket, PropList, Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
hour(RawPacket, PropList, {Hour, Minute, Second}, Options) ->
    case bitstring_to_integer_check(Hour, 0, 23) of
	{ok, Integer} -> 
	    Ret = push({hour, Integer}, PropList),
	    minute(RawPacket, Ret, {Minute, Second}, Options);
	{error, Reason} ->
	    Ret = push({hour, Reason}, PropList),
	    minute(RawPacket, Ret, {Minute, Second}, Options)
    end.

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
minute(RawPacket, PropList, {Minute, Second}, Options) ->
    case bitstring_to_integer_check(Minute, 0, 59) of
	{ok, Integer} ->
	    Ret = push({minute, Integer}, PropList),
	    second(RawPacket, Ret, {Second}, Options);
	{error, Reason} ->
	    Ret = push({minute, Reason}, PropList),
	    second(RawPacket, Ret, {Second}, Options)
    end.

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
second(RawPacket, PropList, {Second}, Options) ->
    case bitstring_to_integer_check(Second, 0, 59) of
	{ok, Integer} ->
	    Ret = push({second, Integer}, PropList),
	    timezone(RawPacket, Ret, Options);
	{error, Reason} ->
	    Ret = push({second, Reason},PropList),
	    timezone(RawPacket, Ret, Options)
    end.

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
timezone(<<"TZ", Rest/bitstring>>, PropList, Options) ->
    hostname(Rest, push({timezone, "TZ"}, PropList), Options);
timezone(RawPacket, PropList, Options) ->
    hostname(RawPacket, PropList, Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
hostname(RawPacket, PropList, Options) ->
    hostname(RawPacket, PropList, <<>>, Options).

hostname(<<>>, PropList, 
	 Hostname, Options) ->
    message(<<>>, push({hostname, Hostname}, PropList), Options);
hostname(<<":", Rest/bitstring>>, PropList, 
	 Hostname, Options) ->
    message(Rest, push({hostname, Hostname}, PropList), Options);
hostname(<<" ", Rest/bitstring>>, PropList, 
	 Hostname, Options) ->
    tag(Rest, push({hostname, Hostname}, PropList), Options);
hostname(<<Char:8, Rest/bitstring>>, PropList, 
	 Hostname, Options) 
  when (Char >= $A andalso Char =< $Z) orelse
       (Char >= $a andalso Char =< $z) orelse
       Char =:= $. orelse Char =:= $- ->
    hostname(Rest, PropList, <<Hostname/bitstring, Char>>, Options);
hostname(<<Char:8, Rest/bitstring>>, PropList, 
	 Hostname, Options)  ->
    hostname(Rest, PropList, <<Hostname/bitstring, Char>>, not_valid, Options).

hostname(<<":", Rest/bitstring>>, PropList, 
	 Hostname, not_valid, Options) ->
    message(Rest, push({hostname, {not_valid, Hostname}}, PropList), Options);
hostname(<<" ", Rest/bitstring>>, PropList, 
	 Hostname, not_valid, Options) ->
    tag(Rest, push({hostname, {not_valid, Hostname}}, PropList), Options);
hostname(<<Char:8, Rest/bitstring>>, PropList, 
	 Hostname, not_valid, Options) 
  when Char >= $A andalso Char =< $Z orelse
       Char >= $a andalso Char =< $z orelse
       Char =:= $. orelse Char =:= $- ->
    hostname(Rest, PropList, <<Hostname/bitstring, Char>>, not_valid, Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
tag(RawPacket, PropList, Options) ->
    tag(RawPacket, PropList, <<>>, Options).

tag(<<>>, PropList, Tag, Options) ->
    PropList;
tag(<<":", Rest/bitstring>>, PropList, Tag, Options) ->
    message(Rest, push({tag, Tag}, PropList), Options);
tag(<<"[", Rest/bitstring>>, PropList, Tag, Options) ->
    processid(Rest, push({tag, Tag}, PropList), Options);
tag(<<Char:8, Rest/bitstring>>, PropList, Tag, Options) 
  when (Char >= $0 andalso Char =<$9) orelse
       (Char >= $A andalso Char =< $Z) orelse
       (Char >= $a andalso Char =< $z) orelse
       (Char =:= $.) orelse 
       (Char =:= $-) ->
    tag(Rest, PropList, <<Tag/bitstring, Char>>, Options);
tag(RawPacket, PropList, Tag, Options) ->
    message(RawPacket, push({tag, bad_tag}, PropList), Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
processid(<<"]", Rest/bitstring>>, PropList, Options) ->
    message(Rest, PropList, Options);
processid(RawPacket, PropList, Options) ->
    processid(RawPacket, PropList, <<>>, Options).

processid(<<"]: ", Rest/bitstring>>, PropList, ProcessID, Options) ->
    try binary_to_integer(ProcessID) of
	Integer when Integer >= 0 ->
	    message(Rest, push({processid, Integer}, PropList), Options);
	Integer ->
	    message(Rest, push({processid, negative_integer}, PropList), Options)
    catch
	error:Reason ->
	    message(Rest, push({processid, not_integer}, PropList), Options)
    end;
processid(<<Char:8, Rest/bitstring>>, PropList, ProcessID, Options) 
  when Char >= $0 andalso Char =< $9 ->
    processid(Rest, PropList, <<ProcessID/bitstring, Char:8>>, Options);
processid(RawPacket, PropList, ProcessID, Options) ->
    message(RawPacket, push({processid, undefined}, PropList), Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
message(RawPacket, PropList, Options) ->
    push({message, RawPacket}, PropList).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-spec bitstring_to_integer_check(bitstring(), integer(), integer()) 
				-> {ok, integer()} |
				   {error, not_integer}.
bitstring_to_integer_check(Bitstring, Min, Max) ->
    try erlang:binary_to_integer(Bitstring) of
	Integer when Integer >= Min andalso 
		     Integer =< Max ->
	    {ok, Integer};
	_ -> {error, not_valid}
    catch
	error:Reason ->
	    {error, not_integer}
    end.
