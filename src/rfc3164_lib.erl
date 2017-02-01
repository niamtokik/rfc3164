%%%-------------------------------------------------------------------
%%% @author Mathieu Kerjouan
%%% @copyright (c) 2017, Mathieu Kerjouan <mk [at] steepath.eu>
%%% @doc 
%%%      rfc3164 library.
%%% @end
%%%-------------------------------------------------------------------

-module(rfc3164_lib).
-export([packet_check/1, packet_check/2]).
-include_lib("eunit/include/eunit.hrl").
-include("rfc3164_lib.hrl").

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-spec options() -> list().
options() ->
    [struct].

%%--------------------------------------------------------------------
%% datastructure wrapper
%%
%% @doc
%%      push function will push value based on exported data type. 
%%      This function can match multiple defined standard structure
%%      as proplist, map and record (rfc3164 defined in 
%%      rfc3164_lib.hrl header file).
%% @end
%%--------------------------------------------------------------------
-spec push(push(), map()) -> map();
	  (push(), list()) -> list();
	  (push(), #rfc3164{}) -> #rfc3164{}.
push({Key, Value}, Prop) ->
    push({Key, Value}, Prop, []).

-spec push(push(), map(), list()) -> map();
	  (push(), list(), list()) -> list();
	  (push(), #rfc3164{}, list()) -> #rfc3164{}.
push({Key, Value}, Prop, Options) 
  when is_map(Prop) ->
    maps:put(Key, Value, Prop);
push({Key, Value}, Prop, Options) 
  when is_list(Prop) ->
    [{Key, Value}] ++ Prop;
?PUSH_RECORD(priority);
?PUSH_RECORD(facility);
?PUSH_RECORD(severity);
?PUSH_RECORD(year);
?PUSH_RECORD(month);
?PUSH_RECORD(day);
?PUSH_RECORD(hour);
?PUSH_RECORD(minute);
?PUSH_RECORD(second);
?PUSH_RECORD(hostname);
?PUSH_RECORD(tag);
?PUSH_RECORD(processid);
?PUSH_RECORD(message).

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
    case proplists:get_value(export, Options, list) of
	as_map -> priority(RawPacket, #{}, Options);
	as_record -> priority(RawPacket, #rfc3164{}, Options);
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
	, Options) 
  when is_bitstring(RawPacket) ->
    year(RawPacket, push({priority, undefined}, PropList), Options);

% encode
priority( List 
	, PropList
	, Options ) 
  when is_list(List) ->
    proplists:get_value(priority, List, <<>>).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
priority_check(RawPacket, PropList, Priority) 
  when is_bitstring(RawPacket) ->
    priority_check(RawPacket, PropList, Priority, []).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
-spec priority_check(raw_packet(), struct(), bitstring(), list())
		    -> struct().
priority_check( RawPacket
	      , PropList
	      , Priority
	      , Options) 
  when is_bitstring(RawPacket) ->
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
facility_and_severity(RawPacket, PropList, Priority, Options) 
  when is_bitstring(RawPacket) ->
    Facility = Priority bsr 3,
    Severity = Priority - (Facility*8),
    ReturnF = push({facility, facility(Facility)}, PropList),
    Ret = push({severity, severity(Severity)}, ReturnF),
    year(RawPacket, Ret, Options);

%encode
facility_and_severity(List, PropList, Priority, Options) 
  when is_list(List) ->
    % <13> if not defined
    Facility = case proplists:get_value(facility, List, user) of
		   Int when is_integer(Int) -> Int;
		   At when is_atom(At) -> facility(At)
	       end,
    Severity = case proplists:get_value(severity, List, syslog) of
		   Integer when is_integer(Integer) -> Integer;
		   Atom when is_atom(Atom) -> severity(Atom)
	       end,
    Priority = erlang:integer_to_binary(Facility*8+Severity),
    <<"<", Priority/bitstring,">">>.


%%--------------------------------------------------------------------
%% facility table, simply hardcoded here.
%%--------------------------------------------------------------------
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
year(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
    month(RawPacket, PropList, Options).


%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
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
month(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
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
day(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
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
ttime(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
    timezone(RawPacket, PropList, Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
hour(RawPacket, PropList, {Hour, Minute, Second}, Options) 
  when is_bitstring(RawPacket) ->
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
minute(RawPacket, PropList, {Minute, Second}, Options) 
  when is_bitstring(RawPacket) ->
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
second(RawPacket, PropList, {Second}, Options) 
  when is_bitstring(RawPacket) ->
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
timezone(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
    hostname(RawPacket, PropList, Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
hostname(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
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
tag(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
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
tag(RawPacket, PropList, Tag, Options) 
  when is_bitstring(RawPacket) ->
    message(RawPacket, push({tag, bad_tag}, PropList), Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
processid(<<"]", Rest/bitstring>>, PropList, Options) ->
    message(Rest, PropList, Options);
processid(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
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
processid(RawPacket, PropList, ProcessID, Options) 
  when is_bitstring(RawPacket) ->
    message(RawPacket, push({processid, undefined}, PropList), Options).

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------
message(RawPacket, PropList, Options) 
  when is_bitstring(RawPacket) ->
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

