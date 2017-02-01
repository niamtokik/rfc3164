%%%-------------------------------------------------------------------
%%% @author Mathieu Kerjouan
%%% @copyright (c) 2017, Mathieu Kerjouan <mk [at] steepath.eu>
%%% @doc 
%%%      rfc3164 implementation interface.
%%% @end
%%%-------------------------------------------------------------------

-module(rfc3164).
-export([encode/1, encode/2]).
-export([decode/1, decode/2]).
-include_lib("eunit/include/eunit.hrl").
-include("rfc3164_lib.hrl").

-spec encode(list() | map())
	    -> bitstring().
encode(_) ->
    ok.

-spec encode(list() | map(), list())
	    -> bitstring().
encode(_,_) ->
    ok.

-spec decode(bitstring() | list()) 
	    -> list() | map().
decode(RawPacket) ->
    decode(RawPacket, []).

-spec decode(bitstring() | list(), list()) 
	    -> list() | map() |
	       {error, bad_args}.
decode(RawPacket, Options) 
  when is_bitstring(RawPacket) ->
    rfc3164_lib:packet_check(RawPacket, Options);
decode(RawPacket, Options)
  when is_list(RawPacket) ->
    Packet = erlang:list_to_bitstring(RawPacket),
    rfc3164_lib:packet_check(Packet, Options);
decode(_, _) ->
    {error, bad_args}.
