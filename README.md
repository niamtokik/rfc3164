# rfc3164

rfc3164 implementation in Erlang. Testing. Don't use it in production! ;)

## Build

    $ rebar3 compile

## Usage

By default, this library use proplists (tuple + lists):

    RawPacket = <<"<0>1999 Oct 10 11:12:13 myhostname process[123]: message test">>
    rfc3164:decode(RawPacket).
    % return:
    % [{message,<<"message test">>},
    %  {processid,123},
    %  {tag,<<"process">>},
    %  {hostname,<<"myhostname">>},
    %  {second,13},
    %  {minute,12},
    %  {hour,11},
    %  {day,10},
    %  {month,10},
    %  {year,1999},
    %  {severity,emerg}]

But, you can also use maps:

    RawPacket = <<"<0>1999 Oct 10 11:12:13 myhostname process[123]: message test">>
    rfc3164:decode(RawPacket, [{struct, map}]).
    % return:
    % #{day => 10,
    %   hostname => <<"myhostname">>,
    %   hour => 11,
    %   message => <<"message test">>,
    %   minute => 12,
    %   month => 10,
    %   processid => 123,
    %   second => 13,
    %   severity => emerg,
    %   tag => <<"process">>,
    %   year => 1999} 

## Todo list

 * Support validation
 * Rename interfaces
 * Rewrite specifications
 * Add more datastructure (record and AST)
 * Benchmark
 * Unit test
 * Documentation

## References

 * https://tools.ietf.org/html/rfc3164

 * https://svnweb.freebsd.org/base/head/usr.sbin/syslogd/
 * https://svnweb.freebsd.org/base/head/lib/libc/gen/syslog.c
 * https://svnweb.freebsd.org/base/head/sys/sys/syslog.h

 * http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/syslogd/
 * http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/sys/syslog.h

 * https://github.com/balabit/syslog-ng

 * https://en.wikipedia.org/wiki/Syslog
 * https://www.sans.org/reading-room/whitepapers/logging/ins-outs-system-logging-syslog-1168
 * 
