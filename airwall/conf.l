%option nounput noinput
%option prefix="confyy"

%{
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include "conf.tab.h"
#include "yyutils.h"

#define YYSTYPE CONFYYSTYPE
#define YYLTYPE CONFYYLTYPE

#define YY_USER_ACTION yylloc->first_line = yylloc->last_line = yylineno; \
  yylloc->first_column = yycolumn; yylloc->last_column = yycolumn+yyleng-1; \
  yycolumn += yyleng;

%}

%option reentrant bison-bridge bison-locations
%x COMMENTS
%%

airwallconf  return AIRWALLCONF;
\{           return OPENBRACE;
\}           return CLOSEBRACE;
;            return SEMICOLON;
,            return COMMA;
own_sack     return OWN_SACK;
default      return DEFAULT;
=            return EQUALS;
disable      return DISABLE;
enable       return ENABLE;
haship       return HASHIP;
hashipport   return HASHIPPORT;
commanded    return COMMANDED;
ratehash     return RATEHASH;
threadcount  return THREADCOUNT;
size         return SIZE;
timer_period_usec return TIMER_PERIOD_USEC;
timer_add    return TIMER_ADD;
initial_tokens return INITIAL_TOKENS;
test_connections return TEST_CONNECTIONS;
conntablesize return CONNTABLESIZE;
mss          return MSS;
wscale       return WSCALE;
tsmss        return TSMSS;
tswscale     return TSWSCALE;
ts_bits      return TS_BITS;
own_mss      return OWN_MSS;
own_wscale   return OWN_WSCALE;
sackconflict return SACKCONFLICT;
remove       return REMOVE;
retain       return RETAIN;
mss_clamp    return MSS_CLAMP;
network_prefix return NETWORK_PREFIX;
network_prefix6 return NETWORK_PREFIX6;
halfopen_cache_max return HALFOPEN_CACHE_MAX;
detect_cache_max return DETECT_CACHE_MAX;
user         return USER;
group        return GROUP;
port         return PORT;
hosts        return HOSTS;
enable_ack   return ENABLE_ACK;
dl_addr      return DL_ADDR;
ul_addr      return UL_ADDR;
ul_alternatives return UL_ALTERNATIVES;
dl_mask      return DL_MASK;
ul_mask      return UL_MASK;
ul_defaultgw return UL_DEFAULTGW;
\"([^\\\"]|\\.)*\"  yylval->s=yy_escape_string(yytext); return STRING_LITERAL;
[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ yylval->i = yy_get_ip(yytext); return IP_LITERAL;

tcp          return TCP;
udp          return UDP;
tcpudp       return TCPUDP;
norgw        return NORGW;
allow_anyport_primary return ALLOW_ANYPORT_PRIMARY;
port_binding_limit return PORT_BINDING_LIMIT;
max_tcp_connections return MAX_TCP_CONNECTIONS;
max_udp_connections return MAX_UDP_CONNECTIONS;
max_icmp_connections return MAX_ICMP_CONNECTIONS;
static_mappings return STATIC_MAPPINGS;

[0-9]+       {
  char *endptr;
  long l;
  errno = 0;
  l=strtol(yytext, &endptr, 10);
  if (errno == ERANGE)
  {
    return ERROR_TOK;
  }
  if (l > INT_MAX || l < INT_MIN)
  {
    return ERROR_TOK;
  }
  if (*endptr != '\0')
  {
    return ERROR_TOK;
  }
  yylval->i = l;
  return INT_LITERAL;
}

\n                                { ++yylineno; yycolumn=1; }
[ \t]+                            /* ignore whitespaces */;
\/\/.*                            /* ignore single-line comments */;
.            return ERROR_TOK;

"/*"                  BEGIN(COMMENTS);
<COMMENTS>"/*"         return ERROR_TOK;
<COMMENTS>"*/"         BEGIN(INITIAL);
<COMMENTS><<EOF>>      return ERROR_TOK;
<COMMENTS>.          ;
<COMMENTS>"\n"       { ++yylineno; yycolumn=1; }

%%
