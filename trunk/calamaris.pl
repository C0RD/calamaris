#!/usr/bin/perl -w
#
# $Id: calamaris.pl,v 1.112 1998-07-09 19:04:32 cord Exp $
#
# DESCRIPTION: calamaris.pl - get statistic out of the Squid Native Log.
#
# Copyright (C) 1997, 1998 Cord Beermann
#
# URL: http://home.pages.de/~cord/tools/squid/
#
# AUTHOR: Cord Beermann (cord@Wunder-Nett.org)
#
# Thanks to these contributors:
#	John Heaton (John@MCC.ac.uk),
#	Andreas Lamprecht (Andreas.Lamprecht@siemens.at)
#	Kenny Ng (kennyng@cyberway.com.sg)
#	Claus Langhans (langhans@rz.uni-frankfurt.de)
#	Andreas Jung (ajung@sz-sb.de)
#	Ernst Heiri (heiri@switch.ch)
#	Shamil R. Yahin (SSHY@cclib.nsu.ru):
#	Thoralf Freitag (Thoralf.Freitag@isst.fhg.de)
#	Marco Paganini (paganini@paganini.net)
#	Michael Riedel (mr@fto.de)
#	Kris Boulez (kris@belbone.be)
#	Mark Visser (mark@snt.utwente.nl)

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software # Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.


# A Perl script is "correct" if it gets the job done before your boss fires
# you.
#   -- 'Programming Perl Second Edition'
#	by Larry Wall, Tom Christiansen & Randal L. Schwartz


# Instructions:

# * Switch 'emulate_httpd_log' off

# * Pipe your Logfile in calamaris


# Example:

# cat access.log.1 access.log.0 |calamaris.pl


# Bugs and shortcomings

# * A Readme and so on has still to be written. (Maybe i should put this
# section into a seperate file?)

# * if you want to parse more than one Logfile (i.e. from the logfilerotate)
# you have to put them in chronological sorted order (oldest first) into
# calamaris, else you get wrong peak values. (Is this something that i should
# fix? Don't think so...)

# * If you use the caching function the peak-values can be wrong if the peak
# is around the time the log-files were rotated.

# * Squid doesn't log outgoing UDP-Requests, so i can't put them into the
# statistics without parsing squid.conf. (Javier Puche
# (Javier.Puche@rediris.es) asked for this), but i don't think that i should
# put this into calamaris... (Check last point of 'Bugs and shortcomings'.)

# * It is written in perl. Yea, perl is a great language for something like
# this (also it is the only one i'm able to write something like this in).
# Calamaris was first intended as demo for what i wanted from a statistical
# software. (OK, it is fun to write it, and it is even more fun to recognize
# that many people use the script). For my Caches with about 150MB-Logfile per
# week it is OK, but for those people on a heavy loaded Parentcach it is
# simply to slow. So if someone wants to rewrite calamaris in a faster
# language: Feel Free! (But respect the GNU-License)

# * Hmmm, while looking through those many different reports i generate, i
# think that i generate more than anybody ever wants to now about squid :-) So
# i added switches, so everybody can switch on or off the reports wanted. But
# this is also a speed disadvantage because of the many checks if set or not...

# todos
# * add report for byte-peak (Andreas Strotmann <A.Strotmann@Uni-Koeln.DE>)

require 5;

use vars qw($opt_a $opt_b $opt_c $opt_d $opt_h $opt_H $opt_i $opt_m $opt_n
	    $opt_o $opt_p $opt_r $opt_s $opt_t $opt_u $opt_w $opt_z);

use Getopt::Std;
use Sys::Hostname;

getopts('ab:cd:hH:i:mno:pr:st:uwz');

$COPYRIGHT='calamaris $Revision: 1.112 $, Copyright (C) 1997, 1998 Cord Beermann.
calamaris comes with ABSOLUTELY NO WARRANTY. It is free software,
and you are welcome to redistribute it under certain conditions.
See source for details.

';

$USAGE='Usage: cat log | ' . $0 . ' [switches]

Reports:
-a	    all  (extracts all reports available)
-d n	    domain (show n Top-level and n second-level destinations)
-p	    peak (measure peak requests)
-r n	    requester (show n Requesters)
-s	    status (show verbose status reports)
-t n	    type (show n content-type, n extensions and requested protocols)

Output Format: (Default is plain text)
-m	    mail  (mail format)
-w	    web   (HTML format)

Caching:
-i file	    input-file (input-datafile for caching)
-o file	    output-file (output-datafile for caching, could be the same as -i)

Misc:
-b n	    benchmark (prints a hash for each n lines)
-H name	    Hostname (a name for the Output, -H \'lookup\' issues a lookup for
		      the current host)
-n	    nolookup (don\'t look IP-Numbers up)
-u	    user (use ident information if available)
-z	    zero (no input via stdin)

-c	    copyright (prints the copyright)
-h	    help (prints out this message)

';

die($USAGE, $COPYRIGHT) if ($opt_h);

die($COPYRIGHT) if ($opt_c);

if ($opt_b and $opt_b < 1) {
  die($USAGE);
} else {
  $|=1;
}

if ($opt_H) {
  if ($opt_H eq '1' or $opt_H eq 'lookup') {
    $hostname = ' ' . hostname() . ' ';
  } else {
    $hostname = ' ' . $opt_H . ' ';
  }
} else {
  $hostname = '';
}

# initialize variables

$counter = $hier = $hier_direct = $hier_direct_size = $hier_direct_time =
  $hier_parent = $hier_parent_size = $hier_parent_time = $hier_sibling =
  $hier_sibling_size = $hier_sibling_time = $hier_size = $hier_time = $invalid
  = $peak_all_hour = $peak_all_hour_time = $peak_all_min = $peak_all_min_time
  = $peak_all_sec = $peak_all_sec_time = $peak_tcp_hour = $peak_tcp_hour_time
  = $peak_tcp_min = $peak_tcp_min_time = $peak_tcp_sec = $peak_tcp_sec_time =
  $peak_udp_hour = $peak_udp_hour_time = $peak_udp_min = $peak_udp_min_time =
  $peak_udp_sec = $peak_udp_sec_time = $size = $tcp = $tcp_hit = $tcp_hit_size
  = $tcp_hit_time = $tcp_miss = $tcp_miss_direct = $tcp_miss_direct_size =
  $tcp_miss_direct_time = $tcp_miss_neighbor_hit = $tcp_miss_neighbor_hit_size
  = $tcp_miss_neighbor_hit_time = $tcp_miss_neighbor_miss =
  $tcp_miss_neighbor_miss_size = $tcp_miss_neighbor_miss_time = $tcp_miss_none
  = $tcp_miss_none_size = $tcp_miss_none_time = $tcp_miss_size =
  $tcp_miss_time = $tcp_size = $tcp_time = $time = $time_end = $time_run =
  $udp = $udp_hit = $udp_hit_size = $udp_hit_time = $udp_miss = $udp_miss_size
  = $udp_miss_time = $udp_size = $udp_time = 0;

$time_begin = 9999999999;

if ($opt_i and -r $opt_i) {
  open(CACHE, "$opt_i") or die("$0: can't open $opt_i for reading: $!\n");
  while (<CACHE>) {
    chomp;
    @cache = split('µ');
    $x = shift(@cache);
    unless ($x) {
      next;
    } elsif ($x eq A and $#cache = 40) {
      ($time_begin, $time_end, $counter, $size, $time, $invalid, $time_run,
       $udp, $udp_size, $udp_time, $udp_hit, $udp_hit_size, $udp_hit_time,
       $udp_miss, $udp_miss_size, $udp_miss_time, $tcp, $tcp_size, $tcp_time,
       $tcp_hit, $tcp_hit_size, $tcp_hit_time, $tcp_miss, $tcp_miss_size,
       $tcp_miss_time, $tcp_miss_none, $tcp_miss_none_size,
       $tcp_miss_none_time, $hier, $hier_size, $hier_time, $hier_direct,
       $hier_direct_size, $hier_direct_time, $hier_sibling,
       $hier_sibling_size, $hier_sibling_time, $hier_parent,
       $hier_parent_size, $hier_parent_time) = @cache;
    } elsif ($x eq B and $#cache = 18) {
      ($peak_udp_sec, $peak_udp_sec_time, $peak_udp_min, $peak_udp_min_time,
       $peak_udp_hour, $peak_udp_hour_time, $peak_tcp_sec, $peak_tcp_sec_time,
       $peak_tcp_min, $peak_tcp_min_time, $peak_tcp_hour, $peak_tcp_hour_time,
       $peak_all_sec, $peak_all_sec_time, $peak_all_min, $peak_all_min_time,
       $peak_all_hour, $peak_all_hour_time) = @cache;
    } elsif ($x eq C and $#cache = 4) {
      $y = shift(@cache);
      ($method{$y}, $method_size{$y}, $method_time{$y}) = @cache;
    } elsif ($x eq D and $#cache = 4) {
      $y = shift(@cache);
      ($udp_hit{$y}, $udp_hit_size{$y}, $udp_hit_time{$y}) = @cache;
    } elsif ($x eq E and $#cache = 4) {
      $y = shift(@cache);
      ($udp_miss{$y}, $udp_miss_size{$y}, $udp_miss_time{$y}) = @cache;
    } elsif ($x eq F and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_hit{$y}, $tcp_hit_size{$y}, $tcp_hit_time{$y}) = @cache;
    } elsif ($x eq G and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_miss{$y}, $tcp_miss_size{$y}, $tcp_miss_time{$y}) = @cache;
    } elsif ($x eq H and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_miss_none{$y}, $tcp_miss_none_size{$y}, $tcp_miss_none_time{$y}) =
	@cache;
    } elsif ($x eq I and $#cache = 4) {
      $y = shift(@cache);
      ($hier_direct{$y}, $hier_direct_size{$y}, $hier_direct_time{$y}) =
	@cache;
    } elsif ($x eq J and $#cache = 4) {
      $y = shift(@cache);
      ($hier_sibling{$y}, $hier_sibling_size{$y}, $hier_sibling_time{$y}) =
	@cache;
    } elsif ($x eq K and $#cache = 4) {
      $y = shift(@cache);
      ($hier_parent{$y}, $hier_parent_size{$y}, $hier_parent_time{$y}) =
	@cache;
    } elsif ($x eq L and $#cache = 4) {
      $y = shift(@cache);
      ($hier_neighbor{$y}, $hier_neighbor_size{$y}, $hier_neighbor_time{$y}) =
	@cache;
    } elsif ($x eq M and $#cache = 5) {
      $y = shift(@cache);
      $z = shift(@cache);
      ($hier_neighbor_status{$y}{$z}, $hier_neighbor_status_size{$y}{$z},
       $hier_neighbor_status_time{$y}{$z}) = @cache;
    } elsif ($x eq N and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_urlhost{$y}, $tcp_urlhost_size{$y}, $tcp_hit_urlhost{$y}) = @cache;
    } elsif ($x eq O and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_urltld{$y}, $tcp_urltld_size{$y}, $tcp_hit_urltld{$y}) = @cache;
    } elsif ($x eq P and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_urlprot{$y}, $tcp_urlprot_size{$y}, $tcp_hit_urlprot{$y}) = @cache;
    } elsif ($x eq Q and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_content{$y}, $tcp_content_size{$y}, $tcp_hit_content{$y}) = @cache;
    } elsif ($x eq R and $#cache = 4) {
      $y = shift(@cache);
      ($tcp_urlext{$y}, $tcp_urlext_size{$y}, $tcp_hit_urlext{$y}) = @cache;
    } elsif ($x eq S and $#cache = 6) {
      $y = shift(@cache);
      ($udp_requester{$y}, $udp_requester_size{$y}, $udp_requester_time{$y},
       $udp_hit_requester{$y}, $udp_hit_requester_size{$y}) = @cache;
    } elsif ($x eq T and $#cache = 6) {
      $y = shift(@cache);
      ($tcp_requester{$y}, $tcp_requester_size{$y}, $tcp_requester_time{$y},
       $tcp_hit_requester{$y}, $tcp_hit_requester_size{$y}) = @cache;
    } else {
      warn("can't parse cache-line: \"@cache\"\n");
    }
  }
  close(CACHE);
}

unless ($opt_z) {
  print("print a hash for each $opt_b lines:\n") if ($opt_b);
  $time_run = time - $time_run;
  while (<>) {
    ($log_date, $log_reqtime, $log_requester, $log_status, $log_size,
     $log_method, $log_url, $log_ident, $log_hier, $log_content, $foo) =
      split;
    if (not defined $foo or not defined $log_content or $foo ne '' or
	$log_content eq '' ) {
      chomp;
      warn ('invalid line: "' . $_ . "\"\n");
      $invalid++;
      next;
    }
    $log_reqtime = .1 if $log_reqtime == 0;
    $requesterhost = getfqdn($log_requester);
    ($log_hitfail, $log_code) = split(m#/#o,$log_status);
    $log_size = .0000000001 if $log_size == 0;
    @url = split(m#[/\\]#o,$log_url);
    ($urlprot, $urlhost, $urlext) = (@url)[0,2,$#url];
    $urlext = '.<none>' if $#url <= 2;
    if ($#url <= -1) {
      $urlext = '.<error>';
      $urlprot = $urlhost = '<error>';
    }
    $urlext = '.<dynamic>' if ($urlext =~ m#[\?\;\&\$\,\!\@\=\|]#o or
			       $log_method eq POST);
    unless (defined $urlhost) {
      $urlhost = $urlprot;
      $urlprot = '<none>';
    }
    $urlhost =~ s#^.*@##o;
    $urlhost =~ s#[:\?].*$##o;
    @urlext = split(m#\.#o,$urlext);
    $urlext = (@urlext)[$#urlext];
    $urlext = '<none>' if $#urlext <= 0;
    if ($urlhost =~ /^(([0-9][0-9]{0,2}\.){3})[0-9][0-9]{0,2}$/o) {
      $urlhost = $1 . '*';
      $urltld = '<unresolved>';
    } elsif ($urlhost =~ /^(.*\.([^\.]+\.)?)?([^\.]+\.([^\.]+))\.?$/o) {
      @list = split(/\./o, $urlhost);
      $urltld = $urlhost = '.' . pop @list;
      $urlhost = '.' . pop(@list) . $urlhost;
      if ($urltld =~
	  /\.(a[rtu]|br|c[no]|hk|i[dlm]|jp|kr|ly|m[oxy]|nz|p[elnry]|ru|sg|t[hrw]|u[aks]|ve|yu|za)$/o
	  and $#list >= 0) {
	$urlhost = '*.' . pop(@list) . $urlhost;
      } else {
	$urlhost = '*' . $urlhost;
      }
      $urltld = '*' . $urltld;
    } elsif ($urlhost =~ /([!a-z0-9\.\-]|\.\.)/o) {
      $urlhost = $urltld = $urlext = '<error>';
    } else {
      $urltld = $urlhost;
    }
    if ($opt_u) {
      $requester = $log_ident . '@' . $requesterhost;
    } else {
      $requester = $requesterhost;
    }
    ($log_hier_method, $log_hier_host) = (split(m#/#o, $log_hier))[0,1];
    $log_content = '<unknown>' if $log_content eq '-';
    $log_content =~ tr/A-Z/a-z/;
    $log_content = $urlhost = $urltld = $urlext = '<error>' if ($log_code =~
								m#[45]\d\d#o);
    print('#') if ($opt_b and ($counter / $opt_b) eq int($counter / $opt_b));
    $counter++;
    $size += $log_size;
    $time += $log_reqtime;
    $method{$log_method} = $method_size{$log_method} =
      $method_time{$log_method} = 0 unless defined $method{$log_method};
    $method{$log_method}++;
    $method_size{$log_method} += $log_size;
    $method_time{$log_method} += $log_reqtime;
    $time_begin = $log_date if not defined $time_begin or $log_date <
      $time_begin;
    $time_end = $log_date if not defined $time_end or $log_date > $time_end;
    if ($opt_p or $opt_a) {
      $peak_all_sec_pointer++;
      $peak_all_min_pointer++;
      unshift(@peak_all,$log_date);
      $peak_all_sec_pointer-- while $peak_all[$peak_all_sec_pointer - 1] <
	($log_date - 1);
      $peak_all_min_pointer-- while $peak_all[$peak_all_min_pointer - 1] <
	($log_date - 60);
      pop(@peak_all) while $peak_all[$#peak_all] < ($log_date - 3600);
      if ($peak_all_hour < @peak_all) {
	$peak_all_hour = @peak_all;
	$peak_all_hour_time = $log_date - 3600;
      }
      if ($peak_all_min < $peak_all_min_pointer) {
	$peak_all_min = $peak_all_min_pointer;
	$peak_all_min_time = $log_date - 60;
      }
      if ($peak_all_sec < $peak_all_sec_pointer) {
	$peak_all_sec = $peak_all_sec_pointer;
	$peak_all_sec_time = $log_date - 1;
      }
    }
    if ($log_method eq 'ICP_QUERY') {
      $udp++;
      $udp_size += $log_size;
      $udp_time += $log_reqtime;
      if ($opt_r or $opt_a) {
	$udp_requester{$requester} = $udp_requester_size{$requester} =
	  $udp_requester_time{$requester} = $udp_hit_requester{$requester} =
	  $udp_hit_requester_size{$requester} = 0 unless defined
	  $udp_requester{$requester};
	$udp_requester{$requester}++;
	$udp_requester_size{$requester} += $log_size;
	$udp_requester_time{$requester} += $log_reqtime;
      }
      if ($opt_p or $opt_a) {
	$peak_udp_sec_pointer++;
	$peak_udp_min_pointer++;
	unshift(@peak_udp,$log_date);
	$peak_udp_sec_pointer-- while $peak_udp[$peak_udp_sec_pointer - 1] <
	  ($log_date - 1);
	$peak_udp_min_pointer-- while $peak_udp[$peak_udp_min_pointer - 1] <
	  ($log_date - 60);
	pop @peak_udp while $peak_udp[$#peak_udp] < ($log_date - 3600);
	if ($peak_udp_hour < @peak_udp) {
	  $peak_udp_hour = @peak_udp;
	  $peak_udp_hour_time = $log_date - 3600;
	}
	if ($peak_udp_min < $peak_udp_min_pointer) {
	  $peak_udp_min = $peak_udp_min_pointer;
	  $peak_udp_min_time = $log_date - 60;
	}
	if ($peak_udp_sec < $peak_udp_sec_pointer) {
	  $peak_udp_sec = $peak_udp_sec_pointer;
	  $peak_udp_sec_time = $log_date - 1;
	}
      }
      if ($log_hitfail =~ /^UDP_HIT/o) {
	$udp_hit++;
	$udp_hit_size += $log_size;
	$udp_hit_time += $log_reqtime;
	if ($opt_r or $opt_a) {
	  $udp_hit_requester{$requester}++;
	  $udp_hit_requester_size{$requester} += $log_size;
	}
	if ($opt_s or $opt_a) {
	  $udp_hit{$log_hitfail} = $udp_hit_size{$log_hitfail} =
	    $udp_hit_time{$log_hitfail} = 0 unless defined
	    $udp_hit{$log_hitfail};
	  $udp_hit{$log_hitfail}++;
	  $udp_hit_size{$log_hitfail} += $log_size;
	  $udp_hit_time{$log_hitfail} += $log_reqtime;
	}
      } else {
	$udp_miss++;
	$udp_miss_size += $log_size;
	$udp_miss_time += $log_reqtime;
	if ($opt_s or $opt_a) {
	  $udp_miss{$log_hitfail} = $udp_miss_size{$log_hitfail} =
	    $udp_miss_time{$log_hitfail} = 0 unless defined
	    $udp_miss{$log_hitfail};
	  $udp_miss{$log_hitfail}++;
	  $udp_miss_size{$log_hitfail} += $log_size;
	  $udp_miss_time{$log_hitfail} += $log_reqtime;
	}
      }
    } else {
      $tcp++;
      $tcp_size += $log_size;
      $tcp_time += $log_reqtime;
      if ($opt_r or $opt_a) {
	$tcp_requester{$requester} = $tcp_requester_size{$requester} =
	  $tcp_requester_time{$requester} = $tcp_hit_requester{$requester} =
	  $tcp_hit_requester_size{$requester} = 0 unless defined
	  $tcp_requester{$requester};
	$tcp_requester{$requester}++;
	$tcp_requester_size{$requester} += $log_size;
	$tcp_requester_time{$requester} += $log_reqtime;
      }
      if ($opt_d or $opt_a) {
	$tcp_urlhost{$urlhost} = $tcp_urlhost_size{$urlhost} =
	  $tcp_hit_urlhost{$urlhost} = 0 unless defined
	  $tcp_urlhost{$urlhost};
	$tcp_urlhost{$urlhost}++;
	$tcp_urlhost_size{$urlhost} += $log_size;
	$tcp_urltld{$urltld} = $tcp_urltld_size{$urltld} =
	  $tcp_hit_urltld{$urltld} = 0 unless defined $tcp_urltld{$urltld};
	$tcp_urltld{$urltld}++;
	$tcp_urltld_size{$urltld} += $log_size;
      }
      if ($opt_t or $opt_a) {
	$tcp_urlprot{$urlprot} = $tcp_urlprot_size{$urlprot} =
	  $tcp_hit_urlprot{$urlprot} = 0 unless defined
	  $tcp_urlprot{$urlprot};
	$tcp_urlprot{$urlprot}++;
	$tcp_urlprot_size{$urlprot} += $log_size;
      }
      if ($opt_p or $opt_a) {
	$peak_tcp_sec_pointer++;
	$peak_tcp_min_pointer++;
	unshift(@peak_tcp, $log_date);
	$peak_tcp_sec_pointer-- while $peak_tcp[$peak_tcp_sec_pointer - 1] <
	  ($log_date - 1);
	$peak_tcp_min_pointer-- while $peak_tcp[$peak_tcp_min_pointer - 1] <
	  ($log_date - 60);
	pop(@peak_tcp) while $peak_tcp[$#peak_tcp] < ($log_date - 3600);
	if ($peak_tcp_hour < @peak_tcp) {
	  $peak_tcp_hour = @peak_tcp;
	  $peak_tcp_hour_time = $log_date - 3600;
	}
	if ($peak_tcp_min < $peak_tcp_min_pointer) {
	  $peak_tcp_min = $peak_tcp_min_pointer;
	  $peak_tcp_min_time = $log_date - 60;
	}
	if ($peak_tcp_sec < $peak_tcp_sec_pointer) {
	  $peak_tcp_sec = $peak_tcp_sec_pointer;
	  $peak_tcp_sec_time = $log_date - 1;
	}
      }
      if ($opt_t or $opt_a) {
	$tcp_content{$log_content} = $tcp_content_size{$log_content} =
	  $tcp_hit_content{$log_content} = 0 unless defined
	  $tcp_content{$log_content};
	$tcp_content{$log_content}++;
	$tcp_content_size{$log_content} += $log_size;
	$tcp_urlext{$urlext} = $tcp_urlext_size{$urlext} =
	  $tcp_hit_urlext{$urlext} = 0 unless defined $tcp_urlext{$urlext};
	$tcp_urlext{$urlext}++;
	$tcp_urlext_size{$urlext} += $log_size;
      }
      if ($log_hitfail =~ /^TCP\w+HIT/o) {
	$tcp_hit++;
	$tcp_hit_size += $log_size;
	$tcp_hit_time += $log_reqtime;
	if ($opt_s or $opt_a) {
	  $tcp_hit{$log_hitfail} = $tcp_hit_size{$log_hitfail} =
	    $tcp_hit_time{$log_hitfail} = 0 unless defined
	    $tcp_hit{$log_hitfail};
	  $tcp_hit{$log_hitfail}++;
	  $tcp_hit_size{$log_hitfail} += $log_size;
	  $tcp_hit_time{$log_hitfail} += $log_reqtime;
	}
	if ($opt_r or $opt_a) {
	  $tcp_hit_requester{$requester}++;
	  $tcp_hit_requester_size{$requester} += $log_size;
	}
	if ($opt_d or $opt_a) {
	  $tcp_hit_urlhost{$urlhost}++;
	  $tcp_hit_urltld{$urltld}++;
	}
	if ($opt_t or $opt_a) {
	  $tcp_hit_content{$log_content}++;
	  $tcp_hit_urlext{$urlext}++;
	  $tcp_hit_urlprot{$urlprot}++;
	}
      } elsif (($log_hier_method eq 'NONE') or ($log_hitfail =~ /^ERR_/o)) {
	$tcp_miss_none++;
	$tcp_miss_none_size += $log_size;
	$tcp_miss_none_time += $log_reqtime;
	if ($opt_s or $opt_a) {
	  $tcp_miss_none{$log_hitfail} = $tcp_miss_none_size{$log_hitfail} =
	    $tcp_miss_none_time{$log_hitfail} = 0 unless defined
	    $tcp_miss_none{$log_hitfail};
	  $tcp_miss_none{$log_hitfail}++;
	  $tcp_miss_none_size{$log_hitfail} += $log_size;
	  $tcp_miss_none_time{$log_hitfail} += $log_reqtime;
	}
      } else {
	$tcp_miss++;
	$tcp_miss_size += $log_size;
	$tcp_miss_time += $log_reqtime;
	if ($opt_s or $opt_a) {
	  $tcp_miss{$log_hitfail} = $tcp_miss_size{$log_hitfail} =
	    $tcp_miss_time{$log_hitfail} = 0 unless defined
	    $tcp_miss{$log_hitfail};
	  $tcp_miss{$log_hitfail}++;
	  $tcp_miss_size{$log_hitfail} += $log_size;
	  $tcp_miss_time{$log_hitfail} += $log_reqtime;
	}
	if ($opt_r or $opt_a) {
	  $tcp_miss_requester{$requester} =
	    $tcp_miss_requester_size{$requester} = 0 unless defined
	    $tcp_miss_requester{$requester};
	  $tcp_miss_requester{$requester}++;
	  $tcp_miss_requester_size{$requester} += $log_size;
	}
	if ($log_hier_method =~ /(DIRECT|SOURCE_FASTEST)/o) {
	  $tcp_miss_direct++;
	  $tcp_miss_direct_size += $log_size;
	  $tcp_miss_direct_time += $log_reqtime;
	} elsif ($log_hier_method =~ /(PARENT|SIBLING)\w+HIT/o) {
	  $tcp_miss_neighbor_hit++;
	  $tcp_miss_neighbor_hit_time += $log_reqtime;
	  $tcp_miss_neighbor_hit_size += $log_size;
	  $tcp_miss_neighbor_hit{$log_hier_host} =
	    $tcp_miss_neighbor_hit_size{$log_hier_host} =
	    $tcp_miss_neighbor_hit_time{$log_hier_host} = 0 unless defined
	    $tcp_miss_neighbor_hit{$log_hier_host};
	  $tcp_miss_neighbor_hit{$log_hier_host}++;
	  $tcp_miss_neighbor_hit_size{$log_hier_host} += $log_size;
	  $tcp_miss_neighbor_hit_time{$log_hier_host} += $log_reqtime;
	} elsif ($log_hier_method =~
		 /(PARENT_MISS|(DEFAULT|FIRST_UP|SINGLE|PASSTHROUGH|ROUNDROBIN)_PARENT)/o) {
	  $tcp_miss_neighbor_miss++;
	  $tcp_miss_neighbor_miss_size += $log_size;
	  $tcp_miss_neighbor_miss_time += $log_reqtime;
	  $tcp_miss_neighbor{$log_hier_host} =
	    $tcp_miss_neighbor_miss_size{$log_hier_host} =
	    $tcp_miss_neighbor_miss_time{$log_hier_host} = 0 unless defined
	    $tcp_miss_neighbor{$log_hier_host};
	  $tcp_miss_neighbor_miss{$log_hier_host}++;
	  $tcp_miss_neighbor_miss_size{$log_hier_host} += $log_size;
	  $tcp_miss_neighbor_miss_time{$log_hier_host} += $log_reqtime;
	} else {
	  warn("unknown log_hier_method: \"$log_hier_method\"
	    Please report this to calamaris-bug\@cord.de\n");
	}
      }
      if ($log_hier_method ne 'NONE') {
	$hier++;
	$hier_size += $log_size;
	$hier_time += $log_reqtime;
	if ($log_hier_method =~ /(DIRECT|SOURCE_FASTEST)/o) {
	  $hier_direct++;
	  $hier_direct_size += $log_size;
	  $hier_direct_time += $log_reqtime;
	  if ($opt_s or $opt_a) {
	    $hier_direct{$log_hier_method} =
	      $hier_direct_size{$log_hier_method} =
	      $hier_direct_time{$log_hier_method} = 0 unless defined
	      $hier_direct{$log_hier_method};
	    $hier_direct{$log_hier_method}++;
	    $hier_direct_size{$log_hier_method} += $log_size;
	    $hier_direct_time{$log_hier_method} += $log_reqtime;
	  }
	} elsif ($log_hier_method =~ /(PARENT|SIBLING)\w+HIT/o) {
	  $hier_sibling++;
	  $hier_sibling_size += $log_size;
	  $hier_sibling_time += $log_reqtime;
	  if ($opt_s or $opt_a) {
	    $hier_sibling{$log_hier_method} =
	      $hier_sibling_size{$log_hier_method} =
	      $hier_sibling_time{$log_hier_method} = 0 unless defined
	      $hier_sibling{$log_hier_method};
	    $hier_sibling{$log_hier_method}++;
	    $hier_sibling_size{$log_hier_method} += $log_size;
	    $hier_sibling_time{$log_hier_method} += $log_reqtime;
	  }
	  $hier_neighbor{$log_hier_host} =
	    $hier_neighbor_size{$log_hier_host} =
	    $hier_neighbor_time{$log_hier_host} = 0 unless defined
	    $hier_neighbor{$log_hier_host};
	  $hier_neighbor{$log_hier_host}++;
	  $hier_neighbor_size{$log_hier_host} += $log_size;
	  $hier_neighbor_time{$log_hier_host} += $log_reqtime;
	  if ($opt_s or $opt_a) {
	    $hier_neighbor_status{$log_hier_host}{$log_hier_method} =
	      $hier_neighbor_status_size{$log_hier_host}{$log_hier_method} =
	      $hier_neighbor_status_time{$log_hier_host}{$log_hier_method} = 0
	      unless defined
	      $hier_neighbor_status{$log_hier_host}{$log_hier_method};
	    $hier_neighbor_status{$log_hier_host}{$log_hier_method}++;
	    $hier_neighbor_status_size{$log_hier_host}{$log_hier_method} +=
	      $log_size;
	    $hier_neighbor_status_time{$log_hier_host}{$log_hier_method} +=
	      $log_reqtime;
	  }
	} elsif ($log_hier_method =~
		 /(PARENT_MISS|(DEFAULT|FIRST_UP|SINGLE|PASSTHROUGH|ROUNDROBIN)_PARENT)/o) {
	  $hier_parent++;
	  $hier_parent_size += $log_size;
	  $hier_parent_time += $log_reqtime;
	  if ($opt_s or $opt_a) {
	    $hier_parent{$log_hier_method} =
	      $hier_parent_size{$log_hier_method} =
	      $hier_parent_time{$log_hier_method} = 0 unless defined
	      $hier_parent{$log_hier_method};
	    $hier_parent{$log_hier_method}++;
	    $hier_parent_size{$log_hier_method} += $log_size;
	    $hier_parent_time{$log_hier_method} += $log_reqtime;
	  }
	  $hier_neighbor{$log_hier_host} =
	    $hier_neighbor_size{$log_hier_host} =
	    $hier_neighbor_time{$log_hier_host} = 0 unless defined
	    $hier_neighbor{$log_hier_host};
	  $hier_neighbor{$log_hier_host}++;
	  $hier_neighbor_size{$log_hier_host} += $log_size;
	  $hier_neighbor_time{$log_hier_host} += $log_reqtime;
	  if ($opt_s or $opt_a) {
	    $hier_neighbor_status{$log_hier_host}{$log_hier_method} =
	      $hier_neighbor_status_size{$log_hier_host}{$log_hier_method} =
	      $hier_neighbor_status_time{$log_hier_host}{$log_hier_method} = 0
	      unless defined
	      $hier_neighbor_status{$log_hier_host}{$log_hier_method};
	    $hier_neighbor_status{$log_hier_host}{$log_hier_method}++;
	    $hier_neighbor_status_size{$log_hier_host}{$log_hier_method} +=
	      $log_size;
	    $hier_neighbor_status_time{$log_hier_host}{$log_hier_method} +=
	      $log_reqtime;
	  }
	} else {
	  warn("unknown log_hier_method: \"$log_hier_method\"
	    Please report this to calamaris-bug\@cord.de\n");
	}
      }
    }
  }
$time_run = time - $time_run;
}

### Yea! File read. Now give the output...

if ($counter == 0) {
  print('no requests found');
  exit(0);
}
open(CACHE, ">$opt_o") or die("$0: can't open $opt_i for writing: $!\n")
  if ($opt_o);
writecache(A, $time_begin, $time_end, $counter, $size, $time, $invalid,
	   $time_run, $udp, $udp_size, $udp_time, $udp_hit, $udp_hit_size,
	   $udp_hit_time, $udp_miss, $udp_miss_size, $udp_miss_time, $tcp,
	   $tcp_size, $tcp_time, $tcp_hit, $tcp_hit_size, $tcp_hit_time,
	   $tcp_miss, $tcp_miss_size, $tcp_miss_time, $tcp_miss_none,
	   $tcp_miss_none_size, $tcp_miss_none_time, $hier, $hier_size,
	   $hier_time, $hier_direct, $hier_direct_size, $hier_direct_time,
	   $hier_sibling, $hier_sibling_size, $hier_sibling_time,
	   $hier_parent, $hier_parent_size, $hier_parent_time);
writecache(B, $peak_udp_sec, $peak_udp_sec_time, $peak_udp_min,
	   $peak_udp_min_time, $peak_udp_hour, $peak_udp_hour_time,
	   $peak_tcp_sec, $peak_tcp_sec_time, $peak_tcp_min,
	   $peak_tcp_min_time, $peak_tcp_hour, $peak_tcp_hour_time,
	   $peak_all_sec, $peak_all_sec_time, $peak_all_min,
	   $peak_all_min_time, $peak_all_hour, $peak_all_hour_time);
$date_start = convertdate($time_begin);
$date_stop = convertdate($time_end);
if ($opt_p or $opt_a) {
  $date_peak_udp_sec = convertdate($peak_udp_sec_time);
  $date_peak_tcp_sec = convertdate($peak_tcp_sec_time);
  $date_peak_all_sec = convertdate($peak_all_sec_time);
  $date_peak_udp_min = convertdate($peak_udp_min_time);
  $date_peak_tcp_min = convertdate($peak_tcp_min_time);
  $date_peak_all_min = convertdate($peak_all_min_time);
  $date_peak_udp_hour = convertdate($peak_udp_hour_time);
  $date_peak_tcp_hour = convertdate($peak_tcp_hour_time);
  $date_peak_all_hour = convertdate($peak_all_hour_time);
}
print("Content-Type: text/html; charset=us-ascii
Content-Transfer-Encoding: 7bit\n") if ($opt_m and $opt_w);
printf("Subject:%sSquid-Report (%s - %s)\n\n", $hostname, $date_start,
       $date_stop) if ($opt_m);
if ($opt_w) {
  print("<html><head><title>Squid-Report</title></head><body>\n");
  printf("<h1><a name=\"0\">%sSquid-Report (%s - %s)</a></h1>\n", $hostname,
	 $date_start, $date_stop);
  print("<hr><ul>\n");
  outref('Summary', 1);
  outref('Incoming request peak per protocol', 2) if ($opt_p or $opt_a);
  outref('Incoming requests by method', 3);
  outref('Incoming UDP-requests by status', 4);
  outref('Incoming TCP-requests by status', 5);
  outref('Outgoing requests by status', 6);
  outref('Outgoing requests by destination', 7);
  if ($opt_d or $opt_a) {
    outref('Request-destinations by 2ndlevel-domain', 8);
    outref('Request-destinations by toplevel-domain', 9);
  }
  if ($opt_t or $opt_a) {
    outref('TCP-Request-protocol', 10);
    outref('Requested content-type', 11);
    outref('Requested extensions', 12);
  }
  if ($opt_r or $opt_a) {
    outref('Incoming UDP-requests by host', 13);
    outref('Incoming TCP-requests by host', 14);
  }
  print("</ul><hr>\n");
} else {
  printf("%sSquid-Report (%s - %s)\n", $hostname, $date_start, $date_stop);
}

@format=(19,8);
if ($hostname) {
  outtitle('Summary for' . $hostname, 1);
} else {
  outtitle('Summary', 1);
}
outstart();
outline('lines parsed:', $counter);
outline('invalid lines:', $invalid);
outline('unique hosts/users:', scalar keys %tcp_requester);
outline('parse time (sec):', $time_run);
outstop();

@format=(3,4,18,5,18,7,18);
if ($opt_p or $opt_a) {
  outtitle('Incoming request peak per protocol', 2);
  outstart();
  outheader('prt', ' sec', 'peak begins at', ' min', 'peak begins at', ' hour',
	    'peak begins at');
  outseperator();
  outline('UDP', $peak_udp_sec, $date_peak_udp_sec, $peak_udp_min,
	  $date_peak_udp_min, $peak_udp_hour, $date_peak_udp_hour);
  outline('TCP', $peak_tcp_sec, $date_peak_tcp_sec, $peak_tcp_min,
	  $date_peak_tcp_min, $peak_tcp_hour, $date_peak_tcp_hour);
  outseperator();
  outline('ALL', $peak_all_sec, $date_peak_all_sec, $peak_all_min,
	  $date_peak_all_min, $peak_all_hour, $date_peak_all_hour);
  outstop();
}

@format=(33,8,'%',9,'%',4,'kbs');
if ($counter == 0) {
  outtitle('Incoming requests by method: none', 3);
} else {
  outtitle('Incoming requests by method', 3);
  outstart();
  outheader('method',' request','% ','  kByte','% ',' sec',' kB/sec');
  outseperator();
  foreach $method (sort {$method{$b} <=> $method{$a}} keys(%method)) {
    writecache(C, $method, $method{$method}, $method_size{$method},
	       $method_time{$method});
    outline($method, $method{$method}, 100 * $method{$method} / $counter,
	    $method_size{$method} / 1024, 100 * $method_size{$method} / $size,
	    $method_time{$method} / (1000 * $method{$method}), 1000 *
	    $method_size{$method} / (1024 * $method_time{$method}));
  }
  outseperator();
  outline(Sum, $counter, 100, $size / 1024, 100, $time / ($counter * 1000),
	  1000 * $size / (1024 * $time));
  outstop();
}

if ($udp == 0) {
  outtitle('Incoming UDP-requests by status: none', 4);
} else {
  outtitle('Incoming UDP-requests by status', 4);
  outstart();
  outheader('status',' request','% ','  kByte','% ','msec',' kB/sec');
  outseperator();
  if ($udp_hit == 0) {
    outline(HIT,0,0,0,0,0,0);
  } else {
    outline(HIT, $udp_hit, 100 * $udp_hit / $udp, $udp_hit_size / 1024, 100 *
	    $udp_hit_size / $udp_size, $udp_hit_time / $udp_hit, 1000 *
	    $udp_hit_size / (1024 * $udp_hit_time));
    foreach $hitfail (sort {$udp_hit{$b} <=> $udp_hit{$a}} keys(%udp_hit)) {
      writecache(D, $hitfail, $udp_hit{$hitfail}, $udp_hit_size{$hitfail},
		 $udp_hit_time{$hitfail});
      outline(' ' . $hitfail, $udp_hit{$hitfail}, 100 * $udp_hit{$hitfail} /
	      $udp, $udp_hit_size{$hitfail} / 1024, 100 *
	      $udp_hit_size{$hitfail} / $udp_size, $udp_hit_time{$hitfail} /
	      $udp_hit{$hitfail}, 1000 * $udp_hit_size{$hitfail} /
	      (1024 * $udp_hit_time{$hitfail}));
    }
  }
  if ($udp_miss == 0) {
    outline(MISS,0,0,0,0,0,0);
  } else {
    outline(MISS, $udp_miss, 100 * $udp_miss / $udp, $udp_miss_size / 1024,
	    100 * $udp_miss_size / $udp_size, $udp_miss_time / $udp_miss,
	    1000 * $udp_miss_size / (1024 * $udp_miss_time));
    foreach $hitfail (sort {$udp_miss{$b} <=> $udp_miss{$a}} keys(%udp_miss)) {
      writecache(E, $hitfail, $udp_miss{$hitfail}, $udp_miss_size{$hitfail},
		 $udp_miss_time{$hitfail});
      outline(' ' . $hitfail, $udp_miss{$hitfail}, 100 * $udp_miss{$hitfail} /
	      $udp, $udp_miss_size{$hitfail} / 1024, 100 *
	      $udp_miss_size{$hitfail} / $udp_size, $udp_miss_time{$hitfail} /
	      $udp_miss{$hitfail}, 1000 * $udp_miss_size{$hitfail} /
	      (1024 * $udp_miss_time{$hitfail}));
    }
  }
  outseperator();
  outline(Sum, $udp, ' ', $udp_size / 1024, ' ', $udp_time / $udp, 1000 *
	  $udp_size / (1024 * $udp_time));
  outstop();
}

if ($tcp == 0) {
  outtitle('Incoming TCP-requests by status: none', 5);
} else {
  outtitle('Incoming TCP-requests by status', 5);
  outstart();
  outheader('status',' request','% ','  kByte','% ',' sec',' kB/sec');
  outseperator();
  if ($tcp_hit == 0) {
    outline(HIT,0,0,0,0,0,0);
  } else {
    outline(HIT, $tcp_hit, 100 * $tcp_hit / $tcp, $tcp_hit_size / 1024, 100 *
	    $tcp_hit_size / $tcp_size, $tcp_hit_time / (1000 * $tcp_hit),
	    1000 * $tcp_hit_size / (1024 * $tcp_hit_time));
    foreach $hitfail (sort {$tcp_hit{$b} <=> $tcp_hit{$a}} keys(%tcp_hit)) {
      writecache(F, $hitfail, $tcp_hit{$hitfail}, $tcp_hit_size{$hitfail},
		 $tcp_hit_time{$hitfail});
      outline(' ' . $hitfail, $tcp_hit{$hitfail}, 100 * $tcp_hit{$hitfail} /
	      $tcp, $tcp_hit_size{$hitfail} / 1024, 100 *
	      $tcp_hit_size{$hitfail} / $tcp_size, $tcp_hit_time{$hitfail} /
	      (1000 * $tcp_hit{$hitfail}), 1000 * $tcp_hit_size{$hitfail} /
	      (1024 * $tcp_hit_time{$hitfail}));
    }
  }
  if ($tcp_miss == 0) {
    outline(MISS,0,0,0,0,0,0);
  } else {
    outline(MISS, $tcp_miss, 100 * $tcp_miss / $tcp, $tcp_miss_size / 1024,
	    100 * $tcp_miss_size / $tcp_size, $tcp_miss_time /
	    (1000 * $tcp_miss), 1000 * $tcp_miss_size /
	    (1024 * $tcp_miss_time));
    foreach $hitfail (sort {$tcp_miss{$b} <=> $tcp_miss{$a}} keys(%tcp_miss)) {
      writecache(G, $hitfail, $tcp_miss{$hitfail}, $tcp_miss_size{$hitfail},
		 $tcp_miss_time{$hitfail});
      outline(' ' . $hitfail, $tcp_miss{$hitfail}, 100 * $tcp_miss{$hitfail} /
	      $tcp, $tcp_miss_size{$hitfail} / 1024, 100 *
	      $tcp_miss_size{$hitfail} / $tcp_size, $tcp_miss_time{$hitfail} /
	      (1000 * $tcp_miss{$hitfail}), 1000 * $tcp_miss_size{$hitfail} /
	      (1024 * $tcp_miss_time{$hitfail}));
    }
  }
  if ($tcp_miss_none == 0) {
    outline(ERROR,0,0,0,0,0,0);
  } else {
    outline(ERROR, $tcp_miss_none, 100 * $tcp_miss_none / $tcp,
	    $tcp_miss_none_size / 1024, 100 * $tcp_miss_none_size / $tcp_size,
	    $tcp_miss_none_time / (1000 * $tcp_miss_none), 1000 *
	    $tcp_miss_none_size / (1024 * $tcp_miss_none_time));
    foreach $hitfail (sort {$tcp_miss_none{$b} <=> $tcp_miss_none{$a}}
		      keys(%tcp_miss_none)) {
      writecache(H, $hitfail, $tcp_miss_none{$hitfail},
		 $tcp_miss_none_size{$hitfail}, $tcp_miss_none_time{$hitfail});
      outline(' ' .  $hitfail, $tcp_miss_none{$hitfail}, 100 *
	      $tcp_miss_none{$hitfail} / $tcp, $tcp_miss_none_size{$hitfail} /
	      1024, 100 * $tcp_miss_none_size{$hitfail} / $tcp_size,
	      $tcp_miss_none_time{$hitfail} /
	      (1000 * $tcp_miss_none{$hitfail}), 1000 *
	      $tcp_miss_none_size{$hitfail} /
	      (1024 * $tcp_miss_none_time{$hitfail}));
    }
  }
  outseperator();
  outline(Sum, $tcp, ' ', $tcp_size / 1024, ' ', $tcp_time / (1000 * $tcp),
	  1000 * $tcp_size / (1024 * $tcp_time));
  outstop();
}

if ($hier == 0) {
  outtitle('Outgoing requests by status: none', 6);
} else {
  outtitle('Outgoing requests by status', 6);
  outstart();
  outheader('status',' request','% ','  kByte','% ',' sec',' kB/sec');
  outseperator();
  if ($hier_direct == 0) {
    outline('DIRECT',0,0,0,0,0,0);
  } else {
    outline('DIRECT Fetch from Source', $hier_direct, 100 * $hier_direct /
	    $hier, $hier_direct_size / 1024, 100 * $hier_direct_size /
	    $hier_size, $hier_direct_time / (1000 * $hier_direct), 1000 *
	    $hier_direct_size / (1024 * $hier_direct_time));
    foreach $hitfail (sort {$hier_direct{$b} <=> $hier_direct{$a}}
		      keys(%hier_direct)) {
      writecache(I, $hitfail, $hier_direct{$hitfail},
		 $hier_direct_size{$hitfail}, $hier_direct_time{$hitfail});
      outline(' ' . $hitfail, $hier_direct{$hitfail}, 100 *
	      $hier_direct{$hitfail} / $hier, $hier_direct_size{$hitfail} /
	      1024, 100 * $hier_direct_size{$hitfail} / $hier_size,
	      $hier_direct_time{$hitfail} / (1000 * $hier_direct{$hitfail}),
	      1000 * $hier_direct_size{$hitfail} /
	      (1024 * $hier_direct_time{$hitfail}));
    }
  }
  if ($hier_sibling == 0) {
    outline('SIBLING',0,0,0,0,0,0);
  } else {
    outline('HIT on Sibling or Parent Cache', $hier_sibling, 100 *
	    $hier_sibling / $hier, $hier_sibling_size / 1024, 100 *
	    $hier_sibling_size / $hier_size, $hier_sibling_time /
	    (1000 * $hier_sibling), 1000 * $hier_sibling_size /
	    (1024 * $hier_sibling_time));
    foreach $hitfail (sort {$hier_sibling{$b} <=> $hier_sibling{$a}}
		      keys(%hier_sibling)) {
      writecache(J, $hitfail, $hier_sibling{$hitfail},
		 $hier_sibling_size{$hitfail}, $hier_sibling_time{$hitfail});
      outline(' ' . $hitfail, $hier_sibling{$hitfail}, 100 *
	      $hier_sibling{$hitfail} / $hier, $hier_sibling_size{$hitfail} /
	      1024, 100 * $hier_sibling_size{$hitfail} / $hier_size,
	      $hier_sibling_time{$hitfail} / (1000 * $hier_sibling{$hitfail}),
	      1000 * $hier_sibling_size{$hitfail} /
	      (1024 * $hier_sibling_time{$hitfail}));
    }
  }
  if ($hier_parent == 0) {
    outline('PARENT',0,0,0,0,0,0);
  } else {
    outline('FETCH from Parent Cache', $hier_parent, 100 * $hier_parent /
	    $hier, $hier_parent_size / 1024, 100 * $hier_parent_size /
	    $hier_size, $hier_parent_time / (1000 * $hier_parent), 1000 *
	    $hier_parent_size / (1024 * $hier_parent_time) );

    foreach $hitfail (sort {$hier_parent{$b} <=> $hier_parent{$a}}
		      keys(%hier_parent)) {
      writecache(K, $hitfail, $hier_parent{$hitfail},
		 $hier_parent_size{$hitfail}, $hier_parent_time{$hitfail});
      outline(' ' . $hitfail, $hier_parent{$hitfail}, 100 *
	      $hier_parent{$hitfail} / $hier, $hier_parent_size{$hitfail} /
	      1024, 100 * $hier_parent_size{$hitfail} / $hier_size,
	      $hier_parent_time{$hitfail} / (1000 * $hier_parent{$hitfail}),
	      1000 * $hier_parent_size{$hitfail} /
	      (1024 * $hier_parent_time{$hitfail}));
    }
  }
  outseperator();
  outline(Sum, $hier, ' ', $hier_size / 1024, ' ', $hier_time /
	  (1000 * $hier), 1000 * $hier_size / (1024 * $hier_time));
  outstop();
}

if ($tcp_miss == 0) {
  outtitle('Outgoing requests by destination: none', 7);
} else {
  outtitle('Outgoing requests by destination', 7);
  outstart();
  outheader('neighbor type',' request','% ',' kByte','% ',' sec', ' kB/sec');
  outseperator();
  outline(DIRECT, $hier_direct, 100 * $hier_direct / $hier, $hier_direct_size
	  / 1024, 100 * $hier_direct_size / $hier_size, $hier_direct_time /
	  (1000 * $hier_direct), 1000 * $hier_direct_size /
	  (1024 * $hier_direct_time)) unless $tcp_miss_direct == 0;
  foreach $neighbor (sort {$hier_neighbor{$b} <=> $hier_neighbor{$a}}
		     keys(%hier_neighbor)) {
    writecache(L, $neighbor, $hier_neighbor{$neighbor},
	       $hier_neighbor_size{$neighbor},
	       $hier_neighbor_time{$neighbor});
    outline($neighbor, $hier_neighbor{$neighbor}, 100 *
	    $hier_neighbor{$neighbor} / $hier, $hier_neighbor_size{$neighbor}
	    / 1024, 100 * $hier_neighbor_size{$neighbor} / $hier_size,
	    $hier_neighbor_time{$neighbor} / (1000 * $hier), 1000 *
	    $hier_neighbor_size{$neighbor} / (1024 *
	    $hier_neighbor_time{$neighbor}));
    foreach $status (sort {$hier_neighbor_status{$neighbor}{$b} <=>
			   $hier_neighbor_status{$neighbor}{$a}}
		     keys(%{$hier_neighbor_status{$neighbor}})) {
      writecache(M, $neighbor, $status,
		 $hier_neighbor_status{$neighbor}{$status},
		 $hier_neighbor_status_size{$neighbor}{$status},
		 $hier_neighbor_status_time{$neighbor}{$status});
      outline(' ' .  $status, $hier_neighbor_status{$neighbor}{$status},
	      100 * $hier_neighbor_status{$neighbor}{$status} / $hier,
	      $hier_neighbor_status_size{$neighbor}{$status} / 1024, 100 *
	      $hier_neighbor_status_size{$neighbor}{$status} /
	      $hier_size, $hier_neighbor_status_time{$neighbor}{$status} /
	      (1000 * $hier), 1000 *
	      $hier_neighbor_status_size{$neighbor}{$status} /
	      (1024 * $hier_neighbor_status_time{$neighbor}{$status}));
    }
  }
  outseperator();
  outline(Sum, $hier, ' ', $hier_size / 1024, ' ', $hier_time / (1000 * $hier),
	  1000 * $hier_size / (1024 * $hier_time));
  outstop();
}

@format=(39,8,'%',9,'%','%');
if ($opt_d or $opt_a) {
  if ($tcp == 0) {
    outtitle('Request-destinations: none', 8);
  } else {
    outtitle('Request-destinations by 2ndlevel-domain', 8);
    outstart();
    outheader('destination',' request','% ','  kByte','% ','hit-%');
    outseperator();
    @counter = keys %tcp_urlhost;
    $other_urlhost = $#counter + 1;
    $other = $tcp;
    $other_size = $tcp_size;
    $other_hit = $tcp_hit;
    $other_count = $opt_d;
    foreach $urlhost (sort {$tcp_urlhost{$b} <=> $tcp_urlhost{$a}}
		      keys(%tcp_urlhost)) {
      $other_urlhost--;
      $other -= $tcp_urlhost{$urlhost};
      $other_size -= $tcp_urlhost_size{$urlhost};
      $other_hit -= $tcp_hit_urlhost{$urlhost};
      writecache(N, $urlhost, $tcp_urlhost{$urlhost},
		 $tcp_urlhost_size{$urlhost}, $tcp_hit_urlhost{$urlhost});
      outline($urlhost, $tcp_urlhost{$urlhost}, 100 * $tcp_urlhost{$urlhost} /
	      $tcp, $tcp_urlhost_size{$urlhost} / 1024, 100 *
	      $tcp_urlhost_size{$urlhost} / $tcp_size, 100 *
	      $tcp_hit_urlhost{$urlhost} / $tcp_urlhost{$urlhost});
      last if (--$other_count == 0 and $other != 1);
    }
    if ($other) {
      writecache(N, '<other>', $other, $other_size, $other_hit);
      outline('other: ' . $other_urlhost . ' 2nd-level-domains', $other,
	      100 * $other / $tcp, $other_size / 1024, 100 * $other_size /
	      $tcp_size, 100 * $other_hit / $other);
    }
    outseperator();
    outline(Sum, $tcp, 100, $tcp_size / 1024, 100, 100 * $tcp_hit / $tcp);
    outstop();
    outtitle('Request-destinations by toplevel-domain', 9);
    outstart();
    outheader('destination',' request','% ','  kByte','% ','hit-%');
    outseperator();
    @counter = keys %tcp_urltld;
    $other_tld = $#counter + 1;
    $other = $tcp;
    $other_size = $tcp_size;
    $other_hit = $tcp_hit;
    $other_count = $opt_d;
    foreach $urltld (sort {$tcp_urltld{$b} <=> $tcp_urltld{$a}}
		     keys(%tcp_urltld)) {
      $other_tld--;
      $other -= $tcp_urltld{$urltld};
      $other_size -= $tcp_urltld_size{$urltld};
      $other_hit -= $tcp_hit_urltld{$urltld};
      writecache(O, $urltld, $tcp_urltld{$urltld}, $tcp_urltld_size{$urltld},
		 $tcp_hit_urltld{$urltld});
      outline($urltld, $tcp_urltld{$urltld}, 100 * $tcp_urltld{$urltld} /
	      $tcp, $tcp_urltld_size{$urltld} / 1024, 100 *
	      $tcp_urltld_size{$urltld} / $tcp_size, 100 *
	      $tcp_hit_urltld{$urltld} / $tcp_urltld{$urltld});
      last if (--$other_count == 0 and $other != 1);
    }
    if ($other) {
      writecache(O, '<other>', $other, $other_size, $other_hit);
      outline('other: ' . $other_tld . ' top-level-domains', $other, 100 *
	      $other / $tcp, $other_size / 1024, 100 * $other_size /
	      $tcp_size, 100 * $other_hit / $other);
    }
    outseperator();
    outline(Sum, $tcp, 100, $tcp_size / 1024, 100, 100 * $tcp_hit / $tcp);
    outstop();
  }
}

if ($opt_t or $opt_a) {
  if ($tcp == 0) {
    outtitle('TCP-Request-protocol: none', 10);
  } else {
    outtitle('TCP-Request-protocol', 10);
    outstart();
    outheader('protocol',' request','% ','  kByte','% ','hit-%');
    outseperator();
    foreach $urlprot (sort {$tcp_urlprot{$b} <=> $tcp_urlprot{$a}}
		      keys(%tcp_urlprot)) {
      writecache(P, $urlprot, $tcp_urlprot{$urlprot},
		 $tcp_urlprot_size{$urlprot}, $tcp_hit_urlprot{$urlprot});
      outline($urlprot, $tcp_urlprot{$urlprot}, 100 * $tcp_urlprot{$urlprot} /
	      $tcp, $tcp_urlprot_size{$urlprot} / 1024, 100 *
	      $tcp_urlprot_size{$urlprot} / $tcp_size, 100 *
	      $tcp_hit_urlprot{$urlprot} / $tcp_urlprot{$urlprot});
    }
    outseperator();
    outline(Sum, $tcp, 100, $tcp_size / 1024, 100, 100 * $tcp_hit / $tcp);
    outstop();
  }
  if ($tcp == 0) {
    outtitle('Requested content-type: none', 11);
  } else {
    outtitle('Requested content-type', 11);
    outstart();
    outheader('content-type',' request','% ','  kByte','% ','hit-%');
    outseperator();
    @counter = keys %tcp_content;
    $other_content = $#counter + 1;
    $other = $tcp;
    $other_size = $tcp_size;
    $other_hit = $tcp_hit;
    $other_count = $opt_t;
    foreach $content (sort {$tcp_content{$b} <=> $tcp_content{$a}}
		      keys(%tcp_content)) {
      $other_content--;
      $other -= $tcp_content{$content};
      $other_size -= $tcp_content_size{$content};
      $other_hit -= $tcp_hit_content{$content};
      writecache(Q, $content, $tcp_content{$content},
		 $tcp_content_size{$content}, $tcp_hit_content{$content});
      outline($content, $tcp_content{$content}, 100 * $tcp_content{$content} /
	      $tcp, $tcp_content_size{$content} / 1024, 100 *
	      $tcp_content_size{$content} / $tcp_size, 100 *
	      $tcp_hit_content{$content} / $tcp_content{$content});
      last if (--$other_count == 0 and $other != 1);
    }
    if ($other) {
      writecache(Q, '<other>', $other, $other_size, $other_hit);
      outline('other: '. $other_content . ' content-types', $other, 100 *
	      $other / $tcp, $other_size / 1024, 100 * $other_size /
	      $tcp_size, 100 * $other_hit / $other);
    }
    outseperator();
    outline(Sum, $tcp, 100, $tcp_size / 1024, 100, 100 * $tcp_hit / $tcp);
    outstop();
  }
  if ($tcp == 0) {
    outtitle('Requested extensions: none', 12);
  } else {
    outtitle('Requested extensions', 12);
    outstart();
    outheader('extensions',' request','% ','  kByte','% ','hit-%');
    outseperator();
    @counter = keys %tcp_urlext;
    $other_urlext = $#counter + 1;
    $other = $tcp;
    $other_size = $tcp_size;
    $other_hit = $tcp_hit;
    $other_count = $opt_t;
    foreach $urlext (sort {$tcp_urlext{$b} <=> $tcp_urlext{$a}}
		     keys(%tcp_urlext)) {
      $other_urlext--;
      $other -= $tcp_urlext{$urlext};
      $other_size -= $tcp_urlext_size{$urlext};
      $other_hit -= $tcp_hit_urlext{$urlext};
      writecache(R, $urlext, $tcp_urlext{$urlext}, $tcp_urlext_size{$urlext},
		 $tcp_hit_urlext{$urlext});
      outline($urlext, $tcp_urlext{$urlext}, 100 * $tcp_urlext{$urlext} /
	      $tcp, $tcp_urlext_size{$urlext} / 1024, 100 *
	      $tcp_urlext_size{$urlext} / $tcp_size, 100 *
	      $tcp_hit_urlext{$urlext} / $tcp_urlext{$urlext});
      last if (--$other_count == 0 and $other != 1);
    }
    if ($other) {
      writecache(R, '<other>', $other, $other_size, $other_hit);
      outline('other: '. $other_urlext . ' extensions', $other, 100 * $other /
	      $tcp, $other_size / 1024, 100 * $other_size / $tcp_size,
	      100 * $other_hit / $other);
    }
    outseperator();
    outline(Sum, $tcp, 100, $tcp_size / 1024, 100, 100 * $tcp_hit / $tcp);
    outstop();
  }
}

@format=(33,8,'%',9,'%',4,'kbs');
if ($opt_r or $opt_a) {
  if ($udp == 0) {
    outtitle('Incoming UDP-requests by host: none', 13);
  } else {
    outtitle('Incoming UDP-requests by host', 13);
    outstart();
    outheader('host',' request','hit-%','  kByte','hit-%','msec',' kB/sec');
    outseperator();
    foreach $neighbor (sort {$udp_requester{$b} <=> $udp_requester{$a}}
		       keys(%udp_requester)) {
      writecache(S, $neighbor, $udp_requester{$neighbor},
		 $udp_requester_size{$neighbor},
		 $udp_requester_time{$neighbor},
		 $udp_hit_requester{$neighbor},
		 $udp_hit_requester_size{$neighbor});
      outline($neighbor, $udp_requester{$neighbor}, 100 *
	      $udp_hit_requester{$neighbor} / $udp_requester{$neighbor},
	      $udp_requester_size{$neighbor} / 1024, 100 *
	      $udp_hit_requester_size{$neighbor} /
	      $udp_requester_size{$neighbor}, $udp_requester_time{$neighbor} /
	      $udp_requester{$neighbor}, 1000 *
	      $udp_requester_size{$neighbor} /
	      (1024 * $udp_requester_time{$neighbor}));
    }
    outseperator();
    outline(Sum, $udp, 100 * $udp_hit / $udp, $udp_size / 1024, 100 *
	    $udp_hit_size / $udp_size, $udp_time / $udp, 1000 * $udp_size /
	    (1024 * $udp_time));
    outstop();
  }

  if ($tcp == 0) {
    outtitle('Incoming TCP-Requests by host: none', 14);
  } else {
    outtitle('Incoming TCP-requests by host', 14);
    outstart();
    outheader('host',' request','hit-%','  kByte','hit-%','sec',' kB/sec');
    outseperator();
    @counter = keys %tcp_requester;
    $other_requester = $#counter + 1;
    $other = $tcp;
    $other_size = $tcp_size;
    $other_time = $tcp_time;
    $other_hit = $tcp_hit;
    $other_hit_size = $tcp_hit_size;
    $other_count = $opt_r;
    foreach $requester (sort {$tcp_requester{$b} <=> $tcp_requester{$a}}
			keys(%tcp_requester)) {
      $other_requester--;
      $other -= $tcp_requester{$requester};
      $other_size -= $tcp_requester_size{$requester};
      $other_time -= $tcp_requester_time{$requester};
      $other_hit -= $tcp_hit_requester{$requester};
      $other_hit_size -= $tcp_hit_requester_size{$requester};
      writecache(T, $requester, $tcp_requester{$requester},
		 $tcp_requester_size{$requester},
		 $tcp_requester_time{$requester},
		 $tcp_hit_requester{$requester},
		 $tcp_hit_requester_size{$requester});
      outline($requester, $tcp_requester{$requester}, 100 *
	      $tcp_hit_requester{$requester} / $tcp_requester{$requester},
	      $tcp_requester_size{$requester} / 1024, 100 *
	      $tcp_hit_requester_size{$requester} /
	      $tcp_requester_size{$requester}, $tcp_requester_time{$requester}
	      / (1000 * $tcp_requester{$requester}), 1000 *
	      $tcp_requester_size{$requester} / (1024 *
	      $tcp_requester_time{$requester}));
      last if(--$other_count == 0 and $other != 1);
    }
    if ($other) {
      writecache(T, '<other>', $other, $other_size, $other_time, $other_hit,
		 $other_hit_size);
      outline('other: ' . $other_requester . ' requesting hosts', $other, 100 *
	      $other_hit / $other, $other_size / 1024, 100 * $other_hit_size /
	      $other_size, $other_time / (1000 * $tcp), 1000 * $other_size /
	      (1024 * $tcp_time));
    }
    outseperator();
    outline(Sum, $tcp, 100 * $tcp_hit / $tcp, $tcp_size / 1024, 100 *
	    $tcp_hit_size / $tcp_size, $tcp_time / (1000 * $tcp), 1000 *
	    $tcp_size / (1024 * $tcp_time));
    outstop();
  }
}
close(CACHE);

if ($opt_w) {
  print("<address>$COPYRIGHT</address>\n</body></html>\n");
} else {
  print("\n\n\n$COPYRIGHT\n");
}

sub getfqdn {
  my ($host) = @_;
  if ($opt_n) {
    return $host;
  } elsif ($host =~ /^([0-9][0-9]{0,2}\.){3}[0-9][0-9]{0,2}$/) {
    $hostcache{$host} = addtonam($host) unless defined $hostcache{$host};
    return $hostcache{$host};
  } else {
    return $host;
  }
}

sub addtonam {
  my ($address) = shift (@_);
  my (@octets);
  my ($hostname, $aliases, $type, $len, $addr);
  my ($ip_number);
  @octets = split ('\.', $address) ;
  if ($#octets != 3) {
    undef;
  }
  $ip = pack ("CCCC", @octets[0..3]);
  ($hostname, $aliases, $type, $len, $addr) = gethostbyaddr ($ip, 2);
  if ($hostname) {
    $hostname;
  } else {
    $address;
  }
}

sub convertdate {
  my $date = shift(@_);
  if ($date) {
    my ($sec,$min,$hour,$mday,$mon,$year) = (localtime($date))[0,1,2,3,4,5,6];
    my $month = ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct',
		 'Nov','Dec')[$mon];
    my $retdate = sprintf("%02d.%s %02d %02d:%02d:%02d\n", $mday, $month,
			  $year, $hour, $min, $sec);
    chomp($retdate);
    return $retdate;
  } else {
    return '                  ';
  }
}

sub outtitle {
  my $print = shift(@_);
  my $name = shift(@_);
  if ($opt_w) {
    print("<h2><a name=\"$name\">$print</a></h2>\n");
  } else {
    print("\n# $print\n");
  }
}

sub outref {
  my $print = shift(@_);
  my $name = shift(@_);
  print("<li><a href=\"#$name\">$print</a>\n");
}

sub outstart {
  print("<table border=\"1\">\n") if ($opt_w);
}

sub outheader {
  my $print;
  my $no = 0;
  print('<tr>') if ($opt_w);
  foreach (@_) {
    $p = $_;
    if ($opt_w) {
      $p =~ s/ +/ /go;
      $p =~ s/(^ | $)//go;
      print("<th>$p");
    } elsif ($format[$no] =~ m#\%#o) {
      print(' ' x (6 - length($p)), substr($p,0,6), ' ');
    } elsif ($format[$no] =~ m#kbs#o) {
      print(substr($p,0,7) . ' ' x (7 - length($p)), ' ');
    } else {
      print(substr($p,0,$format[$no]) . ' ' x ($format[$no] - length($p)),
	    ' ');
    }
    $no++;
  }
  print('</th>') if ($opt_w);
  print("\n");
}

sub outline {
  my $print;
  my $no = 0;
  print('<tr>') if ($opt_w);
  foreach (@_) {
    $print = $_;
    if ($opt_w) {
      $print =~ s/ +/ /go;
      $print =~ s/ $//go;
      $print =~ s/</\&lt\;/go;
      $print =~ s/>/\&gt\;/go;
      if ($no == 0) {
	unless ($print =~ s/^ //go) {
	  print("<td><strong>$print</strong>");
	} else {
	  print("<td>$print");
	}
      } elsif ($format[$no] eq '%' or $format[$no] eq 'kbs') {
	if ($print eq '') {
	  print('<td>');
	} else {
	  printf("<td align=\"right\">%.2f", $print);
	}
      } elsif ($no == 1 or $print =~ m#^[\d\.e\-\+]+$#o) {
	printf("<td align=\"right\">%d", $print);
      } else {
	print("<td align=\"right\">$print");
      }
    } else {
      if ($no == 0) {
	if (length($print) > $format[$no]) {
	  print("$print\n" . ' ' x $format[$no], ' ');
	} else {
	  print($print .  ' ' x ($format[$no] - length($print)), ' ');
	}
      } elsif ($format[$no] =~ m#%#o) {
	if ($print eq ' ') {
	  printf(' ' x 7);
	} else {
	  printf("%6.2f ", $print);
	}
      } elsif ($format[$no] eq 'kbs') {
	printf("%7.2f ", $print);
      } else {
	$print = sprintf("%d", $print + .5) if $print =~ m#^[\d\.e\-\+]+$#o;
	print(' ' x ($format[$no] - length($print)) .
	      substr($print,0,$format[$no]), ' ');
      }
    }
    $no++;
  }
  print('</tr>') if ($opt_w);
  print("\n");
}

sub outseperator {
  my $print;
  print('<tr>') if ($opt_w);
  foreach $print (@format) {
    if ($opt_w) {
      print('<td>');
    } elsif ($print eq '%') {
      print('-' x 6, ' ');
    } elsif ($print eq 'kbs') {
      print('-' x 7, ' ');
    } else {
      print('-' x $print, ' ');
    }
  }
  print('</tr>') if ($opt_w);
  print("\n");
}

sub outstop {
  if ($opt_w) {
    print("</table>\n");
    print("<p><a href=\"#0\">Back to Top</a>\n");
    print("<hr>\n");
  }
}

sub writecache {
  if ($opt_o) {
    print CACHE join('µ', @_) . "\n";
  }
}
