#!/usr/bin/perl -w
#
# $Id: calamaris.pl,v 1.1 1997-12-23 20:52:59 cord Exp $
#
# DESCRIPTION: calamaris.pl - get statistic out of the Squid Native Log.
#
# Copyright (C) 1997 Cord Beermann
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
# ('Programming Perl Second Edition' by Larry Wall, Tom Christiansen
#  & Randal. L. Schwartz)


# Instructions:

# * Switch 'emulate_httpd_log' off

# * Pipe your Logfile in calamaris


# Example:

# cat access.log.1 access.log.0 |calamaris.pl


# Bugs and shortcomings

# * if you want to parse more than one Logfile (i.e. from the logfilerotate)
# you have to put them in chronological sorted order (oldest first) into
# calamaris, else you get wrong peak values. (Is this something that i should
# fix? Don't think so...)

# * Squid doesn't log outgoing UDP-Requests, so i can't put them into the
# statistics without parsing squid.conf. (Javier Puche
# (Javier.Puche@rediris.es) asked for this), but i don't think that i should
# put this into calamaris... (Check last point of 'Bugs and
# shortcomings'-section.)

# * It is written in perl. Yea, perl is a great language for something like
# this (also it is the only one i'm able to write something like this in).
# Calamaris was first intended as demo for what i wanted from a statistical
# software. (OK, it is fun to write it, and it is even more fun to recognize
# that many people use the script). For my Caches with about 150MB-Logfile per
# week it is OK, but for those people on a heavy loaded Parentcaches it is
# simply to slow. So if someone wants to rewrite calamaris in a faster
# language: Feel Free! (But respect the GNU-License)

# * Hmmm, while looking through those many different reports i generate, i
# think that i generate more than anybody ever wants to now about squid :-) So
# i added switches, so everybody can switch on or off the reports wanted. But
# this is also a disadvantage because of the many checks if set or not ...


# Todo

# * caching (so we don't have to keep all logfiles of the timerange we
# want a report about)


use vars qw($opt_a $opt_b $opt_c $opt_d $opt_h $opt_m $opt_n $opt_p $opt_r
	    $opt_s $opt_t $opt_u $opt_w);

use Getopt::Std;
use Sys::Hostname;

getopts('ab:cd:hmnprs:t:uw');

$COPYRIGHT='calamaris $Revision: 1.1 $, Copyright (C) 1997 Cord Beermann
calamaris comes with ABSOLUTELY NO WARRANTY. It is free software,
and you are welcome to redistribute it under certain conditions.
See source for details.

';

$USAGE='Usage: cat access.log | ' . $0 . ' [-achmpstuw]

Reports:
-a	all  (extracts all reports available)
-p	peak (measure peak requests)
-s	status (show verbose status reports)
-r n	requester (show n Requesters)
-t n	type (show n content-type, n extensions and requested protocols)
-d n	domain (show n Top-level and n second-level destinations)

-b n	benchmark (prints a hash for each n lines)
-n	nolookup (don\'t look IP-Numbers up)
-u	user (use ident information if available)

Output Format: (Default is plain text)
-m	mail (mail format)
-w	web  (HTML format)

Misc:
-c	copyright (prints the copyright)
-h	help (prints out this message)

';

die($USAGE, $COPYRIGHT) if ($opt_h);

die($COPYRIGHT) if ($opt_c);

if ($opt_b && $opt_b < 1) {
    die($USAGE);
} else {
    $|=1;
}

# initialize variables

$counter = $hier_counter = $hier_direct_counter = $hier_direct_size_sum =
    $hier_direct_time_sum = $hier_parent_counter = $hier_parent_size_sum =
    $hier_parent_time_sum = $hier_sibling_counter = $hier_sibling_size_sum =
    $hier_sibling_time_sum = $hier_size_sum = $hier_time_sum =
    $invalid_counter = $peak_all_hour = $peak_all_min = $peak_all_sec =
    $peak_tcp_hour = $peak_tcp_min = $peak_tcp_sec = $peak_udp_hour =
    $peak_udp_min = $peak_udp_sec = $size_sum = $tcp_counter =
    $tcp_hit_counter = $tcp_hit_size_sum = $tcp_hit_time_sum =
    $tcp_miss_counter = $tcp_miss_direct_counter = $tcp_miss_direct_size_sum =
    $tcp_miss_direct_time_sum = $tcp_miss_neighbor_hit_counter =
    $tcp_miss_neighbor_hit_size_sum = $tcp_miss_neighbor_hit_time_sum =
    $tcp_miss_neighbor_miss_counter = $tcp_miss_neighbor_miss_size_sum =
    $tcp_miss_neighbor_miss_time_sum = $tcp_miss_none_counter =
    $tcp_miss_none_size_sum = $tcp_miss_none_time_sum = $tcp_miss_size_sum =
    $tcp_miss_time_sum = $tcp_size_sum = $tcp_time_sum = $time_sum =
    $udp_counter = $udp_hit_counter = $udp_hit_size_sum = $udp_hit_time_sum =
    $udp_miss_counter = $udp_miss_size_sum = $udp_miss_time_sum =
    $udp_size_sum = $udp_time_sum = 0;

print("print a hash for each $opt_b lines:\n") if ($opt_b);

$runtime=time;

while (<>) {
    ($log_date, $log_reqtime, $log_requester, $log_status, $log_size,
     $log_method, $log_url, $log_ident, $log_hierarchie, $log_content, $foo) =
     split;

    if (not defined $foo or not defined $log_content or $foo ne '' or
	$log_content eq '' ) {
	chomp;
	warn ('invalid line: "' . $_ . "\"\n");
	$invalid_counter++;
	next;
    }

    $log_reqtime = .1 if $log_reqtime == 0;

    $requesterhost = getfqdn($log_requester);

    $log_hitorfail = (split(m#/#o,$log_status))[0];

    $log_size = .0000000001 if $log_size == 0;

    @url = split(m#/#o,$log_url);
    ($urlprot, $urlhost, $urlext) = (@url)[0,2,$#url];
    $urlext = '.<none>' if $#url <= 2;
    $urlext = '.<dynamic>' if $urlext =~ m#[\?\;\&]#o;

    unless (defined $urlhost) {
	$urlhost = $urlprot;
	$urlprot = '<none>';
    }

    $urlhost =~ s#^.*@##o;
    $urlhost =~ s#:.*$##o;
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

	if ($urltld =~ /\.(at|au|br|jp|mx|nz|uk)$/o) {
	    $urlhost = '*.' . pop(@list) . $urlhost;
	} else {
	    $urlhost = '*' . $urlhost;
	}
	$urltld = '*' . $urltld;
    } else {
	$urltld = $urlhost;
    }

    if ($opt_u) {
	$requester = $log_ident . '@' . $requesterhost;
    } else {
	$requester = $requesterhost;
    }

    ($log_hierarchie_method, $log_hierarchie_host) =
	(split(m#/#o, $log_hierarchie))[0,1];

    $log_content = '<unknown>' if $log_content eq '-';
    $log_content =~ tr/A-Z/a-z/;

    print('#') if ($opt_b && ($counter / $opt_b) eq int($counter / $opt_b));

    $counter++;
    $size_sum += $log_size;
    $time_sum += $log_reqtime;
    $method_counter{$log_method} = $method_size_sum{$log_method} =
	$method_time_sum{$log_method} = 0 unless defined
	$method_counter{$log_method};
    $method_counter{$log_method}++;
    $method_size_sum{$log_method} += $log_size;
    $method_time_sum{$log_method} += $log_reqtime;

    $starttime = $log_date if not defined $starttime or $log_date < $starttime;
    $endtime = $log_date if not defined $endtime or $log_date > $endtime;

    if ($opt_p || $opt_a) {
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
	$udp_counter++;
        $udp_size_sum += $log_size;
	$udp_time_sum += $log_reqtime;

	if ($opt_r || $opt_a) {
	    $udp_requester_counter{$requester} =
		$udp_requester_size_sum{$requester} =
		$udp_requester_time_sum{$requester} =
		$udp_hit_requester_counter{$requester} =
		$udp_hit_requester_size_sum{$requester} =
		$udp_hit_requester_time_sum{$requester} = 0 unless defined
		$udp_requester_counter{$requester};
	    $udp_requester_counter{$requester}++;
	    $udp_requester_size_sum{$requester} += $log_size;
	    $udp_requester_time_sum{$requester} += $log_reqtime;
	}

	if ($opt_p || $opt_a) {
	    $peak_udp_sec_pointer++;
	    $peak_udp_min_pointer++;
	    unshift(@peak_udp,$log_date);

	    $peak_udp_sec_pointer-- while $peak_udp[$peak_udp_sec_pointer - 1]
		< ($log_date - 1);

	    $peak_udp_min_pointer-- while $peak_udp[$peak_udp_min_pointer - 1]
		< ($log_date - 60);

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

	if ($log_hitorfail =~ /^UDP_HIT/o) {
	    $udp_hit_counter++;
	    $udp_hit_size_sum += $log_size;
	    $udp_hit_time_sum += $log_reqtime;
	    if ($opt_r || $opt_a) {
		$udp_hit_requester_counter{$requester}++;
		$udp_hit_requester_size_sum{$requester} += $log_size;
		$udp_hit_requester_time_sum{$requester} += $log_reqtime;
	    }
	    if ($opt_s || $opt_a) {
		$udp_hit_counter{$log_hitorfail} =
		    $udp_hit_size_sum{$log_hitorfail} =
		    $udp_hit_time_sum{$log_hitorfail} = 0 unless defined
		    $udp_hit_counter{$log_hitorfail};
		$udp_hit_counter{$log_hitorfail}++;
		$udp_hit_size_sum{$log_hitorfail} += $log_size;
		$udp_hit_time_sum{$log_hitorfail} += $log_reqtime;
	    }
	} else {
            $udp_miss_counter++;
	    $udp_miss_size_sum += $log_size;
	    $udp_miss_time_sum += $log_reqtime;
	    if ($opt_s || $opt_a) {
		$udp_miss_counter{$log_hitorfail} =
		    $udp_miss_size_sum{$log_hitorfail} =
		    $udp_miss_time_sum{$log_hitorfail} = 0 unless defined
		    $udp_miss_counter{$log_hitorfail};
		$udp_miss_counter{$log_hitorfail}++;
		$udp_miss_size_sum{$log_hitorfail} += $log_size;
		$udp_miss_time_sum{$log_hitorfail} += $log_reqtime;
	    }
	}
    } else {
	$tcp_counter++;
	$tcp_size_sum += $log_size;
	$tcp_time_sum += $log_reqtime;
	if ($opt_r || $opt_a) {
	    $tcp_requester_counter{$requester} =
		$tcp_requester_size_sum{$requester} =
		$tcp_requester_time_sum{$requester} =
		$tcp_hit_requester_counter{$requester} =
		$tcp_hit_requester_size_sum{$requester} = 0 unless defined
		$tcp_requester_counter{$requester};
	    $tcp_requester_counter{$requester}++;
	    $tcp_requester_size_sum{$requester} += $log_size;
	    $tcp_requester_time_sum{$requester} += $log_reqtime;
	}
	if ($opt_d || $opt_a) {
	    $tcp_url_counter{$urlhost} = $tcp_url_size_sum{$urlhost} =
		$tcp_hit_url_counter{$urlhost} = 0 unless defined
		$tcp_url_counter{$urlhost};
	    $tcp_url_counter{$urlhost}++;
	    $tcp_url_size_sum{$urlhost} += $log_size;
	    $tcp_urltld_counter{$urltld} = $tcp_urltld_size_sum{$urltld} =
		$tcp_hit_urltld_counter{$urltld} = 0 unless defined
		$tcp_urltld_counter{$urltld};
	    $tcp_urltld_counter{$urltld}++;
	    $tcp_urltld_size_sum{$urltld} += $log_size;
	}
	if ($opt_t || $opt_a) {
	    $tcp_urlprot_counter{$urlprot} = $tcp_urlprot_size_sum{$urlprot} =
		$tcp_hit_urlprot_counter{$urlprot} = 0 unless defined
		$tcp_urlprot_counter{$urlprot};
	    $tcp_urlprot_counter{$urlprot}++;
	    $tcp_urlprot_size_sum{$urlprot} += $log_size;
	}
	if ($opt_p || $opt_a) {
	    $peak_tcp_sec_pointer++;
	    $peak_tcp_min_pointer++;
	    unshift(@peak_tcp,$log_date);

	    $peak_tcp_sec_pointer-- while $peak_tcp[$peak_tcp_sec_pointer - 1]
		< ($log_date - 1);

	    $peak_tcp_min_pointer-- while $peak_tcp[$peak_tcp_min_pointer - 1]
		< ($log_date - 60);

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

	if ($opt_t || $opt_a) {
	    $tcp_content_counter{$log_content} =
		$tcp_content_size_sum{$log_content} =
		$tcp_hit_content_counter{$log_content} = 0 unless defined
		$tcp_content_counter{$log_content};
	    $tcp_content_counter{$log_content}++;
	    $tcp_content_size_sum{$log_content} += $log_size;
	    $tcp_urlext_counter{$urlext} = $tcp_urlext_size_sum{$urlext} =
		$tcp_hit_urlext_counter{$urlext} = 0 unless defined
		$tcp_urlext_counter{$urlext};
	    $tcp_urlext_counter{$urlext}++;
	    $tcp_urlext_size_sum{$urlext} += $log_size;
	}

	if ($log_hitorfail =~ /^TCP\w+HIT/o) {
	    $tcp_hit_counter++;
	    $tcp_hit_size_sum += $log_size;
	    $tcp_hit_time_sum += $log_reqtime;
	    if ($opt_s || $opt_a) {
		$tcp_hit_counter{$log_hitorfail} =
		    $tcp_hit_size_sum{$log_hitorfail} =
		    $tcp_hit_time_sum{$log_hitorfail} = 0 unless defined
		    $tcp_hit_counter{$log_hitorfail};
		$tcp_hit_counter{$log_hitorfail}++;
		$tcp_hit_size_sum{$log_hitorfail} += $log_size;
		$tcp_hit_time_sum{$log_hitorfail} += $log_reqtime;
	    }
	    if ($opt_r || $opt_a) {
		$tcp_hit_requester_counter{$requester}++;
		$tcp_hit_requester_size_sum{$requester} += $log_size;
	    }
	    if ($opt_d || $opt_a) {
		$tcp_hit_url_counter{$urlhost}++;
		$tcp_hit_urltld_counter{$urltld}++;
	    }
	    if ($opt_t || $opt_a) {
		$tcp_hit_content_counter{$log_content}++;
		$tcp_hit_urlext_counter{$urlext}++;
		$tcp_hit_urlprot_counter{$urlprot}++;
	    }
	} elsif (($log_hierarchie_method eq 'NONE') or
		 ($log_hitorfail =~ /^ERR_/o)) {
	    $tcp_miss_none_counter++;
	    $tcp_miss_none_size_sum += $log_size;
	    $tcp_miss_none_time_sum += $log_reqtime;
	    if ($opt_s || $opt_a) {
		$tcp_miss_none_counter{$log_hitorfail} =
		    $tcp_miss_none_size_sum{$log_hitorfail} =
		    $tcp_miss_none_time_sum{$log_hitorfail} = 0 unless defined
		    $tcp_miss_none_counter{$log_hitorfail};
		$tcp_miss_none_counter{$log_hitorfail}++;
		$tcp_miss_none_size_sum{$log_hitorfail} += $log_size;
		$tcp_miss_none_time_sum{$log_hitorfail} += $log_reqtime;
	    }
	} else {
	    $tcp_miss_counter++;
	    $tcp_miss_size_sum += $log_size;
	    $tcp_miss_time_sum += $log_reqtime;
	    if ($opt_s || $opt_a) {
		$tcp_miss_counter{$log_hitorfail} =
		    $tcp_miss_size_sum{$log_hitorfail} =
		    $tcp_miss_time_sum{$log_hitorfail} = 0 unless defined
		    $tcp_miss_counter{$log_hitorfail};
		$tcp_miss_counter{$log_hitorfail}++;
		$tcp_miss_size_sum{$log_hitorfail} += $log_size;
		$tcp_miss_time_sum{$log_hitorfail} += $log_reqtime;
	    }
	    if ($opt_r || $opt_a) {
		$tcp_miss_requester_counter{$requester} =
		    $tcp_miss_requester_size_sum{$requester} = 0 unless defined
		    $tcp_miss_requester_counter{$requester};
		$tcp_miss_requester_counter{$requester}++;
		$tcp_miss_requester_size_sum{$requester} += $log_size;
	    }
	    if ($log_hierarchie_method =~ /(DIRECT|SOURCE_FASTEST)/o) {
		$tcp_miss_direct_counter++;
		$tcp_miss_direct_size_sum += $log_size;
		$tcp_miss_direct_time_sum += $log_reqtime;
	    } elsif ($log_hierarchie_method =~ /(PARENT|SIBLING)\w+HIT/o) {
		$tcp_miss_neighbor_hit_counter++;
		$tcp_miss_neighbor_hit_time_sum += $log_reqtime;
		$tcp_miss_neighbor_hit_size_sum += $log_size;
		$tcp_miss_neighbor_hit_counter{$log_hierarchie_host} =
		    $tcp_miss_neighbor_hit_size_sum{$log_hierarchie_host} =
		    $tcp_miss_neighbor_hit_time_sum{$log_hierarchie_host} = 0
		    unless defined
		    $tcp_miss_neighbor_hit_counter{$log_hierarchie_host};
		$tcp_miss_neighbor_hit_counter{$log_hierarchie_host}++;
		$tcp_miss_neighbor_hit_size_sum{$log_hierarchie_host} +=
		    $log_size;
		$tcp_miss_neighbor_hit_time_sum{$log_hierarchie_host} +=
		    $log_reqtime;
	    } elsif ($log_hierarchie_method =~
		     /(PARENT_MISS|(DEFAULT|FIRST_UP|SINGLE|PASSTHROUGH|ROUNDROBIN)_PARENT)/o) {
		$tcp_miss_neighbor_miss_counter++;
		$tcp_miss_neighbor_miss_size_sum += $log_size;
		$tcp_miss_neighbor_miss_time_sum += $log_reqtime;
		$tcp_miss_neighbor_counter{$log_hierarchie_host} =
		    $tcp_miss_neighbor_miss_size_sum{$log_hierarchie_host} =
		    $tcp_miss_neighbor_miss_time_sum{$log_hierarchie_host} = 0
		    unless defined
		    $tcp_miss_neighbor_counter{$log_hierarchie_host};
		$tcp_miss_neighbor_miss_counter{$log_hierarchie_host}++;
		$tcp_miss_neighbor_miss_size_sum{$log_hierarchie_host} +=
		    $log_size;
		$tcp_miss_neighbor_miss_time_sum{$log_hierarchie_host} +=
		    $log_reqtime;
	    } else {
		warn("unknown log_hierarchie_method: $log_hierarchie_method\n");
	    }
	}
	if ($log_hierarchie_method ne 'NONE') {
	    $hier_counter++;
	    $hier_size_sum += $log_size;
	    $hier_time_sum += $log_reqtime;

	    if ($log_hierarchie_method =~ /(DIRECT|SOURCE_FASTEST)/o) {
		$hier_direct_counter++;
		$hier_direct_size_sum += $log_size;
		$hier_direct_time_sum += $log_reqtime;
		if ($opt_s || $opt_a) {
		    $hier_direct_counter{$log_hierarchie_method} =
			$hier_direct_size_sum{$log_hierarchie_method} =
			$hier_direct_time_sum{$log_hierarchie_method} = 0
			unless defined
			$hier_direct_counter{$log_hierarchie_method};
		    $hier_direct_counter{$log_hierarchie_method}++;
		    $hier_direct_size_sum{$log_hierarchie_method} += $log_size;
		    $hier_direct_time_sum{$log_hierarchie_method} += $log_reqtime;
		}
	    } elsif ($log_hierarchie_method =~ /(PARENT|SIBLING)\w+HIT/o) {
		$hier_sibling_counter++;
		$hier_sibling_size_sum += $log_size;
		$hier_sibling_time_sum += $log_reqtime;
		if ($opt_s || $opt_a) {
		    $hier_sibling_counter{$log_hierarchie_method} =
			$hier_sibling_size_sum{$log_hierarchie_method} =
			$hier_sibling_time_sum{$log_hierarchie_method} = 0
			unless defined
			$hier_sibling_counter{$log_hierarchie_method};
		    $hier_sibling_counter{$log_hierarchie_method}++;
		    $hier_sibling_size_sum{$log_hierarchie_method} += $log_size;
		    $hier_sibling_time_sum{$log_hierarchie_method} += $log_reqtime;
		}
		$hier_neighbor_counter{$log_hierarchie_host} =
		    $hier_neighbor_size_sum{$log_hierarchie_host} =
		    $hier_neighbor_time_sum{$log_hierarchie_host} = 0 unless
		    $hier_neighbor_counter{$log_hierarchie_host};
		$hier_neighbor_counter{$log_hierarchie_host}++;
		$hier_neighbor_size_sum{$log_hierarchie_host} += $log_size;
		$hier_neighbor_time_sum{$log_hierarchie_host} += $log_reqtime;
		if ($opt_s || $opt_a) {
		    $hier_neighbor_state_counter{$log_hierarchie_host}{$log_hierarchie_method} =
			$hier_neighbor_state_size_sum{$log_hierarchie_host}{$log_hierarchie_method} =
			$hier_neighbor_state_time_sum{$log_hierarchie_host}{$log_hierarchie_method} = 0 unless
			$hier_neighbor_state_counter{$log_hierarchie_host}{$log_hierarchie_method};
		    $hier_neighbor_state_counter{$log_hierarchie_host}{$log_hierarchie_method}++;
		    $hier_neighbor_state_size_sum{$log_hierarchie_host}{$log_hierarchie_method} += $log_size;
		    $hier_neighbor_state_time_sum{$log_hierarchie_host}{$log_hierarchie_method} += $log_reqtime;
		}
	    } elsif ($log_hierarchie_method =~ /(PARENT_MISS|(DEFAULT|FIRST_UP|SINGLE|PASSTHROUGH|ROUNDROBIN)_PARENT)/o) {
		$hier_parent_counter++;
		$hier_parent_size_sum += $log_size;
		$hier_parent_time_sum += $log_reqtime;
		if ($opt_s || $opt_a) {
		    $hier_parent_counter{$log_hierarchie_method} =
			$hier_parent_size_sum{$log_hierarchie_method} =
			$hier_parent_time_sum{$log_hierarchie_method} = 0 unless
			defined $hier_parent_counter{$log_hierarchie_method};
		    $hier_parent_counter{$log_hierarchie_method}++;
		    $hier_parent_size_sum{$log_hierarchie_method} += $log_size;
		    $hier_parent_time_sum{$log_hierarchie_method} += $log_reqtime;
		}
		$hier_neighbor_counter{$log_hierarchie_host} =
		    $hier_neighbor_size_sum{$log_hierarchie_host} =
		    $hier_neighbor_time_sum{$log_hierarchie_host} = 0 unless
		    defined $hier_neighbor_counter{$log_hierarchie_host};
		$hier_neighbor_counter{$log_hierarchie_host}++;
		$hier_neighbor_size_sum{$log_hierarchie_host} += $log_size;
		$hier_neighbor_time_sum{$log_hierarchie_host} += $log_reqtime;
		if ($opt_s || $opt_a) {
		    $hier_neighbor_state_counter{$log_hierarchie_host}{$log_hierarchie_method} =
			$hier_neighbor_state_size_sum{$log_hierarchie_host}{$log_hierarchie_method} =
			$hier_neighbor_state_time_sum{$log_hierarchie_host}{$log_hierarchie_method} = 0 unless
			$hier_neighbor_state_counter{$log_hierarchie_host}{$log_hierarchie_method};
		    $hier_neighbor_state_counter{$log_hierarchie_host}{$log_hierarchie_method}++;
		    $hier_neighbor_state_size_sum{$log_hierarchie_host}{$log_hierarchie_method} += $log_size;
		    $hier_neighbor_state_time_sum{$log_hierarchie_host}{$log_hierarchie_method} += $log_reqtime;
		}
	    } else {
		warn("unknown log_hierarchie_method: $log_hierarchie_method\n");
	    }
	}
    }
}

$runtime=time - $runtime;

### Yea! File read. Now give the output...

if ($counter == 0) {
    print('no requests found');
    exit(0);
}

    $date_start = convert_date($starttime);
    $date_stop = convert_date($endtime);
    if ($opt_p || $opt_a) {
	$date_peak_udp_hour = convert_date($peak_udp_hour_time);
	$date_peak_tcp_hour = convert_date($peak_tcp_hour_time);
	$date_peak_all_hour = convert_date($peak_all_hour_time);
	$date_peak_udp_min = convert_date($peak_udp_min_time);
	$date_peak_tcp_min = convert_date($peak_tcp_min_time);
	$date_peak_all_min = convert_date($peak_all_min_time);
	$date_peak_udp_sec = convert_date($peak_udp_sec_time);
	$date_peak_tcp_sec = convert_date($peak_tcp_sec_time);
	$date_peak_all_sec = convert_date($peak_all_sec_time);
    }

printf("Subject: %s Squid-Report (%s - %s)\n\n", hostname() , $date_start,
       $date_stop) if ($opt_m);

if ($opt_w) {
    print("<html><head><title>Squid-Report</title></head><body>\n");
    printf("<h1>%s Squid-Report (%s - %s)</h1>\n", hostname() , $date_start,
	   $date_stop);
} else {
    printf("%s Squid-Report (%s - %s)\n", hostname() , $date_start,
	   $date_stop);
}

@format=(17,8);
reporttitle('Summary for ' . hostname());
reportstart();
reportline('lines parsed:', $counter);
reportline('invalid lines:', $invalid_counter);
reportline('parse time (sec):', $runtime);
reportstop();

@format=(3,4,18,5,18,7,18);
if ($opt_p || $opt_a) {
    reporttitle('Incoming request peak per protocol');
    reportstart();
    reportheader(' ', ' sec', 'peak begins at', ' min', 'peak begins at',
		 '  hour', 'peak begins at');
    reportsep();
    reportline('UDP', $peak_udp_sec, $date_peak_udp_sec, $peak_udp_min,
	       $date_peak_udp_min, $peak_udp_hour, $date_peak_udp_hour);
    reportline('TCP', $peak_tcp_sec, $date_peak_tcp_sec, $peak_tcp_min,
	       $date_peak_tcp_min, $peak_tcp_hour, $date_peak_tcp_hour);
    reportsep();
    reportline('ALL', $peak_all_sec, $date_peak_all_sec, $peak_all_min,
	       $date_peak_all_min, $peak_all_hour, $date_peak_all_hour);
    reportstop();
}

@format=(35,7,'%',8,'%',4,'kbs');
if ($counter == 0) {
    reporttitle('Incoming requests by method: none');
} else {
    reporttitle('Incoming requests by method');
    reportstart();
    reportheader('method','request','% ','  kByte','% ',' sec',' kB/sec');
    reportsep();
    foreach $method (sort {$method_counter{$b} <=> $method_counter{$a}}
		     keys(%method_counter)) {
	reportline($method, $method_counter{$method}, 100 *
		   $method_counter{$method} / $counter,
		   $method_size_sum{$method} / 1024, 100 *
		   $method_size_sum{$method} / $size_sum,
		   $method_time_sum{$method} / (1000 *
		   $method_counter{$method}), 1000 * $method_size_sum{$method}
		   / (1024 * $method_time_sum{$method}));
    }
    reportsep();
    reportline('Sum', $counter, 100, $size_sum / 1024, 100, $time_sum /
	       ($counter * 1000), 1000 * $size_sum / (1024 * $time_sum));
    reportstop();
}

if ($udp_counter == 0) {
    reporttitle('Incoming UDP-requests by status: none');
} else {
    reporttitle('Incoming UDP-requests by status');
    reportstart();
    reportheader('status','request','% ','  kByte','% ','msec',' kB/sec');
    reportsep();

    if ($udp_hit_counter == 0) {
	reportline('HIT',0,0,0,0,0,0);
    } else {
	reportline('HIT', $udp_hit_counter, 100 * $udp_hit_counter /
		   $udp_counter, $udp_hit_size_sum / 1024, 100 *
		   $udp_hit_size_sum / $udp_size_sum, $udp_hit_time_sum /
		   $udp_hit_counter, 1000 * $udp_hit_size_sum / (1024 *
		   $udp_hit_time_sum));
	foreach $hitorfail (sort {$udp_hit_counter{$b} <=>
				  $udp_hit_counter{$a}}
				  keys(%udp_hit_counter)) {
	    reportline(' ' . $hitorfail, $udp_hit_counter{$hitorfail}, 100 *
		       $udp_hit_counter{$hitorfail} / $udp_counter,
		       $udp_hit_size_sum{$hitorfail} / 1024, 100 *
		       $udp_hit_size_sum{$hitorfail} / ($udp_size_sum),
		       $udp_hit_time_sum{$hitorfail} /
		       $udp_hit_counter{$hitorfail}, 1000 *
		       $udp_hit_size_sum{$hitorfail} / (1024 *
		       $udp_hit_time_sum{$hitorfail}));
	}
    }

    if ($udp_miss_counter == 0) {
	reportline('MISS',0,0,0,0,0,0);
    } else {
	reportline('MISS', $udp_miss_counter, 100 * $udp_miss_counter /
		   $udp_counter, $udp_miss_size_sum / 1024, 100 *
		   $udp_miss_size_sum / $udp_size_sum, $udp_miss_time_sum /
		   $udp_miss_counter, 1000 * $udp_miss_size_sum / (1024 *
		   $udp_miss_time_sum));
	foreach $hitorfail (sort {$udp_miss_counter{$b} <=>
			    $udp_miss_counter{$a}} keys(%udp_miss_counter)) {
	    reportline(' ' . $hitorfail, $udp_miss_counter{$hitorfail}, 100 *
		       $udp_miss_counter{$hitorfail} / $udp_counter,
		       $udp_miss_size_sum{$hitorfail} / 1024, 100 *
		       $udp_miss_size_sum{$hitorfail} / $udp_size_sum,
		       $udp_miss_time_sum{$hitorfail} /
		       $udp_miss_counter{$hitorfail}, 1000 *
		       $udp_miss_size_sum{$hitorfail} / (1024 *
		       $udp_miss_time_sum{$hitorfail}));
	}
    }
    reportsep();
    reportline('Sum', $udp_counter, ' ', $udp_size_sum / 1024, ' ',
	       $udp_time_sum / $udp_counter, 1000 * $udp_size_sum / (1024 *
	       $udp_time_sum));
    reportstop();
}

if ($tcp_counter == 0) {
    reporttitle('Incoming TCP-requests by status: none');
} else {
    reporttitle('Incoming TCP-requests by status');
    reportstart();
    reportheader('status','request','% ','  kByte','% ',' sec',' kB/sec');
    reportsep();

    if ($tcp_hit_counter == 0) {
	reportline('HIT',0,0,0,0,0,0);
    } else {
	reportline('HIT', $tcp_hit_counter, 100 * $tcp_hit_counter /
		   $tcp_counter, $tcp_hit_size_sum / 1024, 100 *
		   $tcp_hit_size_sum / $tcp_size_sum, $tcp_hit_time_sum /
		   (1000 * $tcp_hit_counter), 1000 * $tcp_hit_size_sum / (1024
		   * $tcp_hit_time_sum));
	foreach $hitorfail (sort {$tcp_hit_counter{$b} <=>
			    $tcp_hit_counter{$a}} keys(%tcp_hit_counter)) {
	    reportline(' ' . $hitorfail, $tcp_hit_counter{$hitorfail}, 100 *
		       $tcp_hit_counter{$hitorfail} / $tcp_counter,
		       $tcp_hit_size_sum{$hitorfail} / 1024, 100 *
		       $tcp_hit_size_sum{$hitorfail} / $tcp_size_sum,
		       $tcp_hit_time_sum{$hitorfail} / (1000 *
		       $tcp_hit_counter{$hitorfail}), 1000 *
		       $tcp_hit_size_sum{$hitorfail} / (1024 *
		       $tcp_hit_time_sum{$hitorfail}));
	}
    }

    if ($tcp_miss_counter == 0) {
	reportline('MISS',0,0,0,0,0,0);
    } else {
	reportline('MISS', $tcp_miss_counter, 100 * $tcp_miss_counter /
		   $tcp_counter, $tcp_miss_size_sum / 1024, 100 *
		   $tcp_miss_size_sum / $tcp_size_sum, $tcp_miss_time_sum /
		   (1000 * $tcp_miss_counter), 1000 * $tcp_miss_size_sum /
		   (1024 * $tcp_miss_time_sum));
	foreach $hitorfail (sort {$tcp_miss_counter{$b} <=>
			    $tcp_miss_counter{$a}} keys(%tcp_miss_counter)) {
	    reportline(' ' . $hitorfail, $tcp_miss_counter{$hitorfail}, 100 *
		   $tcp_miss_counter{$hitorfail} / $tcp_counter,
		   $tcp_miss_size_sum{$hitorfail} / 1024, 100 *
		   $tcp_miss_size_sum{$hitorfail} / $tcp_size_sum,
		   $tcp_miss_time_sum{$hitorfail} / (1000 *
		   $tcp_miss_counter{$hitorfail}), 1000 *
		   $tcp_miss_size_sum{$hitorfail} / (1024 *
		   $tcp_miss_time_sum{$hitorfail}));
	}
    }

    if ($tcp_miss_none_counter == 0) {
	reportline('ERROR',0,0,0,0,0,0);
    } else {
	reportline('ERROR', $tcp_miss_none_counter, 100 *
		   $tcp_miss_none_counter / $tcp_counter,
		   $tcp_miss_none_size_sum / 1024, 100 *
		   $tcp_miss_none_size_sum / $tcp_size_sum,
		   $tcp_miss_none_time_sum / (1000 * $tcp_miss_none_counter),
		   1000 * $tcp_miss_none_size_sum / (1024 *
		   $tcp_miss_none_time_sum));

	foreach $hitorfail (sort {$tcp_miss_none_counter{$b} <=>
			    $tcp_miss_none_counter{$a}}
			    keys(%tcp_miss_none_counter)) {
	    reportline(' ' .  $hitorfail, $tcp_miss_none_counter{$hitorfail},
		       100 * $tcp_miss_none_counter{$hitorfail} /
		       $tcp_counter, $tcp_miss_none_size_sum{$hitorfail} /
		       1024, 100 * $tcp_miss_none_size_sum{$hitorfail} /
		       $tcp_size_sum, $tcp_miss_none_time_sum{$hitorfail} /
		       (1000 * $tcp_miss_none_counter{$hitorfail}), 1000 *
		       $tcp_miss_none_size_sum{$hitorfail} / (1024 *
		       $tcp_miss_none_time_sum{$hitorfail}));
	}
    }

    reportsep();
    reportline('Sum', $tcp_counter, ' ', $tcp_size_sum / 1024, ' ',
	       $tcp_time_sum / (1000 * $tcp_counter), 1000 * $tcp_size_sum /
	       (1024 * $tcp_time_sum));
    reportstop();
}

if ($hier_counter == 0) {
    reporttitle('Outgoing requests by status: none');
} else {
    reporttitle('Outgoing requests by status');
    reportstart();
    reportheader('status','request','% ','  kByte','% ',' sec',' kB/sec');
    reportsep();

    if ($hier_direct_counter == 0) {
	reportline('DIRECT',0,0,0,0,0,0);
    } else {
	reportline('DIRECT Fetch from Source', $hier_direct_counter, 100 *
		   $hier_direct_counter / $hier_counter, $hier_direct_size_sum
		   / 1024, 100 * $hier_direct_size_sum / $hier_size_sum,
		   $hier_direct_time_sum / (1000 * $hier_direct_counter), 1000
		   * $hier_direct_size_sum / (1024 * $hier_direct_time_sum));
	foreach $hitorfail (sort {$hier_direct_counter{$b} <=>
			    $hier_direct_counter{$a}}
			    keys(%hier_direct_counter)) {
	    reportline(' ' . $hitorfail, $hier_direct_counter{$hitorfail}, 100
		       * $hier_direct_counter{$hitorfail} / $hier_counter,
		       $hier_direct_size_sum{$hitorfail} / 1024, 100 *
		       $hier_direct_size_sum{$hitorfail} / $hier_size_sum,
		       $hier_direct_time_sum{$hitorfail} / (1000 *
		       $hier_direct_counter{$hitorfail}), 1000 *
		       $hier_direct_size_sum{$hitorfail} / (1024 *
		       $hier_direct_time_sum{$hitorfail}));
	}
    }

    if ($hier_sibling_counter == 0) {
	reportline('SIBLING',0,0,0,0,0,0);
    } else {
	reportline('HIT on Sibling or Parent Cache', $hier_sibling_counter,
		   100 * $hier_sibling_counter / $hier_counter,
		   $hier_sibling_size_sum / 1024, 100 * $hier_sibling_size_sum
		   / $hier_size_sum, $hier_sibling_time_sum / (1000 *
		   $hier_sibling_counter), 1000 * $hier_sibling_size_sum /
		   (1024 * $hier_sibling_time_sum) );

	foreach $hitorfail (sort {$hier_sibling_counter{$b} <=>
				  $hier_sibling_counter{$a}}
			    keys(%hier_sibling_counter)) {
	    reportline(' ' . $hitorfail, $hier_sibling_counter{$hitorfail},
		       100 * $hier_sibling_counter{$hitorfail} /
		       $hier_counter, $hier_sibling_size_sum{$hitorfail} /
		       1024, 100 * $hier_sibling_size_sum{$hitorfail} /
		       $hier_size_sum, $hier_sibling_time_sum{$hitorfail} /
		       (1000 * $hier_sibling_counter{$hitorfail}), 1000 *
		       $hier_sibling_size_sum{$hitorfail} / (1024 *
		       $hier_sibling_time_sum{$hitorfail}));
	}
    }

    if ($hier_parent_counter == 0) {
	reportline('PARENT',0,0,0,0,0,0);
    } else {
	reportline('FETCH from Parent Cache', $hier_parent_counter, 100 *
		   $hier_parent_counter / $hier_counter, $hier_parent_size_sum
		   / 1024, 100 * $hier_parent_size_sum / $hier_size_sum,
		   $hier_parent_time_sum / (1000 * $hier_parent_counter), 1000
		   * $hier_parent_size_sum / (1024 * $hier_parent_time_sum) );

	foreach $hitorfail (sort {$hier_parent_counter{$b} <=>
				  $hier_parent_counter{$a}}
			    keys(%hier_parent_counter)) {
	    reportline(' ' . $hitorfail, $hier_parent_counter{$hitorfail}, 100
		       * $hier_parent_counter{$hitorfail} / $hier_counter,
		       $hier_parent_size_sum{$hitorfail} / 1024, 100 *
		       $hier_parent_size_sum{$hitorfail} / $hier_size_sum,
		       $hier_parent_time_sum{$hitorfail} / (1000 *
		       $hier_parent_counter{$hitorfail}), 1000 *
		       $hier_parent_size_sum{$hitorfail} / (1024 *
		       $hier_parent_time_sum{$hitorfail}));
	}
    }

    reportsep();
    reportline('Sum', $hier_counter, ' ', $hier_size_sum / 1024, ' ',
	       $hier_time_sum / (1000 * $hier_counter), 1000 * $hier_size_sum
	       / (1024 * $hier_time_sum));
    reportstop();
}

if ($tcp_miss_counter == 0) {
    reporttitle('Outgoing requests by destination: none');
} else {
    reporttitle('Outgoing requests by destination');
    reportstart();
    reportheader('neighbor type','request','% ','  kByte','% ',' sec',' kB/sec');
    reportsep();

    unless ($tcp_miss_direct_counter == 0) {
	reportline(DIRECT, $hier_direct_counter, 100 * $hier_direct_counter /
		   $hier_counter, $hier_direct_size_sum / 1024, 100 *
		   $hier_direct_size_sum / $hier_size_sum,
		   $hier_direct_time_sum / (1000 * $hier_direct_counter), 1000
		   * $hier_direct_size_sum / (1024 * $hier_direct_time_sum));
    }

    foreach $neighbor (sort {$hier_neighbor_counter{$b} <=>
			     $hier_neighbor_counter{$a}}
		       keys(%hier_neighbor_counter)) {
	reportline($neighbor, $hier_neighbor_counter{$neighbor}, 100 *
		   $hier_neighbor_counter{$neighbor} / $hier_counter,
		   $hier_neighbor_size_sum{$neighbor} / 1024, 100 *
		   $hier_neighbor_size_sum{$neighbor} / $hier_size_sum,
		   $hier_neighbor_time_sum{$neighbor} / (1000 *
		   $hier_counter), 1000 * $hier_neighbor_size_sum{$neighbor} /
		   (1024 * $hier_neighbor_time_sum{$neighbor}));
	foreach $state (sort {$hier_neighbor_state_counter{$neighbor}{$b} <=>
			      $hier_neighbor_state_counter{$neighbor}{$a}}
			keys(%{$hier_neighbor_state_counter{$neighbor}})) {
	    reportline(' ' .  $state,
		       $hier_neighbor_state_counter{$neighbor}{$state}, 100 *
		       $hier_neighbor_state_counter{$neighbor}{$state} /
		       $hier_counter,
		       $hier_neighbor_state_size_sum{$neighbor}{$state} /
		       1024, 100 *
		       $hier_neighbor_state_size_sum{$neighbor}{$state} /
		       $hier_size_sum,
		       $hier_neighbor_state_time_sum{$neighbor}{$state} /
		       (1000 * $hier_counter + 1), 1000 *
		       $hier_neighbor_state_size_sum{$neighbor}{$state} /
		       (1024 *
		       $hier_neighbor_state_time_sum{$neighbor}{$state}));
	}
    }

    reportsep();
    reportline('Sum', $hier_counter, ' ', $hier_size_sum / 1024, ' ',
	       $hier_time_sum / (1000 * $hier_counter), 1000 * $hier_size_sum
	       / (1024 * $hier_time_sum));
    reportstop();
}

@format=(41,7,'%',8,'%','%');
if ($opt_d || $opt_a) {
    if ($tcp_counter == 0) {
	reporttitle('Request-destinations: none');
    } else {
	reporttitle('Request-destinations by 2ndlevel-domain');
	reportstart();
	reportheader('destination','request','% ','  kByte','% ','hit-%');
	reportsep();
	@counter = keys %tcp_url_counter;
	$other_host = $#counter + 1;
	$other_counter = $tcp_counter;
	$other_size_sum = $tcp_size_sum;
	$other_hit_counter = $tcp_hit_counter;
	$linecounter = $opt_d;

	foreach $urlhost (sort {$tcp_url_counter{$b} <=> $tcp_url_counter{$a}}
			  keys(%tcp_url_counter)) {
	    $other_host--;
	    $other_counter -= $tcp_url_counter{$urlhost};
	    $other_size_sum -= $tcp_url_size_sum{$urlhost};
	    $other_hit_counter -= $tcp_hit_url_counter{$urlhost};
	    reportline($urlhost, $tcp_url_counter{$urlhost}, 100 *
		       $tcp_url_counter{$urlhost} / $tcp_counter,
		       $tcp_url_size_sum{$urlhost} / 1024, 100 *
		       $tcp_url_size_sum{$urlhost} / $tcp_size_sum, 100 *
		       $tcp_hit_url_counter{$urlhost} /
		       $tcp_url_counter{$urlhost});
	    last if (--$linecounter == 0 && $other_counter != 1);
	}

	reportline('other: ' . $other_host . ' 2nd-level-domains',
		   $other_counter, 100 * $other_counter / $tcp_counter,
		   $other_size_sum / 1024, 100 * $other_size_sum /
		   $tcp_size_sum, 100 * $other_hit_counter / $other_counter)
		   if $other_counter;
	reportsep();
	reportline('Sum', $tcp_counter, 100, $tcp_size_sum / 1024, 100, 100 *
		   $tcp_hit_counter / $tcp_counter);
	reportstop();

	reporttitle('Request-destinations by toplevel-domain');
	reportstart();
	reportheader('destination','request','% ','  kByte','% ','hit-%');
	reportsep();

	@counter = keys %tcp_urltld_counter;
	$other_tld = $#counter + 1;
	$other_counter = $tcp_counter;
	$other_size_sum = $tcp_size_sum;
	$other_hit_counter = $tcp_hit_counter;
	$linecounter = $opt_d;

	foreach $urltld (sort {$tcp_urltld_counter{$b} <=>
			       $tcp_urltld_counter{$a}}
			 keys(%tcp_urltld_counter)) {

	    $other_tld--;
	    $other_counter -= $tcp_urltld_counter{$urltld};
	    $other_size_sum -= $tcp_urltld_size_sum{$urltld};
	    $other_hit_counter -= $tcp_hit_urltld_counter{$urltld};
	    reportline($urltld, $tcp_urltld_counter{$urltld}, 100 *
		       $tcp_urltld_counter{$urltld} / $tcp_counter,
		       $tcp_urltld_size_sum{$urltld} / 1024, 100 *
		       $tcp_urltld_size_sum{$urltld} / $tcp_size_sum, 100 *
		       $tcp_hit_urltld_counter{$urltld} /
		       $tcp_urltld_counter{$urltld});
	    last if (--$linecounter == 0 && $other_counter != 1);
	}
	reportline('other: ' . $other_tld . ' top-level-domains',
		   $other_counter, 100 * $other_counter / $tcp_counter,
		   $other_size_sum / 1024, 100 * $other_size_sum /
		   $tcp_size_sum, 100 * $other_hit_counter / $other_counter)
		   if $other_counter;
	reportsep();
	reportline(Sum, $tcp_counter, 100, $tcp_size_sum / 1024, 100, 100 *
		   $tcp_hit_counter / $tcp_counter);
	reportstop();
    }
}

if ($opt_t || $opt_a) {
    if ($tcp_counter == 0) {
	reporttitle('TCP-Request-protocol: none');
    } else {
	reporttitle('TCP-Request-protocol');
	reportstart();
	reportheader('protocol','request','% ','  kByte','% ','hit-%');
	reportsep();
	foreach $urlprot (sort {$tcp_urlprot_counter{$b} <=>
				$tcp_urlprot_counter{$a}}
			  keys(%tcp_urlprot_counter)) {
	    reportline($urlprot, $tcp_urlprot_counter{$urlprot}, 100 *
		       $tcp_urlprot_counter{$urlprot} / $tcp_counter,
		       $tcp_urlprot_size_sum{$urlprot} / 1024, 100 *
		       $tcp_urlprot_size_sum{$urlprot} / $tcp_size_sum, 100 *
		       $tcp_hit_urlprot_counter{$urlprot} /
		       $tcp_urlprot_counter{$urlprot});
	}
	reportsep();
	reportline(Sum, $tcp_counter, 100, $tcp_size_sum / 1024, 100, 100 *
		   $tcp_hit_counter / $tcp_counter);
	reportstop();
    }

    if ($tcp_counter == 0) {
	reporttitle('Requested content-type: none');
    } else {
	reporttitle('Requested content-type');
	reportstart();
	reportheader('content-type','request','% ','  kByte','% ','hit-%');
	reportsep();

	@counter = keys %tcp_content_counter;
	$other_content = $#counter + 1;
	$other_counter = $tcp_counter;
	$other_size_sum = $tcp_size_sum;
	$other_hit_counter = $tcp_hit_counter;
	$linecounter = $opt_t;

	foreach $content (sort {$tcp_content_counter{$b} <=>
				$tcp_content_counter{$a}}
			  keys(%tcp_content_counter)) {

	    $other_content--;
	    $other_counter -= $tcp_content_counter{$content};
	    $other_size_sum -= $tcp_content_size_sum{$content};
	    $other_hit_counter -= $tcp_hit_content_counter{$content};
	    reportline(substr($content,0,41), $tcp_content_counter{$content},
		       100 * $tcp_content_counter{$content} / $tcp_counter,
		       $tcp_content_size_sum{$content} / 1024, 100 *
		       $tcp_content_size_sum{$content} / $tcp_size_sum, 100 *
		       $tcp_hit_content_counter{$content} /
		       $tcp_content_counter{$content});
	    last if (--$linecounter == 0 && $other_counter != 1);
	}
    	reportline('other: '. $other_content . ' content-types',
		   $other_counter, 100 * $other_counter / $tcp_counter,
		   $other_size_sum / 1024, 100 * $other_size_sum /
		   $tcp_size_sum, 100 * $other_hit_counter / $other_counter)
		   if $other_counter;
	reportsep();
	reportline(Sum, $tcp_counter, 100, $tcp_size_sum / 1024, 100, 100 *
		   $tcp_hit_counter / $tcp_counter);
	reportstop();
    }

    if ($tcp_counter == 0) {
	reporttitle('Requested extensions: none');
    } else {
	reporttitle('Requested extensions');
	reportstart();
	reportheader('extensions','request','% ','  kByte','% ','hit-%');
	reportsep();

	@counter = keys %tcp_urlext_counter;
	$other_urlext = $#counter + 1;
	$other_counter = $tcp_counter;
	$other_size_sum = $tcp_size_sum;
	$other_hit_counter = $tcp_hit_counter;
	$linecounter = $opt_t;

	foreach $urlext (sort {$tcp_urlext_counter{$b} <=>
			       $tcp_urlext_counter{$a}}
			 keys(%tcp_urlext_counter)) {
	    $other_urlext--;
	    $other_counter -= $tcp_urlext_counter{$urlext};
	    $other_size_sum -= $tcp_urlext_size_sum{$urlext};
	    $other_hit_counter -= $tcp_hit_urlext_counter{$urlext};
	    reportline(substr($urlext,0,41), $tcp_urlext_counter{$urlext}, 100
		       * $tcp_urlext_counter{$urlext} / $tcp_counter,
		       $tcp_urlext_size_sum{$urlext} / 1024, 100 *
		       $tcp_urlext_size_sum{$urlext} / $tcp_size_sum, 100 *
		       $tcp_hit_urlext_counter{$urlext} /
		       $tcp_urlext_counter{$urlext});
	    last if (--$linecounter == 0 && $other_counter != 1);
	}
	reportline('other: '. $other_urlext . ' extensions', $other_counter,
		   100 * $other_counter / $tcp_counter, $other_size_sum /
		   1024, 100 * $other_size_sum / $tcp_size_sum, 100 *
		   $other_hit_counter / $other_counter) if $other_counter;
	reportsep();
	reportline(Sum, $tcp_counter, 100, $tcp_size_sum / 1024, 100, 100 *
		   $tcp_hit_counter / $tcp_counter);
	reportstop();
    }
}

@format=(35,7,'%',8,'%',4,'kbs');
if ($opt_r || $opt_a) {
    if ($udp_counter == 0) {
	reporttitle('Incoming UDP-requests by host: none');
    } else {
	reporttitle('Incoming UDP-requests by host');
	reportstart();
	reportheader('host','request','hit-%','  kByte','hit-%','msec',' kB/sec');
	reportsep();
	foreach $neighbor (sort {$udp_requester_counter{$b} <=>
				 $udp_requester_counter{$a}}
			   keys(%udp_requester_counter)) {
	    reportline($neighbor, $udp_requester_counter{$neighbor}, 100 *
		       $udp_hit_requester_counter{$neighbor} /
		       $udp_requester_counter{$neighbor},
		       $udp_requester_size_sum{$neighbor} / 1024, 100 *
		       $udp_hit_requester_size_sum{$neighbor} /
		       $udp_requester_size_sum{$neighbor},
		       $udp_requester_time_sum{$neighbor} /
		       $udp_requester_counter{$neighbor}, 1000 *
		       $udp_requester_size_sum{$neighbor} / (1024 *
		       $udp_requester_time_sum{$neighbor}));
	}
	reportsep();
	reportline(Sum, $udp_counter, 100 * $udp_hit_counter / $udp_counter,
		   $udp_size_sum / 1024, 100 * $udp_hit_size_sum /
		   $udp_size_sum, $udp_time_sum / $udp_counter, 1000 *
		   $udp_size_sum / (1024 * $udp_time_sum));
	reportstop();
    }

    if ($tcp_counter == 0) {
	reporttitle('Incoming TCP-Requests by host: none');
    } else {
	reporttitle('Incoming TCP-requests by host');
	reportstart();
	reportheader('host','request','hit-%','  kByte','hit-%','sec',' kB/sec');
	reportsep();

	@counter = keys %tcp_size_sum;
	$other_requester = $#tcp_counter + 1;
	$other_counter = $tcp_counter;
	$other_size_sum = $tcp_size_sum;
	$other_time_sum = $tcp_time_sum;
	$other_hit_counter = $tcp_hit_counter;
	$linecounter = $opt_r;

	foreach $requester (sort {$tcp_requester_counter{$b} <=>
				  $tcp_requester_counter{$a}}
			    keys(%tcp_requester_counter)) {
	    $other_requester--;
	    $other_counter -= $tcp_requester_counter{$requester};
	    $other_size_sum -= $tcp_requester_size_sum{$requester};
	    $other_time_sum -= $tcp_requester_time_sum{$requester};
	    $other_hit_counter -= $tcp_hit_requester_counter{$requester};
	    reportline($requester, $tcp_requester_counter{$requester}, 100 *
		       $tcp_hit_requester_counter{$requester} /
		       $tcp_requester_counter{$requester},
		       $tcp_requester_size_sum{$requester} / 1024, 100 *
		       $tcp_hit_requester_size_sum{$requester} /
		       $tcp_requester_size_sum{$requester},
		       $tcp_requester_time_sum{$requester} / (1000 *
		       $tcp_requester_counter{$requester}), 1000 *
		       $tcp_requester_size_sum{$requester} / (1024 *
		       $tcp_requester_time_sum{$requester}));
	    last if(--$linecounter==0 && $other_counter != 1);
	}
	reportline('other: ' . $other_requester . ' requesting hosts',
		   $other_counter, 100 * $other_hit_counter / $tcp_counter,
		   $other_size_sum / 1024, 100 * $other_size_sum /
		   $tcp_size_sum, $other_time_sum / (1000 * $tcp_counter),
		   1000 * $other_size_sum / (1024 * $tcp_time_sum)) if
		   $other_counter;
	reportsep();
	reportline(Sum, $tcp_counter, 100 * $tcp_hit_counter / $tcp_counter,
		   $tcp_size_sum / 1024, 100 * $tcp_hit_size_sum /
		   $tcp_size_sum, $tcp_time_sum / (1000 * $tcp_counter), 1000
		   * $tcp_size_sum / (1024 * $tcp_time_sum) );
	reportstop();
    }
}

if ($opt_w) {
    print("<hr>\n<address>$COPYRIGHT</address>\n</body></html>\n");
} else {
    print("\n\n\n" . $COPYRIGHT . "\n");
}

sub getfqdn {
    my ($host) = @_;
    if ($opt_n) {
	return $host;
    } elsif ($host =~ /^([0-9][0-9]{0,2}\.){3}[0-9][0-9]{0,2}$/) {
	$nscache{$host} = &address_to_name($host) unless defined
	    $nscache{$host};
	return $nscache{$host};
    } else {
	return $host;
    }
}

sub address_to_name {
    my ($address) = shift (@_);
    my (@octets);
    my ($name, $aliases, $type, $len, $addr);
    my ($ip_number);
    @octets = split ('\.', $address) ;
    if ($#octets != 3) {
	undef;
    }
    $ip_number = pack ("CCCC", @octets[0..3]);
    ($name, $aliases, $type, $len, $addr) = gethostbyaddr ($ip_number, 2);
    if ($name) {
	$name;
    } else {
	$address;
    }
}

sub convert_date {
    my $date = shift(@_);
    if ($date) {
	my ($sec,$min,$hour,$mday,$mon,$year) =
	    (localtime($date))[0,1,2,3,4,5,6];
	my $month = ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep',
		     'Oct','Nov','Dec')[$mon];
	my $retdate = sprintf("%02d.%s %02d %02d:%02d:%02d\n",
			      $mday,
			      $month,
			      $year,
			      $hour,
			      $min,
			      $sec
			      );
	chomp($retdate);
	return $retdate;
    } else {
	return '                  ';
    }
}

sub reporttitle {
    my $print = shift(@_);
    if ($opt_w) {
	print("<h2>$print</h2>\n");
    } else {
	print("\n# $print\n");
    }
}

sub reportstart {
    print("<table>\n") if ($opt_w);
}

sub reportheader {
    my $print;
    my $no = 0;
    print('<th>') if ($opt_w);
    foreach (@_) {
	$print = $_;
	if ($opt_w) {
	    $print =~ s/ +/ /go;
	    $print =~ s/(^ | $)//go;
	    print("<td>$print");
	} elsif ($format[$no] =~ m#\%#o) {
	    print(' ' x (6 - length($print)), substr($print,0,6), ' ');
	} elsif ($format[$no] =~ m#kbs#o) {
	    print(substr($print,0,7) .
		  ' ' x (7 - length($print)), ' ');
	} else {
	    print(substr($print,0,$format[$no]) .
		  ' ' x ($format[$no] - length($print)), ' ');
	}
	$no++;
    }
    print('</th>') if ($opt_w);
    print("\n");
}

sub reportline {
    my $print;
    my $no = 0;
    print('<tr>') if ($opt_w);
    foreach (@_) {
	$print = $_;
	if ($opt_w) {
	    $print =~ s/ +/ /go;
	    $print =~ s/(^ | $)//go;
	    print("<td>$print");
	} elsif ($no == 0) {
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
	    $print = int($print + .5) unless $print =~ m#[ a-df-z]#o;
	    print(' ' x ($format[$no] - length($print)) .
		  substr($print,0,$format[$no]) , ' ');
	}
	$no++;
    }
    print('</tr>') if ($opt_w);
    print("\n");
}

sub reportsep {
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

sub reportstop {
    print("</table>\n") if ($opt_w);
}
