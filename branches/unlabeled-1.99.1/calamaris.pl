#!/usr/bin/perl -w
#
# $Id: calamaris.pl,v 1.99.1.1 1997-12-29 20:53:02 cord Exp $
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
#   -- 'Programming Perl Second Edition'
#	by Larry Wall, Tom Christiansen & Randal L. Schwartz


# Instructions:

# * Switch 'emulate_httpd_log' off

# * Pipe your Logfile in calamaris


# Example:

# cat access.log.1 access.log.0 |calamaris.pl


# Bugs and shortcomings

# * after long sleep, rewrite, test, and debug, i want to keep my promise and
# i release this as first beta-version of calamaris V2.x just in '97

# * A Readme and so on has still to be written.

# * if you want to parse more than one Logfile (i.e. from the logfilerotate)
# you have to put them in chronological sorted order (oldest first) into
# calamaris, else you get wrong peak values. (Is this something that i should
# fix? Don't think so...)

# * If you use the caching function the peak-values can be wrong if the peak
# lies around the time the log-files were rotated.

# * Squid doesn't log outgoing UDP-Requests, so i can't put them into the
# statistics without parsing squid.conf. (Javier Puche
# (Javier.Puche@rediris.es) asked for this), but i don't think that i should
# put this into calamaris... (Check last point of 'Bugs and
# shortcomings'-section.)

# * To make calamaris shorter and (hopefully) faster i changed all the long
# variables names to shorter ones. (Example: $tcp_miss_neighbor_hit_size is
# now $t_m_n_h_sz) This makes calamaris over 20k shorter, but it reduces the
# readability and the chance for anybody else to understand the routines,
# while i didn't comment the script. (My programming teacher is going to kill
# me ;-) Hopefully I understand the program if i had to go in it in half a
# year...

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


use vars qw($opt_a $opt_b $opt_c $opt_d $opt_h $opt_i $opt_m $opt_n $opt_o
	    $opt_p $opt_r $opt_s $opt_t $opt_u $opt_w $opt_z);

use Getopt::Std;
use Sys::Hostname;

getopts('ab:cd:hi:mno:pr:st:uwz');

$COPYRIGHT='calamaris $Revision: 1.99.1.1 $, Copyright (C) 1997 Cord Beermann
calamaris comes with ABSOLUTELY NO WARRANTY. It is free software,
and you are welcome to redistribute it under certain conditions.
See source for details.

';

$USAGE='Usage: cat access.log | ' . $0 . ' [-achmnpsuwz] [-bdrt[n]] [-io file]

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

Misc:
-i file	    input-file (input-datafile for caching)
-o file	    output-file (output-datafile for caching, could be the same as -i)

-b n	    benchmark (prints a hash for each n lines)
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

# initialize variables
$c = $h = $h_d = $h_d_sz = $h_d_tm = $h_p = $h_p_sz = $h_p_tm = $h_s = $h_s_sz
    = $h_s_tm = $h_sz = $h_tm = $i = $p_a_h = $p_a_h_tm = $p_a_m = $p_a_m_tm =
    $p_a_s = $p_a_s_tm = $p_t_h = $p_t_h_tm = $p_t_m = $p_t_m_tm = $p_t_s =
    $p_t_s_tm = $p_u_h = $p_u_h_tm = $p_u_m = $p_u_m_tm = $p_u_s = $p_u_s_tm =
    $sz = $t = $t_h = $t_h_sz = $t_h_tm = $t_m = $t_m_d = $t_m_d_sz =
    $t_m_d_tm = $t_m_n_h = $t_m_n_h_sz = $t_m_n_h_tm = $t_m_n_m = $t_m_n_m_sz
    = $t_m_n_m_tm = $t_m_nn = $t_m_nn_sz = $t_m_nn_tm = $t_m_sz = $t_m_tm =
    $t_sz = $t_tm = $tm = $tm_e = $tm_r = $u = $u_h = $u_h_sz = $u_h_tm = $u_m
    = $u_m_sz = $u_m_tm = $u_sz = $u_tm = 0;
$tm_b = 9999999999;

if ($opt_i and -r $opt_i) {
    open(CACHE, "$opt_i") or die("$0: can't open $opt_i for reading: $!\n");
    while (<CACHE>) {
	chomp;
	@c = split('µ');
	$x = shift(@c);
	unless ($x) {
	    next;
	} elsif ($x eq A and $#c = 40) {
	    ($tm_b, $tm_e, $c, $sz, $tm, $i, $tm_r, $u, $u_sz, $u_tm, $u_h,
	     $u_h_sz, $u_h_tm, $u_m, $u_m_sz, $u_m_tm, $t, $t_sz, $t_tm, $t_h,
	     $t_h_sz, $t_h_tm, $t_m, $t_m_sz, $t_m_tm, $t_m_nn, $t_m_nn_sz,
	     $t_m_nn_tm, $h, $h_sz, $h_tm, $h_d, $h_d_sz, $h_d_tm, $h_s,
	     $h_s_sz, $h_s_tm, $h_p, $h_p_sz, $h_p_tm) = @c;
	} elsif ($x eq B and $#c = 18) {
	    ($p_u_s, $p_u_s_tm, $p_u_m, $p_u_m_tm, $p_u_h, $p_u_h_tm, $p_t_s,
	     $p_t_s_tm, $p_t_m, $p_t_m_tm, $p_t_h, $p_t_h_tm, $p_a_s,
	     $p_a_s_tm, $p_a_m, $p_a_m_tm, $p_a_h, $p_a_h_tm) = @c;
	} elsif ($x eq C and $#c = 4) {
	    $y = shift(@c);
	    ($m{$y}, $m_sz{$y}, $m_tm{$y}) = @c;
	} elsif ($x eq D and $#c = 4) {
	    $y = shift(@c);
	    ($u_h{$y}, $u_h_sz{$y}, $u_h_tm{$y}) = @c;
	} elsif ($x eq E and $#c = 4) {
	    $y = shift(@c);
	    ($u_m{$y}, $u_m_sz{$y}, $u_m_tm{$y}) = @c;
	} elsif ($x eq F and $#c = 4) {
	    $y = shift(@c);
	    ($t_h{$y}, $t_h_sz{$y}, $t_h_tm{$y}) = @c;
	} elsif ($x eq G and $#c = 4) {
	    $y = shift(@c);
	    ($t_m{$y}, $t_m_sz{$y}, $t_m_tm{$y}) = @c;
	} elsif ($x eq H and $#c = 4) {
	    $y = shift(@c);
	    ($t_m_nn{$y}, $t_m_nn_sz{$y}, $t_m_nn_tm{$y}) = @c;
	} elsif ($x eq I and $#c = 4) {
	    $y = shift(@c);
	    ($h_d{$y}, $h_d_sz{$y}, $h_d_tm{$y}) = @c;
	} elsif ($x eq J and $#c = 4) {
	    $y = shift(@c);
	    ($h_s{$y}, $h_s_sz{$y}, $h_s_tm{$y}) = @c;
	} elsif ($x eq K and $#c = 4) {
	    $y = shift(@c);
	    ($h_p{$y}, $h_p_sz{$y}, $h_p_tm{$y}) = @c;
	} elsif ($x eq L and $#c = 4) {
	    $y = shift(@c);
	    ($h_n{$y}, $h_n_sz{$y}, $h_n_tm{$y}) = @c;
	} elsif ($x eq M and $#c = 5) {
	    $y = shift(@c);
	    $z = shift(@c);
	    ($h_n_st{$y}{$z}, $h_n_st_sz{$y}{$z}, $h_n_st_tm{$y}{$z}) = @c;
	} elsif ($x eq N and $#c = 4) {
	    $y = shift(@c);
	    ($t_u{$y}, $t_u_sz{$y}, $t_h_u{$y}) = @c;
	} elsif ($x eq O and $#c = 4) {
	    $y = shift(@c);
	    ($t_ut{$y}, $t_ut_sz{$y}, $t_h_ut{$y}) = @c;
	} elsif ($x eq P and $#c = 4) {
	    $y = shift(@c);
	    ($t_up{$y}, $t_up_sz{$y}, $t_h_up{$y}) = @c;
	} elsif ($x eq Q and $#c = 4) {
	    $y = shift(@c);
	    ($t_ct{$y}, $t_ct_sz{$y}, $t_h_ct{$y}) = @c;
	} elsif ($x eq R and $#c = 4) {
	    $y = shift(@c);
	    ($t_ue{$y}, $t_ue_sz{$y}, $t_h_ue{$y}) = @c;
	} elsif ($x eq S and $#c = 6) {
	    $y = shift(@c);
	    ($u_r{$y}, $u_r_sz{$y}, $u_r_tm{$y}, $u_h_r{$y}, $u_h_r_sz{$y}) =
		@c;
	} elsif ($x eq T and $#c = 6) {
	    $y = shift(@c);
	    ($t_r{$y}, $t_r_sz{$y}, $t_r_tm{$y}, $t_h_r{$y}, $t_h_r_sz{$y}) =
		@c;
	} else {
	    warn("can't parse cache-line: \"@c\"\n");
	}
    }
    close(CACHE);
}

unless ($opt_z) {
    print("print a hash for each $opt_b lines:\n") if ($opt_b);
    $tm_r = time - $tm_r;
    while (<>) {
	($l_d, $l_tm, $l_r, $l_st, $l_sz, $l_m, $l_u, $l_i, $l_h, $l_c, $foo)
	    = split;
	if (not defined $foo or not defined $l_c or $foo ne '' or $l_c eq '' )
	{
	    chomp;
	    warn ('invalid line: "' . $_ . "\"\n");
	    $i++;
	    next;
	}
	$l_tm = .1 if $l_tm == 0;
	$rh = getfqdn($l_r);
	$l_hf = (split(m#/#o,$l_st))[0];
	$l_sz = .0000000001 if $l_sz == 0;
	@u = split(m#[/\\]#o,$l_u);
	($up, $uh, $ue) = (@u)[0,2,$#u];
	$ue = '.<none>' if $#u <= 2;
	$ue = '.<dynamic>' if $ue =~ m#[\?\;\&\$\,\!\@\=\|]#o;
	unless (defined $uh) {
	    $uh = $up;
	    $up = '<none>';
	}
	$uh =~ s#^.*@##o;
	$uh =~ s#[:\?].*$##o;
	@ue = split(m#\.#o,$ue);
	$ue = (@ue)[$#ue];
	$ue = '<none>' if $#ue <= 0;
	if ($uh =~ /^(([0-9][0-9]{0,2}\.){3})[0-9][0-9]{0,2}$/o) {
	    $uh = $1 . '*';
	    $ut = '<unresolved>';
	} elsif ($uh =~ /^(.*\.([^\.]+\.)?)?([^\.]+\.([^\.]+))\.?$/o) {
	    @list = split(/\./o, $uh);
	    $ut = $uh = '.' . pop @list;
	    $uh = '.' . pop(@list) . $uh;
	    if ($ut =~
		/\.(ar|au|br|co|hk|id|il|jp|kr|mx|nz|pe|pl|sg|th|tr|tw|uk|us|yu|za)$/o
		and $#list >= 0) {
		$uh = '*.' . pop(@list) . $uh;
	    } else {
		$uh = '*' . $uh;
	    }
	    $ut = '*' . $ut;
	} elsif ($uh =~ /([!a-z0-9\.\-]|\.\.)/o) {
	    $uh = $ut = $ue = '<error>';
	} else {
	    $ut = $uh;
	}
	if ($opt_u) {
	    $r = $l_i . '@' . $rh;
	} else {
	    $r = $rh;
	}
	($l_h_m, $l_h_h) = (split(m#/#o, $l_h))[0,1];
	$l_c = '<unknown>' if $l_c eq '-';
	$l_c =~ tr/A-Z/a-z/;
	print('#') if ($opt_b and ($c / $opt_b) eq int($c / $opt_b));
	$c++;
	$sz += $l_sz;
	$tm += $l_tm;
	$m{$l_m} = $m_sz{$l_m} = $m_tm{$l_m} = 0 unless defined $m{$l_m};
	$m{$l_m}++;
	$m_sz{$l_m} += $l_sz;
	$m_tm{$l_m} += $l_tm;
	$tm_b = $l_d if not defined $tm_b or $l_d < $tm_b;
	$tm_e = $l_d if not defined $tm_e or $l_d > $tm_e;
	if ($opt_p or $opt_a) {
	    $p_a_s_pntr++;
	    $p_a_m_pntr++;
	    unshift(@p_a,$l_d);
	    $p_a_s_pntr-- while $p_a[$p_a_s_pntr - 1] < ($l_d - 1);
	    $p_a_m_pntr-- while $p_a[$p_a_m_pntr - 1] < ($l_d - 60);
	    pop(@p_a) while $p_a[$#p_a] < ($l_d - 3600);
	    if ($p_a_h < @p_a) {
		$p_a_h = @p_a;
		$p_a_h_tm = $l_d - 3600;
	    }
	    if ($p_a_m < $p_a_m_pntr) {
		$p_a_m = $p_a_m_pntr;
		$p_a_m_tm = $l_d - 60;
	    }
	    if ($p_a_s < $p_a_s_pntr) {
		$p_a_s = $p_a_s_pntr;
		$p_a_s_tm = $l_d - 1;
	    }
	}
	if ($l_m eq 'ICP_QUERY') {
	    $u++;
	    $u_sz += $l_sz;
	    $u_tm += $l_tm;
	    if ($opt_r or $opt_a) {
		$u_r{$r} = $u_r_sz{$r} = $u_r_tm{$r} = $u_h_r{$r} =
		    $u_h_r_sz{$r} = 0 unless defined $u_r{$r};
		$u_r{$r}++;
		$u_r_sz{$r} += $l_sz;
		$u_r_tm{$r} += $l_tm;
	    }
	    if ($opt_p or $opt_a) {
		$p_u_s_pntr++;
		$p_u_m_pntr++;
		unshift(@p_u,$l_d);
		$p_u_s_pntr-- while $p_u[$p_u_s_pntr - 1] < ($l_d - 1);
		$p_u_m_pntr-- while $p_u[$p_u_m_pntr - 1] < ($l_d - 60);
		pop @p_u while $p_u[$#p_u] < ($l_d - 3600);
		if ($p_u_h < @p_u) {
		    $p_u_h = @p_u;
		    $p_u_h_tm = $l_d - 3600;
		}
		if ($p_u_m < $p_u_m_pntr) {
		    $p_u_m = $p_u_m_pntr;
		    $p_u_m_tm = $l_d - 60;
		}
		if ($p_u_s < $p_u_s_pntr) {
		    $p_u_s = $p_u_s_pntr;
		    $p_u_s_tm = $l_d - 1;
		}
	    }
	    if ($l_hf =~ /^UDP_HIT/o) {
		$u_h++;
		$u_h_sz += $l_sz;
		$u_h_tm += $l_tm;
		if ($opt_r or $opt_a) {
		    $u_h_r{$r}++;
		    $u_h_r_sz{$r} += $l_sz;
		}
		if ($opt_s or $opt_a) {
		    $u_h{$l_hf} = $u_h_sz{$l_hf} = $u_h_tm{$l_hf} = 0 unless
			defined $u_h{$l_hf};
		    $u_h{$l_hf}++;
		    $u_h_sz{$l_hf} += $l_sz;
		    $u_h_tm{$l_hf} += $l_tm;
		}
	    } else {
		$u_m++;
		$u_m_sz += $l_sz;
		$u_m_tm += $l_tm;
		if ($opt_s or $opt_a) {
		    $u_m{$l_hf} = $u_m_sz{$l_hf} = $u_m_tm{$l_hf} = 0 unless
			defined $u_m{$l_hf};
		    $u_m{$l_hf}++;
		    $u_m_sz{$l_hf} += $l_sz;
		    $u_m_tm{$l_hf} += $l_tm;
		}
	    }
	} else {
	    $t++;
	    $t_sz += $l_sz;
	    $t_tm += $l_tm;
	    if ($opt_r or $opt_a) {
		$t_r{$r} = $t_r_sz{$r} = $t_r_tm{$r} = $t_h_r{$r} =
		    $t_h_r_sz{$r} = 0 unless defined $t_r{$r};
		$t_r{$r}++;
		$t_r_sz{$r} += $l_sz;
		$t_r_tm{$r} += $l_tm;
	    }
	    if ($opt_d or $opt_a) {
		$t_u{$uh} = $t_u_sz{$uh} = $t_h_u{$uh} = 0 unless defined
		    $t_u{$uh};
		$t_u{$uh}++;
		$t_u_sz{$uh} += $l_sz;
		$t_ut{$ut} = $t_ut_sz{$ut} = $t_h_ut{$ut} = 0 unless defined
		    $t_ut{$ut};
		$t_ut{$ut}++;
		$t_ut_sz{$ut} += $l_sz;
	    }
	    if ($opt_t or $opt_a) {
		$t_up{$up} = $t_up_sz{$up} = $t_h_up{$up} = 0 unless defined
		    $t_up{$up};
		$t_up{$up}++;
		$t_up_sz{$up} += $l_sz;
	    }
	    if ($opt_p or $opt_a) {
		$p_t_s_pntr++;
		$p_t_m_pntr++;
		unshift(@p_t, $l_d);
		$p_t_s_pntr-- while $p_t[$p_t_s_pntr - 1] < ($l_d - 1);
		$p_t_m_pntr-- while $p_t[$p_t_m_pntr - 1] < ($l_d - 60);
		pop(@p_t) while $p_t[$#p_t] < ($l_d - 3600);
		if ($p_t_h < @p_t) {
		    $p_t_h = @p_t;
		    $p_t_h_tm = $l_d - 3600;
		}
		if ($p_t_m < $p_t_m_pntr) {
		    $p_t_m = $p_t_m_pntr;
		    $p_t_m_tm = $l_d - 60;
		}
		if ($p_t_s < $p_t_s_pntr) {
		    $p_t_s = $p_t_s_pntr;
		    $p_t_s_tm = $l_d - 1;
		}
	    }
	    if ($opt_t or $opt_a) {
		$t_ct{$l_c} = $t_ct_sz{$l_c} = $t_h_ct{$l_c} = 0 unless
		    defined $t_ct{$l_c};
		$t_ct{$l_c}++;
		$t_ct_sz{$l_c} += $l_sz;
		$t_ue{$ue} = $t_ue_sz{$ue} = $t_h_ue{$ue} = 0 unless defined
		    $t_ue{$ue};
		$t_ue{$ue}++;
		$t_ue_sz{$ue} += $l_sz;
	    }
	    if ($l_hf =~ /^TCP\w+HIT/o) {
		$t_h++;
		$t_h_sz += $l_sz;
		$t_h_tm += $l_tm;
		if ($opt_s or $opt_a) {
		    $t_h{$l_hf} = $t_h_sz{$l_hf} = $t_h_tm{$l_hf} = 0 unless
			defined $t_h{$l_hf};
		    $t_h{$l_hf}++;
		    $t_h_sz{$l_hf} += $l_sz;
		    $t_h_tm{$l_hf} += $l_tm;
		}
		if ($opt_r or $opt_a) {
		    $t_h_r{$r}++;
		    $t_h_r_sz{$r} += $l_sz;
		}
		if ($opt_d or $opt_a) {
		    $t_h_u{$uh}++;
		    $t_h_ut{$ut}++;
		}
		if ($opt_t or $opt_a) {
		    $t_h_ct{$l_c}++;
		    $t_h_ue{$ue}++;
		    $t_h_up{$up}++;
		}
	    } elsif (($l_h_m eq 'NONE') or ($l_hf =~ /^ERR_/o)) {
		$t_m_nn++;
		$t_m_nn_sz += $l_sz;
		$t_m_nn_tm += $l_tm;
		if ($opt_s or $opt_a) {
		    $t_m_nn{$l_hf} = $t_m_nn_sz{$l_hf} = $t_m_nn_tm{$l_hf} = 0
			unless defined $t_m_nn{$l_hf};
		    $t_m_nn{$l_hf}++;
		    $t_m_nn_sz{$l_hf} += $l_sz;
		    $t_m_nn_tm{$l_hf} += $l_tm;
		}
	    } else {
		$t_m++;
		$t_m_sz += $l_sz;
		$t_m_tm += $l_tm;
		if ($opt_s or $opt_a) {
		    $t_m{$l_hf} = $t_m_sz{$l_hf} = $t_m_tm{$l_hf} = 0 unless
			defined $t_m{$l_hf};
		    $t_m{$l_hf}++;
		    $t_m_sz{$l_hf} += $l_sz;
		    $t_m_tm{$l_hf} += $l_tm;
		}
		if ($opt_r or $opt_a) {
		    $t_m_r{$r} = $t_m_r_sz{$r} = 0 unless defined $t_m_r{$r};
		    $t_m_r{$r}++;
		    $t_m_r_sz{$r} += $l_sz;
		}
		if ($l_h_m =~ /(DIRECT|SOURCE_FASTEST)/o) {
		    $t_m_d++;
		    $t_m_d_sz += $l_sz;
		    $t_m_d_tm += $l_tm;
		} elsif ($l_h_m =~ /(PARENT|SIBLING)\w+HIT/o) {
		    $t_m_n_h++;
		    $t_m_n_h_tm += $l_tm;
		    $t_m_n_h_sz += $l_sz;
		    $t_m_n_h{$l_h_h} = $t_m_n_h_sz{$l_h_h} =
			$t_m_n_h_tm{$l_h_h} = 0 unless defined
			$t_m_n_h{$l_h_h};
		    $t_m_n_h{$l_h_h}++;
		    $t_m_n_h_sz{$l_h_h} += $l_sz;
		    $t_m_n_h_tm{$l_h_h} += $l_tm;
		} elsif ($l_h_m =~
		     /(PARENT_MISS|(DEFAULT|FIRST_UP|SINGLE|PASSTHROUGH|ROUNDROBIN)_PARENT)/o)
		{
		    $t_m_n_m++;
		    $t_m_n_m_sz += $l_sz;
		    $t_m_n_m_tm += $l_tm;
		    $t_m_n{$l_h_h} = $t_m_n_m_sz{$l_h_h} = $t_m_n_m_tm{$l_h_h}
			= 0 unless defined $t_m_n{$l_h_h};
		    $t_m_n_m{$l_h_h}++;
		    $t_m_n_m_sz{$l_h_h} += $l_sz;
		    $t_m_n_m_tm{$l_h_h} += $l_tm;
		} else {
		    warn("unknown l_h_m: \"$l_h_m\"
			  Please report this to cord\@Wunder-Nett.org\n");
		}
	    }
	    if ($l_h_m ne 'NONE') {
		$h++;
		$h_sz += $l_sz;
		$h_tm += $l_tm;
		if ($l_h_m =~ /(DIRECT|SOURCE_FASTEST)/o) {
		    $h_d++;
		    $h_d_sz += $l_sz;
		    $h_d_tm += $l_tm;
		    if ($opt_s or $opt_a) {
			$h_d{$l_h_m} = $h_d_sz{$l_h_m} = $h_d_tm{$l_h_m} = 0
			    unless defined $h_d{$l_h_m};
			$h_d{$l_h_m}++;
			$h_d_sz{$l_h_m} += $l_sz;
			$h_d_tm{$l_h_m} += $l_tm;
		    }
		} elsif ($l_h_m =~ /(PARENT|SIBLING)\w+HIT/o) {
		    $h_s++;
		    $h_s_sz += $l_sz;
		    $h_s_tm += $l_tm;
		    if ($opt_s or $opt_a) {
			$h_s{$l_h_m} = $h_s_sz{$l_h_m} = $h_s_tm{$l_h_m} = 0
			    unless defined $h_s{$l_h_m};
			$h_s{$l_h_m}++;
			$h_s_sz{$l_h_m} += $l_sz;
			$h_s_tm{$l_h_m} += $l_tm;
		    }
		    $h_n{$l_h_h} = $h_n_sz{$l_h_h} = $h_n_tm{$l_h_h} = 0
			unless $h_n{$l_h_h};
		    $h_n{$l_h_h}++;
		    $h_n_sz{$l_h_h} += $l_sz;
		    $h_n_tm{$l_h_h} += $l_tm;
		    if ($opt_s or $opt_a) {
			$h_n_st{$l_h_h}{$l_h_m} = $h_n_st_sz{$l_h_h}{$l_h_m} =
			    $h_n_st_tm{$l_h_h}{$l_h_m} = 0 unless
			    $h_n_st{$l_h_h}{$l_h_m};
			$h_n_st{$l_h_h}{$l_h_m}++;
			$h_n_st_sz{$l_h_h}{$l_h_m} += $l_sz;
			$h_n_st_tm{$l_h_h}{$l_h_m} += $l_tm;
		    }
		} elsif ($l_h_m =~
			 /(PARENT_MISS|(DEFAULT|FIRST_UP|SINGLE|PASSTHROUGH|ROUNDROBIN)_PARENT)/o)
		{
		    $h_p++;
		    $h_p_sz += $l_sz;
		    $h_p_tm += $l_tm;
		    if ($opt_s or $opt_a) {
			$h_p{$l_h_m} = $h_p_sz{$l_h_m} = $h_p_tm{$l_h_m} = 0
			    unless defined $h_p{$l_h_m};
			$h_p{$l_h_m}++;
			$h_p_sz{$l_h_m} += $l_sz;
			$h_p_tm{$l_h_m} += $l_tm;
		    }
		    $h_n{$l_h_h} = $h_n_sz{$l_h_h} = $h_n_tm{$l_h_h} = 0
			unless defined $h_n{$l_h_h};
		    $h_n{$l_h_h}++;
		    $h_n_sz{$l_h_h} += $l_sz;
		    $h_n_tm{$l_h_h} += $l_tm;
		    if ($opt_s or $opt_a) {
			$h_n_st{$l_h_h}{$l_h_m} = $h_n_st_sz{$l_h_h}{$l_h_m} =
			    $h_n_st_tm{$l_h_h}{$l_h_m} = 0 unless
			    $h_n_st{$l_h_h}{$l_h_m};
			$h_n_st{$l_h_h}{$l_h_m}++;
			$h_n_st_sz{$l_h_h}{$l_h_m} += $l_sz;
			$h_n_st_tm{$l_h_h}{$l_h_m} += $l_tm;
		    }
		} else {
		    warn("unknown l_h_m: \"$l_h_m\"
			 Please report this to cord\@Wunder-Nett.org\n");
		}
	    }
	}
    }
$tm_r = time - $tm_r;
}

### Yea! File read. Now give the output...

if ($c == 0) {
    print('no requests found');
    exit(0);
}
open(CACHE, ">$opt_o") or die("$0: can't open $opt_i for writing: $!\n")
    if ($opt_o);
writec(A, $tm_b, $tm_e, $c, $sz, $tm, $i, $tm_r, $u, $u_sz, $u_tm, $u_h,
       $u_h_sz, $u_h_tm, $u_m, $u_m_sz, $u_m_tm, $t, $t_sz, $t_tm, $t_h,
       $t_h_sz, $t_h_tm, $t_m, $t_m_sz, $t_m_tm, $t_m_nn, $t_m_nn_sz,
       $t_m_nn_tm, $h, $h_sz, $h_tm, $h_d, $h_d_sz, $h_d_tm, $h_s, $h_s_sz,
       $h_s_tm, $h_p, $h_p_sz, $h_p_tm);
writec(B, $p_u_s, $p_u_s_tm, $p_u_m, $p_u_m_tm, $p_u_h, $p_u_h_tm, $p_t_s,
       $p_t_s_tm, $p_t_m, $p_t_m_tm, $p_t_h, $p_t_h_tm, $p_a_s, $p_a_s_tm,
       $p_a_m, $p_a_m_tm, $p_a_h, $p_a_h_tm);
    $d_start = condat($tm_b);
    $d_stop = condat($tm_e);
    if ($opt_p or $opt_a) {
	$d_p_u_s = condat($p_u_s_tm);
	$d_p_t_s = condat($p_t_s_tm);
	$d_p_a_s = condat($p_a_s_tm);
	$d_p_u_m = condat($p_u_m_tm);
	$d_p_t_m = condat($p_t_m_tm);
	$d_p_a_m = condat($p_a_m_tm);
	$d_p_u_h = condat($p_u_h_tm);
	$d_p_t_h = condat($p_t_h_tm);
	$d_p_a_h = condat($p_a_h_tm);
    }

printf("Subject: %s Squid-Report (%s - %s)\n\n", hostname, $d_start,
       $d_stop) if ($opt_m);

if ($opt_w) {
    print("<html><head><title>Squid-Report</title></head><body>\n");
    printf("<h1>%s Squid-Report (%s - %s)</h1>\n", hostname, $d_start,
	   $d_stop);
} else {
    printf("%s Squid-Report (%s - %s)\n", hostname, $d_start, $d_stop);
}

@f=(17,8);
reptit('Summary for ' . hostname);
repsta();
replin('lines parsed:', $c);
replin('invalid lines:', $i);
replin('parse time (sec):', $tm_r);
repsto();

@f=(3,4,18,5,18,7,18);
if ($opt_p or $opt_a) {
    reptit('Incoming request peak per protocol');
    repsta();
    rephea('prt', ' sec', 'peak begins at', ' min', 'peak begins at',
		 '  hour', 'peak begins at');
    repsep();
    replin('UDP', $p_u_s, $d_p_u_s, $p_u_m, $d_p_u_m, $p_u_h, $d_p_u_h);
    replin('TCP', $p_t_s, $d_p_t_s, $p_t_m, $d_p_t_m, $p_t_h, $d_p_t_h);
    repsep();
    replin('ALL', $p_a_s, $d_p_a_s, $p_a_m, $d_p_a_m, $p_a_h, $d_p_a_h);
    repsto();
}

@f=(33,8,'%',9,'%',4,'kbs');
if ($c == 0) {
    reptit('Incoming requests by method: none');
} else {
    reptit('Incoming requests by method');
    repsta();
    rephea('method',' request','% ','  kByte','% ',' sec',' kB/sec');
    repsep();
    foreach $m (sort {$m{$b} <=> $m{$a}} keys(%m)) {
	writec(C, $m, $m{$m}, $m_sz{$m}, $m_tm{$m});
	replin($m, $m{$m}, 100 * $m{$m} / $c, $m_sz{$m} / 1024, 100 *
	       $m_sz{$m} / $sz, $m_tm{$m} / (1000 * $m{$m}), 1000 * $m_sz{$m}
	       / (1024 * $m_tm{$m}));
    }
    repsep();
    replin(Sum, $c, 100, $sz / 1024, 100, $tm / ($c * 1000), 1000 * $sz /
	   (1024 * $tm));
    repsto();
}

if ($u == 0) {
    reptit('Incoming UDP-requests by status: none');
} else {
    reptit('Incoming UDP-requests by status');
    repsta();
    rephea('status',' request','% ','  kByte','% ','msec',' kB/sec');
    repsep();
    if ($u_h == 0) {
	replin(HIT,0,0,0,0,0,0);
    } else {
	replin(HIT, $u_h, 100 * $u_h / $u, $u_h_sz / 1024, 100 * $u_h_sz /
	       $u_sz, $u_h_tm / $u_h, 1000 * $u_h_sz / (1024 * $u_h_tm));
	foreach $hf (sort {$u_h{$b} <=> $u_h{$a}} keys(%u_h)) {
	    writec(D, $hf, $u_h{$hf}, $u_h_sz{$hf}, $u_h_tm{$hf});
	    replin(' ' . $hf, $u_h{$hf}, 100 * $u_h{$hf} / $u, $u_h_sz{$hf} /
		   1024, 100 * $u_h_sz{$hf} / $u_sz, $u_h_tm{$hf} / $u_h{$hf},
		   1000 * $u_h_sz{$hf} / (1024 * $u_h_tm{$hf}));
	}
    }
    if ($u_m == 0) {
	replin(MISS,0,0,0,0,0,0);
    } else {
	replin(MISS, $u_m, 100 * $u_m / $u, $u_m_sz / 1024, 100 * $u_m_sz /
	       $u_sz, $u_m_tm / $u_m, 1000 * $u_m_sz / (1024 * $u_m_tm));
	foreach $hf (sort {$u_m{$b} <=> $u_m{$a}} keys(%u_m)) {
	    writec(E, $hf, $u_m{$hf}, $u_m_sz{$hf}, $u_m_tm{$hf});
	    replin(' ' . $hf, $u_m{$hf}, 100 * $u_m{$hf} / $u, $u_m_sz{$hf} /
		   1024, 100 * $u_m_sz{$hf} / $u_sz, $u_m_tm{$hf} / $u_m{$hf},
		   1000 * $u_m_sz{$hf} / (1024 * $u_m_tm{$hf}));
	}
    }
    repsep();
    replin(Sum, $u, ' ', $u_sz / 1024, ' ', $u_tm / $u, 1000 * $u_sz / (1024 *
	   $u_tm));
    repsto();
}

if ($t == 0) {
    reptit('Incoming TCP-requests by status: none');
} else {
    reptit('Incoming TCP-requests by status');
    repsta();
    rephea('status',' request','% ','  kByte','% ',' sec',' kB/sec');
    repsep();
    if ($t_h == 0) {
	replin(HIT,0,0,0,0,0,0);
    } else {
	replin(HIT, $t_h, 100 * $t_h / $t, $t_h_sz / 1024, 100 * $t_h_sz /
	       $t_sz, $t_h_tm / (1000 * $t_h), 1000 * $t_h_sz / (1024 *
	       $t_h_tm));
	foreach $hf (sort {$t_h{$b} <=> $t_h{$a}} keys(%t_h)) {
	    writec(F, $hf, $t_h{$hf}, $t_h_sz{$hf}, $t_h_tm{$hf});
	    replin(' ' . $hf, $t_h{$hf}, 100 * $t_h{$hf} / $t, $t_h_sz{$hf} /
		   1024, 100 * $t_h_sz{$hf} / $t_sz, $t_h_tm{$hf} / (1000 *
		   $t_h{$hf}), 1000 * $t_h_sz{$hf} / (1024 * $t_h_tm{$hf}));
	}
    }
    if ($t_m == 0) {
	replin(MISS,0,0,0,0,0,0);
    } else {
	replin(MISS, $t_m, 100 * $t_m / $t, $t_m_sz / 1024, 100 * $t_m_sz /
	       $t_sz, $t_m_tm / (1000 * $t_m), 1000 * $t_m_sz / (1024 *
	       $t_m_tm));
	foreach $hf (sort {$t_m{$b} <=> $t_m{$a}} keys(%t_m)) {
	    writec(G, $hf, $t_m{$hf}, $t_m_sz{$hf}, $t_m_tm{$hf});
	    replin(' ' . $hf, $t_m{$hf}, 100 * $t_m{$hf} / $t, $t_m_sz{$hf} /
		   1024, 100 * $t_m_sz{$hf} / $t_sz, $t_m_tm{$hf} / (1000 *
		   $t_m{$hf}), 1000 * $t_m_sz{$hf} / (1024 * $t_m_tm{$hf}));
	}
    }
    if ($t_m_nn == 0) {
	replin(ERROR,0,0,0,0,0,0);
    } else {
	replin(ERROR, $t_m_nn, 100 * $t_m_nn / $t, $t_m_nn_sz / 1024, 100 *
	       $t_m_nn_sz / $t_sz, $t_m_nn_tm / (1000 * $t_m_nn), 1000 *
	       $t_m_nn_sz / (1024 * $t_m_nn_tm));
	foreach $hf (sort {$t_m_nn{$b} <=> $t_m_nn{$a}} keys(%t_m_nn)) {
	    writec(H, $hf, $t_m_nn{$hf}, $t_m_nn_sz{$hf}, $t_m_nn_tm{$hf});
	    replin(' ' .  $hf, $t_m_nn{$hf}, 100 * $t_m_nn{$hf} / $t,
		   $t_m_nn_sz{$hf} / 1024, 100 * $t_m_nn_sz{$hf} / $t_sz,
		   $t_m_nn_tm{$hf} / (1000 * $t_m_nn{$hf}), 1000 *
		   $t_m_nn_sz{$hf} / (1024 * $t_m_nn_tm{$hf}));
	}
    }
    repsep();
    replin(Sum, $t, ' ', $t_sz / 1024, ' ', $t_tm / (1000 * $t), 1000 * $t_sz
	   / (1024 * $t_tm));
    repsto();
}

if ($h == 0) {
    reptit('Outgoing requests by status: none');
} else {
    reptit('Outgoing requests by status');
    repsta();
    rephea('status',' request','% ','  kByte','% ',' sec',' kB/sec');
    repsep();
    if ($h_d == 0) {
	replin('DIRECT',0,0,0,0,0,0);
    } else {
	replin('DIRECT Fetch from Source', $h_d, 100 * $h_d / $h, $h_d_sz /
	       1024, 100 * $h_d_sz / $h_sz, $h_d_tm / (1000 * $h_d), 1000 *
	       $h_d_sz / (1024 * $h_d_tm));
	foreach $hf (sort {$h_d{$b} <=> $h_d{$a}} keys(%h_d)) {
	    writec(I, $hf, $h_d{$hf}, $h_d_sz{$hf}, $h_d_tm{$hf});
	    replin(' ' . $hf, $h_d{$hf}, 100 * $h_d{$hf} / $h, $h_d_sz{$hf} /
		   1024, 100 * $h_d_sz{$hf} / $h_sz, $h_d_tm{$hf} / (1000 *
		   $h_d{$hf}), 1000 * $h_d_sz{$hf} / (1024 * $h_d_tm{$hf}));
	}
    }
    if ($h_s == 0) {
	replin('SIBLING',0,0,0,0,0,0);
    } else {
	replin('HIT on Sibling or Parent Cache', $h_s, 100 * $h_s / $h,
	       $h_s_sz / 1024, 100 * $h_s_sz / $h_sz, $h_s_tm / (1000 * $h_s),
	       1000 * $h_s_sz / (1024 * $h_s_tm) );
	foreach $hf (sort {$h_s{$b} <=> $h_s{$a}} keys(%h_s)) {
	    writec(J, $hf, $h_s{$hf}, $h_s_sz{$hf}, $h_s_tm{$hf});
	    replin(' ' . $hf, $h_s{$hf}, 100 * $h_s{$hf} / $h, $h_s_sz{$hf} /
		   1024, 100 * $h_s_sz{$hf} / $h_sz, $h_s_tm{$hf} / (1000 *
		   $h_s{$hf}), 1000 * $h_s_sz{$hf} / (1024 * $h_s_tm{$hf}));
	}
    }
    if ($h_p == 0) {
	replin('PARENT',0,0,0,0,0,0);
    } else {
	replin('FETCH from Parent Cache', $h_p, 100 * $h_p / $h, $h_p_sz /
	       1024, 100 * $h_p_sz / $h_sz, $h_p_tm / (1000 * $h_p), 1000 *
	       $h_p_sz / (1024 * $h_p_tm) );
	foreach $hf (sort {$h_p{$b} <=> $h_p{$a}} keys(%h_p)) {
	    writec(K, $hf, $h_p{$hf}, $h_p_sz{$hf}, $h_p_tm{$hf});
	    replin(' ' . $hf, $h_p{$hf}, 100 * $h_p{$hf} / $h, $h_p_sz{$hf} /
		   1024, 100 * $h_p_sz{$hf} / $h_sz, $h_p_tm{$hf} / (1000 *
		   $h_p{$hf}), 1000 * $h_p_sz{$hf} / (1024 * $h_p_tm{$hf}));
	}
    }
    repsep();
    replin(Sum, $h, ' ', $h_sz / 1024, ' ', $h_tm / (1000 * $h), 1000 * $h_sz
	   / (1024 * $h_tm));
    repsto();
}

if ($t_m == 0) {
    reptit('Outgoing requests by destination: none');
} else {
    reptit('Outgoing requests by destination');
    repsta();
    rephea('neighbor type',' request','% ',' kByte','% ',' sec', ' kB/sec');
    repsep();
    replin(DIRECT, $h_d, 100 * $h_d / $h, $h_d_sz / 1024, 100 * $h_d_sz /
	   $h_sz, $h_d_tm / (1000 * $h_d), 1000 * $h_d_sz / (1024 * $h_d_tm))
	   unless $t_m_d == 0;
    foreach $n (sort {$h_n{$b} <=> $h_n{$a}} keys(%h_n)) {
	writec(L, $n, $h_n{$n}, $h_n_sz{$n}, $h_n_tm{$n});
	replin($n, $h_n{$n}, 100 * $h_n{$n} / $h, $h_n_sz{$n} / 1024, 100 *
	       $h_n_sz{$n} / $h_sz, $h_n_tm{$n} / (1000 * $h), 1000 *
	       $h_n_sz{$n} / (1024 * $h_n_tm{$n}));
	foreach $st (sort {$h_n_st{$n}{$b} <=> $h_n_st{$n}{$a}}
			keys(%{$h_n_st{$n}})) {
	    writec(M, $n, $st, $h_n_st{$n}{$st}, $h_n_st_sz{$n}{$st},
		   $h_n_st_tm{$n}{$st});
	    replin(' ' .  $st, $h_n_st{$n}{$st}, 100 * $h_n_st{$n}{$st} / $h,
		   $h_n_st_sz{$n}{$st} / 1024, 100 * $h_n_st_sz{$n}{$st} /
		   $h_sz, $h_n_st_tm{$n}{$st} / (1000 * $h), 1000 *
		   $h_n_st_sz{$n}{$st} / (1024 * $h_n_st_tm{$n}{$st}));
	}
    }
    repsep();
    replin(Sum, $h, ' ', $h_sz / 1024, ' ', $h_tm / (1000 * $h), 1000 * $h_sz
	   / (1024 * $h_tm));
    repsto();
}

@f=(39,8,'%',9,'%','%');
if ($opt_d or $opt_a) {
    if ($t == 0) {
	reptit('Request-destinations: none');
    } else {
	reptit('Request-destinations by 2ndlevel-domain');
	repsta();
	rephea('destination',' request','% ','  kByte','% ','hit-%');
	repsep();
	@c = keys %t_u;
	$o_u = $#c + 1;
	$o = $t;
	$o_sz = $t_sz;
	$o_h = $t_h;
	$o_c = $opt_d;
	foreach $uh (sort {$t_u{$b} <=> $t_u{$a}} keys(%t_u)) {
	    $o_u--;
	    $o -= $t_u{$uh};
	    $o_sz -= $t_u_sz{$uh};
	    $o_h -= $t_h_u{$uh};
	    writec(N, $uh, $t_u{$uh}, $t_u_sz{$uh}, $t_h_u{$uh});
	    replin($uh, $t_u{$uh}, 100 * $t_u{$uh} / $t, $t_u_sz{$uh} / 1024,
		   100 * $t_u_sz{$uh} / $t_sz, 100 * $t_h_u{$uh} / $t_u{$uh});
	    last if (--$o_c == 0 and $o != 1);
	}
	if ($o) {
	    writec(N, '<other>', $o, $o_sz, $o_h);
	    replin('other: ' . $o_u . ' 2nd-level-domains', $o, 100 * $o / $t,
		   $o_sz / 1024, 100 * $o_sz / $t_sz, 100 * $o_h / $o);
	}
	repsep();
	replin(Sum, $t, 100, $t_sz / 1024, 100, 100 * $t_h / $t);
	repsto();
	reptit('Request-destinations by toplevel-domain');
	repsta();
	rephea('destination',' request','% ','  kByte','% ','hit-%');
	repsep();
	@c = keys %t_ut;
	$o_tld = $#c + 1;
	$o = $t;
	$o_sz = $t_sz;
	$o_h = $t_h;
	$o_c = $opt_d;
	foreach $ut (sort {$t_ut{$b} <=> $t_ut{$a}} keys(%t_ut)) {
	    $o_tld--;
	    $o -= $t_ut{$ut};
	    $o_sz -= $t_ut_sz{$ut};
	    $o_h -= $t_h_ut{$ut};
	    writec(O, $ut, $t_ut{$ut}, $t_ut_sz{$ut}, $t_h_ut{$ut});
	    replin($ut, $t_ut{$ut}, 100 * $t_ut{$ut} / $t, $t_ut_sz{$ut} /
		   1024, 100 * $t_ut_sz{$ut} / $t_sz, 100 * $t_h_ut{$ut} /
		   $t_ut{$ut});
	    last if (--$o_c == 0 and $o != 1);
	}
	if ($o) {
	    writec(O, '<other>', $o, $o_sz, $o_h);
	    replin('other: ' . $o_tld . ' top-level-domains', $o, 100 * $o /
		   $t, $o_sz / 1024, 100 * $o_sz / $t_sz, 100 * $o_h / $o);
	}
	repsep();
	replin(Sum, $t, 100, $t_sz / 1024, 100, 100 * $t_h / $t);
	repsto();
    }
}

if ($opt_t or $opt_a) {
    if ($t == 0) {
	reptit('TCP-Request-protocol: none');
    } else {
	reptit('TCP-Request-protocol');
	repsta();
	rephea('protocol',' request','% ','  kByte','% ','hit-%');
	repsep();
	foreach $up (sort {$t_up{$b} <=> $t_up{$a}} keys(%t_up)) {
	    writec(P, $up, $t_up{$up}, $t_up_sz{$up}, $t_h_up{$up});
	    replin($up, $t_up{$up}, 100 * $t_up{$up} / $t, $t_up_sz{$up} /
		   1024, 100 * $t_up_sz{$up} / $t_sz, 100 * $t_h_up{$up} /
		   $t_up{$up});
	}
	repsep();
	replin(Sum, $t, 100, $t_sz / 1024, 100, 100 * $t_h / $t);
	repsto();
    }
    if ($t == 0) {
	reptit('Requested content-type: none');
    } else {
	reptit('Requested content-type');
	repsta();
	rephea('content-type',' request','% ','  kByte','% ','hit-%');
	repsep();
	@c = keys %t_ct;
	$o_ct = $#c + 1;
	$o = $t;
	$o_sz = $t_sz;
	$o_h = $t_h;
	$o_c = $opt_t;
	foreach $ct (sort {$t_ct{$b} <=> $t_ct{$a}} keys(%t_ct)) {
	    $o_ct--;
	    $o -= $t_ct{$ct};
	    $o_sz -= $t_ct_sz{$ct};
	    $o_h -= $t_h_ct{$ct};
	    writec(Q, $ct, $t_ct{$ct}, $t_ct_sz{$ct}, $t_h_ct{$ct});
	    replin($ct, $t_ct{$ct}, 100 * $t_ct{$ct} / $t, $t_ct_sz{$ct} /
		   1024, 100 * $t_ct_sz{$ct} / $t_sz, 100 * $t_h_ct{$ct} /
		   $t_ct{$ct});
	    last if (--$o_c == 0 and $o != 1);
	}
	if ($o) {
	    writec(Q, '<other>', $o, $o_sz, $o_h);
	    replin('other: '. $o_ct . ' content-types', $o, 100 * $o / $t,
		   $o_sz / 1024, 100 * $o_sz / $t_sz, 100 * $o_h / $o);
	}
	repsep();
	replin(Sum, $t, 100, $t_sz / 1024, 100, 100 * $t_h / $t);
	repsto();
    }
    if ($t == 0) {
	reptit('Requested extensions: none');
    } else {
	reptit('Requested extensions');
	repsta();
	rephea('extensions',' request','% ','  kByte','% ','hit-%');
	repsep();
	@c = keys %t_ue;
	$o_ue = $#c + 1;
	$o = $t;
	$o_sz = $t_sz;
	$o_h = $t_h;
	$o_c = $opt_t;
	foreach $ue (sort {$t_ue{$b} <=> $t_ue{$a}} keys(%t_ue)) {
	    $o_ue--;
	    $o -= $t_ue{$ue};
	    $o_sz -= $t_ue_sz{$ue};
	    $o_h -= $t_h_ue{$ue};
	    writec(R, $ue, $t_ue{$ue}, $t_ue_sz{$ue}, $t_h_ue{$ue});
	    replin($ue, $t_ue{$ue}, 100 * $t_ue{$ue} / $t, $t_ue_sz{$ue} /
		   1024, 100 * $t_ue_sz{$ue} / $t_sz, 100 * $t_h_ue{$ue} /
		   $t_ue{$ue});
	    last if (--$o_c == 0 and $o != 1);
	}
	if ($o) {
	    writec(R, '<other>', $o, $o_sz, $o_h);
	    replin('other: '. $o_ue . ' extensions', $o, 100 * $o / $t, $o_sz
		   / 1024, 100 * $o_sz / $t_sz, 100 * $o_h / $o);
	}
	repsep();
	replin(Sum, $t, 100, $t_sz / 1024, 100, 100 * $t_h / $t);
	repsto();
    }
}

@f=(33,8,'%',9,'%',4,'kbs');
if ($opt_r or $opt_a) {
    if ($u == 0) {
	reptit('Incoming UDP-requests by host: none');
    } else {
	reptit('Incoming UDP-requests by host');
	repsta();
	rephea('host',' request','hit-%','  kByte','hit-%','msec',' kB/sec');
	repsep();
	foreach $n (sort {$u_r{$b} <=> $u_r{$a}} keys(%u_r)) {
	    writec(S, $n, $u_r{$n}, $u_r_sz{$n}, $u_r_tm{$n}, $u_h_r{$n},
		   $u_h_r_sz{$n});
	    replin($n, $u_r{$n}, 100 * $u_h_r{$n} / $u_r{$n}, $u_r_sz{$n} /
		   1024, 100 * $u_h_r_sz{$n} / $u_r_sz{$n}, $u_r_tm{$n} /
		   $u_r{$n}, 1000 * $u_r_sz{$n} / (1024 * $u_r_tm{$n}));
	}
	repsep();
	replin(Sum, $u, 100 * $u_h / $u, $u_sz / 1024, 100 * $u_h_sz / $u_sz,
	       $u_tm / $u, 1000 * $u_sz / (1024 * $u_tm));
	repsto();
    }

    if ($t == 0) {
	reptit('Incoming TCP-Requests by host: none');
    } else {
	reptit('Incoming TCP-requests by host');
	repsta();
	rephea('host',' request','hit-%','  kByte','hit-%','sec',' kB/sec');
	repsep();
	@c = keys %t_r;
	$o_r = $#c + 1;
	$o = $t;
	$o_sz = $t_sz;
	$o_tm = $t_tm;
	$o_h = $t_h;
	$o_h_sz = $t_h_sz;
	$o_c = $opt_r;
	foreach $r (sort {$t_r{$b} <=> $t_r{$a}} keys(%t_r)) {
	    $o_r--;
	    $o -= $t_r{$r};
	    $o_sz -= $t_r_sz{$r};
	    $o_tm -= $t_r_tm{$r};
	    $o_h -= $t_h_r{$r};
	    $o_h_sz -= $t_h_r_sz{$r};
	    writec(T, $r, $t_r{$r}, $t_r_sz{$r}, $t_r_tm{$r}, $t_h_r{$r},
		   $t_h_r_sz{$r});
	    replin($r, $t_r{$r}, 100 * $t_h_r{$r} / $t_r{$r}, $t_r_sz{$r} /
		   1024, 100 * $t_h_r_sz{$r} / $t_r_sz{$r}, $t_r_tm{$r} /
		   (1000 * $t_r{$r}), 1000 * $t_r_sz{$r} / (1024 *
		   $t_r_tm{$r}));
	    last if(--$o_c == 0 and $o != 1);
	}
	if ($o) {
	    writec(T, '<other>', $o, $o_sz, $o_tm, $o_h, $o_h_sz);
	    replin('other: ' . $o_r . ' requesting hosts', $o, 100 * $o_h /
		   $o, $o_sz / 1024, 100 * $o_h_sz / $o_sz, $o_tm / (1000 *
		   $t), 1000 * $o_sz / (1024 * $t_tm));
	}
	repsep();
	replin(Sum, $t, 100 * $t_h / $t, $t_sz / 1024, 100 * $t_h_sz / $t_sz,
	       $t_tm / (1000 * $t), 1000 * $t_sz / (1024 * $t_tm));
	repsto();
    }
}
close(CACHE);

if ($opt_w) {
    print("<hr>\n<address>$COPYRIGHT</address>\n</body></html>\n");
} else {
    print("\n\n\n$COPYRIGHT\n");
}

sub getfqdn {
    my ($h) = @_;
    if ($opt_n) {
	return $h;
    } elsif ($h =~ /^([0-9][0-9]{0,2}\.){3}[0-9][0-9]{0,2}$/) {
	$nsc{$h} = addtonam($h) unless defined $nsc{$h};
	return $nsc{$h};
    } else {
	return $h;
    }
}

sub addtonam {
    my ($address) = shift (@_);
    my (@octets);
    my ($name, $aliases, $type, $len, $addr);
    my ($ip_number);
    @octets = split ('\.', $address) ;
    if ($#octets != 3) {
	undef;
    }
    $ip = pack ("CCCC", @octets[0..3]);
    ($name, $aliases, $type, $len, $addr) = gethostbyaddr ($ip, 2);
    if ($name) {
	$name;
    } else {
	$address;
    }
}

sub condat {
    my $d = shift(@_);
    if ($d) {
	my ($s,$m,$h,$mday,$mon,$y) = (localtime($d))[0,1,2,3,4,5,6];
	my $month = ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep',
		     'Oct','Nov','Dec')[$mon];
	my $retdate = sprintf("%02d.%s %02d %02d:%02d:%02d\n", $mday, $month,
			      $y, $h, $m, $s);
	chomp($retdate);
	return $retdate;
    } else {
	return '                  ';
    }
}

sub reptit {
    my $p = shift(@_);
    if ($opt_w) {
	print("<h2>$p</h2>\n");
    } else {
	print("\n# $p\n");
    }
}

sub repsta {
    print("<table border=\"1\">\n") if ($opt_w);
}

sub rephea {
    my $p;
    my $no = 0;
    print('<tr>') if ($opt_w);
    foreach (@_) {
	$p = $_;
	if ($opt_w) {
	    $p =~ s/ +/ /go;
	    $p =~ s/(^ | $)//go;
	    print("<th>$p");
	} elsif ($f[$no] =~ m#\%#o) {
	    print(' ' x (6 - length($p)), substr($p,0,6), ' ');
	} elsif ($f[$no] =~ m#kbs#o) {
	    print(substr($p,0,7) . ' ' x (7 - length($p)), ' ');
	} else {
	    print(substr($p,0,$f[$no]) . ' ' x ($f[$no] - length($p)), ' ');
	}
	$no++;
    }
    print('</th>') if ($opt_w);
    print("\n");
}

sub replin {
    my $p;
    my $no = 0;
    print('<tr>') if ($opt_w);
    foreach (@_) {
	$p = $_;
	if ($opt_w) {
	    $p =~ s/ +/ /go;
	    $p =~ s/ $//go;
	    $p =~ s/</\&lt\;/go;
	    $p =~ s/>/\&gt\;/go;
	    if ($no == 0) {
		unless ($p =~ s/^ //go) {
		    print("<td><strong>$p</strong>");
		} else {
		    print("<td>$p");
		}
	    } elsif ($f[$no] eq '%' or $f[$no] eq 'kbs') {
		if ($p eq '') {
		    print('<td>');
		} else {
		    printf("<td align=\"right\">%.2f", $p);
		}
	    } elsif ($no == 1 or $p =~ m#^[\d\.e\-\+]+$#o) {
		printf("<td align=\"right\">%d", $p);
	    } else {
		print("<td align=\"right\">$p");
	    }
	} else {
	    if ($no == 0) {
		if (length($p) > $f[$no]) {
		    print("$p\n" . ' ' x $f[$no], ' ');
		} else {
		    print($p .  ' ' x ($f[$no] - length($p)), ' ');
		}
	    } elsif ($f[$no] =~ m#%#o) {
		if ($p eq ' ') {
		    printf(' ' x 7);
		} else {
		    printf("%6.2f ", $p);
		}
	    } elsif ($f[$no] eq 'kbs') {
		printf("%7.2f ", $p);
	    } else {
		$p = sprintf("%d", $p + .5) if $p =~ m#^[\d\.e\-\+]+$#o;
		print(' ' x ($f[$no] - length($p)) . substr($p,0,$f[$no]),
		      ' ');
	    }
	}
	$no++;
    }
    print('</tr>') if ($opt_w);
    print("\n");
}

sub repsep {
    my $p;
    print('<tr>') if ($opt_w);
    foreach $p (@f) {
	if ($opt_w) {
	    print('<td>');
	} elsif ($p eq '%') {
	    print('-' x 6, ' ');
	} elsif ($p eq 'kbs') {
	    print('-' x 7, ' ');
	} else {
	    print('-' x $p, ' ');
	}
    }

    print('</tr>') if ($opt_w);
    print("\n");
}

sub repsto {
    print("</table>\n") if ($opt_w);
}

sub writec {
    if ($opt_o) {
	print CACHE join('µ', @_) . "\n";
    }
}
