#!/usr/bin/perl -w
#
# $Id: calamaris.pl,v 2.11 1998-10-22 19:36:52 cord Exp $
#
# DESCRIPTION: calamaris.pl - statistic for Squid and NetCache Native Log-files
#
# Copyright (C) 1997, 1998 Cord Beermann
#
# URL: http://www.Cord.de/~cord/tools/squid/calamaris/
# Announcement-Mailing-list: send Mail with 'subscribe' in the Mail-Body to
#			    Calamaris-announce-request@Cord.de
#
# AUTHOR: Cord Beermann (Cord@Wunder-Nett.org)
#
# Thanks to these contributors, bug reporters, and feature requesters:
#	John Heaton (John@MCC.ac.uk)
#	Andreas Lamprecht (Andreas.Lamprecht@siemens.at)
#	Kenny Ng (kennyng@cyberway.com.sg)
#	Claus Langhans (langhans@rz.uni-frankfurt.de)
#	Andreas Jung (ajung@sz-sb.de)
#	Ernst Heiri (heiri@switch.ch)
#	Shamil R. Yahin (SSHY@cclib.nsu.ru)
#	Thoralf Freitag (Thoralf.Freitag@isst.fhg.de)
#	Marco Paganini (paganini@paganini.net)
#	Michael Riedel (mr@fto.de)
#	Kris Boulez (krbou@pgsgent.be)
#	Mark Visser (mark@snt.utwente.nl)
#	Gary Palmer (gjp@erols.com)
#	Stefan Watermann (stefan@metronet.de)
#	Roar Smith (Roar.Smith@Ericsson.Dk)
#	Bernd Lienau (lienau@tli.de)
#	Gary Lindstrom (gplindstrom@exodus.nnc.edu)
#	Jost Krieger (Jost.Krieger@ruhr-uni-bochum.de)
#	Gerd Michael Hoffmann <Hoffmann@dvgw.de>

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.

# (If you modify and want to publish it under the name 'Calamaris', please
# ask me. I don't want to confuse the 'audience' with many different versions
# of the same name and/or Version number.)

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307, USA.


# A Perl script is "correct" if it gets the job done before your boss fires
# you.
#   -- 'Programming Perl Second Edition'
#	by Larry Wall, Tom Christiansen & Randal L. Schwartz

require 5;

use vars qw($opt_a $opt_b $opt_c $opt_d $opt_h $opt_H $opt_i $opt_m $opt_n
	    $opt_o $opt_O $opt_p $opt_P $opt_r $opt_s $opt_t $opt_u $opt_w
	    $opt_z);
use Getopt::Std;
use Sys::Hostname;

getopts('ab:cd:hH:i:mno:OpP:r:st:uwz');

$COPYRIGHT='calamaris $Revision: 2.11 $, Copyright (C) 1997, 1998 Cord Beermann.
Calamaris comes with ABSOLUTELY NO WARRANTY. It is free software,
and you are welcome to redistribute it under certain conditions.
See source for details.

';

$USAGE='Usage: cat log | ' . $0 . ' [switches]

Reports:
-a	    all  (extracts all reports available,
		  -a equals -d 20 -p -P 60 -r -1 -s -t 20)
-d n	    domain (show n Top-level and n second-level destinations,
		    -1 = unlimited)
-p	    peak (measure peak requests)
-P n	    Performance (show throughput data for every n minutes)
-r n	    requester (show n Requesters, -1 = unlimited)
-s	    status (show verbose status reports)
-t n	    type (show n content-type, n extensions and requested protocols,
		  -1 = unlimited)

Output Format: (Default is plain text)
-m	    mail  (mail format)
-w	    web   (HTML format, can be combined with -m)

Caching:
-i file	    input-file (input-datafile for caching, to add many files
			separate them with a \':\')
-o file	    output-file (output-datafile for caching, can be the same as -i)

Misc:
-b n	    benchmark (prints a hash for each n lines)
-H name	    Host-name (a name for the Output, -H \'lookup\' issues a lookup
		       for the current host)
-n	    no-lookup (don\'t look IP-Numbers up)
-O	    order (changes the sort order in the reports to request size,
		   default is sorting by number of requests)
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

$sortorder = '';
$sortorder = '_size' if ($opt_O);

if ($opt_a) {
  $opt_s = 1;
  $opt_p = 1;
  $opt_P = 60 unless $opt_P;
  $opt_d = 20 unless $opt_d;
  $opt_r = -1 unless $opt_r;
  $opt_t = 20 unless $opt_t;
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
  = $tcp_hit_time = $tcp_miss = $tcp_miss_none = $tcp_miss_none_size =
  $tcp_miss_none_time = $tcp_miss_size = $tcp_miss_time = $tcp_size =
  $tcp_time = $time = $time_end = $time_run = $udp = $udp_hit = $udp_hit_size
  = $udp_hit_time = $udp_miss = $udp_miss_size = $udp_miss_time = $udp_size =
$udp_time = 0;
$time_begin = 9999999999;

### Read Cache. 
if ($opt_i) {
  foreach $file (split ':', $opt_i) {
    open(CACHE, "$file") or die("$0: can't open $file for reading: $!\n");
    while (<CACHE>) {
      chomp;
      @cache = split 'µ';
      $x = shift(@cache);
      unless ($x) {
	next;
      } elsif ($x eq A and $#cache == 39) {
	$time_begin = $cache[0] if $cache[0] < $time_begin;
	$time_end = $cache[1] if $cache[1] > $time_end;
	$counter += $cache[2];
	$size += $cache[3];
	$time += $cache[4];
	$invalid += $cache[5];
	$time_run += $cache[6];
	$udp += $cache[7];
	$udp_size += $cache[8];
	$udp_time += $cache[9];
	$udp_hit += $cache[10];
	$udp_hit_size += $cache[11];
	$udp_hit_time += $cache[12];
	$udp_miss += $cache[13];
	$udp_miss_size += $cache[14];
	$udp_miss_time += $cache[15];
	$tcp += $cache[16];
	$tcp_size += $cache[17];
	$tcp_time += $cache[18];
	$tcp_hit += $cache[19];
	$tcp_hit_size += $cache[20];
	$tcp_hit_time += $cache[21];
	$tcp_miss += $cache[22];
	$tcp_miss_size += $cache[23];
	$tcp_miss_time += $cache[24];
	$tcp_miss_none += $cache[25];
	$tcp_miss_none_size += $cache[26];
	$tcp_miss_none_time += $cache[27];
	$hier += $cache[28];
	$hier_size += $cache[29];
	$hier_time += $cache[30];
	$hier_direct += $cache[31];
	$hier_direct_size += $cache[32];
	$hier_direct_time += $cache[33];
	$hier_sibling += $cache[34];
	$hier_sibling_size += $cache[35];
	$hier_sibling_time += $cache[36];
	$hier_parent += $cache[37];
	$hier_parent_size += $cache[38];
	$hier_parent_time += $cache[39];
      } elsif ($x eq B and $#cache == 17) {
	if ($peak_udp_sec < $cache[0]) {
	  $peak_udp_sec = $cache[0];
	  $peak_udp_sec_time = $cache[1];
	}
	if ($peak_udp_min < $cache[2]) {
	  $peak_udp_min = $cache[2];
	  $peak_udp_min_time = $cache[3];
	}
	if ($peak_udp_hour < $cache[4]) {
	  $peak_udp_hour = $cache[4];
	  $peak_udp_hour_time = $cache[5];
	}
	if ($peak_tcp_sec < $cache[6]) {
	  $peak_tcp_sec = $cache[6];
	  $peak_tcp_sec_time = $cache[7];
	}
	if ($peak_tcp_min < $cache[8]) {
	  $peak_tcp_min = $cache[8];
	  $peak_tcp_min_time = $cache[9];
	}
	if ($peak_tcp_hour < $cache[10]) {
	  $peak_tcp_hour = $cache[10];
	  $peak_tcp_hour_time = $cache[11];
	}
	if ($peak_all_sec < $cache[12]) {
	  $peak_all_sec = $cache[12];
	  $peak_all_sec_time = $cache[13];
	}
	if ($peak_all_min < $cache[14]) {
	  $peak_all_min = $cache[14];
	  $peak_all_min_time = $cache[15];
	}
	if ($peak_all_hour < $cache[16]) {
	  $peak_all_hour = $cache[16];
	  $peak_all_hour_time = $cache[17];
	}
      } elsif ($x eq C and $#cache == 3) {
	$y = shift(@cache);
	$method{$y} = $method_size{$y} = $method_time{$y} = 0 unless defined
	  $method{$y};
	$method{$y} += $cache[0];
	$method_size{$y} += $cache[1];
	$method_time{$y} += $cache[2];
      } elsif ($x eq D and $#cache == 3) {
	$y = shift(@cache);
	$udp_hit{$y} = $udp_hit_size{$y} = $udp_hit_time{$y} = 0 unless
	  defined $udp_hit{$y};
	$udp_hit{$y} += $cache[0];
	$udp_hit_size{$y} += $cache[1];
	$udp_hit_time{$y} += $cache[2];
      } elsif ($x eq E and $#cache == 3) {
	$y = shift(@cache);
	$udp_miss{$y} = $udp_miss_size{$y} = $udp_miss_time{$y} = 0 unless
	  defined $udp_miss{$y};
	$udp_miss{$y} += $cache[0];
	$udp_miss_size{$y} += $cache[1];
	$udp_miss_time{$y} += $cache[2];
      } elsif ($x eq F and $#cache == 3) {
	$y = shift(@cache);
	$tcp_hit{$y} = $tcp_hit_size{$y} = $tcp_hit_time{$y} = 0 unless
	  defined $tcp_hit{$y};
	$tcp_hit{$y} += $cache[0];
	$tcp_hit_size{$y} += $cache[1];
	$tcp_hit_time{$y} += $cache[2];
      } elsif ($x eq G and $#cache == 3) {
	$y = shift(@cache);
	$tcp_miss{$y} = $tcp_miss_size{$y} = $tcp_miss_time{$y} = 0 unless
	  defined $tcp_miss{$y};
	$tcp_miss{$y} += $cache[0];
	$tcp_miss_size{$y} += $cache[1];
	$tcp_miss_time{$y} += $cache[2];
      } elsif ($x eq H and $#cache == 3) {
	$y = shift(@cache);
	$tcp_miss_none{$y} = $tcp_miss_none_size{$y} = $tcp_miss_none_time{$y}
	  = 0 unless defined $tcp_miss_none{$y};
	$tcp_miss_none{$y} += $cache[0];
	$tcp_miss_none_size{$y} += $cache[1];
	$tcp_miss_none_time{$y} += $cache[2];
      } elsif ($x eq I and $#cache == 3) {
	$y = shift(@cache);
	$hier_direct{$y} = $hier_direct_size{$y} = $hier_direct_time{$y} = 0
	  unless defined $hier_direct{$y};
	$hier_direct{$y} += $cache[0];
	$hier_direct_size{$y} += $cache[1];
	$hier_direct_time{$y} += $cache[2];
      } elsif ($x eq J and $#cache == 3) {
	$y = shift(@cache);
	$hier_sibling{$y} = $hier_sibling_size{$y} = $hier_sibling_time{$y} =
	  0 unless defined $hier_sibling{$y};
	$hier_sibling{$y} += $cache[0];
	$hier_sibling_size{$y} += $cache[1];
	$hier_sibling_time{$y} += $cache[2];
      } elsif ($x eq K and $#cache == 3) {
	$y = shift(@cache);
	$hier_parent{$y} = $hier_parent_size{$y} = $hier_parent_time{$y} = 0
	  unless defined $hier_parent{$y};
	$hier_parent{$y} += $cache[0];
	$hier_parent_size{$y} += $cache[1];
	$hier_parent_time{$y} += $cache[2];
      } elsif ($x eq L and $#cache == 3) {
	$y = shift(@cache);
	$hier_neighbor{$y} = $hier_neighbor_size{$y} = $hier_neighbor_time{$y}
	  = 0 unless defined $hier_neighbor{$y};
	$hier_neighbor{$y} += $cache[0];
	$hier_neighbor_size{$y} += $cache[1];
	$hier_neighbor_time{$y} += $cache[2];
      } elsif ($x eq M and $#cache == 4) {
	$y = shift(@cache);
	$z = shift(@cache);
	$hier_neighbor_status{$y}{$z} = $hier_neighbor_status_size{$y}{$z} =
	  $hier_neighbor_status_time{$y}{$z} = 0 unless defined
	  $hier_neighbor_status{$y}{$z};
	$hier_neighbor_status{$y}{$z} += $cache[0];
	$hier_neighbor_status_size{$y}{$z} += $cache[1];
	$hier_neighbor_status_time{$y}{$z} += $cache[2];
      } elsif ($x eq N and $#cache == 3) {
	$y = shift(@cache);
	$tcp_urlhost{$y} = $tcp_urlhost_size{$y} = $tcp_hit_urlhost{$y} = 0
	  unless defined $tcp_urlhost{$y};
	$tcp_urlhost{$y} += $cache[0];
	$tcp_urlhost_size{$y} += $cache[1];
	$tcp_hit_urlhost{$y} += $cache[2];
      } elsif ($x eq O and $#cache == 3) {
	$y = shift(@cache);
	$tcp_urltld{$y} = $tcp_urltld_size{$y} = $tcp_hit_urltld{$y} = 0
	  unless defined $tcp_urltld{$y};
	$tcp_urltld{$y} += $cache[0];
	$tcp_urltld_size{$y} += $cache[1];
	$tcp_hit_urltld{$y} += $cache[2];
      } elsif ($x eq P and $#cache == 3) {
	$y = shift(@cache);
	$tcp_urlprot{$y} = $tcp_urlprot_size{$y} = $tcp_hit_urlprot{$y} = 0
	  unless defined $tcp_urlprot{$y};
	$tcp_urlprot{$y} += $cache[0];
	$tcp_urlprot_size{$y} += $cache[1];
	$tcp_hit_urlprot{$y} += $cache[2];
      } elsif ($x eq Q and $#cache == 3) {
	$y = shift(@cache);
	$tcp_content{$y} = $tcp_content_size{$y} = $tcp_hit_content{$y} = 0
	  unless defined $tcp_content{$y};
	$tcp_content{$y} += $cache[0];
	$tcp_content_size{$y} += $cache[1];
	$tcp_hit_content{$y} += $cache[2];
      } elsif ($x eq R and $#cache == 3) {
	$y = shift(@cache);
	$tcp_urlext{$y} = $tcp_urlext_size{$y} = $tcp_hit_urlext{$y} = 0
	  unless defined $tcp_urlext{$y};
	$tcp_urlext{$y} += $cache[0];
	$tcp_urlext_size{$y} += $cache[1];
	$tcp_hit_urlext{$y} += $cache[2];
      } elsif ($x eq S and $#cache == 5) {
	$y = shift(@cache);
	$udp_requester{$y} = $udp_requester_size{$y} = $udp_requester_time{$y}
	  = $udp_hit_requester{$y} = $udp_hit_requester_size{$y} = 0 unless
	  defined $udp_requester{$y};
	$udp_requester{$y} += $cache[0];
	$udp_requester_size{$y} += $cache[1];
	$udp_requester_time{$y} += $cache[2];
	$udp_hit_requester{$y} += $cache[3];
	$udp_hit_requester_size{$y} += $cache[4];
      } elsif ($x eq T and $#cache == 5) {
	$y = shift(@cache);
	$tcp_requester{$y} = $tcp_requester_size{$y} = $tcp_requester_time{$y}
	  = $tcp_hit_requester{$y} = $tcp_hit_requester_size{$y} = 0 unless
	  defined $tcp_requester{$y};
	$tcp_requester{$y} += $cache[0];
	$tcp_requester_size{$y} += $cache[1];
	$tcp_requester_time{$y} += $cache[2];
	$tcp_hit_requester{$y} += $cache[3];
	$tcp_hit_requester_size{$y} += $cache[4];
      } elsif ($x eq U and $#cache == 13) {
	$y = shift(@cache);
	($perf_counter{$y}, $perf_size{$y}, $perf_time{$y},
	 $perf_tcp_hit_size{$y}, $perf_tcp_hit_time{$y},
	 $perf_tcp_miss_size{$y}, $perf_tcp_miss_time{$y},
	 $perf_hier_direct_size{$y}, $perf_hier_direct_time{$y},
	 $perf_hier_sibling_size{$y}, $perf_hier_sibling_time{$y},
	 $perf_hier_parent_size{$y}, $perf_hier_parent_time{$y}) = @cache;
# This is for a stupid bug I brought in... it should save older Cache-Files,
# and put them in so that we can work with them.. I'll remove it in a
# later release...
      } elsif ($x eq U and $#cache == 12) {
	$y = shift(@cache);
	($perf_counter{$y}, $perf_size{$y}, $perf_time{$y},
	 $perf_tcp_hit_size{$y}, $perf_tcp_miss_size{$y},
	 $perf_tcp_miss_time{$y}, $perf_hier_direct_size{$y},
	 $perf_hier_direct_time{$y}, $perf_hier_sibling_size{$y},
	 $perf_hier_sibling_time{$y}, $perf_hier_parent_size{$y},
	 $perf_hier_parent_time{$y}) = @cache;
	# stupid, yes...
	# I set this to 0/.000001 so removezerotime prints a - in the report.
	$perf_tcp_hit_size{$y} = 0;
	$perf_tcp_hit_time{$y} = .000001;
# End of stupid bug-workaround
      } else {
	warn("can't parse cache-line: \"$x @cache\"\n");
      }
    }
    close(CACHE);
  }
}

unless ($opt_z) {
  print("print a hash for each $opt_b lines:\n") if ($opt_b);
  $loop = '
while (<>) {
  ($log_date, $log_reqtime, $log_requester, $log_status, $log_size,
   $log_method, $log_url, $log_ident, $log_hier, $log_content, $foo) = split;
  if (not defined $foo or not defined $log_content or $foo ne m#^-?$#o or
      $log_content eq \'\') {
    chomp;
    warn (\'invalid line: "\' . $_ . "\"\n");
    $invalid++;
    next;
  }
  $log_reqtime = .1 if $log_reqtime == 0;
  ($log_hitfail, $log_code) = split \'/\', $log_status;
  $log_size = .0000000001 if $log_size == 0;
  @url = split m#[/\\\]#o, $log_url;
  ($urlprot, $urlhost, $urlext) = (@url)[0,2,$#url];
  $urlext = \'.<none>\' if $#url <= 2;
  if ($#url <= -1) {
    $urlext = \'.<error>\';
    $urlprot = $urlhost = \'<error>\';
  }
  $urlext = \'.<dynamic>\' if ($urlext =~ m#[\?;&\$,!@=|]#o or
			       $log_method eq POST);
  unless (defined $urlhost) {
    $urlhost = $urlprot;
    $urlprot = \'<none>\';
  }
  $urlhost =~ s#^.*@##o;
  $urlhost =~ s#[:\?].*$##o;
  @urlext = split \'\.\', $urlext;
  $urlext = (@urlext)[$#urlext];
  $urlext = \'<none>\' if $#urlext <= 0;
  if ($urlhost =~ /^(([0-9][0-9]{0,2}\.){3})[0-9][0-9]{0,2}$/o) {
    $urlhost = $1 . \'*\';
    $urltld = \'<unresolved>\';
  } elsif ($urlhost =~ /^(.*\.([^\.]+\.)?)?([^\.]+\.([^\.]+))\.?$/o) {
    @list = split \'\.\', $urlhost;
    $urltld = $urlhost = \'.\' . pop @list;
    $urlhost = \'.\' . pop(@list) . $urlhost;
    $urlhost = \'.\' . pop(@list) . $urlhost if ($urltld =~
						 /\.(a[rtu]|br|c[no]|hk|i[dlm]|jp|kr|l[by]|m[oxy]|nz|p[elnry]|ru|sg|t[hrw]|u[aks]|ve|yu|za)$/o
						 and $#list >= 0);
    $urlhost = \'*\' . $urlhost;
    $urltld = \'*\' . $urltld;
  } elsif ($urlhost =~ m#([!a-z0-9\.\-]|\.\.)#o) {
    $urlhost = $urltld = $urlext = \'<error>\';
  } else {
    $urltld = $urlhost;
  }';
  if ($opt_u) {
    $loop .= '
  $requester = $log_ident . \'@\' . $log_requester;';
  } else {
    $loop .= '
  $requester = $log_requester;';
  }
  $loop .= '
  ($log_hier_method, $log_hier_host) = (split \'/\', $log_hier)[0,1];
  $log_content = \'<unknown>\' if $log_content eq \'-\';
  $log_content =~ tr/A-Z/a-z/;
  $log_content = $urlhost = $urltld = $urlext = \'<error>\' if
    ($log_code =~ m#^[45]#o);';
  $loop .= "
  print('#') if (\$counter / $opt_b) eq int(\$counter / $opt_b);" if $opt_b;
  $loop .= '
  $counter++;';
  $loop .= '
  $size += $log_size;
  $time += $log_reqtime;
  $method{$log_method} = $method_size{$log_method} = $method_time{$log_method}
    = 0 unless defined $method{$log_method};
  $method{$log_method}++;
  $method_size{$log_method} += $log_size;
  $method_time{$log_method} += $log_reqtime;
  $time_begin = $log_date if $log_date < $time_begin;
  $time_end = $log_date if $log_date > $time_end;';
  if ($opt_p) {
    $loop .= '
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
  }';
  }
  $loop .= '
  if (($log_method eq \'ICP_QUERY\') or ($log_status =~ m#^ICP#o)) {
    $udp++;
    $udp_size += $log_size;
    $udp_time += $log_reqtime;';
  if ($opt_r) {
    $loop .= '
    $udp_requester{$requester} = $udp_requester_size{$requester} =
      $udp_requester_time{$requester} = $udp_hit_requester{$requester} =
      $udp_hit_requester_size{$requester} = 0 unless defined
      $udp_requester{$requester};
    $udp_requester{$requester}++;
    $udp_requester_size{$requester} += $log_size;
    $udp_requester_time{$requester} += $log_reqtime;';
  }
  if ($opt_p) {
    $loop .= '
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
    }';
  }
  $loop .= '
    if ($log_hitfail =~ m#^UDP_HIT#o or $log_hitfail =~ m#^ICP_HIT#o) {
      $udp_hit++;
      $udp_hit_size += $log_size;
      $udp_hit_time += $log_reqtime;';
  if ($opt_r) {
    $loop .= '
      $udp_hit_requester{$requester}++;
      $udp_hit_requester_size{$requester} += $log_size;';
  }
  if ($opt_s) {
    $loop .= '
      $udp_hit{$log_hitfail} = $udp_hit_size{$log_hitfail} =
	$udp_hit_time{$log_hitfail} = 0 unless defined $udp_hit{$log_hitfail};
      $udp_hit{$log_hitfail}++;
      $udp_hit_size{$log_hitfail} += $log_size;
      $udp_hit_time{$log_hitfail} += $log_reqtime;';
  }
  $loop .= '
    } else {
      $udp_miss++;
      $udp_miss_size += $log_size;
      $udp_miss_time += $log_reqtime;';
  if ($opt_s) {
    $loop .= '
      $udp_miss{$log_hitfail} = $udp_miss_size{$log_hitfail} =
      $udp_miss_time{$log_hitfail} = 0 unless defined $udp_miss{$log_hitfail};
      $udp_miss{$log_hitfail}++;
      $udp_miss_size{$log_hitfail} += $log_size;
      $udp_miss_time{$log_hitfail} += $log_reqtime;';
  }
    $loop .= '
    }
  } else {
    $tcp++;
    $tcp_size += $log_size;
    $tcp_time += $log_reqtime;';
  if ($opt_P) {
    $loop .= '
    $perf_date = int($log_date / (60 * ' . "$opt_P)) * 60 * $opt_P;" . '
    unless (defined $perf_counter{$perf_date}) {
      $perf_counter{$perf_date} = $perf_size{$perf_date} =
	$perf_tcp_hit_size{$perf_date} = $perf_tcp_miss_size{$perf_date} =
	$perf_hier_direct_size{$perf_date} =
	$perf_hier_sibling_size{$perf_date} =
	$perf_hier_parent_size{$perf_date} = 0;
      $perf_time{$perf_date} = $perf_tcp_hit_time{$perf_date} =
	$perf_tcp_miss_time{$perf_date} = $perf_hier_direct_time{$perf_date} =
	$perf_hier_sibling_time{$perf_date} =
	$perf_hier_parent_time{$perf_date} = .0000000001;
      }
    $perf_counter{$perf_date}++;
    $perf_size{$perf_date} += $log_size;
    $perf_time{$perf_date} += $log_reqtime;';
  }
  if ($opt_r) {
    $loop .= '
    $tcp_requester{$requester} = $tcp_requester_size{$requester} =
      $tcp_requester_time{$requester} = $tcp_hit_requester{$requester} =
      $tcp_hit_requester_size{$requester} = 0 unless defined
      $tcp_requester{$requester};
    $tcp_requester{$requester}++;
    $tcp_requester_size{$requester} += $log_size;
    $tcp_requester_time{$requester} += $log_reqtime;';
  }
  if ($opt_d) {
    $loop .= '
    $tcp_urlhost{$urlhost} = $tcp_urlhost_size{$urlhost} =
      $tcp_hit_urlhost{$urlhost} = 0 unless defined $tcp_urlhost{$urlhost};
    $tcp_urlhost{$urlhost}++;
    $tcp_urlhost_size{$urlhost} += $log_size;
    $tcp_urltld{$urltld} = $tcp_urltld_size{$urltld} =
      $tcp_hit_urltld{$urltld} = 0 unless defined $tcp_urltld{$urltld};
    $tcp_urltld{$urltld}++;
    $tcp_urltld_size{$urltld} += $log_size;';
  }
  if ($opt_t) {
    $loop .= '
    $tcp_urlprot{$urlprot} = $tcp_urlprot_size{$urlprot} =
      $tcp_hit_urlprot{$urlprot} = 0 unless defined $tcp_urlprot{$urlprot};
    $tcp_urlprot{$urlprot}++;
    $tcp_urlprot_size{$urlprot} += $log_size;';
  }
  if ($opt_p) {
    $loop .= '
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
    }';
  }
  if ($opt_t) {
    $loop .= '
    $tcp_content{$log_content} = $tcp_content_size{$log_content} =
      $tcp_hit_content{$log_content} = 0 unless defined
      $tcp_content{$log_content};
    $tcp_content{$log_content}++;
    $tcp_content_size{$log_content} += $log_size;
    $tcp_urlext{$urlext} = $tcp_urlext_size{$urlext} =
      $tcp_hit_urlext{$urlext} = 0 unless defined $tcp_urlext{$urlext};
    $tcp_urlext{$urlext}++;
    $tcp_urlext_size{$urlext} += $log_size;';
  }
  $loop .= '
    if ($log_hitfail =~ /^TCP\w+HIT/o) {
      $tcp_hit++;
      $tcp_hit_size += $log_size;
      $tcp_hit_time += $log_reqtime;';
  if ($opt_P) {
    $loop .= '
      $perf_tcp_hit_size{$perf_date} += $log_size;
      $perf_tcp_hit_time{$perf_date} += $log_reqtime;';
  }
  if ($opt_s) {
    $loop .= '
      $tcp_hit{$log_hitfail} = $tcp_hit_size{$log_hitfail} =
	$tcp_hit_time{$log_hitfail} = 0 unless defined $tcp_hit{$log_hitfail};
      $tcp_hit{$log_hitfail}++;
      $tcp_hit_size{$log_hitfail} += $log_size;
      $tcp_hit_time{$log_hitfail} += $log_reqtime;';
  }
  if ($opt_r) {
    $loop .= '
      $tcp_hit_requester{$requester}++;
      $tcp_hit_requester_size{$requester} += $log_size;';
  }
  if ($opt_d) {
    $loop .= '
      $tcp_hit_urlhost{$urlhost}++;
      $tcp_hit_urltld{$urltld}++;';
  }
  if ($opt_t) {
    $loop .= '
      $tcp_hit_content{$log_content}++;
      $tcp_hit_urlext{$urlext}++;
      $tcp_hit_urlprot{$urlprot}++;';
  }
  $loop .= '
    } elsif ($log_hier_method eq \'NONE\' or $log_hitfail =~ m#^ERR_#o) {
      $tcp_miss_none++;
      $tcp_miss_none_size += $log_size;
      $tcp_miss_none_time += $log_reqtime;';
  if ($opt_s) {
    $loop .= '
      $tcp_miss_none{$log_hitfail} = $tcp_miss_none_size{$log_hitfail} =
	$tcp_miss_none_time{$log_hitfail} = 0 unless defined
	$tcp_miss_none{$log_hitfail};
      $tcp_miss_none{$log_hitfail}++;
      $tcp_miss_none_size{$log_hitfail} += $log_size;
      $tcp_miss_none_time{$log_hitfail} += $log_reqtime;';
  }
  $loop .= '
    } else {
      $tcp_miss++;
      $tcp_miss_size += $log_size;
      $tcp_miss_time += $log_reqtime;';
  if ($opt_P) {
    $loop .= '
      $perf_tcp_miss_size{$perf_date} += $log_size;
      $perf_tcp_miss_time{$perf_date} += $log_reqtime;';
  }
  if ($opt_s) {
    $loop .= '
      $tcp_miss{$log_hitfail} = $tcp_miss_size{$log_hitfail} =
	$tcp_miss_time{$log_hitfail} = 0 unless defined
	$tcp_miss{$log_hitfail};
      $tcp_miss{$log_hitfail}++;
      $tcp_miss_size{$log_hitfail} += $log_size;
      $tcp_miss_time{$log_hitfail} += $log_reqtime;';
  }
  if ($opt_r) {
    $loop .= '
      $tcp_miss_requester{$requester} = $tcp_miss_requester_size{$requester} =
	0 unless defined $tcp_miss_requester{$requester};
      $tcp_miss_requester{$requester}++;
      $tcp_miss_requester_size{$requester} += $log_size;';
  }
  $loop .= '
    }
    if ($log_hier_method ne \'NONE\') {
      $hier++;
      $hier_size += $log_size;
      $hier_time += $log_reqtime;
      if ($log_hier_method =~ m#DIRECT#o or $log_hier_method =~ m#SOURCE_FASTEST#o) {
	$hier_direct++;
	$hier_direct_size += $log_size;
	$hier_direct_time += $log_reqtime;';
  if ($opt_P) {
    $loop .= '
	$perf_hier_direct_size{$perf_date} += $log_size;
	$perf_hier_direct_time{$perf_date} += $log_reqtime;';
  }
  if ($opt_s) {
    $loop .= '
	$hier_direct{$log_hier_method} = $hier_direct_size{$log_hier_method} =
	  $hier_direct_time{$log_hier_method} = 0 unless defined
	  $hier_direct{$log_hier_method};
	$hier_direct{$log_hier_method}++;
	$hier_direct_size{$log_hier_method} += $log_size;
	$hier_direct_time{$log_hier_method} += $log_reqtime;';
  }
  $loop .= '
      } elsif ($log_hier_method =~ m#CACHE_DIGEST_\w*HIT#o or $log_hier_method
	       =~ m#NEIGHBOR_\w*HIT#o or $log_hier_method =~ m#PARENT_\w*HIT#o
	       or $log_hier_method =~ m#SIBLING_\w*HIT#o) {
	$hier_sibling++;
	$hier_sibling_size += $log_size;
	$hier_sibling_time += $log_reqtime;';
  if ($opt_P) {
    $loop .= '
	$perf_hier_sibling_size{$perf_date} += $log_size;
	$perf_hier_sibling_time{$perf_date} += $log_reqtime;';
  }
  if ($opt_s) {
    $loop .= '
	$hier_sibling{$log_hier_method} = $hier_sibling_size{$log_hier_method}
	  = $hier_sibling_time{$log_hier_method} = 0 unless defined
	  $hier_sibling{$log_hier_method};
	$hier_sibling{$log_hier_method}++;
	$hier_sibling_size{$log_hier_method} += $log_size;
	$hier_sibling_time{$log_hier_method} += $log_reqtime;';
  }
  $loop .= '
	$hier_neighbor{$log_hier_host} = $hier_neighbor_size{$log_hier_host} =
	  $hier_neighbor_time{$log_hier_host} = 0 unless defined
	  $hier_neighbor{$log_hier_host};
	$hier_neighbor{$log_hier_host}++;
	$hier_neighbor_size{$log_hier_host} += $log_size;
	$hier_neighbor_time{$log_hier_host} += $log_reqtime;';
  if ($opt_s) {
    $loop .= '
	$hier_neighbor_status{$log_hier_host}{$log_hier_method} =
	  $hier_neighbor_status_size{$log_hier_host}{$log_hier_method} =
	  $hier_neighbor_status_time{$log_hier_host}{$log_hier_method} = 0
	  unless defined
	  $hier_neighbor_status{$log_hier_host}{$log_hier_method};
	$hier_neighbor_status{$log_hier_host}{$log_hier_method}++;
	$hier_neighbor_status_size{$log_hier_host}{$log_hier_method} +=
	  $log_size;
	$hier_neighbor_status_time{$log_hier_host}{$log_hier_method} +=
	  $log_reqtime;';
  }
  $loop .= '
      } elsif ($log_hier_method =~ m#CARP#o or $log_hier_method =~
	       m#CLOSEST_PARENT#o or $log_hier_method =~ m#DEFAULT_PARENT#o or
	       $log_hier_method =~ m#FIRST_UP_PARENT#o or $log_hier_method =~
	       m#PARENT_MISS#o or $log_hier_method =~ m#PASSTHROUGH_PARENT#o
	       or $log_hier_method =~ m#ROUNDROBIN_PARENT#o or
	       $log_hier_method =~ m#SINGLE_PARENT#o) {
	$hier_parent++;
	$hier_parent_size += $log_size;
	$hier_parent_time += $log_reqtime;';
  if ($opt_P) {
    $loop .= '
	$perf_hier_parent_size{$perf_date} += $log_size;
	$perf_hier_parent_time{$perf_date} += $log_reqtime;';
  }
  if ($opt_s) {
    $loop .= '
	$hier_parent{$log_hier_method} = $hier_parent_size{$log_hier_method} =
	  $hier_parent_time{$log_hier_method} = 0 unless defined
	  $hier_parent{$log_hier_method};
	$hier_parent{$log_hier_method}++;
	$hier_parent_size{$log_hier_method} += $log_size;
	$hier_parent_time{$log_hier_method} += $log_reqtime;';
  }
  $loop .= '
	$hier_neighbor{$log_hier_host} = $hier_neighbor_size{$log_hier_host} =
	  $hier_neighbor_time{$log_hier_host} = 0 unless defined
	  $hier_neighbor{$log_hier_host};
	$hier_neighbor{$log_hier_host}++;
	$hier_neighbor_size{$log_hier_host} += $log_size;
	$hier_neighbor_time{$log_hier_host} += $log_reqtime;';
  if ($opt_s) {
    $loop .= '
	$hier_neighbor_status{$log_hier_host}{$log_hier_method} =
	  $hier_neighbor_status_size{$log_hier_host}{$log_hier_method} =
	  $hier_neighbor_status_time{$log_hier_host}{$log_hier_method} = 0
	  unless defined
	  $hier_neighbor_status{$log_hier_host}{$log_hier_method};
	$hier_neighbor_status{$log_hier_host}{$log_hier_method}++;
	$hier_neighbor_status_size{$log_hier_host}{$log_hier_method} +=
	  $log_size;
	$hier_neighbor_status_time{$log_hier_host}{$log_hier_method} +=
	  $log_reqtime;';
  }
  $loop .= '
      } else {
	warn("unknown log_hier_method: \"$log_hier_method\"
	      Please report this to Calamaris-bug\@Cord.de\n");
      }
    }
  }
}'; 
  $time_run = time - $time_run;
  eval $loop;
  die $@ if $@;
  $time_run = time - $time_run;
}

### Yea! File read. Now for something completely different ;-)

if ($counter == 0) {
  print("\nno requests found\n");
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
$date_start = convertdate($time_begin);
$date_stop = convertdate($time_end);

print("Content-Type: text/html; charset=us-ascii
Content-Transfer-Encoding: 7bit\n") if ($opt_m and $opt_w);
printf("Subject:%sProxy-Report (%s - %s)\n\n", $hostname, $date_start,
       $date_stop) if ($opt_m);
if ($opt_w) {
  print("<html><head><title>Proxy-Report</title></head><body>\n");
  printf("<h1><a name=\"0\">%sProxy-Report (%s - %s)</a></h1>\n", $hostname,
	 $date_start, $date_stop);
  print("<hr><ul>\n");
  outref('Summary', 1);
  outref('Incoming request peak per protocol', 2) if ($opt_p);
  outref('Incoming requests by method', 3);
  outref('Incoming UDP-requests by status', 4);
  outref('Incoming TCP-requests by status', 5);
  outref('Outgoing requests by status', 6);
  outref('Outgoing requests by destination', 7);
  if ($opt_d) {
    outref('Request-destinations by 2ndlevel-domain', 8);
    outref('Request-destinations by toplevel-domain', 9);
  }
  if ($opt_t) {
    outref('TCP-Request-protocol', 10);
    outref('Requested content-type', 11);
    outref('Requested extensions', 12);
  }
  if ($opt_r) {
    outref('Incoming UDP-requests by host', 13);
    outref('Incoming TCP-requests by host', 14);
  }
  outref("Performance in $opt_P minute steps", 15) if ($opt_P);
  print("</ul><hr>\n");
} else {
  printf("\n%sProxy-Report (%s - %s)\n", $hostname, $date_start, $date_stop);
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
if ($opt_p) {
  writecache(B, $peak_udp_sec, $peak_udp_sec_time, $peak_udp_min,
	   $peak_udp_min_time, $peak_udp_hour, $peak_udp_hour_time,
	   $peak_tcp_sec, $peak_tcp_sec_time, $peak_tcp_min,
	   $peak_tcp_min_time, $peak_tcp_hour, $peak_tcp_hour_time,
	   $peak_all_sec, $peak_all_sec_time, $peak_all_min,
	   $peak_all_min_time, $peak_all_hour, $peak_all_hour_time);
  outtitle('Incoming request peak per protocol', 2);
  outstart();
  outheader('prt', ' sec', 'peak begins at', ' min', 'peak begins at', ' hour',
	    'peak begins at');
  outseperator();
  outline('UDP', $peak_udp_sec, convertdate($peak_udp_sec_time),
	  $peak_udp_min, convertdate($peak_udp_min_time), $peak_udp_hour,
	  convertdate($peak_udp_hour_time));
  outline('TCP', $peak_tcp_sec, convertdate($peak_tcp_sec_time),
	  $peak_tcp_min, convertdate($peak_tcp_min_time), $peak_tcp_hour,
	  convertdate($peak_tcp_hour_time));
  outseperator();
  outline('ALL', $peak_all_sec, convertdate($peak_all_sec_time),
	  $peak_all_min, convertdate($peak_all_min_time), $peak_all_hour,
	  convertdate($peak_all_hour_time));
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
  foreach $method (sort {${"method$sortorder"}{$b} <=>
			 ${"method$sortorder"}{$a}} keys(%method)) {
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
    foreach $hitfail (sort {${"udp_hit$sortorder"}{$b} <=>
			    ${"udp_hit$sortorder"}{$a}} keys(%udp_hit)) {
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
    foreach $hitfail (sort {${"udp_miss$sortorder"}{$b} <=>
			    ${"udp_miss$sortorder"}{$a}} keys(%udp_miss)) {
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
    foreach $hitfail (sort {${"tcp_hit$sortorder"}{$b} <=>
			    ${"tcp_hit$sortorder"}{$a}} keys(%tcp_hit)) {
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
    foreach $hitfail (sort {${"tcp_miss$sortorder"}{$b} <=>
			    ${"tcp_miss$sortorder"}{$a}} keys(%tcp_miss)) {
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
    foreach $hitfail (sort {${"tcp_miss_none$sortorder"}{$b} <=>
			    ${"tcp_miss_none$sortorder"}{$a}}
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
    foreach $hitfail (sort {${"hier_direct$sortorder"}{$b} <=>
			    ${"hier_direct$sortorder"}{$a}}
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
    foreach $hitfail (sort {${"hier_sibling$sortorder"}{$b} <=>
			    ${"hier_sibling$sortorder"}{$a}}
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
	    $hier_parent_size / (1024 * $hier_parent_time));
    foreach $hitfail (sort {${"hier_parent$sortorder"}{$b} <=>
			    ${"hier_parent$sortorder"}{$a}}
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
	  (1024 * $hier_direct_time)) unless $hier_direct == 0;
  foreach $neighbor (sort {${"hier_neighbor$sortorder"}{$b} <=>
			   ${"hier_neighbor$sortorder"}{$a}}
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
    foreach $status (sort {${"hier_neighbor_status$sortorder"}{$neighbor}{$b}
			   <=>
			   ${"hier_neighbor_status$sortorder"}{$neighbor}{$a}}
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
if ($opt_d) {
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
    foreach $urlhost (sort {${"tcp_urlhost$sortorder"}{$b} <=>
			    ${"tcp_urlhost$sortorder"}{$a}}
		      keys(%tcp_urlhost)) {
      next if $urlhost eq '<other>';
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
    foreach $urltld (sort {${"tcp_urltld$sortorder"}{$b} <=>
			   ${"tcp_urltld$sortorder"}{$a}}
		     keys(%tcp_urltld)) {
      next if $urltld eq '<other>';
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

if ($opt_t) {
  if ($tcp == 0) {
    outtitle('TCP-Request-protocol: none', 10);
  } else {
    outtitle('TCP-Request-protocol', 10);
    outstart();
    outheader('protocol',' request','% ','  kByte','% ','hit-%');
    outseperator();
    foreach $urlprot (sort {${"tcp_urlprot$sortorder"}{$b} <=>
			    ${"tcp_urlprot$sortorder"}{$a}}
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
    foreach $content (sort {${"tcp_content$sortorder"}{$b} <=>
			    ${"tcp_content$sortorder"}{$a}}
		      keys(%tcp_content)) {
      next if $content eq '<other>';
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
    foreach $urlext (sort {${"tcp_urlext$sortorder"}{$b} <=>
			   ${"tcp_urlext$sortorder"}{$a}} keys(%tcp_urlext)) {
      next if $urlext eq '<other>';
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
if ($opt_r) {
  if ($udp == 0) {
    outtitle('Incoming UDP-requests by host: none', 13);
  } else {
    outtitle('Incoming UDP-requests by host', 13);
    outstart();
    outheader('host',' request','hit-%','  kByte','hit-%','msec',' kB/sec');
    outseperator();
    foreach $requester (sort {${"udp_requester$sortorder"}{$b} <=>
			      ${"udp_requester$sortorder"}{$a}}
			keys(%udp_requester)) {
      writecache(S, $requester, $udp_requester{$requester},
		 $udp_requester_size{$requester},
		 $udp_requester_time{$requester},
		 $udp_hit_requester{$requester},
		 $udp_hit_requester_size{$requester});
      outline(getfqdn($requester), $udp_requester{$requester}, 100 *
	      $udp_hit_requester{$requester} / $udp_requester{$requester},
	      $udp_requester_size{$requester} / 1024, 100 *
	      $udp_hit_requester_size{$requester} /
	      $udp_requester_size{$requester}, $udp_requester_time{$requester}
	      / $udp_requester{$requester}, 1000 *
	      $udp_requester_size{$requester} / (1024 *
	      $udp_requester_time{$requester}));
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
    foreach $requester (sort {${"tcp_requester$sortorder"}{$b} <=>
			      ${"tcp_requester$sortorder"}{$a}}
			keys(%tcp_requester)) {
      next if $requester eq '<other>';
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
      outline(getfqdn($requester), $tcp_requester{$requester}, 100 *
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

@format=(15,8,6,'kbs','kbs','kbs','kbs','kbs','kbs');
if ($opt_P) {
  outtitle("Performance in $opt_P minute steps", 15); outstart();
  outheader('', '', '', 'incomin', '   hit', '  miss', ' direct', 'sibling',
	    ' fetch');
  outheader('date', ' request', ' MByte', ' kB/sec', ' kB/sec', ' kB/sec',
	    ' kB/sec', ' kB/sec', ' kB/sec');
  outseperator();
  foreach $perf_date (sort keys(%perf_counter)) {
    writecache(U, $perf_date, $perf_counter{$perf_date},
	       $perf_size{$perf_date}, $perf_time{$perf_date},
	       $perf_tcp_hit_size{$perf_date}, $perf_tcp_hit_time{$perf_date},
	       $perf_tcp_miss_size{$perf_date},
	       $perf_tcp_miss_time{$perf_date},
	       $perf_hier_direct_size{$perf_date},
	       $perf_hier_direct_time{$perf_date},
	       $perf_hier_sibling_size{$perf_date},
	       $perf_hier_sibling_time{$perf_date},
	       $perf_hier_parent_size{$perf_date},
	       $perf_hier_parent_time{$perf_date});

    outline(substr(convertdate($perf_date),0,15), $perf_counter{$perf_date},
	    $perf_size{$perf_date} / (1024 * 1024),
	    removezerotimes($perf_size{$perf_date}, $perf_time{$perf_date}),
	    removezerotimes($perf_tcp_hit_size{$perf_date},
			    $perf_tcp_hit_time{$perf_date}),
	    removezerotimes($perf_tcp_miss_size{$perf_date},
			    $perf_tcp_miss_time{$perf_date}),
	    removezerotimes($perf_hier_direct_size{$perf_date},
			    $perf_hier_direct_time{$perf_date}),
	    removezerotimes($perf_hier_sibling_size{$perf_date},
			    $perf_hier_sibling_time{$perf_date}),
	    removezerotimes($perf_hier_parent_size{$perf_date},
			    $perf_hier_parent_time{$perf_date}));
  }
  outseperator();
  outline('overall', $counter, $size / (1024 * 1024),
	  removezerotimes($size, $time),
	  removezerotimes($tcp_hit_size, $tcp_hit_time),
	  removezerotimes($tcp_miss_size, $tcp_miss_time),
	  removezerotimes($hier_direct_size, $hier_direct_time),
	  removezerotimes($hier_sibling_size, $hier_sibling_time),
	  removezerotimes($hier_parent_size, $hier_parent_time));
  outstop();
}
close(CACHE);

if ($opt_w) {
  print("<address>$COPYRIGHT</address>\n</body></html>\n");
} else {
  print("\n\n\n$COPYRIGHT\n");
}

sub removezerotimes {
  my ($size) = shift (@_);
  my ($time) = shift (@_);
  if ($size == 0) {
    return '-';
  } else {
    return 1000 * $size / (1024 * $time);
  }
}

sub getfqdn {
  my ($host) = @_;
  if ($opt_n) {
    return $host;
  } elsif ($host =~ /^([^@]+@)?(([0-9][0-9]{0,2}\.){3}[0-9][0-9]{0,2}$)/) {
    $hostcache{$2} = addtonam($2) unless defined $hostcache{$2};
    return $1 . $hostcache{$2} if defined $1;
    return $hostcache{$2};
  } else {
    return $host;
  }
}

sub addtonam {
  my ($address) = shift (@_);
  my (@octets);
  my ($hostname, $aliases, $type, $len, $addr);
  my ($ip_number);
  @octets = split '\.', $address;
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
    } elsif ($format[$no] eq '%') {
      print(' ' x (6 - length($p)), substr($p,0,6), ' ');
    } elsif ($format[$no] eq 'kbs') {
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
	if ($print eq '' or $print eq '-') {
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
      } elsif ($format[$no] eq '%') {
	if ($print eq ' ') {
	  printf(' ' x 7);
	} else {
	  printf("%6.2f ", $print);
	}
      } elsif ($format[$no] eq 'kbs') {
	if ($print eq '-') {
	  printf('    -   ');
	} else {
	  printf("%7.2f ", $print);
	}
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
